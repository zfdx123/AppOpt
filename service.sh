#!/system/bin/sh
# ============================================================
# LOVE 8Gen3 线程调度模块主服务脚本
#
# 相对于旧版的关键改动：
#   1. 【重要】删除 core_ctl min_cpus=max_cpus 钉核逻辑
#      旧代码把每个 cluster 的 min_cpus 强制写成 max_cpus 并 chmod a-w 锁只读，
#      导致 hotplug 彻底失效、8 核永久通电，空载功耗和发热显著抬升，而且
#      锁上之后再没有任何东西能改回来，必须重启。
#   2. AppOpt 改为守护循环 + 自动重启（旧版只 nohup 一次，进程死后整个
#      模块静默失效 —— 实测设备上就是这么死了 6 天 23 小时）。
#   3. 启动日志不再丢：旧版把 stdout/stderr 全部重定向到 /dev/null，
#      出问题完全看不到；现在写到 log/AppOpt.log，并加了轮转。
#   4. 修正降级分支的参数：旧版传的 -t 75000 会被 AppOpt 当成"配置文件路径"，
#      直接覆盖掉真正的 -t <tuber.conf>，导致配置读不到。
#      温度参数应使用 -T（毫摄氏度）。
#   5. 启动前清理残留的 AppOpt 实例，避免重复拉起。
# ============================================================

MODDIR=${0%/*}
MODULE_PROP="$MODDIR/module.prop"
CONFIG_FILE="$MODDIR/applist.conf"
LOG_DIR="$MODDIR/log"
CONFIGTUBER_FILE="$MODDIR/tuber.conf"
APPOPT_LOG="$LOG_DIR/AppOpt.log"

# 温控触发温度（毫摄氏度），传给 AppOpt 的 -T；
# 留空则完全以 tuber.conf 的 [power] temp_limit_mc 为准。
TEMP_LIMIT_MC=75000

wait_sys_boot_completed() {
    local i=9
    until [ "$(getprop sys.boot_completed)" == "1" ] || [ $i -le 0 ]; do
        i=$((i-1))
        sleep 9
    done
}

love_log() {
    local module="$1"
    local msg="$2"
    local log_file="$LOG_DIR/${module}.log"
    mkdir -p "$LOG_DIR"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $msg" >> "$log_file"
    local lines=$(wc -l < "$log_file" 2>/dev/null)
    [ -n "$lines" ] && [ "$lines" -gt 500 ] 2>/dev/null && {
        tail -200 "$log_file" > "${log_file}.tmp"
        mv "${log_file}.tmp" "$log_file"
    }
}

cleanup_old_logs() {
    mkdir -p "$LOG_DIR"
    find "$LOG_DIR" -name "*.log" -type f -mtime +7 -delete 2>/dev/null
    love_log "service" "已清理7天前的旧日志"
}

# 轮转 AppOpt 自己的输出日志（常驻进程会一直写）
rotate_appopt_log() {
    [ -f "$APPOPT_LOG" ] || return 0
    local lines
    lines=$(wc -l < "$APPOPT_LOG" 2>/dev/null)
    [ -n "$lines" ] && [ "$lines" -gt 2000 ] 2>/dev/null && {
        tail -500 "$APPOPT_LOG" > "${APPOPT_LOG}.tmp" 2>/dev/null && \
            mv "${APPOPT_LOG}.tmp" "$APPOPT_LOG" 2>/dev/null
    }
}

# 选出可用的 AppOpt 二进制
pick_appopt() {
    if [ -x "$MODDIR/AppOpt" ]; then
        echo "$MODDIR/AppOpt"
    elif [ -x "$MODDIR/bin/arm64-v8a/AppOpt" ]; then
        echo "$MODDIR/bin/arm64-v8a/AppOpt"
    elif [ -x "$MODDIR/bin/armeabi-v7a/AppOpt" ]; then
        echo "$MODDIR/bin/armeabi-v7a/AppOpt"
    elif [ -x "$MODDIR/bin/x86_64/AppOpt" ]; then
        echo "$MODDIR/bin/x86_64/AppOpt"
    elif [ -x "$MODDIR/bin/x86/AppOpt" ]; then
        echo "$MODDIR/bin/x86/AppOpt"
    fi
}

start_appopt() {
    local bin="$1"
    local pid

    # 清理残留实例，避免重复拉起
    for pid in $(pidof AppOpt 2>/dev/null); do
        kill -TERM "$pid" 2>/dev/null
        love_log "service" "已终止残留 AppOpt 实例 PID=$pid"
    done
    sleep 1

    mkdir -p "$LOG_DIR"

    # 守护循环：AppOpt 退出就重启，并把 stdout/stderr 落盘
    # （旧版重定向到 /dev/null，进程挂了什么都查不到）
    (
        while true; do
            rotate_appopt_log
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] === AppOpt 启动: $bin ===" >> "$APPOPT_LOG"
            "$bin" -c "$CONFIG_FILE" -t "$CONFIGTUBER_FILE" -p -T "$TEMP_LIMIT_MC" >> "$APPOPT_LOG" 2>&1
            rc=$?
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] === AppOpt 退出 rc=$rc，5s 后重启 ===" >> "$APPOPT_LOG"
            sleep 5
        done
    ) &
    love_log "service" "AppOpt 守护循环已启动 PID=$!"
}

main() {
    love_log "service" "模块服务启动"

    cleanup_old_logs

    local bin
    bin="$(pick_appopt)"
    if [ -n "$bin" ]; then
        chmod 755 "$bin" 2>/dev/null
        start_appopt "$bin"
    else
        love_log "service" "错误: 未找到可执行的 AppOpt"
    fi

    # 注意：这里刻意不再碰 core_ctl/min_cpus。
    # 旧版把 min_cpus 写成 max_cpus 并 chmod a-w，会让 hotplug 永久失效；
    # 内核的 hotplug 调度本身已经够用，不需要也不应该锁死。
    love_log "service" "已跳过 core_ctl 钉核（改为由内核 hotplug 自主调度）"
}

wait_sys_boot_completed
cd "$MODDIR"
main
