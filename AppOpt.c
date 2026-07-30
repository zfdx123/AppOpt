#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define VERSION            "1.6.0"
#define BASE_CPUSET        "/dev/cpuset/AppOpt"
#define MAX_PKG_LEN        128
#define MAX_THREAD_LEN     32
#define MAX_CLUSTERS        4
#define THERMAL_ZONE_BASE  "/sys/class/thermal/thermal_zone"
#define TOP_APP_CPUSET     "/dev/cpuset/top-app"
#define KMOD_ENABLED      "/sys/kernel/abk_soc_opt/enabled"
#define KMOD_FREQ_LIMITS  "/sys/kernel/abk_soc_opt/freq_limits"
#define KMOD_POLL_MS      "/sys/kernel/abk_soc_opt/poll_ms"

typedef struct {
    char pkg[MAX_PKG_LEN];
    char thread[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
} AffinityRule;

typedef struct {
    pid_t tid;
    char name[MAX_THREAD_LEN];
    char cpuset_dir[256];
    cpu_set_t cpus;
} ThreadInfo;

typedef struct {
    pid_t pid;
    char pkg[MAX_PKG_LEN];
    char base_cpuset[128];
    cpu_set_t base_cpus;
    ThreadInfo* threads;
    size_t num_threads;
    size_t threads_cap;
    AffinityRule** thread_rules;
    size_t num_thread_rules;
    size_t thread_rules_cap;
} ProcessInfo;

typedef struct {
    cpu_set_t cpus;
    int max_freq;
    char name[16];
} CpuCluster;

typedef struct {
    cpu_set_t present_cpus;
    char present_str[128];
    char mems_str[32];
    bool cpuset_enabled;
    int base_cpuset_fd;
    CpuCluster clusters[MAX_CLUSTERS];
    int num_clusters;
    char soc_name[64];
    bool is_sm8650;
    bool power_save_mode;
    int temp_limit_mc;
    int max_freq_limit;
    int thermal_freq_limit;
    int cluster_freqs[MAX_CLUSTERS];         // per-cluster日常限频, 0=不限制
    int thermal_cluster_freqs[MAX_CLUSTERS]; // per-cluster超温限频
    bool use_cluster_freqs;
    bool use_thermal_cluster_freqs;
    int poll_ms;                               // 内核模块轮询周期(ms), -1=不写入
    int display_off_freqs[MAX_CLUSTERS];       // 息屏时 per-cluster 频率
    int display_off_poll_ms;                   // 息屏时 poll_ms, -1=不写入
    bool use_display_off_freqs;
} CpuTopology;

typedef struct {
    atomic_int ref_count;
    AffinityRule* rules;
    size_t num_rules;
    time_t mtime;
    CpuTopology topo;
    char** pkgs;
    size_t num_pkgs;
    char config_file[4096];
} AppConfig;

typedef struct {
    ProcessInfo* procs;
    size_t num_procs;
    size_t procs_cap;
    int last_proc_count;
    bool scan_all_proc;
    pid_t* tracked_pids;
    size_t num_tracked_pids;
    size_t tracked_pids_cap;
} ProcCache;

static atomic_int config_updated = ATOMIC_VAR_INIT(0);
static int inotify_fd = -1;
static int inotify_wd = -1;
static int inotify_supported = 0;
static _Atomic(AppConfig*) current_config = NULL;

static char* strtrim(char* s) {
    char* end;
    while (isspace(*s)) s++;
    if (*s == 0) return s;
    end = s + strlen(s) - 1;
    while (end > s && isspace(*end)) end--;
    *(end + 1) = 0;
    return s;
}

static bool read_file(int dir_fd, const char* filename, char* buf, size_t buf_size) {
    int fd = openat(dir_fd, filename, O_RDONLY | O_CLOEXEC);
    if (fd == -1) return false;
    ssize_t n = read(fd, buf, buf_size - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    return true;
}

static bool write_file(int dir_fd, const char* filename, const char* content, int flags) {
    int fd = openat(dir_fd, filename, flags | O_CLOEXEC, 0644);
    if (fd == -1) return false;
    ssize_t n = write(fd, content, strlen(content));
    close(fd);
    return (n == (ssize_t)strlen(content));
}

static int build_str(char *dest, size_t dest_size, ...) {
    va_list args;
    const char *segment;
    char *p = dest;
    size_t remaining = dest_size - 1;
    va_start(args, dest_size);
    while ((segment = va_arg(args, const char *)) != NULL) {
        size_t len = strlen(segment);
        if (len > remaining) {
            va_end(args);
            return 0;
        }
        memcpy(p, segment, len);
        p += len;
        remaining -= len;
    }
    *p = '\0';
    va_end(args);
    return 1;
}

static void parse_cpu_ranges(const char* spec, cpu_set_t* set, const cpu_set_t* present) {
    if (!spec) return;
    char* copy = strdup(spec);
    if (!copy) return;
    char* s = copy;

    while (*s) {
        char* end;
        unsigned long a = strtoul(s, &end, 10);
        if (end == s) {
            s++;
            continue;
        }

        unsigned long b = a;
        if (*end == '-') {
            s = end + 1;
            b = strtoul(s, &end, 10);
            if (end == s) b = a;
        }

        if (a > b) { unsigned long t = a; a = b; b = t; }
        for (unsigned long i = a; i <= b && i < CPU_SETSIZE; i++) {
            if (present && !CPU_ISSET(i, present)) continue;
            CPU_SET(i, set);
        }

        s = (*end == ',') ? end + 1 : end;
    }
    free(copy);
}

static char* cpu_set_to_str(const cpu_set_t *set) {
    size_t buf_size = 8 * CPU_SETSIZE;
    char *buf = malloc(buf_size);
    if (!buf) return NULL;
    int start = -1, end = -1;
    char *p = buf;
    size_t remain = buf_size - 1;
    bool first = true;

    for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, set)) {
            if (start == -1) {
                start = end = i;
            } else if (i == end + 1) {
                end = i;
            } else {
                int needed;
                if (start == end) {
                    needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start);
                } else {
                    needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, end);
                }
                if (needed < 0 || (size_t)needed > remain) {
                    free(buf);
                    return NULL;
                }
                p += needed;
                remain -= needed;
                start = end = i;
                first = false;
            }
        }
    }
    if (start != -1) {
        int needed;
        if (start == end) {
            needed = snprintf(p, remain + 1, "%s%d", first ? "" : ",", start);
        } else {
            needed = snprintf(p, remain + 1, "%s%d-%d", first ? "" : ",", start, end);
        }
        if (needed < 0 || (size_t)needed > remain) {
            free(buf);
            return NULL;
        }
        p += needed;
    }
    *p = '\0';
    return buf;
}

static bool create_cpuset_dir(const char *path, const char *cpus, const char *mems) {
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return false;
    if (chmod(path, 0755) != 0) return false;
    if (chown(path, 0, 0) != 0) return false;

    char cpus_path[256];
    build_str(cpus_path, sizeof(cpus_path), path, "/cpus", NULL);
    if (!write_file(AT_FDCWD, cpus_path, cpus, O_WRONLY | O_CREAT | O_TRUNC)) return false;

    char mems_path[256];
    build_str(mems_path, sizeof(mems_path), path, "/mems", NULL);
    return write_file(AT_FDCWD, mems_path, mems, O_WRONLY | O_CREAT | O_TRUNC);
}

/* ---- 8 Gen 3 优化: 前向声明 ---- */
static void detect_soc(CpuTopology* topo);
static void analyze_cpu_clusters(CpuTopology* topo);

static CpuTopology init_cpu_topo(void) {
    CpuTopology topo = { .cpuset_enabled = false, .base_cpuset_fd = -1 };
    CPU_ZERO(&topo.present_cpus);

    if (read_file(AT_FDCWD, "/sys/devices/system/cpu/present", topo.present_str, sizeof(topo.present_str))) {
        strtrim(topo.present_str);
    }
    parse_cpu_ranges(topo.present_str, &topo.present_cpus, NULL);

    if (access("/dev/cpuset", F_OK) != 0) return topo;

    if (create_cpuset_dir(BASE_CPUSET, topo.present_str, "0")) {
        topo.base_cpuset_fd = open(BASE_CPUSET, O_RDONLY | O_DIRECTORY);
        if (topo.base_cpuset_fd != -1) topo.cpuset_enabled = true;
    }

    char mems_path[256];
    build_str(mems_path, sizeof(mems_path), BASE_CPUSET, "/mems", NULL);
    if (!read_file(AT_FDCWD, mems_path, topo.mems_str, sizeof(topo.mems_str))) {
        build_str(topo.mems_str, sizeof(topo.mems_str), "0", NULL);
    } else {
        strtrim(topo.mems_str);
    }

    detect_soc(&topo);
    analyze_cpu_clusters(&topo);

    return topo;
}

static void detect_soc(CpuTopology* topo) {
    topo->soc_name[0] = '\0';
    topo->is_sm8650 = false;

    char buf[128] = {0};
    if (read_file(AT_FDCWD, "/sys/devices/soc0/machine", buf, sizeof(buf))) {
        strtrim(buf);
        build_str(topo->soc_name, sizeof(topo->soc_name), buf, NULL);
    }
    if (!topo->soc_name[0]) {
        FILE* fp = fopen("/proc/cpuinfo", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "Hardware", 8) == 0) {
                    char* colon = strchr(line, ':');
                    if (colon) {
                        char* val = strtrim(colon + 1);
                        build_str(topo->soc_name, sizeof(topo->soc_name), val, NULL);
                    }
                    break;
                }
            }
            fclose(fp);
        }
    }
    if (strstr(topo->soc_name, "SM8650") || strstr(topo->soc_name, "sm8650"))
        topo->is_sm8650 = true;
}

static int cmp_cluster_freq(const void* a, const void* b) {
    return ((const CpuCluster*)a)->max_freq - ((const CpuCluster*)b)->max_freq;
}

static void analyze_cpu_clusters(CpuTopology* topo) {
    topo->num_clusters = 0;
    cpu_set_t seen;
    CPU_ZERO(&seen);

    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &topo->present_cpus)) continue;
        if (CPU_ISSET(cpu, &seen)) continue;

        char path[128];
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
        char buf[32] = {0};
        int max_freq = 0;
        if (read_file(AT_FDCWD, path, buf, sizeof(buf)))
            max_freq = atoi(buf);
        if (max_freq <= 0) {
            snprintf(path, sizeof(path),
                     "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
            if (read_file(AT_FDCWD, path, buf, sizeof(buf)))
                max_freq = atoi(buf);
        }
        if (max_freq <= 0) max_freq = 1000000;

        cpu_set_t cluster_cpus;
        CPU_ZERO(&cluster_cpus);
        for (int cpu2 = cpu; cpu2 < CPU_SETSIZE; cpu2++) {
            if (!CPU_ISSET(cpu2, &topo->present_cpus)) continue;
            if (CPU_ISSET(cpu2, &seen)) continue;
            snprintf(path, sizeof(path),
                     "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu2);
            char buf2[32] = {0};
            int freq2 = 0;
            if (read_file(AT_FDCWD, path, buf2, sizeof(buf2)))
                freq2 = atoi(buf2);
            if (freq2 <= 0) {
                snprintf(path, sizeof(path),
                         "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu2);
                if (read_file(AT_FDCWD, path, buf2, sizeof(buf2)))
                    freq2 = atoi(buf2);
            }
            if (freq2 == max_freq || abs(freq2 - max_freq) < 50000) {
                CPU_SET(cpu2, &cluster_cpus);
                CPU_SET(cpu2, &seen);
            }
        }
        if (topo->num_clusters >= MAX_CLUSTERS) break;
        if (CPU_COUNT(&cluster_cpus) == 0) continue;
        topo->clusters[topo->num_clusters].cpus = cluster_cpus;
        topo->clusters[topo->num_clusters].max_freq = max_freq;
        topo->num_clusters++;
    }

    qsort(topo->clusters, topo->num_clusters, sizeof(CpuCluster), cmp_cluster_freq);

    const char* full_names[] = {"little", "mid", "big", "prime"};
    int start = (topo->num_clusters >= 4) ? 0 : (4 - topo->num_clusters);
    for (int i = 0; i < topo->num_clusters && i < MAX_CLUSTERS; i++) {
        const char* n = (topo->num_clusters == 1) ? "all" : full_names[start + i];
        build_str(topo->clusters[i].name, sizeof(topo->clusters[i].name), n, NULL);
    }
}

static __attribute__((unused)) bool is_cpu_in_cluster(const CpuTopology* topo, int cpu, const char* name) {
    for (int i = 0; i < topo->num_clusters; i++) {
        if (strcmp(topo->clusters[i].name, name) == 0)
            return CPU_ISSET(cpu, &topo->clusters[i].cpus);
    }
    return false;
}

static int read_thermal_max(void) {
    int max_temp = 0;
    for (int i = 0; i < 30; i++) {
        char path[64];
        // Check type first — only read temp for relevant zones
        snprintf(path, sizeof(path), THERMAL_ZONE_BASE "%d/type", i);
        char tbuf[64] = {0};
        if (!read_file(AT_FDCWD, path, tbuf, sizeof(tbuf))) continue;
        strtrim(tbuf);
        bool relevant = (strstr(tbuf, "cpu") || strstr(tbuf, "soc") ||
                         strstr(tbuf, "skin") || strstr(tbuf, "battery") ||
                         strstr(tbuf, "pa") || strstr(tbuf, "xo") ||
                         strstr(tbuf, "gpu"));
        if (!relevant) continue;

        snprintf(path, sizeof(path), THERMAL_ZONE_BASE "%d/temp", i);
        char buf[32] = {0};
        if (read_file(AT_FDCWD, path, buf, sizeof(buf))) {
            int t = atoi(buf);
            if (t > max_temp) max_temp = t;
        }
    }
    return max_temp;
}

static void apply_freq_limit(int freq_khz, const CpuTopology* topo) {
    if (freq_khz <= 0) return;
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", freq_khz);

    // 写 policy 级节点
    for (int policy = 1; policy <= 8; policy++) {
        char path[128];
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpufreq/policy%d/scaling_max_freq", policy);
        write_file(AT_FDCWD, path, buf, O_WRONLY | O_TRUNC);
    }

    // 写 per-CPU 节点兜底
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &topo->present_cpus)) continue;
        char path[128];
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
        write_file(AT_FDCWD, path, buf, O_WRONLY | O_TRUNC);
    }
}

static void apply_cluster_freqs(const int freqs[MAX_CLUSTERS], const CpuTopology* topo) {
    char buf[32];
    for (int c = 0; c < topo->num_clusters && c < MAX_CLUSTERS; c++) {
        if (freqs[c] <= 0) continue;
        snprintf(buf, sizeof(buf), "%d", freqs[c]);
        for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
            if (CPU_ISSET(cpu, &topo->clusters[c].cpus)) {
                char path[128];
                snprintf(path, sizeof(path),
                         "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
                write_file(AT_FDCWD, path, buf, O_WRONLY | O_TRUNC);
            }
        }
    }
}

/* --- 内核模块集成 (abk_soc_opt) ------------------------------------ */

static bool kmod_available(void) {
    return access(KMOD_ENABLED, W_OK) == 0;
}

static void kmod_write_freqs(const int freqs[MAX_CLUSTERS],
                              int count, const CpuTopology* topo) {
    if (!kmod_available()) return;
    (void)topo;

    /* 跳过全零（无限制，不应写入内核模块） */
    bool all_zero = true;
    for (int i = 0; i < count; i++)
        if (freqs[i] != 0) { all_zero = false; break; }
    if (all_zero) return;

    char buf[128];
    int pos = 0;
    for (int i = 0; i < count && pos < (int)sizeof(buf) - 1; i++) {
        if (i > 0 && pos < (int)sizeof(buf) - 1) buf[pos++] = ',';
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%d", freqs[i]);
    }
    if (pos > 0)
        write_file(AT_FDCWD, KMOD_FREQ_LIMITS, buf, O_WRONLY | O_TRUNC);
}

static void kmod_write_poll_ms(int ms) {
    if (ms < 0 || !kmod_available()) return;
    char buf[16];
    snprintf(buf, sizeof(buf), "%d", ms);
    write_file(AT_FDCWD, KMOD_POLL_MS, buf, O_WRONLY | O_TRUNC);
}

static bool is_display_off(void) {
    const char* paths[] = {
        "/sys/class/backlight/panel0-backlight/brightness",
        "/sys/class/backlight/backlight/brightness",
        NULL
    };
    char buf[16] = {0};
    for (const char** p = paths; *p; p++) {
        if (read_file(AT_FDCWD, *p, buf, sizeof(buf)))
            return strtol(buf, NULL, 10) == 0;
    }
    return false;
}

static int read_top_app_pids(pid_t* out, int max_out) {
    int count = 0;
    char buf[4096];
    if (!read_file(AT_FDCWD, TOP_APP_CPUSET "/tasks", buf, sizeof(buf)))
        return 0;
    char* p = buf;
    while (*p && count < max_out) {
        char* end;
        long pid = strtol(p, &end, 10);
        if (end != p && pid > 0) {
            out[count++] = (pid_t)pid;
        }
        p = (*end) ? end + 1 : end;
    }
    return count;
}

static bool is_top_app(pid_t pid, const pid_t* top_pids, int num_top) {
    for (int i = 0; i < num_top; i++) {
        if (top_pids[i] == pid) return true;
    }
    return false;
}

static void apply_power_save(ProcCache* cache, const CpuTopology* topo) {
    if (!topo->power_save_mode) return;

    pid_t top_pids[64];
    int num_top = read_top_app_pids(top_pids, 64);
    bool thermal_throttle = false;
    if (topo->temp_limit_mc > 0) {
        int cur_temp = read_thermal_max();
        if (cur_temp > topo->temp_limit_mc) thermal_throttle = true;
    }

    for (size_t i = 0; i < cache->num_procs; i++) {
        ProcessInfo* proc = &cache->procs[i];
        bool foreground = is_top_app(proc->pid, top_pids, num_top);

        cpu_set_t allowed;
        CPU_ZERO(&allowed);

        if (thermal_throttle) {
            // Force little cluster only
            for (int c = 0; c < topo->num_clusters; c++) {
                if (strcmp(topo->clusters[c].name, "little") == 0 ||
                    strcmp(topo->clusters[c].name, "all") == 0) {
                    CPU_OR(&allowed, &allowed, &topo->clusters[c].cpus);
                }
            }
        } else if (foreground) {
            // Foreground: little + mid + big (exclude prime)
            for (int c = 0; c < topo->num_clusters; c++) {
                if (strcmp(topo->clusters[c].name, "prime") != 0) {
                    CPU_OR(&allowed, &allowed, &topo->clusters[c].cpus);
                }
            }
        } else {
            // Background: little + mid only
            for (int c = 0; c < topo->num_clusters; c++) {
                if (strcmp(topo->clusters[c].name, "little") == 0 ||
                    strcmp(topo->clusters[c].name, "mid") == 0 ||
                    strcmp(topo->clusters[c].name, "all") == 0) {
                    CPU_OR(&allowed, &allowed, &topo->clusters[c].cpus);
                }
            }
        }

        // Apply to threads — thermal throttle overrides everything
        for (size_t j = 0; j < proc->num_threads; j++) {
            ThreadInfo* ti = &proc->threads[j];
            if (CPU_COUNT(&ti->cpus) == 0) continue;

            if (thermal_throttle) {
                // 超温强制：无条件锁小核，覆盖所有规则
                ti->cpus = allowed;
                char* dir_str = cpu_set_to_str(&allowed);
                if (dir_str) {
                    build_str(ti->cpuset_dir, sizeof(ti->cpuset_dir), dir_str, NULL);
                    free(dir_str);
                }
                continue;
            }

            // 正常模式：不覆盖显式线程规则
            bool has_thread_rule = false;
            for (size_t k = 0; k < proc->num_thread_rules; k++) {
                if (fnmatch(proc->thread_rules[k]->thread, ti->name, FNM_NOESCAPE) == 0) {
                    has_thread_rule = true;
                    break;
                }
            }
            if (has_thread_rule) continue;

            cpu_set_t new_cpus;
            CPU_AND(&new_cpus, &ti->cpus, &allowed);
            if (CPU_COUNT(&new_cpus) > 0) {
                ti->cpus = new_cpus;
                char* dir_str = cpu_set_to_str(&new_cpus);
                if (dir_str) {
                    build_str(ti->cpuset_dir, sizeof(ti->cpuset_dir), dir_str, NULL);
                    free(dir_str);
                }
            }
        }
    }
}

static AppConfig* load_config(const char* config_file, const CpuTopology* topo, time_t* last_mtime) {
    struct stat st;
    if (stat(config_file, &st)) return NULL;
    AppConfig* cfg = calloc(1, sizeof(AppConfig));
    if (!cfg) return NULL;
    cfg->ref_count = 1;
    cfg->topo = *topo;
    build_str(cfg->config_file, sizeof(cfg->config_file), config_file, NULL);

    if (last_mtime && *last_mtime == st.st_mtime && *last_mtime != -1) {
        free(cfg);
        return NULL;
    }

    FILE* fp = fopen(config_file, "r");
    if (!fp) {
        free(cfg);
        return NULL;
    }

    AffinityRule* new_rules = NULL;
    char** new_pkgs = NULL;
    size_t rules_cnt = 0, pkgs_cnt = 0;
    char line[256];

    while (fgets(line, sizeof(line), fp)) {
        char* p = strtrim(line);
        if (*p == '#' || !*p) continue;

        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq++ = 0;

        char* br = strchr(p, '{');
        char* thread = "";
        if (br) {
            *br++ = 0;
            char* eb = strchr(br, '}');
            if (!eb) continue;
            *eb = 0;
            thread = strtrim(br);
        }

        char* pkg = strtrim(p);
        char* cpus = strtrim(eq);
        if (strlen(pkg) >= MAX_PKG_LEN || strlen(thread) >= MAX_THREAD_LEN) continue;

        cpu_set_t set;
        CPU_ZERO(&set);
        parse_cpu_ranges(cpus, &set, &cfg->topo.present_cpus);
        if (CPU_COUNT(&set) == 0) continue;

        char* dir_name = cpu_set_to_str(&set);
        if (!dir_name) continue;

        char path[256];
        build_str(path, sizeof(path), BASE_CPUSET, "/", dir_name, NULL);
        if (!create_cpuset_dir(path, dir_name, cfg->topo.mems_str)) {
            free(dir_name);
            continue;
        }

        AffinityRule rule = {0};
        build_str(rule.pkg, sizeof(rule.pkg), pkg, NULL);
        build_str(rule.thread, sizeof(rule.thread), thread, NULL);
        build_str(rule.cpuset_dir, sizeof(rule.cpuset_dir), dir_name, NULL);
        rule.cpus = set;
        free(dir_name);

        AffinityRule* tmp_rules = realloc(new_rules, (rules_cnt + 1) * sizeof(AffinityRule));
        if (!tmp_rules) goto error;
        new_rules = tmp_rules;
        memcpy(&new_rules[rules_cnt], &rule, sizeof(AffinityRule));
        rules_cnt++;

        bool exists = false;
        if (new_pkgs != NULL) {
            for (size_t i = 0; i < pkgs_cnt; i++) {
                if (strcmp(new_pkgs[i], pkg) == 0) {
                    exists = true;
                    break;
                }
            }
        }
        if (!exists) {
            char** tmp_pkgs = realloc(new_pkgs, (pkgs_cnt + 1) * sizeof(char*));
            if (!tmp_pkgs) goto error;
            new_pkgs = tmp_pkgs;
            new_pkgs[pkgs_cnt] = strdup(pkg);
            if (!new_pkgs[pkgs_cnt]) goto error;
            pkgs_cnt++;
        }
    }

    if (cfg->rules) free(cfg->rules);
    if (cfg->pkgs) {
        for (size_t i = 0; i < cfg->num_pkgs; i++) free(cfg->pkgs[i]);
        free(cfg->pkgs);
    }

    if (last_mtime) *last_mtime = st.st_mtime;
    cfg->rules = new_rules;
    cfg->num_rules = rules_cnt;
    cfg->pkgs = new_pkgs;
    cfg->num_pkgs = pkgs_cnt;
    cfg->mtime = st.st_mtime;

    fclose(fp);
    printf("配置文件解析完成，共加载 %zu 条规则\n", rules_cnt);
    return cfg;

error:
    if (new_rules) free(new_rules);
    if (new_pkgs) {
        for (size_t i = 0; i < pkgs_cnt; i++) free(new_pkgs[i]);
        free(new_pkgs);
    }
    fclose(fp);
    free(cfg);
    return NULL;
}

static void proc_collect(const AppConfig* cfg, ProcCache* cache, size_t* count) {
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return;
    int proc_fd = dirfd(proc_dir);
    *count = 0;

    if (cache->procs == NULL) {
        cache->procs_cap = 2048;
        cache->procs = calloc(cache->procs_cap, sizeof(ProcessInfo));
        if (!cache->procs) {
            closedir(proc_dir);
            return;
        }
    }

    struct dirent* ent;
    time_t current_time = time(NULL);
    while ((ent = readdir(proc_dir))) {
        char *end;
        long pid = strtol(ent->d_name, &end, 10);
        if (*end != '\0')  continue;

        if (!cache->scan_all_proc) {
            bool is_tracked = false;
            for (size_t i = 0; i < cache->num_tracked_pids; i++) {
                if (cache->tracked_pids[i] == pid) {
                    is_tracked = true;
                    break;
                }
            }
            if (!is_tracked) {
                struct stat statbuf;
                if (fstatat(proc_fd, ent->d_name, &statbuf, AT_SYMLINK_NOFOLLOW) != 0) continue;
                if (current_time - statbuf.st_mtime > 60) continue;
            }
        }

        int pid_fd = openat(proc_fd, ent->d_name, O_RDONLY | O_DIRECTORY);
        if (pid_fd == -1) continue;

        char cmd[MAX_PKG_LEN] = {0};
        if (!read_file(pid_fd, "cmdline", cmd, sizeof(cmd))) {
            close(pid_fd);
            continue;
        }
        char* name = strrchr(cmd, '/');
        name = name ? name + 1 : cmd;

        bool found = false;
        for (size_t j = 0; j < cfg->num_pkgs; j++) {
            if (strcmp(name, cfg->pkgs[j]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            close(pid_fd);
            continue;
        }

        if (*count >= cache->procs_cap) {
            size_t new_cap = cache->procs_cap * 2;
            ProcessInfo* new_procs = realloc(cache->procs, new_cap * sizeof(ProcessInfo));
            if (!new_procs) {
                close(pid_fd);
                continue;
            }
            memset(new_procs + cache->procs_cap, 0, (new_cap - cache->procs_cap) * sizeof(ProcessInfo));
            cache->procs = new_procs;
            cache->procs_cap = new_cap;
        }

        ProcessInfo* proc = &cache->procs[*count];

        proc->pid = pid;
        build_str(proc->pkg, sizeof(proc->pkg), name, NULL);
        CPU_ZERO(&proc->base_cpus);
        proc->base_cpuset[0] = '\0';
        proc->num_threads = 0;
        proc->num_thread_rules = 0;

        if (!proc->thread_rules || proc->thread_rules_cap < 8) {
            size_t new_cap = proc->thread_rules_cap ? proc->thread_rules_cap * 2 : 8;
            AffinityRule** tmp = realloc(proc->thread_rules, new_cap * sizeof(AffinityRule*));
            if (!tmp) {
                close(pid_fd);
                continue;
            }
            proc->thread_rules = tmp;
            proc->thread_rules_cap = new_cap;
        }

        for (size_t i = 0; i < cfg->num_rules; i++) {
            const AffinityRule* rule = &cfg->rules[i];
            if (strcmp(rule->pkg, proc->pkg) != 0) continue;

            if (rule->thread[0]) {
                if (proc->num_thread_rules >= proc->thread_rules_cap) {
                    size_t new_cap = proc->thread_rules_cap * 2;
                    AffinityRule** tmp = realloc(proc->thread_rules, new_cap * sizeof(AffinityRule*));
                    if (!tmp) break;
                    proc->thread_rules = tmp;
                    proc->thread_rules_cap = new_cap;
                }
                proc->thread_rules[proc->num_thread_rules++] = (AffinityRule*)rule;
            } else {
                CPU_OR(&proc->base_cpus, &proc->base_cpus, &rule->cpus);
                build_str(proc->base_cpuset, sizeof(proc->base_cpuset), rule->cpuset_dir, NULL);
            }
        }

        if (CPU_COUNT(&proc->base_cpus) == 0 && proc->num_thread_rules == 0) {
            close(pid_fd);
            continue;
        }

        int task_fd = openat(pid_fd, "task", O_RDONLY | O_DIRECTORY);
        close(pid_fd);
        if (task_fd == -1) {
            continue;
        }

        DIR* task_dir = fdopendir(task_fd);
        if (!task_dir) {
            close(task_fd);
            continue;
        }

        if (!proc->threads || proc->threads_cap < 512) {
            size_t new_cap = proc->threads_cap ? proc->threads_cap * 2 : 64;
            ThreadInfo* tmp = realloc(proc->threads, new_cap * sizeof(ThreadInfo));
            if (!tmp) {
                closedir(task_dir);
                continue;
            }
            proc->threads = tmp;
            proc->threads_cap = new_cap;
        }

        struct dirent* tent;
        while ((tent = readdir(task_dir))) {
            char *end2;
            long tid = strtol(tent->d_name, &end2, 10);
            if (*end2 != '\0')  continue;
            char tname[MAX_THREAD_LEN] = {0};

            int tid_fd = openat(task_fd, tent->d_name, O_RDONLY | O_DIRECTORY);
            if (tid_fd == -1) continue;

            if (!read_file(tid_fd, "comm", tname, sizeof(tname))) {
                close(tid_fd);
                continue;
            }
            close(tid_fd);

            strtrim(tname);

            if (proc->num_threads >= proc->threads_cap) {
                size_t new_cap = proc->threads_cap * 2;
                ThreadInfo* tmp = realloc(proc->threads, new_cap * sizeof(ThreadInfo));
                if (!tmp) continue;
                proc->threads = tmp;
                proc->threads_cap = new_cap;
            }

            ThreadInfo* ti = &proc->threads[proc->num_threads];
            ti->tid = tid;
            build_str(ti->name, sizeof(ti->name), tname, NULL);
            CPU_ZERO(&ti->cpus);
            const char* matched = NULL;

            for (size_t i = 0; i < proc->num_thread_rules; i++) {
                const AffinityRule* rule = proc->thread_rules[i];
                if (fnmatch(rule->thread, ti->name, FNM_NOESCAPE) == 0) {
                    CPU_OR(&ti->cpus, &ti->cpus, &rule->cpus);
                    matched = rule->cpuset_dir;
                }
            }

            if (matched) {
                build_str(ti->cpuset_dir, sizeof(ti->cpuset_dir), matched, NULL);
            } else {
                ti->cpus = proc->base_cpus;
                build_str(ti->cpuset_dir, sizeof(ti->cpuset_dir), proc->base_cpuset, NULL);
            }

            proc->num_threads++;
        }

        closedir(task_dir);
        (*count)++;
    }
    closedir(proc_dir);
}

static void update_cache(ProcCache* cache, const AppConfig* cfg, bool* force_affinity) {
    bool need_reload = false;
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        need_reload = true;
    } else {
        int current_proc_count = info.procs;
        if (current_proc_count > cache->last_proc_count + 11) {
            need_reload = true;
        } else if (current_proc_count > cache->last_proc_count) {
            *force_affinity = true;
        }
        cache->last_proc_count = current_proc_count;
    }
    if (cache->procs != NULL && !cache->scan_all_proc) {
        for (size_t i = 0; i < cache->num_procs; i++) {
            if (kill(cache->procs[i].pid, 0) != 0) {
                cache->scan_all_proc = true;
                break;
            }
        }
    }
    if (need_reload || cache->scan_all_proc) {
        size_t new_count = 0;
        proc_collect(cfg, cache, &new_count);

        if (new_count > cache->tracked_pids_cap) {
            size_t new_cap = cache->tracked_pids_cap ? cache->tracked_pids_cap * 2 : new_count;
            pid_t* new_pids = realloc(cache->tracked_pids, new_cap * sizeof(pid_t));
            if (new_pids) {
                cache->tracked_pids = new_pids;
                cache->tracked_pids_cap = new_cap;
            }
        }

        if (cache->tracked_pids) {
            cache->num_tracked_pids = 0;
            for (size_t i = 0; i < new_count; i++) {
                if (cache->num_tracked_pids < cache->tracked_pids_cap) {
                    cache->tracked_pids[cache->num_tracked_pids++] = cache->procs[i].pid;
                }
            }
        }
        
        cache->num_procs = new_count;
        *force_affinity = true;
        if (cache->scan_all_proc) cache->scan_all_proc = false;
    }
}

static void apply_affinity(ProcCache* cache, const CpuTopology* topo) {
    for (size_t i = 0; i < cache->num_procs; i++) {
        const ProcessInfo* proc = &cache->procs[i];
        for (size_t j = 0; j < proc->num_threads; j++) {
            const ThreadInfo* ti = &proc->threads[j];
            if (topo->cpuset_enabled && topo->base_cpuset_fd != -1) {
                char tid_str[32];
                snprintf(tid_str, sizeof(tid_str), "%d\n", ti->tid);
                if (CPU_COUNT(&ti->cpus) == 0) {
                    cpu_set_t curr;
                    if (sched_getaffinity(ti->tid, sizeof(curr), &curr) == -1) continue;
                    if (CPU_EQUAL(&topo->present_cpus, &curr)) continue;
                    write_file(topo->base_cpuset_fd, "tasks", tid_str, O_WRONLY | O_APPEND);
                } else {
                    cpu_set_t curr;
                    if (sched_getaffinity(ti->tid, sizeof(curr), &curr) == -1) continue;
                    if (CPU_EQUAL(&ti->cpus, &curr)) continue;
                    if (ti->cpuset_dir[0]) {
                        int fd = openat(topo->base_cpuset_fd, ti->cpuset_dir, O_RDONLY | O_DIRECTORY);
                        if (fd != -1) {
                            write_file(fd, "tasks", tid_str, O_WRONLY | O_APPEND);
                            close(fd);
                        }
                    }
                }
            }
            if (CPU_COUNT(&ti->cpus) == 0) continue;
            if (sched_setaffinity(ti->tid, sizeof(ti->cpus), &ti->cpus) == -1 && errno == ESRCH) {
                cache->scan_all_proc = true;
            }
        }
    }
}

static void config_release(AppConfig* cfg) {
    if (!cfg) return;
    if (atomic_fetch_sub(&cfg->ref_count, 1) == 1) {
        if (cfg->rules) free(cfg->rules);
        if (cfg->pkgs) {
            for (size_t i = 0; i < cfg->num_pkgs; i++) free(cfg->pkgs[i]);
            free(cfg->pkgs);
        }
        free(cfg);
    }
}

static AppConfig* get_config() {
    AppConfig* cfg = atomic_load_explicit(&current_config, memory_order_acquire);
    if (!cfg) return NULL;
    int old_ref = atomic_fetch_add_explicit(&cfg->ref_count, 1, memory_order_acq_rel);
    if (old_ref <= 0) {
        atomic_fetch_sub_explicit(&cfg->ref_count, 1, memory_order_release);
        return NULL;
    }
    if (atomic_load_explicit(&current_config, memory_order_acquire) != cfg) {
        atomic_fetch_sub_explicit(&cfg->ref_count, 1, memory_order_release);
        return NULL;
    }
    return cfg;
}

static void* config_loader_thread(void* arg) {
    int interval = *(int*)arg;
    free(arg);
    pthread_setname_np(pthread_self(), "ConfigLoader");

    time_t last_mtime = -1;
    while (1) {
        if (inotify_supported) {
            fd_set rfds;
            struct timeval tv;
            FD_ZERO(&rfds);
            FD_SET(inotify_fd, &rfds);
            tv.tv_sec = interval;
            tv.tv_usec = 0;

            int ret = select(inotify_fd + 1, &rfds, NULL, NULL, &tv);
            if (ret < 0) {
                if (errno == EINTR) continue;
                inotify_supported = 0;
                close(inotify_fd);
                inotify_fd = -1;
                continue;
            } else if (ret == 0) {
                continue;
            }

            char buf[4096] __attribute__((aligned(8)));
            ssize_t len = read(inotify_fd, buf, sizeof(buf));
            if (len <= 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    inotify_supported = 0;
                    close(inotify_fd);
                    inotify_fd = -1;
                }
                continue;
            }

            bool reload_needed = false;
            for (char* p = buf; p < buf + len;) {
                struct inotify_event* event = (struct inotify_event*)p;
                if (event->mask & (IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF)) {
                    reload_needed = true;

                    if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                        sleep(interval);
                        AppConfig* cfg = get_config();
                        if (cfg) {
                            inotify_rm_watch(inotify_fd, inotify_wd);
                            inotify_wd = inotify_add_watch(inotify_fd, cfg->config_file, IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
                            last_mtime = -1;
                            config_release(cfg);
                        }
                        if (inotify_wd < 0) {
                            inotify_supported = 0;
                            close(inotify_fd);
                            inotify_fd = -1;
                            break;
                        }
                    }
                }
                p += sizeof(struct inotify_event) + event->len;
            }

            if (reload_needed) {
                AppConfig* cfg = get_config();
                if (cfg) {
                    AppConfig* new_config = load_config(cfg->config_file, &cfg->topo, &last_mtime);
                    if (new_config) {
                        AppConfig* old_config = atomic_exchange(&current_config, new_config);
                        atomic_store(&config_updated, 1);
                        if (old_config) config_release(old_config);
                    }
                    config_release(cfg);
                }
            }
        } else {
            AppConfig* cfg = get_config();
            if (cfg) {
                AppConfig* new_config = load_config(cfg->config_file, &cfg->topo, &last_mtime);
                if (new_config) {
                    AppConfig* old_config = atomic_exchange(&current_config, new_config);
                    atomic_store(&config_updated, 1);
                    if (old_config) config_release(old_config);
                }
                config_release(cfg);
            }
            sleep(interval);
        }
    }
    return NULL;
}

static int parse_freq_list(const char* str, int* out, int max_out) {
    int count = 0;
    char* copy = strdup(str);
    if (!copy) return 0;
    char* tok = strtok(copy, ",");
    while (tok && count < max_out) {
        char* end;
        long val = strtol(tok, &end, 10);
        if (end != tok && val >= 0) out[count++] = (int)val;
        tok = strtok(NULL, ",");
    }
    free(copy);
    return count;
}

/* ---- tuber.conf 运行时配置 ---------------------------------------- */

typedef struct {
    /* [app] */
    int  sleep_interval;
    int  freq_interval;        /* 无内核模块时频率写入间隔(秒) */
    int  freq_interval_kmod;   /* 有内核模块时频率写入间隔(秒) */

    /* [power] */
    bool power_save_enabled;
    int  temp_limit_mc;

    /* [freq_on] */
    int  on_freqs[MAX_CLUSTERS];
    int  on_poll_ms;

    /* [freq_off] */
    int  off_freqs[MAX_CLUSTERS];
    int  off_poll_ms;
    int  off_sleep_interval;
    int  off_delay_sec;

    /* [thermal] */
    int  thermal_freqs[MAX_CLUSTERS];
} TuberConfig;

static TuberConfig tuber_defaults(void) {
    TuberConfig c = {0};
    c.sleep_interval      = 2;
    c.freq_interval       = 4;
    c.freq_interval_kmod  = 30;
    c.power_save_enabled  = false;
    c.temp_limit_mc       = 0;
    c.on_poll_ms          = -1;   /* -1 = 不写内核模块 */
    c.off_poll_ms         = -1;
    c.off_sleep_interval  = 10;
    c.off_delay_sec       = 180;
    memset(c.on_freqs,    0, sizeof(c.on_freqs));
    memset(c.off_freqs,   0, sizeof(c.off_freqs));
    memset(c.thermal_freqs, 0, sizeof(c.thermal_freqs));
    return c;
}

static int parse_int_val(const char* line, const char* key, int* out) {
    const char* p = strstr(line, key);
    if (!p) return 0;
    p += strlen(key);
    while (*p == ' ' || *p == '=' || *p == ' ') p++;
    char* end;
    long v = strtol(p, &end, 10);
    if (end == p) return 0;
    *out = (int)v;
    return 1;
}

static int parse_freqs_val(const char* line, const char* key,
                            int* out, int max_out) {
    const char* p = strstr(line, key);
    if (!p) return 0;
    p += strlen(key);
    while (*p == ' ' || *p == '=' || *p == ' ') p++;
    return parse_freq_list(p, out, max_out);
}

static int parse_bool_val(const char* line, const char* key, bool* out) {
    const char* p = strstr(line, key);
    if (!p) return 0;
    p += strlen(key);
    while (*p == ' ' || *p == '=' || *p == ' ') p++;
    if (strncmp(p, "true", 4) == 0 || strncmp(p, "1", 1) == 0)
        { *out = true; return 1; }
    if (strncmp(p, "false", 5) == 0 || strncmp(p, "0", 1) == 0)
        { *out = false; return 1; }
    return 0;
}

static bool load_tuber_config(const char* path, TuberConfig* cfg) {
    FILE* fp = fopen(path, "r");
    if (!fp) return false;

    char line[256];
    char section[32] = "";
    int count = 0;

    while (fgets(line, sizeof(line), fp)) {
        char* t = strtrim(line);
        if (!t[0] || t[0] == '#') continue;

        if (t[0] == '[') {
            char* end = strchr(t, ']');
            if (end) {
                size_t len = (size_t)(end - t - 1);
                if (len >= sizeof(section)) len = sizeof(section) - 1;
                memcpy(section, t + 1, len);
                section[len] = '\0';
            }
            continue;
        }

        if (strcmp(section, "app") == 0) {
            count += parse_int_val(t, "sleep_interval", &cfg->sleep_interval);
            count += parse_int_val(t, "freq_interval", &cfg->freq_interval);
            count += parse_int_val(t, "freq_interval_kmod", &cfg->freq_interval_kmod);
        } else if (strcmp(section, "power") == 0) {
            count += parse_bool_val(t, "enabled", &cfg->power_save_enabled);
            count += parse_int_val(t, "temp_limit_mc", &cfg->temp_limit_mc);
        } else if (strcmp(section, "freq_on") == 0) {
            count += parse_freqs_val(t, "limits", cfg->on_freqs, MAX_CLUSTERS);
            count += parse_int_val(t, "poll_ms", &cfg->on_poll_ms);
        } else if (strcmp(section, "freq_off") == 0) {
            count += parse_freqs_val(t, "limits", cfg->off_freqs, MAX_CLUSTERS);
            count += parse_int_val(t, "poll_ms", &cfg->off_poll_ms);
            count += parse_int_val(t, "sleep_interval", &cfg->off_sleep_interval);
            count += parse_int_val(t, "delay_sec", &cfg->off_delay_sec);
        } else if (strcmp(section, "thermal") == 0) {
            count += parse_freqs_val(t, "limits", cfg->thermal_freqs, MAX_CLUSTERS);
        }
    }
    fclose(fp);
    printf("加载配置: %s (%d 项)\n", path, count);
    return count > 0;
}

static void print_help(const char* prog_name) {
    printf("Usage: %s [-c <applist>] [-t <tuber.conf>]\n", prog_name);
    printf("\n");
    printf("  -c <file>  进程绑定规则文件 (默认: ./applist.conf)\n");
    printf("  -t <file>  运行时配置文件 (默认: ./tuber.conf)\n");
    printf("  -v         显示版本\n");
    printf("  -h         帮助\n");
    printf("\n");
    printf("所有运行时参数(频率/温控/息屏/轮询周期)统一在 tuber.conf 中配置。\n");
}

int main(int argc, char **argv) {
    CpuTopology topo = init_cpu_topo();

    if (topo.soc_name[0]) {
        printf("检测到SoC: %s", topo.soc_name);
        if (topo.is_sm8650) printf(" (骁龙8Gen3)");
        printf("\n");
    }
    if (topo.num_clusters > 0) {
        printf("CPU集群拓扑: ");
        for (int i = 0; i < topo.num_clusters; i++) {
            if (i > 0) printf(" | ");
            char* s = cpu_set_to_str(&topo.clusters[i].cpus);
            printf("%s(%s %.0fMHz)", topo.clusters[i].name,
                   s ? s : "?", topo.clusters[i].max_freq / 1000.0);
            free(s);
        }
        printf("\n");
    }

    /* 加载 tuber.conf */
    TuberConfig tcfg = tuber_defaults();
    load_tuber_config("./tuber.conf", &tcfg);

    char config_file[4096] = "./applist.conf";
    int sleep_interval = tcfg.sleep_interval;
    topo.power_save_mode = tcfg.power_save_enabled;
    topo.temp_limit_mc   = tcfg.temp_limit_mc;
    memcpy(topo.cluster_freqs, tcfg.on_freqs, sizeof(topo.cluster_freqs));
    memcpy(topo.thermal_cluster_freqs, tcfg.thermal_freqs, sizeof(topo.thermal_cluster_freqs));
    /* 检查是否有非零 per-cluster 值 */
    for (int i = 0; i < MAX_CLUSTERS; i++) {
        if (topo.cluster_freqs[i] != 0) { topo.use_cluster_freqs = true; break; }
        if (topo.thermal_cluster_freqs[i] != 0) { topo.use_thermal_cluster_freqs = true; break; }
    }
    topo.poll_ms                = tcfg.on_poll_ms;
    topo.display_off_poll_ms     = tcfg.off_poll_ms;
    memcpy(topo.display_off_freqs, tcfg.off_freqs, sizeof(topo.display_off_freqs));
    for (int i = 0; i < MAX_CLUSTERS; i++)
        if (topo.display_off_freqs[i] != 0) { topo.use_display_off_freqs = true; break; }

    int opt;
    char tuber_path[256] = "./tuber.conf";

    while ((opt = getopt(argc, argv, "c:t:hv")) != -1) {
        switch (opt) {
            case 'c':
                build_str(config_file, sizeof(config_file), optarg, NULL);
                printf("进程规则: %s\n", config_file);
                break;
            case 't':
                build_str(tuber_path, sizeof(tuber_path), optarg, NULL);
                printf("TuBer配置: %s\n", tuber_path);
                break;
            case 'v':
                printf("AppOpt 版本 %s\n", VERSION);
                exit(EXIT_SUCCESS);
            case 'h':
                print_help(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                print_help(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    /* 重新加载 tuber.conf（可能被 -t 改变了路径） */
    if (strcmp(tuber_path, "./tuber.conf") != 0) {
        tcfg = tuber_defaults();
        load_tuber_config(tuber_path, &tcfg);
        /* 重新应用配置 */
        topo.power_save_mode = tcfg.power_save_enabled;
        topo.temp_limit_mc   = tcfg.temp_limit_mc;
        memcpy(topo.cluster_freqs, tcfg.on_freqs, sizeof(topo.cluster_freqs));
        memcpy(topo.thermal_cluster_freqs, tcfg.thermal_freqs, sizeof(topo.thermal_cluster_freqs));
        topo.use_cluster_freqs = false;
        topo.use_thermal_cluster_freqs = false;
        for (int i = 0; i < MAX_CLUSTERS; i++) {
            if (topo.cluster_freqs[i] != 0) topo.use_cluster_freqs = true;
            if (topo.thermal_cluster_freqs[i] != 0) topo.use_thermal_cluster_freqs = true;
        }
        topo.poll_ms = tcfg.on_poll_ms;
        topo.display_off_poll_ms = tcfg.off_poll_ms;
        memcpy(topo.display_off_freqs, tcfg.off_freqs, sizeof(topo.display_off_freqs));
        topo.use_display_off_freqs = false;
        for (int i = 0; i < MAX_CLUSTERS; i++)
            if (topo.display_off_freqs[i] != 0) topo.use_display_off_freqs = true;
    }

    struct stat st;
    if (stat(config_file, &st) != 0) {
        const char* initial_content = "# 规则编写与使用说明请参考 http://AppOpt.suto.top\n\n";
        if (write_file(AT_FDCWD, config_file, initial_content, O_WRONLY | O_CREAT | O_TRUNC)) {
            printf("配置文件不存在，重建一个空的配置文件: %s\n", config_file);
        }
    }

    AppConfig* initial_config = load_config(config_file, &topo, NULL);
    if (!initial_config) {
        fprintf(stderr, "初始配置加载失败\n");
        exit(EXIT_FAILURE);
    }
    atomic_store(&current_config, initial_config);
    atomic_store(&config_updated, 1);

    inotify_fd = inotify_init1(IN_CLOEXEC);
    if (inotify_fd >= 0) {
        int flags = fcntl(inotify_fd, F_GETFL);
        if (flags >= 0) fcntl(inotify_fd, F_SETFL, flags | O_NONBLOCK);
        inotify_wd = inotify_add_watch(inotify_fd, config_file, IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
        if (inotify_wd >= 0) {
            inotify_supported = 1;
            printf("启用inotify监控配置文件变更\n");
        } else {
            close(inotify_fd);
            inotify_fd = -1;
            printf("inotify初始化失败，使用轮询模式\n");
        }
    }

    pthread_t loader_thread;
    int* interval_ptr = malloc(sizeof(int));
    if (!interval_ptr) {
        config_release(initial_config);
        if (inotify_supported) close(inotify_fd);
        exit(EXIT_FAILURE);
    }
    *interval_ptr = sleep_interval;

    if (pthread_create(&loader_thread, NULL, config_loader_thread, interval_ptr) != 0) {
        perror("配置加载器线程创建失败");
        free(interval_ptr);
        config_release(initial_config);
        if (inotify_supported) close(inotify_fd);
        exit(EXIT_FAILURE);
    }
    pthread_detach(loader_thread);

    ProcCache cache = {0};
    cache.scan_all_proc = true;
    bool affinity_force = false;
    printf("启动AppOpt服务 v%s\n", VERSION);
    /* 启动时写入内核 poll_ms */
    kmod_write_poll_ms(topo.poll_ms);
    if (topo.use_display_off_freqs)
        printf("息屏降频已启用 (%d clusters)\n", topo.num_clusters);
    if (kmod_available())
        printf("检测到 abk_soc_opt 内核模块，频率限制由内核强制执行\n");

    bool prev_display_off = false;
    time_t display_off_at = 0, last_affinity = 0, last_thermal = 0, last_freq = 0;

    bool thermal_active = false;
    int active_freq = 0;

    for (;;) {
        if (atomic_exchange(&config_updated, 0)) cache.scan_all_proc = true;

        AppConfig* cfg = get_config();
        if (cfg) {
            /* 屏幕状态切换（带延迟） */
            bool display_off = is_display_off();
            time_t now = time(NULL);

            if (display_off && !prev_display_off)
                display_off_at = now;
            else if (!display_off)
                display_off_at = 0;

            bool eff_off = display_off &&
                (display_off_at > 0) &&
                (now - display_off_at >= (time_t)tcfg.off_delay_sec);

            if (eff_off != prev_display_off) {
                if (eff_off && cfg->topo.use_display_off_freqs) {
                    apply_cluster_freqs(cfg->topo.display_off_freqs, &cfg->topo);
                    kmod_write_freqs(cfg->topo.display_off_freqs,
                                     cfg->topo.num_clusters, &cfg->topo);
                    kmod_write_poll_ms(cfg->topo.display_off_poll_ms);
                    sleep_interval = tcfg.off_sleep_interval;
                    printf("息屏模式 (延迟%lds) → 省电频率, poll=%dms, 间隔=%ds\n",
                           now - display_off_at, cfg->topo.display_off_poll_ms, sleep_interval);
                } else {
                    if (cfg->topo.use_cluster_freqs) {
                        apply_cluster_freqs(cfg->topo.cluster_freqs, &cfg->topo);
                        kmod_write_freqs(cfg->topo.cluster_freqs,
                                         cfg->topo.num_clusters, &cfg->topo);
                    }
                    kmod_write_poll_ms(cfg->topo.poll_ms);
                    sleep_interval = tcfg.sleep_interval;
                    printf("亮屏恢复 → 日常频率, poll=%dms, 间隔=%ds\n",
                           cfg->topo.poll_ms, sleep_interval);
                }
            }
            prev_display_off = eff_off;

            update_cache(&cache, cfg, &affinity_force);

            /* ── 亲和性写入: 每N秒或强制 ── */
            int aff_int = eff_off ? 10 : 5;
            if (affinity_force || now - last_affinity >= aff_int) {
                apply_affinity(&cache, &cfg->topo);
                if (cfg->topo.power_save_mode)
                    apply_power_save(&cache, &cfg->topo);
                last_affinity = now;
                affinity_force = false;
            }

            /* ── 温控检测: 每 10 秒 ── */
            if (cfg->topo.power_save_mode && cfg->topo.temp_limit_mc > 0 &&
                now - last_thermal >= 10) {
                    int cur_temp = read_thermal_max();
                    bool was_active = thermal_active;
                    thermal_active = (cur_temp > cfg->topo.temp_limit_mc);

                    if (thermal_active) {
                        apply_power_save(&cache, &cfg->topo);
                        apply_affinity(&cache, &cfg->topo);
                        // 超温立刻降频：per-cluster > 全局
                        if (cfg->topo.use_thermal_cluster_freqs) {
                            apply_cluster_freqs(cfg->topo.thermal_cluster_freqs, &cfg->topo);
                            kmod_write_freqs(cfg->topo.thermal_cluster_freqs,
                                               cfg->topo.num_clusters, &cfg->topo);
                        } else if (cfg->topo.thermal_freq_limit > 0 && active_freq != cfg->topo.thermal_freq_limit) {
                            apply_freq_limit(cfg->topo.thermal_freq_limit, &cfg->topo);
                            active_freq = cfg->topo.thermal_freq_limit;
                        }
                    } else if (was_active) {
                        cache.scan_all_proc = true;
                        // 立刻恢复频率：per-cluster > 全局 > 全速
                        if (cfg->topo.use_cluster_freqs) {
                            apply_cluster_freqs(cfg->topo.cluster_freqs, &cfg->topo);
                            kmod_write_freqs(cfg->topo.cluster_freqs,
                                               cfg->topo.num_clusters, &cfg->topo);
                        } else {
                            int restore = cfg->topo.max_freq_limit;
                            if (restore <= 0) restore = 9999999;
                            if (restore != active_freq) {
                                apply_freq_limit(restore, &cfg->topo);
                                active_freq = restore;
                            }
                        }
                    }
                last_thermal = now;
            }

            /* ── 频率写入: 有kmod间隔长, 无kmod间隔短, 息屏加倍 ── */
            int freq_int = kmod_available() ? tcfg.freq_interval_kmod : tcfg.freq_interval;
            if (eff_off) freq_int *= 2;
            if (!thermal_active && now - last_freq >= freq_int) {
                if (cfg->topo.use_cluster_freqs) {
                    apply_cluster_freqs(cfg->topo.cluster_freqs, &cfg->topo);
                    kmod_write_freqs(cfg->topo.cluster_freqs,
                                     cfg->topo.num_clusters, &cfg->topo);
                } else {
                    int target = cfg->topo.max_freq_limit;
                    if (target > 0 && target != active_freq) {
                        apply_freq_limit(target, &cfg->topo);
                        active_freq = target;
                    }
                }
                last_freq = now;
            }

            config_release(cfg);
        }
        sleep(sleep_interval);
    }
}
