#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/input.h>
#include <linux/fb.h>
#include <linux/notifier.h>
#include <linux/cpumask.h>
#include <linux/cpufreq.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/proc_fs.h>
#include <linux/thermal.h>
#include <linux/power_supply.h>
#include <linux/freezer.h>
#include <linux/kallsyms.h>
#include <linux/vmalloc.h>
#include <linux/pid.h>
#include <linux/sched/task.h>

#define APP_CATEGORY_SYSTEM 0
#define APP_CATEGORY_BACKGROUND 1
#define APP_CATEGORY_INTERACTIVE 2

#define MODE_DYNAMIC 0
#define MODE_WHITELIST 1

#define LOCK_FREQ_KHZ 300000U
#define BIG_CORE_IDLE_FREQ_KHZ 300000U
#define BIG_CORE_MID_FREQ_KHZ 900000U
#define BIG_CORE_BOOST_KHZ 1500000U
#define BIG_CORE_MAX_FREQ_KHZ 2000000U
#define LITTLE_CORE_MIN_KHZ 400000U
#define LITTLE_CORE_MAX_KHZ 1600000U

#define LITTLE_START 0
#define LITTLE_END 3
#define BIG_START 4
#define BIG_END 7

#define BOOST_DURATION_MS 2000
#define BIG_BOOST_DURATION_MS 4000
#define SCREEN_OFF_DELAY_MS 1000
#define IDLE_NO_TOUCH_DELAY_MS 5000
#define CHECK_INTERVAL_MS 500
#define POWER_CHECK_INTERVAL_MS 5000
#define MAX_TASK_CHECK 50

#define LOAD_THRESHOLD_HIGH 75

#define POWER_THRESHOLD_CRITICAL 5000
#define TEMP_THRESHOLD_CRITICAL 80

#define WHITELIST_FILE_PATH "/data/media/0/Android/boost.json"
#define MAX_WHITELIST_APPS 100
#define MAX_PACKAGE_NAME_LEN 256
#define MAX_CMD_LINE_LEN 512
#define MAX_JSON_FILE_SIZE 4096
#define MAX_APP_NAME_LEN 256

#define PID_CHECK_INTERVAL_MS 2000
#define THERMAL_RETRY_DELAY_MS 100
#define MAX_PROCESS_SCAN 50
#define PID_DETECT_TIMEOUT_MS 50

#define CLUSTER_TYPE_LITTLE 0
#define CLUSTER_TYPE_BIG 1
#define CLUSTER_TYPE_ALL 2

static cpumask_t little_mask;
static cpumask_t big_mask;
static cpumask_t all_mask;
static cpumask_t screen_off_mask;

static pid_t fg_pid = 0;
static bool screen_on = true;
static bool boot_complete = false;
static bool screen_off_processed = false;
static bool thermal_emergency_mode = false;
static bool power_emergency_mode = false;
static bool full_power_mode = false;
static bool screen_idle_mode = false;
static bool input_handler_registered = false;
static DEFINE_MUTEX(fg_lock);
static unsigned long last_touch_jiffies;
static unsigned long screen_off_jiffies;
static unsigned long power_check_jiffies;
static unsigned long thermal_check_jiffies;
static struct kobject *fa_kobj;

static unsigned long last_power_uw = 0;
static unsigned long avg_power_uw = 0;
static unsigned long max_power_uw = 0;
static unsigned long power_samples[10];
static int power_sample_index = 0;
static int power_sample_count = 0;

static int last_temperature = 25;

static char **small_cluster_apps = NULL;
static char **large_cluster_apps = NULL;
static char **all_cluster_apps = NULL;
static int small_count = 0;
static int large_count = 0;
static int all_count = 0;
static int current_mode = MODE_DYNAMIC;
static DEFINE_MUTEX(cluster_lock);

static struct delayed_work check_work;
static struct work_struct boost_work;
static struct delayed_work screen_off_work;
static struct delayed_work boot_complete_work;
static struct delayed_work power_check_work;
static struct delayed_work thermal_check_work;
static struct delayed_work idle_check_work;
static struct delayed_work pid_detect_work;
static struct workqueue_struct *fa_wq;

struct app_profile {
    char package_name[MAX_PACKAGE_NAME_LEN];
    int category;
    int cluster_type;
    unsigned long total_runtime;
    unsigned long last_update;
    struct list_head list;
};

struct task_info {
    pid_t pid;
    char package_name[MAX_PACKAGE_NAME_LEN];
    bool is_foreground;
    bool is_whitelisted;
    unsigned long last_boost_jiffies;
    unsigned long app_start_jiffies;
    bool is_frozen;
    int cluster_type;
    struct list_head list;
};

static LIST_HEAD(task_list);
static LIST_HEAD(app_profiles);
static DEFINE_SPINLOCK(task_list_lock);
static DEFINE_SPINLOCK(app_profiles_lock);

static DEFINE_SPINLOCK(pid_detect_lock);
static bool pid_detect_in_progress = false;
static unsigned long pid_detect_start_jiffies = 0;

static const char *foreground_process_patterns[] = {
    "com.android.systemui",
    "com.android.launcher",
    "com.miui.home",
    "com.tencent.mm",
    "com.tencent.mobileqq",
    "com.eg.android.AlipayGphone",
    "com.android.chrome",
    NULL
};

static const char *default_essential_apps[] = {
    "com.android.systemui",
    "com.android.phone",
    "com.android.mms",
    "com.android.providers.telephony",
    "com.android.dialer",
    "android.process.acore",
    "system_server",
    "surfaceflinger",
    NULL
};

static void emergency_power_throttle(void);
static void apply_thermal_throttle(void);
static unsigned int get_cpu_load(int cpu);
static void load_config_from_file(void);
static void free_cluster_apps(void);
static bool is_essential_app(const char *package_name);
static void unfreeze_all_tasks(void);
static struct task_info *find_task_info(pid_t pid);
static void enter_screen_idle_mode(void);
static void exit_screen_idle_mode(void);
static void online_all_little_cores(void);
static int detect_app_category(const char *package_name);
static struct app_profile *find_app_profile(const char *package_name);
static int get_app_cluster_type(const char *package_name);
static void schedule_app_by_cluster(struct task_struct *p, struct task_info *info, int cluster_type);
static void schedule_normal_app(struct task_struct *p, struct task_info *info);
static void adjust_frequencies_with_power(void);
static void update_power_statistics(void);
static int get_cpu_temperature(void);
static void check_thermal_status(void);
static void full_power_work_func(struct work_struct *work);
static void exit_full_power_mode(void);
static void update_task_info(struct task_struct *task);
static void schedule_screen_off_mode(void);
static void schedule_screen_on_mode(void);
static void idle_check_work_func(struct work_struct *work);
static void check_work_func(struct work_struct *work);
static void boost_work_func(struct work_struct *work);
static void screen_off_work_func(struct work_struct *work);
static void power_check_work_func(struct work_struct *work);
static void thermal_check_work_func(struct work_struct *work);
static void boot_complete_work_func(struct work_struct *work);
static void pid_detect_work_func(struct work_struct *work);
static int fb_notif_call(struct notifier_block *nb, unsigned long event, void *data);
static int fa_input_connect(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id);
static void fa_input_disconnect(struct input_handle *handle);
static void fa_input_event(struct input_handle *handle, unsigned int type, unsigned int code, int value);
static void detect_foreground_pid_safe(void);
static int read_temperature_from_file(const char *path);
static int read_temperature_from_thermal(void);
static bool get_package_name_safe(pid_t pid, char *buf, size_t buf_size);
static bool pid_detect_timeout_check(void);
static bool is_app_in_cluster_list(const char *package_name, char **list, int count);
static void parse_json_config(const char *buffer, ssize_t len);

static const struct input_device_id fa_ids[] = {
    { .driver_info = 1 },
    { }
};

static struct input_handler fa_input_handler = {
    .event = fa_input_event,
    .connect = fa_input_connect,
    .disconnect = fa_input_disconnect,
    .name = "frame_aware_unfair",
    .id_table = fa_ids,
};

static struct notifier_block fb_notifier = {
    .notifier_call = fb_notif_call,
};

static void init_masks(void)
{
    int i;
    cpumask_clear(&little_mask);
    for (i = LITTLE_START; i <= LITTLE_END; i++) {
        if (cpu_possible(i)) {
            cpumask_set_cpu(i, &little_mask);
        }
    }
    cpumask_clear(&big_mask);
    for (i = BIG_START; i <= BIG_END; i++) {
        if (cpu_possible(i))
            cpumask_set_cpu(i, &big_mask);
    }
    cpumask_copy(&all_mask, cpu_possible_mask);
    cpumask_copy(&screen_off_mask, &little_mask);
}

static unsigned int get_cpu_load(int cpu)
{
    unsigned long total_time = 0, idle_time = 0;
    static unsigned long prev_total[NR_CPUS] = {0};
    static unsigned long prev_idle[NR_CPUS] = {0};
    unsigned long delta_total, delta_idle;
    unsigned int load = 0;
    if (cpu < 0 || cpu >= NR_CPUS)
        return 0;
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
    {
        struct kernel_cpustat *kcpustat;
        kcpustat = &kcpustat_cpu(cpu);
        total_time = kcpustat->cpustat[CPUTIME_USER] +
                     kcpustat->cpustat[CPUTIME_NICE] +
                     kcpustat->cpustat[CPUTIME_SYSTEM] +
                     kcpustat->cpustat[CPUTIME_IDLE] +
                     kcpustat->cpustat[CPUTIME_IOWAIT] +
                     kcpustat->cpustat[CPUTIME_IRQ] +
                     kcpustat->cpustat[CPUTIME_SOFTIRQ];
        idle_time = kcpustat->cpustat[CPUTIME_IDLE] +
                    kcpustat->cpustat[CPUTIME_IOWAIT];
    }
#else
    total_time = jiffies;
    idle_time = jiffies / 2;
#endif
    if (prev_total[cpu] > 0) {
        delta_total = total_time - prev_total[cpu];
        delta_idle = idle_time - prev_idle[cpu];
        if (delta_total > 0) {
            load = 100 * (delta_total - delta_idle) / delta_total;
            if (load > 100) load = 100;
        } else {
            load = 0;
        }
    } else {
        load = 0;
    }
    prev_total[cpu] = total_time;
    prev_idle[cpu] = idle_time;
    return load;
}

static unsigned int get_big_core_load(void)
{
    int cpu;
    unsigned int total_load = 0;
    int count = 0;
    for_each_cpu(cpu, &big_mask) {
        if (cpu_online(cpu)) {
            total_load += get_cpu_load(cpu);
            count++;
        }
    }
    return count > 0 ? (total_load / count) : 0;
}

static unsigned int get_little_core_load(void)
{
    int cpu;
    unsigned int total_load = 0;
    int count = 0;
    for_each_cpu(cpu, &little_mask) {
        if (cpu_online(cpu)) {
            total_load += get_cpu_load(cpu);
            count++;
        }
    }
    return count > 0 ? (total_load / count) : 0;
}

static unsigned int get_all_core_load(void)
{
    int cpu;
    unsigned int total_load = 0;
    int count = 0;
    for_each_online_cpu(cpu) {
        total_load += get_cpu_load(cpu);
        count++;
    }
    return count > 0 ? (total_load / count) : 0;
}

static void set_cpu_freq(const cpumask_t *mask, unsigned int khz)
{
#ifdef CONFIG_CPU_FREQ
    int cpu;
    struct cpufreq_policy *policy;
    for_each_cpu(cpu, mask) {
        if (!cpu_online(cpu))
            continue;
        policy = cpufreq_cpu_get(cpu);
        if (!policy)
            continue;
        if (policy->cur != khz) {
            cpufreq_driver_target(policy, khz, CPUFREQ_RELATION_L);
        }
        cpufreq_cpu_put(policy);
    }
#endif
}

static void set_all_big_core_freq(unsigned int khz)
{
    set_cpu_freq(&big_mask, khz);
}

static void set_all_little_core_freq(unsigned int khz)
{
    set_cpu_freq(&little_mask, khz);
}

static void online_all_little_cores(void)
{
#ifdef CONFIG_HOTPLUG_CPU
    int cpu;
    for_each_cpu(cpu, &little_mask) {
        if (!cpu_online(cpu))
            cpu_up(cpu);
    }
#endif
}

static bool get_package_name_safe(pid_t pid, char *buf, size_t buf_size)
{
    char path[64];
    struct file *fp = NULL;
    loff_t pos = 0;
    ssize_t len;
    char cmdline[MAX_CMD_LINE_LEN];
    char *pkg_end, *pkg_name;
    
    if (!buf || buf_size == 0 || buf_size < 2)
        return false;
        
    if (pid <= 0 || pid > PID_MAX_LIMIT) {
        return false;
    }
    
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    
    fp = filp_open(path, O_RDONLY | O_NONBLOCK, 0);
    if (IS_ERR(fp)) {
        return false;
    }
    
    len = kernel_read(fp, cmdline, sizeof(cmdline) - 1, &pos);
    filp_close(fp, NULL);
    
    if (len <= 0) {
        return false;
    }
    
    if (len >= (ssize_t)sizeof(cmdline))
        len = sizeof(cmdline) - 1;
    cmdline[len] = '\0';
    
    if (cmdline[0] == '\0') {
        return false;
    }
    
    pkg_end = strchr(cmdline, ' ');
    if (pkg_end) {
        *pkg_end = '\0';
    }
    
    pkg_name = strrchr(cmdline, '/');
    if (pkg_name) {
        pkg_name++;
    } else {
        pkg_name = cmdline;
    }
    
    if (strlen(pkg_name) == 0) {
        return false;
    }
    
    strncpy(buf, pkg_name, buf_size - 1);
    buf[buf_size - 1] = '\0';
    
    if (strlen(buf) < 3) {
        return false;
    }
    
    return true;
}

static bool is_essential_app(const char *package_name)
{
    int i;
    if (!package_name)
        return false;
    for (i = 0; default_essential_apps[i] != NULL; i++) {
        if (strstr(package_name, default_essential_apps[i])) {
            return true;
        }
    }
    if (strstr(package_name, "system") ||
        strstr(package_name, ".provider") ||
        strstr(package_name, ".service") ||
        strstr(package_name, "android.")) {
        return true;
    }
    return false;
}

static bool is_app_in_cluster_list(const char *package_name, char **list, int count)
{
    int i;
    if (!package_name || !list)
        return false;
    for (i = 0; i < count; i++) {
        if (list[i] && strstr(package_name, list[i])) {
            return true;
        }
    }
    return false;
}

static bool is_whitelisted_app(const char *package_name)
{
    if (!package_name)
        return false;
    
    mutex_lock(&cluster_lock);
    bool result = is_app_in_cluster_list(package_name, small_cluster_apps, small_count) ||
                  is_app_in_cluster_list(package_name, large_cluster_apps, large_count) ||
                  is_app_in_cluster_list(package_name, all_cluster_apps, all_count);
    mutex_unlock(&cluster_lock);
    return result;
}

static void unfreeze_all_tasks(void)
{
    struct task_struct *p;
    struct task_info *info;
    spin_lock(&task_list_lock);
    list_for_each_entry(info, &task_list, list) {
        info->is_frozen = false;
    }
    spin_unlock(&task_list_lock);
    rcu_read_lock();
    for_each_process(p) {
        if (!p->mm || p->flags & PF_KTHREAD)
            continue;
        if (p->pid <= 100)
            continue;
        set_user_nice(p, 0);
        set_cpus_allowed_ptr(p, &all_mask);
    }
    rcu_read_unlock();
}

static struct task_info *find_task_info(pid_t pid)
{
    struct task_info *info;
    spin_lock(&task_list_lock);
    list_for_each_entry(info, &task_list, list) {
        if (info->pid == pid) {
            spin_unlock(&task_list_lock);
            return info;
        }
    }
    spin_unlock(&task_list_lock);
    return NULL;
}

static int get_app_cluster_type(const char *package_name)
{
    if (!package_name)
        return -1;
    
    mutex_lock(&cluster_lock);
    
    if (is_app_in_cluster_list(package_name, small_cluster_apps, small_count)) {
        mutex_unlock(&cluster_lock);
        return CLUSTER_TYPE_LITTLE;
    }
    
    if (is_app_in_cluster_list(package_name, large_cluster_apps, large_count)) {
        mutex_unlock(&cluster_lock);
        return CLUSTER_TYPE_BIG;
    }
    
    if (is_app_in_cluster_list(package_name, all_cluster_apps, all_count)) {
        mutex_unlock(&cluster_lock);
        return CLUSTER_TYPE_ALL;
    }
    
    mutex_unlock(&cluster_lock);
    return -1;
}

static void schedule_app_by_cluster(struct task_struct *p, struct task_info *info, int cluster_type)
{
    if (!info)
        return;
    
    switch (cluster_type) {
        case CLUSTER_TYPE_LITTLE:
            set_user_nice(p, 0);
            set_cpus_allowed_ptr(p, &little_mask);
            break;
        case CLUSTER_TYPE_BIG:
            set_user_nice(p, -10);
            set_cpus_allowed_ptr(p, &big_mask);
            break;
        case CLUSTER_TYPE_ALL:
            set_user_nice(p, -20);
            set_cpus_allowed_ptr(p, &all_mask);
            break;
        default:
            schedule_normal_app(p, info);
            break;
    }
}

static void parse_json_config(const char *buffer, ssize_t len)
{
    char *copy = kzalloc(len + 1, GFP_KERNEL);
    char *ptr = copy;
    char *line;
    int in_small_array = 0;
    int in_large_array = 0;
    int in_all_array = 0;
    
    if (!copy)
        return;
    
    memcpy(copy, buffer, len);
    copy[len] = '\0';
    
    line = copy;
    while (*line) {
        while (*line && (*line == ' ' || *line == '\t' || *line == '\n' ||
                        *line == '\r')) {
            line++;
        }
        
        if (!*line)
            break;
        
        if (strncmp(line, "\"boost\"", 7) == 0) {
            line += 7;
            while (*line && (*line == ' ' || *line == '\t' || *line == ':')) {
                line++;
            }
            if (*line == '"') {
                line++;
                char *end = strchr(line, '"');
                if (end) {
                    *end = '\0';
                    if (strcmp(line, "dynamic") == 0) {
                        current_mode = MODE_DYNAMIC;
                    } else if (strcmp(line, "whitelist") == 0) {
                        current_mode = MODE_WHITELIST;
                    }
                    line = end + 1;
                }
            }
            continue;
        }
        
        if (strncmp(line, "\"small\"", 7) == 0) {
            line += 7;
            while (*line && (*line == ' ' || *line == '\t' || *line == ':')) {
                line++;
            }
            if (*line == '[') {
                line++;
                in_small_array = 1;
                in_large_array = 0;
                in_all_array = 0;
            }
            continue;
        }
        
        if (strncmp(line, "\"large\"", 7) == 0) {
            line += 7;
            while (*line && (*line == ' ' || *line == '\t' || *line == ':')) {
                line++;
            }
            if (*line == '[') {
                line++;
                in_small_array = 0;
                in_large_array = 1;
                in_all_array = 0;
            }
            continue;
        }
        
        if (strncmp(line, "\"all\"", 5) == 0) {
            line += 5;
            while (*line && (*line == ' ' || *line == '\t' || *line == ':')) {
                line++;
            }
            if (*line == '[') {
                line++;
                in_small_array = 0;
                in_large_array = 0;
                in_all_array = 1;
            }
            continue;
        }
        
        if (*line == ']') {
            in_small_array = 0;
            in_large_array = 0;
            in_all_array = 0;
            line++;
            continue;
        }
        
        if (*line == ',' || *line == '{' || *line == '}') {
            line++;
            continue;
        }
        
        if (*line == '"') {
            line++;
            char *end = strchr(line, '"');
            if (end) {
                *end = '\0';
                
                if (strlen(line) > 0 && strlen(line) < MAX_APP_NAME_LEN) {
                    char *app_name = kzalloc(strlen(line) + 1, GFP_KERNEL);
                    if (app_name) {
                        strcpy(app_name, line);
                        
                        mutex_lock(&cluster_lock);
                        
                        if (in_small_array && small_count < MAX_WHITELIST_APPS) {
                            if (!small_cluster_apps) {
                                small_cluster_apps = kzalloc(sizeof(char *) * MAX_WHITELIST_APPS, GFP_KERNEL);
                            }
                            if (small_cluster_apps) {
                                small_cluster_apps[small_count++] = app_name;
                            } else {
                                kfree(app_name);
                            }
                        } else if (in_large_array && large_count < MAX_WHITELIST_APPS) {
                            if (!large_cluster_apps) {
                                large_cluster_apps = kzalloc(sizeof(char *) * MAX_WHITELIST_APPS, GFP_KERNEL);
                            }
                            if (large_cluster_apps) {
                                large_cluster_apps[large_count++] = app_name;
                            } else {
                                kfree(app_name);
                            }
                        } else if (in_all_array && all_count < MAX_WHITELIST_APPS) {
                            if (!all_cluster_apps) {
                                all_cluster_apps = kzalloc(sizeof(char *) * MAX_WHITELIST_APPS, GFP_KERNEL);
                            }
                            if (all_cluster_apps) {
                                all_cluster_apps[all_count++] = app_name;
                            } else {
                                kfree(app_name);
                            }
                        } else {
                            kfree(app_name);
                        }
                        
                        mutex_unlock(&cluster_lock);
                    }
                }
                line = end + 1;
            }
            continue;
        }
        
        line++;
    }
    
    kfree(copy);
}

static void load_config_from_file(void)
{
    struct file *fp = NULL;
    loff_t pos = 0;
    char *buffer = NULL;
    ssize_t len;
    
    mutex_lock(&cluster_lock);
    
    free_cluster_apps();
    current_mode = MODE_DYNAMIC;
    
    fp = filp_open(WHITELIST_FILE_PATH, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        mutex_unlock(&cluster_lock);
        return;
    }
    
    buffer = kzalloc(MAX_JSON_FILE_SIZE, GFP_KERNEL);
    if (!buffer) {
        filp_close(fp, NULL);
        mutex_unlock(&cluster_lock);
        return;
    }
    
    len = kernel_read(fp, buffer, MAX_JSON_FILE_SIZE - 1, &pos);
    filp_close(fp, NULL);
    
    if (len <= 0) {
        kfree(buffer);
        mutex_unlock(&cluster_lock);
        return;
    }
    
    buffer[len] = '\0';
    
    parse_json_config(buffer, len);
    
    kfree(buffer);
    mutex_unlock(&cluster_lock);
}

static void free_cluster_apps(void)
{
    int i;
    
    if (small_cluster_apps) {
        for (i = 0; i < small_count; i++) {
            if (small_cluster_apps[i])
                kfree(small_cluster_apps[i]);
        }
        kfree(small_cluster_apps);
        small_cluster_apps = NULL;
        small_count = 0;
    }
    
    if (large_cluster_apps) {
        for (i = 0; i < large_count; i++) {
            if (large_cluster_apps[i])
                kfree(large_cluster_apps[i]);
        }
        kfree(large_cluster_apps);
        large_cluster_apps = NULL;
        large_count = 0;
    }
    
    if (all_cluster_apps) {
        for (i = 0; i < all_count; i++) {
            if (all_cluster_apps[i])
                kfree(all_cluster_apps[i]);
        }
        kfree(all_cluster_apps);
        all_cluster_apps = NULL;
        all_count = 0;
    }
}

static unsigned long get_system_power_uw_simple(void)
{
    unsigned long power = 0;
    int cpu;
    unsigned int freq, load;
    unsigned long coeff;
    struct cpufreq_policy *policy;
    for_each_online_cpu(cpu) {
        freq = 0;
#ifdef CONFIG_CPU_FREQ
        policy = cpufreq_cpu_get(cpu);
        if (policy) {
            freq = policy->cur;
            cpufreq_cpu_put(policy);
        }
#endif
        load = get_cpu_load(cpu);
        coeff = cpumask_test_cpu(cpu, &big_mask) ? 8 : 3;
        if (freq == 0)
            freq = LITTLE_CORE_MIN_KHZ;
        power += (freq / 1000000) * load * coeff;
    }
    return power * 1000;
}

static void update_power_statistics(void)
{
    unsigned long current_power = get_system_power_uw_simple();
    unsigned long sum = 0;
    int i;
    if (!screen_on) {
        return;
    }
    power_samples[power_sample_index] = current_power;
    power_sample_index = (power_sample_index + 1) % ARRAY_SIZE(power_samples);
    if (power_sample_count < ARRAY_SIZE(power_samples)) {
        power_sample_count++;
    }
    for (i = 0; i < power_sample_count; i++) {
        sum += power_samples[i];
    }
    if (power_sample_count)
        avg_power_uw = sum / power_sample_count;
    if (current_power > max_power_uw) {
        max_power_uw = current_power;
    }
    last_power_uw = current_power;
    
    if (avg_power_uw > POWER_THRESHOLD_CRITICAL * 1000) {
        if (!power_emergency_mode && screen_on) {
            power_emergency_mode = true;
            emergency_power_throttle();
        }
    } else if (avg_power_uw < (POWER_THRESHOLD_CRITICAL - 1000) * 1000) {
        if (power_emergency_mode) {
            power_emergency_mode = false;
            unfreeze_all_tasks();
        }
    }
}

static void emergency_power_throttle(void)
{
    struct task_struct *p;
    set_all_little_core_freq(LOCK_FREQ_KHZ);
    set_all_big_core_freq(BIG_CORE_IDLE_FREQ_KHZ);
    rcu_read_lock();
    for_each_process(p) {
        if (!p->mm || p->flags & PF_KTHREAD)
            continue;
        set_user_nice(p, 19);
        set_cpus_allowed_ptr(p, &little_mask);
    }
    rcu_read_unlock();
}

static int read_temperature_from_file(const char *path)
{
    struct file *fp = NULL;
    loff_t pos = 0;
    char buffer[32];
    ssize_t len;
    int temp = 0;
    
    fp = filp_open(path, O_RDONLY | O_NONBLOCK, 0);
    if (IS_ERR(fp)) {
        return -1;
    }
    
    len = kernel_read(fp, buffer, sizeof(buffer) - 1, &pos);
    filp_close(fp, NULL);
    
    if (len <= 0) {
        return -1;
    }
    
    buffer[len] = '\0';
    if (kstrtoint(buffer, 10, &temp) != 0) {
        return -1;
    }
    
    return temp / 1000;
}

static int read_temperature_from_thermal(void)
{
    int temp = -1;
    const char *thermal_paths[] = {
        "/sys/class/thermal/thermal_zone0/temp",
        "/sys/class/thermal/thermal_zone1/temp",
        "/sys/class/thermal/thermal_zone2/temp",
        "/sys/class/thermal/thermal_zone3/temp",
        "/sys/class/thermal/thermal_zone4/temp",
        "/sys/class/hwmon/hwmon0/temp1_input",
        "/sys/class/hwmon/hwmon1/temp1_input",
        "/sys/devices/virtual/thermal/thermal_zone0/temp",
        NULL
    };
    
    int i;
    for (i = 0; thermal_paths[i] != NULL; i++) {
        temp = read_temperature_from_file(thermal_paths[i]);
        if (temp > 0 && temp < 150) {
            return temp;
        }
    }
    
    return temp;
}

static int get_cpu_temperature(void)
{
    static int last_valid_temp = 25;
    int temp = -1;
    
#ifdef CONFIG_THERMAL
    {
        const char *tz_names[] = {
            "cpu-thermal",
            "cpu_thermal",
            "soc_thermal",
            "therm_est",
            "virtual-thermal",
            "cpu_therm",
            "soc",
            NULL
        };
        
        struct thermal_zone_device *tz = NULL;
        int i;
        
        for (i = 0; tz_names[i] != NULL; i++) {
            tz = thermal_zone_get_zone_by_name(tz_names[i]);
            if (!IS_ERR(tz)) {
                int ret = thermal_zone_get_temp(tz, &temp);
                if (!ret) {
                    temp = temp / 1000;
                    if (temp > 0 && temp < 150) {
                        last_valid_temp = temp;
                        last_temperature = temp;
                        return temp;
                    }
                }
            }
        }
    }
#endif
    
    temp = read_temperature_from_thermal();
    if (temp > 0 && temp < 150) {
        last_valid_temp = temp;
        last_temperature = temp;
        return temp;
    }
    
    last_temperature = last_valid_temp;
    return last_valid_temp;
}

static void check_thermal_status(void)
{
    int temp = get_cpu_temperature();
    if (temp > TEMP_THRESHOLD_CRITICAL) {
        if (!thermal_emergency_mode) {
            thermal_emergency_mode = true;
            apply_thermal_throttle();
        }
    } else if (temp < TEMP_THRESHOLD_CRITICAL - 5) {
        if (thermal_emergency_mode) {
            thermal_emergency_mode = false;
            unfreeze_all_tasks();
        }
    }
}

static void apply_thermal_throttle(void)
{
    struct task_struct *p;
    set_all_big_core_freq(BIG_CORE_IDLE_FREQ_KHZ);
    set_all_little_core_freq(LITTLE_CORE_MIN_KHZ);
    rcu_read_lock();
    for_each_process(p) {
        if (!p->mm || p->flags & PF_KTHREAD)
            continue;
        if (p->static_prio < 0) {
            set_user_nice(p, 0);
        }
    }
    rcu_read_unlock();
}

static void update_task_info(struct task_struct *task)
{
    struct task_info *info;
    char package_name[MAX_PACKAGE_NAME_LEN];
    bool is_foreground = (task->pid == fg_pid);
    if (!get_package_name_safe(task->pid, package_name, sizeof(package_name))) {
        return;
    }
    info = find_task_info(task->pid);
    if (!info) {
        info = kzalloc(sizeof(*info), GFP_ATOMIC);
        if (!info)
            return;
        info->pid = task->pid;
        info->is_foreground = is_foreground;
        strncpy(info->package_name, package_name, sizeof(info->package_name) - 1);
        info->package_name[sizeof(info->package_name) - 1] = '\0';
        info->is_whitelisted = is_whitelisted_app(package_name);
        info->last_boost_jiffies = 0;
        info->app_start_jiffies = jiffies;
        info->is_frozen = false;
        info->cluster_type = get_app_cluster_type(package_name);
        spin_lock(&task_list_lock);
        list_add_tail(&info->list, &task_list);
        spin_unlock(&task_list_lock);
    } else {
        info->is_foreground = is_foreground;
        if (strcmp(info->package_name, package_name) != 0) {
            strncpy(info->package_name, package_name, sizeof(info->package_name) - 1);
            info->package_name[sizeof(info->package_name) - 1] = '\0';
            info->is_whitelisted = is_whitelisted_app(package_name);
            info->cluster_type = get_app_cluster_type(package_name);
            info->app_start_jiffies = jiffies;
        }
    }
}

static void schedule_screen_off_mode(void)
{
    struct task_struct *p;
    struct task_info *info;
    if (screen_off_processed)
        return;
    online_all_little_cores();
    set_all_little_core_freq(LOCK_FREQ_KHZ);
    set_all_big_core_freq(BIG_CORE_IDLE_FREQ_KHZ);
    cancel_delayed_work(&check_work);
    cancel_delayed_work(&power_check_work);
    cancel_delayed_work(&idle_check_work);
    cancel_delayed_work(&pid_detect_work);
    cpumask_copy(&screen_off_mask, &little_mask);
    rcu_read_lock();
    for_each_process(p) {
        if (!p->mm || p->flags & PF_KTHREAD)
            continue;
        if (p->pid <= 100)
            continue;
        info = find_task_info(p->pid);
        if (info && info->is_whitelisted) {
            set_user_nice(p, 0);
            set_cpus_allowed_ptr(p, &screen_off_mask);
        } else {
            set_user_nice(p, 19);
            set_cpus_allowed_ptr(p, &screen_off_mask);
            if (info)
                info->is_frozen = true;
        }
    }
    rcu_read_unlock();
    screen_off_processed = true;
}

static void schedule_screen_on_mode(void)
{
    struct task_struct *p;
    struct task_info *info;
    online_all_little_cores();
    set_all_big_core_freq(BIG_CORE_MID_FREQ_KHZ);
    set_all_little_core_freq(LITTLE_CORE_MIN_KHZ);
    unfreeze_all_tasks();
    rcu_read_lock();
    for_each_process(p) {
        if (!p->mm || p->flags & PF_KTHREAD)
            continue;
        info = find_task_info(p->pid);
        if (info && info->is_whitelisted) {
            set_user_nice(p, 0);
            set_cpus_allowed_ptr(p, &little_mask);
        }
    }
    rcu_read_unlock();
    screen_off_processed = false;
    screen_idle_mode = false;
    if (fa_wq) {
        queue_delayed_work(fa_wq, &check_work, msecs_to_jiffies(CHECK_INTERVAL_MS));
        queue_delayed_work(fa_wq, &power_check_work,
                          msecs_to_jiffies(POWER_CHECK_INTERVAL_MS));
        queue_delayed_work(fa_wq, &idle_check_work,
                          msecs_to_jiffies(IDLE_NO_TOUCH_DELAY_MS));
        queue_delayed_work(fa_wq, &pid_detect_work,
                          msecs_to_jiffies(PID_CHECK_INTERVAL_MS));
    }
}

static void enter_screen_idle_mode(void)
{
    if (!screen_on || screen_idle_mode || screen_off_processed)
        return;
    screen_idle_mode = true;
    set_all_big_core_freq(BIG_CORE_IDLE_FREQ_KHZ);
    set_all_little_core_freq(LITTLE_CORE_MIN_KHZ);
}

static void exit_screen_idle_mode(void)
{
    if (!screen_idle_mode)
        return;
    screen_idle_mode = false;
    set_all_big_core_freq(BIG_CORE_MID_FREQ_KHZ);
    set_all_little_core_freq(LITTLE_CORE_MIN_KHZ);
}

static bool pid_detect_timeout_check(void)
{
    unsigned long now = jiffies;
    unsigned long timeout = msecs_to_jiffies(PID_DETECT_TIMEOUT_MS);
    
    if (time_after(now, pid_detect_start_jiffies + timeout)) {
        return true;
    }
    return false;
}

static void detect_foreground_pid_safe(void)
{
    struct task_struct *p;
    char package_name[MAX_PACKAGE_NAME_LEN];
    pid_t new_fg_pid = 0;
    int i;
    int process_count = 0;
    
    spin_lock(&pid_detect_lock);
    if (pid_detect_in_progress) {
        spin_unlock(&pid_detect_lock);
        return;
    }
    pid_detect_in_progress = true;
    pid_detect_start_jiffies = jiffies;
    spin_unlock(&pid_detect_lock);
    
    rcu_read_lock();
    for_each_process(p) {
        if (pid_detect_timeout_check()) {
            break;
        }
        
        if (process_count++ > MAX_PROCESS_SCAN) {
            break;
        }
        
        if (!p->mm || p->flags & PF_KTHREAD)
            continue;
            
        if (p->pid <= 100)
            continue;
        
        if (!get_package_name_safe(p->pid, package_name, sizeof(package_name)))
            continue;
        
        for (i = 0; foreground_process_patterns[i] != NULL; i++) {
            if (strstr(package_name, foreground_process_patterns[i])) {
                new_fg_pid = p->pid;
                break;
            }
        }
        
        if (new_fg_pid != 0)
            break;
    }
    rcu_read_unlock();
    
    if (new_fg_pid != 0 && new_fg_pid != fg_pid) {
        mutex_lock(&fg_lock);
        fg_pid = new_fg_pid;
        mutex_unlock(&fg_lock);
    }
    
    spin_lock(&pid_detect_lock);
    pid_detect_in_progress = false;
    spin_unlock(&pid_detect_lock);
}

static void schedule_normal_app(struct task_struct *p, struct task_info *info)
{
    unsigned long now = jiffies;
    unsigned long boost_end_time;
    
    if (!info)
        return;
    
    boost_end_time = info->app_start_jiffies + msecs_to_jiffies(BOOST_DURATION_MS);
    if (time_before(now, boost_end_time)) {
        set_user_nice(p, -20);
        set_cpus_allowed_ptr(p, &all_mask);
        return;
    }
    
    if (info->is_whitelisted && current_mode == MODE_WHITELIST) {
        int cluster_type = info->cluster_type;
        if (cluster_type >= 0) {
            schedule_app_by_cluster(p, info, cluster_type);
            
            if (cluster_type == CLUSTER_TYPE_BIG || cluster_type == CLUSTER_TYPE_ALL) {
                boost_end_time = info->app_start_jiffies + msecs_to_jiffies(BIG_BOOST_DURATION_MS);
                if (time_before(now, boost_end_time)) {
                    set_user_nice(p, -20);
                    set_cpus_allowed_ptr(p, &all_mask);
                    return;
                }
            }
        } else {
            unsigned int little_load = get_little_core_load();
            if (little_load < LOAD_THRESHOLD_HIGH) {
                set_user_nice(p, 0);
                set_cpus_allowed_ptr(p, &little_mask);
            } else {
                unsigned int big_load = get_big_core_load();
                if (big_load < LOAD_THRESHOLD_HIGH) {
                    set_user_nice(p, -10);
                    set_cpus_allowed_ptr(p, &big_mask);
                } else {
                    set_user_nice(p, -20);
                    set_cpus_allowed_ptr(p, &all_mask);
                }
            }
        }
    } else {
        if (current_mode == MODE_DYNAMIC) {
            unsigned int little_load = get_little_core_load();
            if (little_load < LOAD_THRESHOLD_HIGH) {
                set_user_nice(p, 0);
                set_cpus_allowed_ptr(p, &little_mask);
            } else {
                unsigned int big_load = get_big_core_load();
                if (big_load < LOAD_THRESHOLD_HIGH) {
                    set_user_nice(p, -10);
                    set_cpus_allowed_ptr(p, &big_mask);
                } else {
                    set_user_nice(p, -20);
                    set_cpus_allowed_ptr(p, &all_mask);
                }
            }
        } else {
            set_user_nice(p, 0);
            set_cpus_allowed_ptr(p, &little_mask);
        }
    }
    
    if (power_emergency_mode || thermal_emergency_mode) {
        if (avg_power_uw > POWER_THRESHOLD_CRITICAL * 1000 || last_temperature > TEMP_THRESHOLD_CRITICAL) {
            set_user_nice(p, 0);
            set_cpus_allowed_ptr(p, &all_mask);
        }
    }
}

static void adjust_frequencies_with_power(void)
{
    if (!screen_on) {
        return;
    }
    
    if (screen_idle_mode) {
        set_all_little_core_freq(LITTLE_CORE_MIN_KHZ);
        set_all_big_core_freq(BIG_CORE_IDLE_FREQ_KHZ);
        return;
    }
    
    if (power_emergency_mode || thermal_emergency_mode) {
        set_all_little_core_freq(LOCK_FREQ_KHZ);
        set_all_big_core_freq(BIG_CORE_IDLE_FREQ_KHZ);
        return;
    }
    
    if (current_mode == MODE_DYNAMIC) {
        unsigned int little_load = get_little_core_load();
        unsigned int big_load = get_big_core_load();
        
        if (little_load < 30) {
            set_all_little_core_freq(LITTLE_CORE_MIN_KHZ);
        } else if (little_load < 60) {
            set_all_little_core_freq((LITTLE_CORE_MIN_KHZ + LITTLE_CORE_MAX_KHZ) / 2);
        } else {
            set_all_little_core_freq(LITTLE_CORE_MAX_KHZ);
        }
        
        if (big_load < 30) {
            set_all_big_core_freq(BIG_CORE_IDLE_FREQ_KHZ);
        } else if (big_load < 60) {
            set_all_big_core_freq(BIG_CORE_MID_FREQ_KHZ);
        } else {
            set_all_big_core_freq(BIG_CORE_BOOST_KHZ);
        }
    } else {
        set_all_little_core_freq(LITTLE_CORE_MIN_KHZ);
        set_all_big_core_freq(BIG_CORE_MID_FREQ_KHZ);
    }
}

static void pid_detect_work_func(struct work_struct *work)
{
    detect_foreground_pid_safe();
    
    if (fa_wq) {
        unsigned long interval = msecs_to_jiffies(PID_CHECK_INTERVAL_MS);
        queue_delayed_work(fa_wq, &pid_detect_work, interval);
    }
}

static void idle_check_work_func(struct work_struct *work)
{
    unsigned long now = jiffies;
    unsigned long idle_timeout = msecs_to_jiffies(IDLE_NO_TOUCH_DELAY_MS);
    if (screen_on && !screen_idle_mode && !screen_off_processed) {
        if (time_after(now, last_touch_jiffies + idle_timeout)) {
            enter_screen_idle_mode();
        } else {
            if (fa_wq)
                queue_delayed_work(fa_wq, &idle_check_work,
                                  msecs_to_jiffies(IDLE_NO_TOUCH_DELAY_MS));
        }
    }
}

static void check_work_func(struct work_struct *work)
{
    struct task_info *info, *tmp;
    struct task_struct *task;
    
    rcu_read_lock();
    for_each_process(task) {
        if (!task->mm || task->flags & PF_KTHREAD)
            continue;
        update_task_info(task);
        info = find_task_info(task->pid);
        if (!info)
            continue;
        
        schedule_normal_app(task, info);
    }
    rcu_read_unlock();
    
    adjust_frequencies_with_power();
    
    spin_lock(&task_list_lock);
    list_for_each_entry_safe(info, tmp, &task_list, list) {
        rcu_read_lock();
        task = find_task_by_vpid(info->pid);
        if (!task) {
            list_del(&info->list);
            kfree(info);
        }
        rcu_read_unlock();
    }
    spin_unlock(&task_list_lock);
    
    if (fa_wq)
        queue_delayed_work(fa_wq, &check_work, msecs_to_jiffies(CHECK_INTERVAL_MS));
}

static void boost_work_func(struct work_struct *work)
{
    struct task_info *info;
    
    if (fg_pid == 0)
        return;
    if (screen_idle_mode) {
        exit_screen_idle_mode();
    }
    info = find_task_info(fg_pid);
    if (info) {
        info->last_boost_jiffies = jiffies;
        if (info->is_whitelisted && current_mode == MODE_WHITELIST) {
            int cluster_type = info->cluster_type;
            if (cluster_type == CLUSTER_TYPE_BIG) {
                set_all_big_core_freq(BIG_CORE_BOOST_KHZ);
            } else if (cluster_type == CLUSTER_TYPE_ALL) {
                set_all_big_core_freq(BIG_CORE_MAX_FREQ_KHZ);
                set_all_little_core_freq(LITTLE_CORE_MAX_KHZ);
            } else {
                set_all_big_core_freq(BIG_CORE_MID_FREQ_KHZ);
            }
        } else {
            set_all_big_core_freq(BIG_CORE_MID_FREQ_KHZ);
        }
    }
}

static void screen_off_work_func(struct work_struct *work)
{
    if (!screen_on && !screen_off_processed) {
        schedule_screen_off_mode();
    }
}

static void power_check_work_func(struct work_struct *work)
{
    if (screen_on) {
        update_power_statistics();
        if (fa_wq)
            queue_delayed_work(fa_wq, &power_check_work,
                              msecs_to_jiffies(POWER_CHECK_INTERVAL_MS));
    }
}

static void thermal_check_work_func(struct work_struct *work)
{
    check_thermal_status();
    if (fa_wq)
        queue_delayed_work(fa_wq, &thermal_check_work,
                          msecs_to_jiffies(5000));
}

static void boot_complete_work_func(struct work_struct *work)
{
    boot_complete = true;
    load_config_from_file();
    if (!input_handler_registered && fa_wq) {
        int rc = input_register_handler(&fa_input_handler);
        if (rc == 0) {
            input_handler_registered = true;
        }
    }
    if (screen_on && fa_wq) {
        queue_delayed_work(fa_wq, &check_work, msecs_to_jiffies(CHECK_INTERVAL_MS));
        queue_delayed_work(fa_wq, &power_check_work, msecs_to_jiffies(POWER_CHECK_INTERVAL_MS));
        queue_delayed_work(fa_wq, &idle_check_work, msecs_to_jiffies(IDLE_NO_TOUCH_DELAY_MS));
        queue_delayed_work(fa_wq, &pid_detect_work, msecs_to_jiffies(PID_CHECK_INTERVAL_MS));
    }
}

static int fb_notif_call(struct notifier_block *nb,
                         unsigned long event, void *data)
{
    int *blankp;
    struct fb_event *evdata = data;
    if (event != FB_EVENT_BLANK)
        return NOTIFY_DONE;
    if (!evdata || !evdata->data)
        return NOTIFY_DONE;
    blankp = evdata->data;
    if (*blankp == FB_BLANK_UNBLANK) {
        if (!screen_on) {
            screen_on = true;
            screen_off_processed = false;
            last_touch_jiffies = jiffies;
            cancel_delayed_work(&screen_off_work);
            schedule_screen_on_mode();
            if (fa_wq)
                queue_work(fa_wq, &boost_work);
        }
    } else {
        if (screen_on) {
            screen_on = false;
            screen_off_jiffies = jiffies;
            cancel_delayed_work(&check_work);
            cancel_delayed_work(&power_check_work);
            cancel_delayed_work(&idle_check_work);
            cancel_delayed_work(&pid_detect_work);
            cancel_delayed_work(&screen_off_work);
            if (fa_wq)
                queue_delayed_work(fa_wq, &screen_off_work,
                                  msecs_to_jiffies(SCREEN_OFF_DELAY_MS));
        }
    }
    return NOTIFY_OK;
}

static int fa_input_connect(struct input_handler *handler,
                            struct input_dev *dev,
                            const struct input_device_id *id)
{
    struct input_handle *h;
    int err;
    h = kzalloc(sizeof(*h), GFP_KERNEL);
    if (!h)
        return -ENOMEM;
    h->dev = dev;
    h->handler = handler;
    h->name = "frame_aware_unfair";
    err = input_register_handle(h);
    if (err) {
        kfree(h);
        return err;
    }
    err = input_open_device(h);
    if (err) {
        input_unregister_handle(h);
        kfree(h);
        return err;
    }
    return 0;
}

static void fa_input_disconnect(struct input_handle *handle)
{
    if (!handle)
        return;
    input_close_device(handle);
    input_unregister_handle(handle);
    kfree(handle);
}

static void fa_input_event(struct input_handle *handle,
                           unsigned int type, unsigned int code, int value)
{
    if (!screen_on || !fa_wq)
        return;
    if (type == EV_ABS || type == EV_KEY || type == EV_SYN) {
        last_touch_jiffies = jiffies;
        if (screen_idle_mode) {
            screen_idle_mode = false;
            exit_screen_idle_mode();
        }
        if (!work_pending(&boost_work))
            queue_work(fa_wq, &boost_work);
        if (!delayed_work_pending(&check_work))
            mod_delayed_work(fa_wq, &check_work, msecs_to_jiffies(50));
    }
}

static int detect_app_category(const char *package_name)
{
    if (!package_name)
        return APP_CATEGORY_BACKGROUND;
    if (strstr(package_name, "system") ||
        strstr(package_name, "android.") ||
        strstr(package_name, "com.android.")) {
        return APP_CATEGORY_SYSTEM;
    }
    if (strstr(package_name, ".launcher") ||
        strstr(package_name, ".home") ||
        strstr(package_name, "com.tencent.mm") ||
        strstr(package_name, "com.tencent.mobileqq")) {
        return APP_CATEGORY_INTERACTIVE;
    }
    return APP_CATEGORY_BACKGROUND;
}

static struct app_profile *find_app_profile(const char *package_name)
{
    struct app_profile *profile;
    spin_lock(&app_profiles_lock);
    list_for_each_entry(profile, &app_profiles, list) {
        if (strcmp(profile->package_name, package_name) == 0) {
            spin_unlock(&app_profiles_lock);
            return profile;
        }
    }
    spin_unlock(&app_profiles_lock);
    return NULL;
}

static ssize_t fg_pid_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    return sprintf(buf, "%d\n", fg_pid);
}

static ssize_t fg_pid_store(struct kobject *k, struct kobj_attribute *a,
                            const char *buf, size_t count)
{
    pid_t v;
    if (kstrtoint(buf, 10, &v) == 0) {
        mutex_lock(&fg_lock);
        fg_pid = v;
        if (screen_on && fa_wq) {
            queue_work(fa_wq, &boost_work);
        }
        mutex_unlock(&fg_lock);
    }
    return count;
}

static ssize_t power_monitor_show(struct kobject *k, struct kobj_attribute *a, char *buf)
{
    int len = 0;
    unsigned int avg_watts = avg_power_uw / 1000000;
    unsigned int avg_milliwatts = (avg_power_uw % 1000000) / 1000;
    unsigned int max_watts = max_power_uw / 1000000;
    unsigned int max_milliwatts = (max_power_uw % 1000000) / 1000;
    len += sprintf(buf + len, "Current Power: %lu uW\n", last_power_uw);
    len += sprintf(buf + len, "Average Power: %u.%03u W\n",
                   avg_watts, avg_milliwatts);
    len += sprintf(buf + len, "Max Power: %u.%03u W\n",
                   max_watts, max_milliwatts);
    len += sprintf(buf + len, "Power Emergency Mode: %s\n",
                   power_emergency_mode ? "Yes" : "No");
    len += sprintf(buf + len, "Temperature: %d°C\n",
                   last_temperature);
    len += sprintf(buf + len, "Thermal Emergency Mode: %s\n",
                   thermal_emergency_mode ? "Yes" : "No");
    len += sprintf(buf + len, "Screen State: %s\n",
                   screen_on ? "On" : "Off");
    len += sprintf(buf + len, "Screen Off Processed: %s\n",
                   screen_off_processed ? "Yes" : "No");
    len += sprintf(buf + len, "Screen Idle Mode: %s\n",
                   screen_idle_mode ? "Yes" : "No");
    len += sprintf(buf + len, "Scheduler Mode: %s\n",
                   current_mode == MODE_DYNAMIC ? "Dynamic" : "Whitelist");
    len += sprintf(buf + len, "Small Cluster Apps: %d\n", small_count);
    len += sprintf(buf + len, "Large Cluster Apps: %d\n", large_count);
    len += sprintf(buf + len, "All Cluster Apps: %d\n", all_count);
    return len;
}

static ssize_t power_monitor_store(struct kobject *k, struct kobj_attribute *a,
                                   const char *buf, size_t count)
{
    return count;
}

static struct kobj_attribute fg_attr = __ATTR(fg_pid, 0644, fg_pid_show, fg_pid_store);
static struct kobj_attribute power_attr = __ATTR(power_monitor, 0644, power_monitor_show, power_monitor_store);

static int __init fa_init(void)
{
    int rc;
    init_masks();
    spin_lock_init(&task_list_lock);
    INIT_LIST_HEAD(&task_list);
    INIT_LIST_HEAD(&app_profiles);
    spin_lock_init(&pid_detect_lock);
    fa_wq = alloc_workqueue("frame_aware_wq", WQ_FREEZABLE | WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
    if (!fa_wq) {
        return -ENOMEM;
    }
    INIT_DELAYED_WORK(&check_work, check_work_func);
    INIT_DELAYED_WORK(&screen_off_work, screen_off_work_func);
    INIT_WORK(&boost_work, boost_work_func);
    INIT_DELAYED_WORK(&boot_complete_work, boot_complete_work_func);
    INIT_DELAYED_WORK(&power_check_work, power_check_work_func);
    INIT_DELAYED_WORK(&thermal_check_work, thermal_check_work_func);
    INIT_DELAYED_WORK(&idle_check_work, idle_check_work_func);
    INIT_DELayed_WORK(&pid_detect_work, pid_detect_work_func);
    rc = fb_register_client(&fb_notifier);
    fa_kobj = kobject_create_and_add("frame_aware", kernel_kobj);
    if (fa_kobj) {
        sysfs_create_file(fa_kobj, &fg_attr.attr);
        sysfs_create_file(fa_kobj, &power_attr.attr);
    }
    last_touch_jiffies = jiffies;
    screen_on = true;
    power_check_jiffies = jiffies;
    thermal_check_jiffies = jiffies;
    if (fa_wq) {
        queue_delayed_work(fa_wq, &thermal_check_work, msecs_to_jiffies(5000));
        queue_delayed_work(fa_wq, &boot_complete_work, msecs_to_jiffies(30000));
        queue_delayed_work(fa_wq, &pid_detect_work, msecs_to_jiffies(1000));
    }
    return 0;
}

static void __exit fa_exit(void)
{
    struct task_info *info, *tmp;
    struct app_profile *profile, *ptmp;
    cancel_delayed_work_sync(&check_work);
    cancel_delayed_work_sync(&screen_off_work);
    cancel_work_sync(&boost_work);
    cancel_delayed_work_sync(&boot_complete_work);
    cancel_delayed_work_sync(&power_check_work);
    cancel_delayed_work_sync(&thermal_check_work);
    cancel_delayed_work_sync(&idle_check_work);
    cancel_delayed_work_sync(&pid_detect_work);
    if (fa_wq) {
        flush_workqueue(fa_wq);
        destroy_workqueue(fa_wq);
    }
    spin_lock(&task_list_lock);
    list_for_each_entry_safe(info, tmp, &task_list, list) {
        list_del(&info->list);
        kfree(info);
    }
    spin_unlock(&task_list_lock);
    spin_lock(&app_profiles_lock);
    list_for_each_entry_safe(profile, ptmp, &app_profiles, list) {
        list_del(&profile->list);
        kfree(profile);
    }
    spin_unlock(&app_profiles_lock);
    free_cluster_apps();
    if (input_handler_registered) {
        input_unregister_handler(&fa_input_handler);
        input_handler_registered = false;
    }
    fb_unregister_client(&fb_notifier);
    if (fa_kobj) {
        sysfs_remove_file(fa_kobj, &fg_attr.attr);
        sysfs_remove_file(fa_kobj, &power_attr.attr);
        kobject_put(fa_kobj);
    }
}

module_init(fa_init);
module_exit(fa_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Frame Aware Scheduler");
MODULE_DESCRIPTION("Cluster-aware task scheduler with dynamic/whitelist modes");
