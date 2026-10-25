/* P2.2 探针 v1：环境自检 + futex PI 原语功能验证（不触发 CVE）
 * 编译：zig cc -target arm-linux-musleabi -static -O2 -pthread -o probe probe.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
/* futex ABI 常量（linux/futex.h 等价） */
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_PRIVATE_FLAG 128
#include <stdint.h>
#include <sys/time.h>
#include <errno.h>

static int futex(uint32_t *u, int op, uint32_t val, const struct timespec *to,
                 uint32_t *u2, uint32_t val3) {
    return syscall(SYS_futex, u, op, val, to, u2, val3);
}

static volatile int spinner_run = 0;
static void *spinner(void *arg) {
    volatile unsigned long x = 0;
    while (spinner_run) { for (int i = 0; i < 100000; i++) x += i; }
    return NULL;
}

static void show_cpus(void) {
    char path[64], buf[16];
    printf("[cpu] online: ");
    for (int i = 0; i < 8; i++) {
        snprintf(path, sizeof path, "/sys/devices/system/cpu/cpu%d/online", i);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        int n = read(fd, buf, sizeof buf - 1); close(fd);
        if (n > 0) { buf[n] = 0; printf("cpu%d=%c ", i, buf[0]); }
    }
    printf("\n");
}

/* --- 测试1: 单线程 PI futex lock/unlock --- */
static int test_pi_basic(void) {
    uint32_t f = 0;
    int r = futex(&f, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (r) { printf("[T1] LOCK_PI failed: %d (%s)\n", r, strerror(errno)); return -1; }
    printf("[T1] LOCK_PI ok, word=0x%08x (owner tid=%d, self=%d)\n",
           f, (int)(f & 0x3fffffff), (int)syscall(SYS_gettid));
    r = futex(&f, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    printf("[T1] UNLOCK_PI %s\n", r ? strerror(errno) : "ok");
    return r ? -1 : 0;
}

/* --- 测试2: WAIT_REQUEUE_PI + CMP_REQUEUE_PI 正常路径（无 bug 触发） --- */
static uint32_t u1 = 0, u2 = 0;
static volatile int waiter_ready = 0, waiter_ret = 0;

static void *pi_waiter(void *arg) {
    __sync_fetch_and_add(&waiter_ready, 1);
    /* 等 u1 == 0，被 requeue 到 u2 并作为 proxy lock 完成者 */
    int r = futex(&u1, FUTEX_WAIT_REQUEUE_PI, 0, NULL, &u2, 0);
    waiter_ret = r;
    int e = errno;
    printf("[T2] waiter returned %d (%s)\n", r, r ? strerror(e) : "ok");
    if (!r) futex(&u2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static int test_requeue_pi(void) {
    pthread_t th;
    if (pthread_create(&th, NULL, pi_waiter, NULL)) { printf("[T2] pthread_create fail\n"); return -1; }
    while (!waiter_ready) usleep(1000);
    usleep(200000); /* 确保已进入 futex_wait_requeue_pi */
    int r = futex(&u1, FUTEX_CMP_REQUEUE_PI, 1, NULL, &u2, 0);
    printf("[T2] CMP_REQUEUE_PI -> %d (%s), u2 word=0x%08x\n",
           r, r < 0 ? strerror(errno) : "ok", u2);
    pthread_join(th, NULL);
    if (u2) futex(&u2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0); /* 清理 */
    return r < 0 ? -1 : 0;
}

int main(void) {
    char buf[256];
    printf("=== probe start ===\n");
    printf("uid=%d euid=%d pid=%d tid=%d\n", getuid(), geteuid(), getpid(), (int)syscall(SYS_gettid));
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd >= 0) { int n = read(fd, buf, sizeof buf - 1); close(fd); if (n > 0) { buf[n] = 0; printf("context=%s", buf); } }
    fd = open("/proc/version", O_RDONLY);
    if (fd >= 0) { int n = read(fd, buf, sizeof buf - 1); close(fd); if (n > 0) { buf[n] = 0; printf("kernel=%s", buf); } }
    printf("pagesize=%ld\n", sysconf(_SC_PAGESIZE));
    show_cpus();

    /* 负载 3 秒，尝试触发 hotplug 让 cpu1-3 上线 */
    pthread_t th[8];
    spinner_run = 1;
    for (int i = 0; i < 8; i++) pthread_create(&th[i], NULL, spinner, NULL);
    sleep(3);
    spinner_run = 0;
    for (int i = 0; i < 8; i++) pthread_join(th[i], NULL);
    printf("[cpu] after load: ");
    show_cpus();

    printf("--- T1 basic PI futex ---\n");
    test_pi_basic();
    printf("--- T2 requeue_pi normal path ---\n");
    test_requeue_pi();
    printf("=== probe done ===\n");
    return 0;
}
