/* klogd: 流式读内核日志（SYSLOG_ACTION_READ），用于抓 panic 现场 */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>

#define SYSLOG_ACTION_READ 2

int main(void) {
    static char buf[8192];
    for (;;) {
        long n = syscall(103 /* __NR_syslog */, SYSLOG_ACTION_READ, buf, sizeof(buf) - 1);
        if (n > 0) {
            ssize_t w = 0;
            while (w < n) {
                ssize_t k = write(1, buf + w, n - w);
                if (k <= 0) break;
                w += k;
            }
        } else {
            usleep(20000);
        }
    }
    return 0;
}
