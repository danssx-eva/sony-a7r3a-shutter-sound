/* A7R3A LD_PRELOAD 探路 .so —— 只证明"能加载"，不做任何危险操作。
 *
 * 设计要点（来自 silverrrr/a7r3-qemu 的经验）：
 *   1. 构造函数【第一件事】unlink 掉 /setting/mode/preload →
 *      这样即使后面崩了，下次也不会再加载（防 boot-loop）。
 *   2. 全程只用裸 syscall（不依赖 libc，glibc 2.11 环境下更稳）。
 *   3. 只往 /log/hook.log 追加日志，不改任何行为、不拦截任何函数。
 *
 * 编译：
 *   arm-linux-gnueabi-gcc -shared -fPIC -nostdlib -O1 -march=armv7-a \
 *       -mfloat-abi=soft -o hook_probe.so hook_probe.c
 */
typedef unsigned long usize;

#define SYS_write 4
#define SYS_open  5
#define SYS_close 6
#define SYS_unlink 10

static long sys1(long nr, long a)
{
    register long r7 __asm__("r7") = nr;
    register long r0 __asm__("r0") = a;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory", "cc");
    return r0;
}

static long sys3(long nr, long a, long b, long c)
{
    register long r7 __asm__("r7") = nr;
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory", "cc");
    return r0;
}

static usize slen(const char *s)
{
    usize n = 0;
    while (s[n]) n++;
    return n;
}

static void logstr(const char *s)
{
    /* O_WRONLY|O_CREAT|O_APPEND */
    int fd = (int)sys3(SYS_open, (long)"/log/hook.log", 0x441, 0644);
    if (fd >= 0) {
        sys3(SYS_write, fd, (long)s, (long)slen(s));
        sys1(SYS_close, fd);
    }
}

__attribute__((constructor)) static void hook_init(void)
{
    /* ① 先拆掉自己的门控（防 boot-loop） */
    sys1(SYS_unlink, (long)"/setting/mode/preload");

    /* ② 留证据 */
    logstr("HOOK_LOADED pid=");
    /* 简单打印 thrives：不解析，只标记 */
    logstr("OK\n");
}
