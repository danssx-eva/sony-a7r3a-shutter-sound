/* memscan_tiny.c —— 无 libc，纯 syscall 的物理内存扫描器
 *
 * 用法: ./memscan_tiny <pattern_file> <start_phys_hex> <size_hex>
 *
 * 编译: arm-linux-gnueabi-gcc -nostdlib -static -Os -fno-builtin -o memscan_tiny memscan_tiny.c
 */

#define SYS_exit    1
#define SYS_read    3
#define SYS_write   4
#define SYS_open    5
#define SYS_close   6
#define SYS_pread64 180

#define CHUNK (1024 * 1024)
#define MAXPAT 128

static unsigned char pat[MAXPAT];
static unsigned char buf[CHUNK + MAXPAT];

/* ---------- syscall 封装 ---------- */
static int sys_open(const char *p, int fl, int mode)
{
    register int r7 __asm__("r7") = SYS_open;
    register int r0 __asm__("r0") = (int)p;
    register int r1 __asm__("r1") = fl;
    register int r2 __asm__("r2") = mode;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2) : "memory");
    return r0;
}

static int sys_read(int fd, void *b, int n)
{
    register int r7 __asm__("r7") = SYS_read;
    register int r0 __asm__("r0") = fd;
    register int r1 __asm__("r1") = (int)b;
    register int r2 __asm__("r2") = n;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2) : "memory");
    return r0;
}

static int sys_close(int fd)
{
    register int r7 __asm__("r7") = SYS_close;
    register int r0 __asm__("r0") = fd;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
}

static int sys_pread(int fd, void *b, int n, unsigned long long off)
{
    register int r7 __asm__("r7") = SYS_pread64;
    register int r0 __asm__("r0") = fd;
    register int r1 __asm__("r1") = (int)b;
    register int r2 __asm__("r2") = n;
    register int r3 __asm__("r3") = (int)(off & 0xffffffffULL);
    register int r4 __asm__("r4") = (int)(off >> 32);
    __asm__ volatile("svc #0" : "+r"(r0)
                     : "r"(r7), "r"(r1), "r"(r2), "r"(r3), "r"(r4) : "memory");
    return r0;
}

static void sys_write(int fd, const void *b, int n)
{
    register int r7 __asm__("r7") = SYS_write;
    register int r0 __asm__("r0") = fd;
    register int r1 __asm__("r1") = (int)b;
    register int r2 __asm__("r2") = n;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2) : "memory");
}

static void sys_exit(int code)
{
    register int r7 __asm__("r7") = SYS_exit;
    register int r0 __asm__("r0") = code;
    __asm__ volatile("svc #0" : : "r"(r7), "r"(r0));
    for (;;) {}
}

/* ---------- 小工具 ---------- */
static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void says(const char *s) { sys_write(1, s, slen(s)); }

static void sayhex(unsigned long v)
{
    char b[11];
    b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 8; i++) {
        int nib = (int)((v >> ((7 - i) * 4)) & 0xf);
        b[2 + i] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
    }
    b[10] = '\n';
    sys_write(1, b, 11);
}

static unsigned long parsehex(const char *s)
{
    unsigned long v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    while (*s) {
        int c = *s++;
        unsigned long d;
        if (c >= '0' && c <= '9') d = (unsigned long)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (unsigned long)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (unsigned long)(c - 'A' + 10);
        else break;
        v = (v << 4) | d;
    }
    return v;
}

/* ---------- 主体 ---------- */
void main_body(int argc, char **argv)
{
    if (argc < 4) {
        says("usage: memscan_tiny <patfile> <start_hex> <size_hex> [devpath]\n");
        sys_exit(2);
    }

    int fd = sys_open(argv[1], 0, 0);
    if (fd < 0) { says("ERR open pattern\n"); sys_exit(2); }
    int pl = sys_read(fd, pat, MAXPAT);
    sys_close(fd);
    if (pl < 4) { says("ERR pattern short\n"); sys_exit(2); }

    unsigned long start = parsehex(argv[2]);
    unsigned long size  = parsehex(argv[3]);

    says("scan start=");
    sayhex(start);
    says("size=");
    sayhex(size);
    says("patlen=");
    sayhex((unsigned long)pl);

    const char *devpath = (argc >= 5) ? argv[4] : "/dev/mem";
    says("dev=");
    says(devpath);
    says("\n");
    int mfd = sys_open(devpath, 0, 0);
    if (mfd < 0) { says("ERR open dev\n"); sys_exit(2); }

    unsigned long off = 0;
    int total = 0;
    int errs = 0;

    while (off < size) {
        unsigned long want = size - off;
        if (want > CHUNK) want = CHUNK;

        int n = sys_pread(mfd, buf, (int)want, (unsigned long long)(start + off));
        if (n <= 0) {
            errs++;
            off += want;
            continue;
        }
        for (int i = 0; i + pl <= n; i++) {
            if (buf[i] != pat[0]) continue;
            int j = 1;
            while (j < pl && buf[i + j] == pat[j]) j++;
            if (j == pl) {
                says("HIT ");
                sayhex(start + off + (unsigned long)i);
                total++;
                if (total >= 50) goto done;
            }
        }
        off += (unsigned long)n;
    }
done:
    says("done hits=");
    sayhex((unsigned long)total);
    sys_exit(total > 0 ? 0 : 1);
}

/* ---------- 入口 ---------- */
__asm__(
".global _start\n"
".type _start, %function\n"
"_start:\n"
"  ldr  r0, [sp]\n"
"  add  r1, sp, #4\n"
"  bl   main_body\n"
"  mov  r0, #2\n"
"  mov  r7, #1\n"
"  svc  #0\n"
".size _start, .-_start\n"
);
