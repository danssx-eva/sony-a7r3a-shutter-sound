/* memscan.c —— 在相机上直接扫描物理内存，查找指定字节模式
 *
 * 用法: ./memscan <pattern_file> <start_phys_hex> <size_hex>
 *   例: ./memscan /log/w/fp.bin 0x0 0x40000000
 *
 * 输出: 每个命中的物理地址
 *
 * 编译: arm-linux-gnueabi-gcc -static -O2 -o memscan memscan.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define CHUNK (1024 * 1024)
#define MAXPAT 256

static unsigned char pat[MAXPAT];
static int patlen = 0;

static int load_pat(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return -1; }
    patlen = (int)fread(pat, 1, MAXPAT, f);
    fclose(f);
    if (patlen < 4) { fprintf(stderr, "pattern too short\n"); return -1; }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <pattern_file> <start_phys_hex> <size_hex>\n", argv[0]);
        return 2;
    }
    if (load_pat(argv[1]) != 0) return 2;

    unsigned long start = strtoul(argv[2], NULL, 16);
    unsigned long size  = strtoul(argv[3], NULL, 16);

    fprintf(stderr, "pattern %d bytes, scanning phys 0x%lx .. 0x%lx (%lu MB)\n",
            patlen, start, start + size, size / (1024 * 1024));

    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open /dev/mem: %s\n", strerror(errno)); return 2; }

    unsigned char *buf = malloc(CHUNK + MAXPAT);
    if (!buf) { fprintf(stderr, "malloc failed\n"); return 2; }

    unsigned long off = 0;
    int total = 0;
    int errcount = 0;

    while (off < size) {
        unsigned long want = size - off;
        if (want > CHUNK) want = CHUNK;

        ssize_t n = pread(fd, buf, want, (off_t)(start + off));
        if (n <= 0) {
            errcount++;
            if (errcount <= 8)
                fprintf(stderr, "  read fail @0x%lx: %s\n", start + off, strerror(errno));
            off += want;
            continue;
        }

        for (ssize_t i = 0; i + patlen <= n; i++) {
            if (buf[i] != pat[0]) continue;
            if (memcmp(buf + i, pat, patlen) == 0) {
                printf("HIT phys=0x%lx\n", start + off + (unsigned long)i);
                total++;
                if (total >= 50) goto done;
            }
        }
        off += (unsigned long)n;
    }
done:
    fprintf(stderr, "done: %d hits, %d read errors\n", total, errcount);
    free(buf);
    close(fd);
    return total > 0 ? 0 : 1;
}
