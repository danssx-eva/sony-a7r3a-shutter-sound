/* Freestanding ARM Linux pw: no libc, no dynamic loader, direct syscalls. */
#include <stdint.h>
#include <stddef.h>

#define SYS_exit 1
#define SYS_read 3
#define SYS_write 4
#define SYS_open 5
#define SYS_close 6
#define SYS_lseek 19
#define SYS_fsync 118
#define O_RDONLY 0
#define O_WRONLY 1
#define SEEK_SET 0
#define SEEK_END 2

static inline int syscall1(int number, int a0) {
    register int r0 __asm__("r0") = a0;
    register int r7 __asm__("r7") = number;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
}

static inline int syscall3(int number, int a0, int a1, int a2) {
    register int r0 __asm__("r0") = a0;
    register int r1 __asm__("r1") = a1;
    register int r2 __asm__("r2") = a2;
    register int r7 __asm__("r7") = number;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}

static int failed(int result) {
    return result < 0 && result >= -4095;
}

static void print(const char *text) {
    int length = 0;
    while (text[length])
        ++length;
    syscall3(SYS_write, 2, (int)text, length);
}

static void print_hex(uint32_t value) {
    char buf[10];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 8; ++i) {
        uint32_t nibble = (value >> (28 - i * 4)) & 15;
        buf[2 + i] = (char)(nibble < 10 ? '0' + nibble : 'a' + nibble - 10);
    }
    syscall3(SYS_write, 2, (int)buf, 10);
}

static int error(const char *message, int code) {
    print(message);
    print_hex((uint32_t)code);
    print("\n");
    return 1;
}

static int parse_offset(const char *text, uint32_t *result) {
    if (!text || !*text || *text == '-')
        return -1;
    uint32_t base = 10;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text += 2;
        if (!*text)
            return -1;
    }
    uint32_t value = 0;
    while (*text) {
        uint32_t digit;
        if (*text >= '0' && *text <= '9')
            digit = (uint32_t)(*text - '0');
        else if (base == 16 && *text >= 'a' && *text <= 'f')
            digit = (uint32_t)(*text - 'a' + 10);
        else if (base == 16 && *text >= 'A' && *text <= 'F')
            digit = (uint32_t)(*text - 'A' + 10);
        else
            return -1;
        if (base == 16) {
            if (value > 0x07ffffffU)
                return -1;
            value = (value << 4) | digit;
        } else {
            if (value > 214748364U || (value == 214748364U && digit > 7))
                return -1;
            value = value * 10 + digit;
        }
        ++text;
    }
    *result = value;
    return 0;
}

static int write_all(int fd, const unsigned char *buf, int size) {
    int done = 0;
    while (done < size) {
        int n = syscall3(SYS_write, fd, (int)(buf + done), size - done);
        if (n == -4)  /* EINTR */
            continue;
        if (n <= 0)
            return n < 0 ? n : -5;  /* EIO */
        done += n;
    }
    return 0;
}

static unsigned char io_buffer[65536];
static unsigned char verify_source[65536];
static unsigned char verify_target[65536];

int pw_main(int argc, char **argv) {
    if (argc != 4) {
        print("usage: pw <target> <offset> <source>\n");
        return 2;
    }
    uint32_t offset;
    if (parse_offset(argv[2], &offset) < 0) {
        print("PW_ERROR invalid_offset\n");
        return 2;
    }
    int src = syscall3(SYS_open, (int)argv[3], O_RDONLY, 0);
    if (failed(src))
        return error("PW_ERROR open_source ", src);
    int source_size = syscall3(SYS_lseek, src, 0, SEEK_END);
    if (failed(source_size))
        return error("PW_ERROR source_size ", source_size);
    if ((uint32_t)source_size > 0x7fffffffU - offset)
        return error("PW_ERROR range_overflow ", -75);
    int rc = syscall3(SYS_lseek, src, 0, SEEK_SET);
    if (failed(rc))
        return error("PW_ERROR source_seek ", rc);

    int dst = syscall3(SYS_open, (int)argv[1], O_WRONLY, 0);  /* No O_TRUNC. */
    if (failed(dst))
        return error("PW_ERROR open_target ", dst);
    int before_size = syscall3(SYS_lseek, dst, 0, SEEK_END);
    if (failed(before_size))
        return error("PW_ERROR target_size ", before_size);
    rc = syscall3(SYS_lseek, dst, (int)offset, SEEK_SET);
    if (failed(rc))
        return error("PW_ERROR target_seek ", rc);

    uint32_t remaining = (uint32_t)source_size;
    while (remaining) {
        int chunk = remaining > sizeof(io_buffer) ? (int)sizeof(io_buffer) : (int)remaining;
        int got = syscall3(SYS_read, src, (int)io_buffer, chunk);
        if (got == -4)
            continue;
        if (got <= 0)
            return error("PW_ERROR read_source ", got < 0 ? got : -5);
        rc = write_all(dst, io_buffer, got);
        if (rc < 0)
            return error("PW_ERROR write_target ", rc);
        remaining -= (uint32_t)got;
    }
    rc = syscall1(SYS_fsync, dst);
    if (failed(rc))
        return error("PW_ERROR fsync ", rc);
    rc = syscall1(SYS_close, dst);
    if (failed(rc))
        return error("PW_ERROR close_target ", rc);
    rc = syscall1(SYS_close, src);
    if (failed(rc))
        return error("PW_ERROR close_source ", rc);

    src = syscall3(SYS_open, (int)argv[3], O_RDONLY, 0);
    if (failed(src))
        return error("PW_ERROR reopen_source ", src);
    dst = syscall3(SYS_open, (int)argv[1], O_RDONLY, 0);
    if (failed(dst))
        return error("PW_ERROR reopen_target ", dst);
    int final_size = syscall3(SYS_lseek, dst, 0, SEEK_END);
    if (failed(final_size))
        return error("PW_ERROR final_size ", final_size);
    int required = (int)(offset + (uint32_t)source_size);
    int expected_final = before_size > required ? before_size : required;
    if (final_size != expected_final)
        return error("PW_ERROR final_size_mismatch ", -5);
    rc = syscall3(SYS_lseek, src, 0, SEEK_SET);
    if (failed(rc))
        return error("PW_ERROR verify_source_seek ", rc);
    rc = syscall3(SYS_lseek, dst, (int)offset, SEEK_SET);
    if (failed(rc))
        return error("PW_ERROR verify_target_seek ", rc);

    remaining = (uint32_t)source_size;
    while (remaining) {
        int chunk = remaining > sizeof(verify_source) ? (int)sizeof(verify_source) : (int)remaining;
        int a = syscall3(SYS_read, src, (int)verify_source, chunk);
        int b = syscall3(SYS_read, dst, (int)verify_target, chunk);
        if (a < 0 || b < 0)
            return error("PW_ERROR verify_read ", a < 0 ? a : b);
        if (a == 0 || b == 0 || a != b)
            return error("PW_ERROR readback_mismatch ", -5);
        for (int i = 0; i < a; ++i) {
            if (verify_source[i] != verify_target[i])
                return error("PW_ERROR readback_mismatch ", -5);
        }
        remaining -= (uint32_t)a;
    }
    syscall1(SYS_close, src);
    syscall1(SYS_close, dst);
    print("PW_OK off=");
    print_hex(offset);
    print(" src=");
    print_hex((uint32_t)source_size);
    print(" final=");
    print_hex((uint32_t)final_size);
    print(" readback=match\n");
    return 0;
}
