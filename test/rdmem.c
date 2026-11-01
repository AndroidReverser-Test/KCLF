/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Device-only diagnostic: print bytes from /proc/<pid>/mem as hex.
 *
 * Used to compare a loaded library's in-memory ELF header with the file on disk
 * (an anti-tamper engine can rewrite it).  Build with the Android NDK and run
 * as root:
 *   clang --target=aarch64-linux-android26 -O2 -fPIE -pie test/rdmem.c -o rdmem
 *   adb push rdmem /data/local/tmp/kclf-rdmem
 *   adb shell "/data/local/tmp/kpatch <KEY> su -c '/data/local/tmp/kclf-rdmem <pid> <hexaddr> 64'"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

int main(int argc, char **argv)
{
    char path[64];
    unsigned long long addr;
    int len = 64, fd, i;
    unsigned char buf[8192];

    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid> <hexaddr> [len]\n", argv[0]);
        return 2;
    }
    if (argc >= 4) len = atoi(argv[3]);
    if (len <= 0 || len > (int)sizeof(buf)) len = 64;
    addr = strtoull(argv[2], NULL, 16);
    snprintf(path, sizeof(path), "/proc/%s/mem", argv[1]);
    fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return 1; }
    ssize_t n = pread(fd, buf, (size_t)len, (off_t)addr);
    if (n < 0) { fprintf(stderr, "pread: %s\n", strerror(errno)); return 1; }
    for (i = 0; i < n; i++) {
        printf("%02x", buf[i]);
        if ((i & 15) == 15) printf("\n"); else printf(" ");
    }
    if (i & 15) printf("\n");
    close(fd);
    return 0;
}
