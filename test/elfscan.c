/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Device-only diagnostic: emulate kclf's loaded-provider scan on a live process.
 *
 * - reads /proc/<pid>/maps and /proc/<pid>/mem
 * - checks the 4-byte ELF magic at every VMA start
 * - parses ehdr/phdr/dynamic and prints the DT_SONAME of each candidate
 * - reports bad headers separately (an anti-tamper engine can rewrite
 *   e_type/e_machine/e_version while leaving the structural fields intact)
 *
 * Build with the Android NDK and run it as root:
 *   clang --target=aarch64-linux-android26 -O2 -fPIE -pie test/elfscan.c -o elfscan
 *   adb push elfscan /data/local/tmp/kclf-elfscan
 *   adb shell "/data/local/tmp/kpatch <KEY> su -c '/data/local/tmp/kclf-elfscan <pid> -v'"
 *
 * It is not part of the module and never changes the target.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#define MAXLINE 1024

struct ehdr64 {
    unsigned char ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct phdr64 {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
};
struct dyn64 { int64_t tag; uint64_t val; };

static int fd_mem;

static ssize_t rd(uint64_t addr, void *buf, size_t len)
{
    return pread(fd_mem, buf, len, (off_t)addr);
}

int main(int argc, char **argv)
{
    char path[128], line[MAXLINE];
    FILE *fp;
    int verbose = 0;
    int nvma = 0, nmagic = 0, nvalid = 0, nsoname = 0, nbad = 0;
    int i;

    if (argc < 2) { fprintf(stderr, "usage: %s <pid> [-v]\n", argv[0]); return 2; }
    if (argc > 2) verbose = 1;
    snprintf(path, sizeof(path), "/proc/%s/mem", argv[1]);
    fd_mem = open(path, O_RDONLY);
    if (fd_mem < 0) { perror(path); return 1; }
    snprintf(path, sizeof(path), "/proc/%s/maps", argv[1]);
    fp = fopen(path, "r");
    if (!fp) { perror(path); return 1; }

    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end;
        char perms[8], dev[16], p[512];
        unsigned long long off, ino;
        int n;
        unsigned char magic[4];
        struct ehdr64 eh;
        struct phdr64 ph;
        uint64_t dyn = 0, dynsz = 0, strtab = 0, strsz = 0, soname = 0;
        int j, ok;

        p[0] = 0;
        n = sscanf(line, "%llx-%llx %7s %llx %15s %llu %511[^\n]", &start, &end, perms, &off, dev, &ino, p);
        if (n < 6) continue;
        nvma++;
        if (rd(start, magic, 4) != 4) continue;
        if (memcmp(magic, "\177ELF", 4)) continue;
        nmagic++;
        if (rd(start, &eh, sizeof(eh)) != sizeof(eh)) { nbad++; continue; }
        ok = !memcmp(eh.ident, "\177ELF\2\1\1", 7) && eh.type == 3 && eh.machine == 183 &&
             eh.version == 1 && eh.ehsize == sizeof(eh) && eh.phentsize == sizeof(struct phdr64) &&
             eh.phnum && eh.phnum <= 64 && eh.phoff >= sizeof(eh) && eh.phoff <= 1024 * 1024;
        if (!ok) {
            nbad++;
            if (verbose)
                printf("BADHDR %llx-%llx %s %llx type=%u mach=%u ver=%u phnum=%u  %s\n",
                       start, end, perms, off, eh.type, eh.machine, eh.version, eh.phnum, p + (p[0] == ' '));
            continue;
        }
        nvalid++;
        for (j = 0; j < eh.phnum; j++) {
            if (rd(start + eh.phoff + (uint64_t)j * sizeof(ph), &ph, sizeof(ph)) != sizeof(ph)) break;
            if (ph.type == 2) { dyn = ph.vaddr; dynsz = ph.memsz; }
        }
        if (dyn && dynsz && dynsz <= 4096 * 16) {
            for (j = 0; j < (int)(dynsz / sizeof(struct dyn64)); j++) {
                struct dyn64 d;
                if (rd(start + dyn + (uint64_t)j * sizeof(d), &d, sizeof(d)) != sizeof(d)) break;
                if (!d.tag) break;
                if (d.tag == 5) strtab = start + d.val;
                if (d.tag == 10) strsz = d.val;
                if (d.tag == 14) soname = d.val;
            }
            if (strtab && strsz && soname < strsz) {
                char name[512];
                size_t k = 0;
                while (k < sizeof(name) - 1 && k < strsz - soname) {
                    if (rd(strtab + soname + k, &name[k], 1) != 1) break;
                    if (!name[k]) break;
                    k++;
                }
                name[k] = 0;
                if (k) {
                    nsoname++;
                    if (verbose) printf("ELF    %llx-%llx %s base=%llx soname=%s path=%s\n",
                                        start, end, perms, start, name, p + (p[0] == ' '));
                }
            } else if (verbose) {
                printf("NO-SONAME %llx-%llx %s %s\n", start, end, perms, p + (p[0] == ' '));
            }
        }
    }
    fclose(fp);
    printf("summary: pid=%s vmas=%d elf_magic=%d valid=%d soname=%d badhdr=%d\n",
           argv[1], nvma, nmagic, nvalid, nsoname, nbad);
    return 0;
}
