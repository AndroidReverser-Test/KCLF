/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host-side generator test: dump programs for objdump review and check the
 * structural invariants the kernel side depends on. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KCLF_CODEGEN_HOST 1
#include "../kclf_codegen.h"
#include "../kclf_param.h"

/* The restart pad is one random fall-through instruction, never a fixed
 * branch, and it must not touch a register the target owns. */
static int restart_pad_ok(unsigned word)
{
    if (word == 0xd503201fu) return 1; /* nop */
    if ((word & 0xffe00000u) == 0xd2800000u) return 1; /* movz xN, #imm16 */
    if ((word & 0xffe00000u) == 0xca000000u) return 1; /* eor xN, xM, xK */
    if ((word & 0xffc00000u) == 0x91000000u) return 1; /* add xN, xM, #imm12 */
    if ((word & 0xffe00000u) == 0xaa000000u) return 1; /* orr xN, xM, xK */
    return 0;
}

static int contains(const unsigned char *haystack, size_t size, const char *needle)
{
    size_t n = strlen(needle), i;
    for (i = 0; i + n <= size; i++)
        if (!memcmp(haystack + i, needle, n)) return 1;
    return 0;
}

static unsigned char page[65536];

int main(int argc, char **argv)
{
    int page_size = 4096;
    unsigned seed;
    int failures = 0;

    if (argc > 1) page_size = atoi(argv[1]);
    if (page_size < 2048 || page_size > (int)sizeof(page) || (page_size & (page_size - 1))) {
        fprintf(stderr, "bad page size\n");
        return 2;
    }
    for (seed = 1; seed <= 8; seed++) {
        struct kclf_prog prog;
        unsigned char *code;
        unsigned i;
        unsigned nonzero = 0;
        char name[64];

        memset(page, 0, sizeof(page));
        if (kclf_prog_build(page, page_size, 0x7f12345000ULL, seed, &prog)) {
            fprintf(stderr, "seed %u: build failed\n", seed);
            return 1;
        }
        code = page + prog.entry_off - 4;
        if (prog.entry_off < 8 || (prog.entry_off & 15) || prog.entry_off >= (u32)page_size) failures++;
        if (prog.compl_off < prog.entry_off || prog.compl_off + 4 > (u32)page_size) failures++;
        if (prog.length < 200 || prog.length > (u32)page_size) failures++;
        if (prog.compl_off & 3) failures++;
        /* the completion site must be the svc the kernel waits for */
        {
            const unsigned char *at = page + prog.compl_off - 4;
            unsigned word = (unsigned)at[0] | ((unsigned)at[1] << 8) | ((unsigned)at[2] << 16) | ((unsigned)at[3] << 24);
            if (word != 0xd4000001u) failures++;
        }
        /* the entry is preceded by a random fall-through restart pad, not by a
         * fixed branch instruction */
        {
            unsigned word = (unsigned)code[0] | ((unsigned)code[1] << 8) |
                            ((unsigned)code[2] << 16) | ((unsigned)code[3] << 24);
            if (!restart_pad_ok(word)) failures++;
        }
        /* no embedded framework tag: the recovery marker is a per-request
         * random token kept in the private page, never a literal in the code */
        if (contains(page, (size_t)page_size, "KCLFBAIL")) failures++;
        /* unused code-page bytes stay randomized */
        for (i = prog.length; i < (unsigned)page_size; i++)
            if (page[i]) nonzero++;
        if (!nonzero) failures++;
        printf("seed=%u entry=0x%x compl=0x%x length=%u\n", seed, prog.entry_off, prog.compl_off, prog.length);
        snprintf(name, sizeof(name), "codegen-%u.bin", seed);
        {
            FILE *f = fopen(name, "wb");
            if (!f) return 1;
            fwrite(code, 1, prog.length, f);
            fclose(f);
        }
    }
    if (failures) {
        fprintf(stderr, "%d structural failures\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
