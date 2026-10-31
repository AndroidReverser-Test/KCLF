/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host-only audit of the 1.5.x completion design.
 *
 * The 1.4.3 audit recognized a fixed 52-instruction completion suffix around a
 * real svc inside the generated page.  1.5.0 removed that anchor by calling
 * libc wrappers instead, and the 1.5.0 self-check then confirmed a new one: at
 * the completion syscall the saved x29 led to a libc frame whose return address
 * pointed into the generated page, where a fixed 72-byte call stub (18 words,
 * the last 56 bytes constant) was validated and the private page located
 * through the [sp,#0x80] slot.
 *
 * 1.5.1 removes that too: the generated program issues no syscall and calls no
 * library function, restores the register file itself, publishes a per-request
 * random token and branches back to the interrupted PC.  This program keeps
 * both historical recognizers and proves that neither matches any generated
 * program, while also rejecting every generated page that still contains an
 * svc.
 *
 * It does not execute ARM64 instructions, install seccomp, access a device, or
 * change the injector.  A match identifies a code template, not execution,
 * authorization or origin.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kclf_codegen.h"
#include "../kclf_param.h"

enum { SUFFIX_WORDS = 52, SVC_INDEX = 10 };
enum { STUB_WORDS = 18 };
static uint32_t page[65536 / 4];

static uint32_t ldrx(unsigned rt, unsigned rn, unsigned offset)
{
    return 0xf9400000u | ((offset / 8) << 10) | (rn << 5) | rt;
}

static uint32_t ldrw(unsigned rt, unsigned rn, unsigned offset)
{
    return 0xb9400000u | ((offset / 4) << 10) | (rn << 5) | rt;
}

static uint32_t add(unsigned rd, unsigned rn, unsigned value)
{
    return 0x91000000u | (value << 10) | (rn << 5) | rd;
}

static uint32_t mov_reg(unsigned rd, unsigned rm)
{
    return 0xaa0003e0u | (rm << 16) | rd;
}

/* The exact 1.4.3 recognizer, kept with its historical fixed offsets. */
static int old_suffix_at(const uint32_t *words, size_t count, size_t svc)
{
    uint32_t expected[SUFFIX_WORDS];
    const uint32_t *w;
    unsigned c, pb, t2, q, cookie, rc, t0, roles[7], seen = 0, i, n = 0;
    if (svc < SVC_INDEX || svc > count || count - svc < SUFFIX_WORDS - SVC_INDEX)
        return 0;
    w = words + svc - SVC_INDEX;
    c = w[0] & 31; pb = (w[0] >> 5) & 31;
    t2 = w[1] & 31; q = w[2] & 31;
    cookie = (w[8] >> 16) & 31; rc = (w[9] >> 16) & 31;
    t0 = w[14] & 31;
    roles[0] = c; roles[1] = pb; roles[2] = t2; roles[3] = q;
    roles[4] = cookie; roles[5] = rc; roles[6] = t0;
    for (i = 0; i < 7; i++) {
        if (roles[i] < 19 || roles[i] > 28 || (seen & (1u << roles[i]))) return 0;
        seen |= 1u << roles[i];
    }

    expected[n++] = ldrw(c, pb, 0x11c);
    expected[n++] = ldrw(t2, pb, 0x118);
    expected[n++] = add(q, pb, 0x120);
    expected[n++] = 0xb4000000u | (11u << 5) | c;
    expected[n++] = ldrw(8, q, 0);
    expected[n++] = 0x4a000000u | (t2 << 16) | (8u << 5) | 8u;
    expected[n++] = ldrx(1, pb, 0x160);
    expected[n++] = ldrx(2, pb, 0x168);
    expected[n++] = mov_reg(0, cookie);
    expected[n++] = mov_reg(3, rc);
    expected[n++] = 0xd4000001u;
    expected[n++] = add(q, q, 4);
    expected[n++] = 0xd1000000u | (1u << 10) | (c << 5) | c;
    expected[n++] = 0xb5000000u | ((0x7ffffu - 8u) << 5) | c;
    expected[n++] = ldrx(t0, pb, 0x178);
    expected[n++] = 0xf9000000u | ((0x110u / 8) << 10) | (pb << 5) | t0;
    expected[n++] = ldrx(16, pb, 0xf8);
    expected[n++] = add(31, 16, 0);
    expected[n++] = ldrx(16, pb, 0x108);
    expected[n++] = 0xd51b4210u;
    expected[n++] = ldrx(16, pb, 0x100);
    for (i = 0; i < 31; i++)
        if (i != 16 && i != pb) expected[n++] = ldrx(i, pb, i * 8);
    expected[n++] = ldrx(pb, pb, pb * 8);
    expected[n++] = 0xd61f0200u;
    return n == SUFFIX_WORDS && !memcmp(w, expected, sizeof(expected));
}

/* The 1.5.0 completion-call stub that the ordinary-App self-check validated:
 *   ldr x9,[sp,#0x80]; ldr x0,[x9,#a]; ldr x16,[x9,#f]; ldr x6,[x9,#c]
 *   mov x7,x6; mov x1..#x5,xzr; mov x10..#x15,xzr; mov x9,xzr; blr x16
 * Only the three ldr offsets were per-request randomized, so the shape (and the
 * last 56 bytes literally) was a fixed anchor at a real completion syscall.
 */
static int stub_at(const uint32_t *w)
{
    const uint32_t offmask = 0x003ffc00u;
    unsigned n = 4, i;

    if (w[0] != ldrx(9, 31, 0x80)) return 0;
    if ((w[1] & ~offmask) != ldrx(0, 9, 0)) return 0;
    if ((w[2] & ~offmask) != ldrx(16, 9, 0)) return 0;
    if ((w[3] & ~offmask) != ldrx(6, 9, 0)) return 0;
    if (w[n++] != mov_reg(7, 6)) return 0;
    for (i = 1; i <= 5; i++)
        if (w[n++] != mov_reg(i, 31)) return 0;
    for (i = 10; i <= 15; i++)
        if (w[n++] != mov_reg(i, 31)) return 0;
    if (w[n++] != mov_reg(9, 31)) return 0;
    if (w[n++] != 0xd63f0200u) return 0; /* blr x16 */
    return n == STUB_WORDS;
}

static unsigned scan_old_143(const uint32_t *words, size_t count)
{
    unsigned matches = 0;
    size_t i;
    for (i = 0; i < count; i++)
        if (words[i] == 0xd4000001u && old_suffix_at(words, count, i)) matches++;
    return matches;
}

static unsigned scan_old_150(const uint32_t *words, size_t count)
{
    unsigned matches = 0;
    size_t i;
    if (count < STUB_WORDS) return 0;
    for (i = 0; i + STUB_WORDS <= count; i++)
        if (stub_at(words + i)) matches++;
    return matches;
}

static uint64_t next_random(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

/* Independent host-side layout randomizer: the kernel does the same thing, but
 * the audit must not rely on the implementation's own generator. */
struct field
{
    unsigned size;
    unsigned align;
    u16 *slot;
};

static int random_layout(struct kclf_priv_layout *pl, uint64_t *rng)
{
    unsigned char used[4096];
    struct field fields[9];
    int i, n = 9;

    memset(pl, 0, sizeof(*pl));
    memset(used, 0, sizeof(used));
    fields[0] = (struct field){ KCLF_SAVED_BYTES, 8, &pl->saved };
    fields[1] = (struct field){ KCLF_QREGS_BYTES, 16, &pl->qregs };
    fields[2] = (struct field){ 8, 8, &pl->fpcr };
    fields[3] = (struct field){ 8, 8, &pl->fpsr };
    fields[4] = (struct field){ 8, 8, &pl->done };
    fields[5] = (struct field){ 8, 8, &pl->donetok };
    fields[6] = (struct field){ 8, 8, &pl->handle };
    fields[7] = (struct field){ 8, 8, &pl->errptr };
    fields[8] = (struct field){ 8, 8, &pl->rc };
    for (i = n - 1; i > 0; i--) {
        int j = (int)(next_random(rng) % (uint64_t)(i + 1));
        struct field t = fields[i];
        fields[i] = fields[j];
        fields[j] = t;
    }
    for (i = 0; i < n; i++) {
        int tries;
        for (tries = 0; tries < 512; tries++) {
            unsigned off = (unsigned)(next_random(rng) % 4096u) & ~(fields[i].align - 1);
            unsigned j;
            if (off + fields[i].size > 4080) continue;
            for (j = 0; j < fields[i].size; j++)
                if (used[off + j]) break;
            if (j != fields[i].size) continue;
            memset(used + off, 1, fields[i].size);
            *fields[i].slot = (u16)off;
            break;
        }
        if (tries == 512) {
            /* Fragmentation is possible with the two large blocks; fall back to
             * a compact random-order layout.  Offsets are still not fixed. */
            unsigned cursor = (unsigned)(next_random(rng) % 64u);
            int j;
            memset(used, 0, sizeof(used));
            for (j = 0; j < n; j++) {
                unsigned off;
                cursor = (cursor + (unsigned)(next_random(rng) % 32u) + fields[j].align - 1) & ~(fields[j].align - 1);
                if (cursor + fields[j].size > 4080) cursor = 0;
                off = cursor;
                cursor += fields[j].size;
                *fields[j].slot = (u16)off;
            }
            break;
        }
    }
    pl->end = 4080;
    return 0;
}

static int has_svc(const unsigned char *code, size_t length)
{
    size_t i;
    for (i = 0; i + 4 <= length; i += 4) {
        unsigned word = (unsigned)code[i] | ((unsigned)code[i + 1] << 8) |
                        ((unsigned)code[i + 2] << 16) | ((unsigned)code[i + 3] << 24);
        if (word == 0xd4000001u) return 1;
    }
    return 0;
}

static int negative_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    long size;
    uint32_t *data;
    unsigned m143, m150;
    if (!f) return 1;
    if (fseek(f, 0, SEEK_END) || (size = ftell(f)) <= 0 || size > 64 * 1024 * 1024 ||
        fseek(f, 0, SEEK_SET)) { fclose(f); return 1; }
    data = malloc((size_t)size);
    if (!data) { fclose(f); return 1; }
    if (fread(data, 1, (size_t)size, f) != (size_t)size) { free(data); fclose(f); return 1; }
    fclose(f);
    m143 = scan_old_143(data, (size_t)size / 4);
    m150 = scan_old_150(data, (size_t)size / 4);
    free(data);
    printf("negative_file=%s old_143_matches=%u old_150_matches=%u\n", path, m143, m150);
    return m143 != 0 || m150 != 0;
}

int main(int argc, char **argv)
{
    static const unsigned sizes[] = { 4096, 16384, 65536 };
    unsigned per_size = 10000, generated = 0, random_pages = 0;
    uint64_t rng = UINT64_C(0x20261031de7ec7);
    unsigned s, i;
    int arg;

    for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        unsigned size = sizes[s];
        for (i = 0; i < per_size; i++) {
            struct kclf_prog prog;
            struct kclf_priv_layout pl;
            uint64_t seed = next_random(&rng);
            uint64_t param = UINT64_C(0x6000000000) + ((next_random(&rng) & 0xfffff) << 16);
            uint64_t priv = param + 0x100000;

            random_layout(&pl, &rng);
            if (kclf_prog_build((u8 *)page, (int)size, param, priv, &pl, seed, &prog)) {
                fprintf(stderr, "build failed size=%u sample=%u saved=%x q=%x done=%x\n", size, i,
                        pl.saved, pl.qregs, pl.done);
                return 1;
            }
            if (prog.entry_off >= size || prog.length > size - prog.entry_off + 4) {
                fprintf(stderr, "bad geometry size=%u sample=%u\n", size, i);
                return 1;
            }
            if (has_svc((unsigned char *)page + prog.entry_off - 4, prog.length)) {
                fprintf(stderr, "svc found size=%u sample=%u\n", size, i);
                return 1;
            }
            if (scan_old_143(page, size / 4)) {
                fprintf(stderr, "old 1.4.3 suffix matched size=%u sample=%u\n", size, i);
                return 1;
            }
            if (scan_old_150(page, size / 4)) {
                fprintf(stderr, "old 1.5.0 completion stub matched size=%u sample=%u\n", size, i);
                return 1;
            }
            generated++;
        }
        for (i = 0; i < 1000; i++) {
            unsigned j;
            for (j = 0; j < size / 4; j++) page[j] = (uint32_t)next_random(&rng);
            page[size / 8] = 0xd4000001u;
            if (scan_old_143(page, size / 4)) return 1;
            if (scan_old_150(page, size / 4)) return 1;
            random_pages++;
        }
        printf("page=%u generated=%u old_143=0 old_150=0 random_negative=%u\n", size, per_size, 1000u);
    }
    for (arg = 1; arg < argc; arg++)
        if (negative_file(argv[arg])) return 1;
    printf("PASS generated=%u random_pages=%u in_page_svc=0 old_143_matches=0 old_150_matches=0\n", generated,
           random_pages);
    puts("scope=host structural audit only; not Android/seccomp/false-positive-rate validation");
    return 0;
}
