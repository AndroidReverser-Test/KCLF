/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host-only audit of the 1.5.0 completion design.
 *
 * The 1.4.3 audit recognized a fixed 52-instruction completion suffix around a
 * real svc inside the generated page.  1.5.0 removed that anchor: completion
 * and RELRO both call resolved libc entries, so the generated page contains no
 * svc at all, and the private-page layout is randomized per request.  This
 * program keeps the old 1.4.3 recognizer (with its literal 1.4.3 offsets) and
 * proves that it no longer matches any generated program, while also rejecting
 * every generated page that still contains an svc.
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

static uint32_t mov(unsigned rd, unsigned rm)
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
    expected[n++] = mov(0, cookie);
    expected[n++] = mov(3, rc);
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

static unsigned old_scan(const uint32_t *words, size_t count)
{
    unsigned matches = 0;
    size_t i;
    for (i = 0; i < count; i++)
        if (words[i] == 0xd4000001u && old_suffix_at(words, count, i)) matches++;
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
static int random_layout(struct kclf_priv_layout *pl, uint64_t *rng)
{
    unsigned char used[4096];
    unsigned sizes[21] = {
        KCLF_SAVED_BYTES, KCLF_QREGS_BYTES, 8, 8, 8, 8, 4, 4, 64,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, KCLF_COMPL_PATH
    };
    unsigned aligns[21] = { 8, 16, 8, 8, 8, 8, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8 };
    unsigned order[21];
    int i, at = 0;
    memset(used, 0, sizeof(used));
    memset(pl, 0, sizeof(*pl));
    for (i = 0; i < 21; i++) order[i] = (unsigned)i;
    for (i = 20; i > 0; i--) {
        int j = (int)(next_random(rng) % (uint64_t)(i + 1)), t = (int)order[i];
        order[i] = (unsigned)j;
        order[j] = (unsigned)t;
    }
    for (i = 0; i < 21; i++) {
        unsigned k = order[i], size = sizes[k], align = aligns[k];
        int tries;
        for (tries = 0; tries < 512; tries++) {
            unsigned off = (unsigned)(next_random(rng) % 4096u);
            unsigned j;
            off &= ~(align - 1);
            if (off + size > 4080) continue;
            for (j = 0; j < size; j++) if (used[off + j]) break;
            if (j != size) continue;
            memset(used + off, 1, size);
            switch (k) {
            case 0: pl->saved = (u16)off; break;
            case 1: pl->qregs = (u16)off; break;
            case 2: pl->fpcr = (u16)off; break;
            case 3: pl->fpsr = (u16)off; break;
            case 4: pl->bail = (u16)off; break;
            case 5: pl->bailtok = (u16)off; break;
            case 6: pl->nrkey = (u16)off; break;
            case 7: pl->nrcnt = (u16)off; break;
            case 8: pl->nrs = (u16)off; break;
            case 9: pl->handle = (u16)off; break;
            case 10: pl->errptr = (u16)off; break;
            case 11: pl->rc = (u16)off; break;
            case 12: pl->cookie = (u16)off; break;
            case 13: pl->mprotfn = (u16)off; break;
            case 14: pl->complfn[0] = (u16)off; break;
            case 15: pl->complfn[1] = (u16)off; break;
            case 16: pl->complfn[2] = (u16)off; break;
            case 17: pl->complarg0[0] = (u16)off; break;
            case 18: pl->complarg0[1] = (u16)off; break;
            case 19: pl->complarg0[2] = (u16)off; break;
            default: pl->path = (u16)off; break;
            }
            at++;
            break;
        }
        if (tries == 512) {
            /* Fragmentation is possible with several 512-byte blocks; fall
             * back to a compact random-order layout.  Offsets are still not
             * the historical fixed ones. */
            unsigned cursor = (unsigned)(next_random(rng) % 64u);
            int j;
            memset(used, 0, sizeof(used));
            at = 0;
            for (j = 0; j < 21; j++) {
                unsigned kk = order[j], sz = sizes[kk], al = aligns[kk];
                unsigned off;
                cursor = (cursor + (unsigned)(next_random(rng) % 32u) + al - 1) & ~(al - 1);
                if (cursor + sz > 4080) cursor = 0;
                off = cursor;
                cursor += sz;
                switch (kk) {
                case 0: pl->saved = (u16)off; break;
                case 1: pl->qregs = (u16)off; break;
                case 2: pl->fpcr = (u16)off; break;
                case 3: pl->fpsr = (u16)off; break;
                case 4: pl->bail = (u16)off; break;
                case 5: pl->bailtok = (u16)off; break;
                case 6: pl->nrkey = (u16)off; break;
                case 7: pl->nrcnt = (u16)off; break;
                case 8: pl->nrs = (u16)off; break;
                case 9: pl->handle = (u16)off; break;
                case 10: pl->errptr = (u16)off; break;
                case 11: pl->rc = (u16)off; break;
                case 12: pl->cookie = (u16)off; break;
                case 13: pl->mprotfn = (u16)off; break;
                case 14: pl->complfn[0] = (u16)off; break;
                case 15: pl->complfn[1] = (u16)off; break;
                case 16: pl->complfn[2] = (u16)off; break;
                case 17: pl->complarg0[0] = (u16)off; break;
                case 18: pl->complarg0[1] = (u16)off; break;
                case 19: pl->complarg0[2] = (u16)off; break;
                default: pl->path = (u16)off; break;
                }
                at++;
            }
            break;
        }
    }
    pl->end = 4080;
    return at == 21 ? 0 : -1;
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
    unsigned matches;
    if (!f) return 1;
    if (fseek(f, 0, SEEK_END) || (size = ftell(f)) <= 0 || size > 64 * 1024 * 1024 ||
        fseek(f, 0, SEEK_SET)) { fclose(f); return 1; }
    data = malloc((size_t)size);
    if (!data) { fclose(f); return 1; }
    if (fread(data, 1, (size_t)size, f) != (size_t)size) { free(data); fclose(f); return 1; }
    fclose(f);
    matches = old_scan(data, (size_t)size / 4);
    free(data);
    printf("negative_file=%s old_matches=%u\n", path, matches);
    return matches != 0;
}

int main(int argc, char **argv)
{
    static const unsigned sizes[] = { 4096, 16384, 65536 };
    unsigned per_size = 10000, generated = 0, random_pages = 0;
    uint64_t rng = UINT64_C(0x20261030de7ec7);
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
            int count = 1 + (int)(next_random(&rng) & 1);

            if (random_layout(&pl, &rng)) {
                fprintf(stderr, "layout failed size=%u sample=%u\n", size, i);
                return 1;
            }
            if (kclf_prog_build((u8 *)page, (int)size, param, priv, &pl, count, seed, &prog)) {
                fprintf(stderr, "build failed size=%u sample=%u saved=%x q=%x path=%x\n", size, i,
                        pl.saved, pl.qregs, pl.path);
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
            if (old_scan(page, size / 4)) {
                fprintf(stderr, "old 1.4.3 suffix matched size=%u sample=%u\n", size, i);
                return 1;
            }
            generated++;
        }
        for (i = 0; i < 1000; i++) {
            unsigned j;
            for (j = 0; j < size / 4; j++) page[j] = (uint32_t)next_random(&rng);
            page[size / 8] = 0xd4000001u;
            if (old_scan(page, size / 4)) return 1;
            random_pages++;
        }
        printf("page=%u generated=%u old_matches=0 random_negative=%u\n", size, per_size, 1000u);
    }
    for (arg = 1; arg < argc; arg++) if (negative_file(argv[arg])) return 1;
    printf("PASS generated=%u random_pages=%u in_page_svc=0 old_suffix_matches=0\n", generated, random_pages);
    puts("scope=host structural audit only; not Android/seccomp/false-positive-rate validation");
    return 0;
}
