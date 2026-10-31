#ifndef PASSIVE_V151_SIGNATURE_H
#define PASSIVE_V151_SIGNATURE_H
#include <stdint.h>
#include <stddef.h>

struct candidate {
    uintptr_t abi, priv;
    unsigned saved, token, done, tail_word;
};

static uint32_t load_x(unsigned rt, unsigned rn, unsigned off)
{ return 0xf9400000u | ((off / 8u) << 10) | (rn << 5) | rt; }
static unsigned load_off(uint32_t w) { return ((w >> 10) & 4095u) * 8u; }

static int imm64(const uint32_t *w, unsigned reg, uintptr_t *value)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 4; i++) {
        uint32_t expect = (i ? 0xf2800000u : 0xd2800000u) | (i << 21) | reg;
        if ((w[i] & ~0x001fffe0u) != expect) return 0;
        v |= (uint64_t)((w[i] >> 5) & 65535u) << (16 * i);
    }
    *value = (uintptr_t)v;
    return 1;
}

/* Recognition input is only bytes. No injector status, seed, address or payload
 * marker is accepted. Runtime corroboration is a separate mandatory stage. */
static int recognize(const uint32_t *words, size_t count, struct candidate *out)
{
    const uint32_t mask = 0x003ffc00u;
    for (size_t end = 34; end < count; end++) {
        if (words[end] != 0xd61f0200u) continue;
        const uint32_t *t = words + end - 4, *w = t - 29;
        if ((t[0] & ~mask) != load_x(16, 10, 0) ||
            (t[1] & ~mask) != (0xf9000000u | (10u << 5) | 16u) ||
            (t[2] & ~mask) != load_x(16, 10, 0) ||
            (t[3] & ~mask) != load_x(10, 10, 0)) continue;
        if (load_off(t[2]) < 256) continue;
        unsigned saved = load_off(t[2]) - 256;
        unsigned token = load_off(t[0]), done = load_off(t[1]);
        if (saved + 272 > 4096 || load_off(t[3]) != saved + 80 ||
            token > 4088 || done > 4088 || token == done ||
            (token >= saved && token < saved + 272) ||
            (done >= saved && done < saved + 272)) continue;
        unsigned seen = 0, i;
        for (i = 0; i < 29; i++) {
            unsigned r = w[i] & 31u;
            if (r == 10 || r == 16 || r == 31 || (seen & (1u << r)) ||
                w[i] != load_x(r, 10, saved + r * 8)) break;
            seen |= 1u << r;
        }
        if (i != 29) continue;
        unsigned pb = (w[-1] >> 16) & 31u;
        if (pb < 19 || pb > 26 || w[-1] != (0xaa0003e0u | (pb << 16) | 10u)) continue;
        for (size_t entry = 4; entry <= 32 && entry + 17 < count; entry += 4) {
            if (words[entry] != 0xd503245fu) continue;
            for (size_t first = entry + 1; first <= entry + 9; first++) {
                uintptr_t abi, priv;
                unsigned p = words[first] & 31u;
                if (p < 19 || p > 26 || p == pb ||
                    !imm64(words + first, p, &abi) || !imm64(words + first + 4, pb, &priv)) continue;
                if (!abi || !priv || (abi & 4095) || (priv & 4095) || abi == priv) continue;
                *out = (struct candidate){abi, priv, saved, token, done, (unsigned)(end - 33)};
                return 1;
            }
        }
    }
    return 0;
}
#endif
