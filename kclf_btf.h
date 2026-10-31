/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KCLF_BTF_H
#define KCLF_BTF_H

/* The caller supplies <stdint.h>, <stddef.h> and string primitives. This
 * parser is also compiled by the host regression test, without KPM headers. */
struct kclf_btf_header
{
    uint16_t magic;
    uint8_t version, flags;
    uint32_t hdr_len, type_off, type_len, str_off, str_len;
};

struct kclf_btf_type
{
    uint32_t name, info, size;
};

struct kclf_btf_member
{
    uint32_t name, type, offset;
};

struct kclf_btf
{
    const unsigned char *types;
    const char *strings;
    size_t type_len, str_len;
};

static int kclf_btf_open(struct kclf_btf *b, const void *data, size_t size)
{
    const struct kclf_btf_header *h = data;
    size_t body;

    memset(b, 0, sizeof(*b));
    if (!data || ((uintptr_t)data & 3) || size < sizeof(*h) || h->magic != 0xeb9f || h->version != 1 || h->flags ||
        h->hdr_len < sizeof(*h) || h->hdr_len > size || (h->hdr_len & 3) || (h->type_off & 3))
        return -1;
    body = size - h->hdr_len;
    if ((h->type_len & 3) || h->type_off > body || h->type_len > body - h->type_off || h->str_off > body ||
        !h->str_len || h->str_len > body - h->str_off || (uint64_t)h->type_off + h->type_len > h->str_off)
        return -1;
    b->types = (const unsigned char *)data + h->hdr_len + h->type_off;
    b->strings = (const char *)data + h->hdr_len + h->str_off;
    b->type_len = h->type_len;
    b->str_len = h->str_len;
    if (b->strings[0] || b->strings[b->str_len - 1]) return -1;
    return 0;
}

static size_t kclf_btf_record(const struct kclf_btf_type *t, size_t remaining)
{
    size_t extra = 0, n;
    unsigned int kind;

    if (remaining < sizeof(*t)) return 0;
    n = t->info & 0xffff;
    kind = (t->info >> 24) & 31;
    switch (kind) {
    case 1:
    case 14:
    case 17:
        extra = 4;
        break;
    case 3:
        extra = 12;
        break;
    case 4:
    case 5:
    case 15:
    case 19:
        extra = n * 12;
        break;
    case 6:
    case 13:
        extra = n * 8;
        break;
    case 2:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 16:
    case 18:
        break;
    default:
        return 0; /* future kinds must not silently desynchronise parsing */
    }
    if (extra > remaining - sizeof(*t)) return 0;
    return sizeof(*t) + extra;
}

static const char *kclf_btf_name(const struct kclf_btf *b, uint32_t off)
{
    return off < b->str_len ? b->strings + off : "";
}

static const struct kclf_btf_type *kclf_btf_find(const struct kclf_btf *b, const char *name, uint32_t id)
{
    size_t off = 0, size;
    uint32_t index = 1;

    while (off < b->type_len) {
        const struct kclf_btf_type *t = (const void *)(b->types + off);
        unsigned int kind;
        size = kclf_btf_record(t, b->type_len - off);
        if (!size) return 0;
        kind = (t->info >> 24) & 31;
        if ((id && id == index) || (name && (kind == 4 || kind == 5) && !strcmp(kclf_btf_name(b, t->name), name)))
            return t;
        off += size;
        index++;
    }
    return 0;
}

static int kclf_btf_offset(const struct kclf_btf *b, const struct kclf_btf_type *t, const char *member, int depth)
{
    unsigned int kind, i, n;
    const struct kclf_btf_member *m;

    if (!t || depth <= 0) return -1;
    kind = (t->info >> 24) & 31;
    if (kind == 8 || kind == 9 || kind == 10 || kind == 11 || kind == 18)
        return kclf_btf_offset(b, kclf_btf_find(b, 0, t->size), member, depth - 1);
    if (kind != 4 && kind != 5) return -1;
    m = (const void *)(t + 1);
    n = t->info & 0xffff;
    for (i = 0; i < n; i++) {
        uint32_t bitoff = (t->info >> 31) ? (m[i].offset & 0xffffff) : m[i].offset;
        int sub;
        if ((bitoff & 7) || ((t->info >> 31) && (m[i].offset >> 24))) continue;
        if (bitoff / 8 >= t->size) continue;
        if (m[i].name && !strcmp(kclf_btf_name(b, m[i].name), member)) return bitoff / 8;
        if (m[i].name) continue;
        sub = kclf_btf_offset(b, kclf_btf_find(b, 0, m[i].type), member, depth - 1);
        if (sub >= 0 && (uint32_t)sub < t->size - bitoff / 8) return bitoff / 8 + sub;
    }
    return -1;
}

static int kclf_btf_member_offset(const struct kclf_btf *b, const char *type, const char *member)
{
    return kclf_btf_offset(b, kclf_btf_find(b, type, 0), member, 8);
}

/* Validate the whole accessed field, not only its first byte. */
static int kclf_btf_member_range(const struct kclf_btf *b, const char *type, const char *member, uint32_t width,
                                 uint32_t alignment)
{
    const struct kclf_btf_type *t = kclf_btf_find(b, type, 0);
    int off = kclf_btf_member_offset(b, type, member);

    if (!t || off < 0 || !width || !alignment || (alignment & (alignment - 1)) || ((uint32_t)off & (alignment - 1)) ||
        (uint32_t)off > t->size || width > t->size - (uint32_t)off)
        return -1;
    return off;
}

/* Resolve typedef/qualifier chains, including type tags, with a cycle bound. */
static inline const struct kclf_btf_type *kclf_btf_resolve(const struct kclf_btf *b, uint32_t id)
{
    int depth;
    for (depth = 0; id && depth < 16; depth++) {
        const struct kclf_btf_type *t = kclf_btf_find(b, 0, id);
        unsigned int kind;
        if (!t) return 0;
        kind = (t->info >> 24) & 31;
        if (kind != 8 && kind != 9 && kind != 10 && kind != 11 && kind != 18) return t;
        id = t->size;
    }
    return 0;
}

static inline const struct kclf_btf_type *kclf_btf_func_proto(const struct kclf_btf *b, const char *name)
{
    size_t off = 0, size;
    while (off < b->type_len) {
        const struct kclf_btf_type *t = (const void *)(b->types + off);
        size = kclf_btf_record(t, b->type_len - off);
        if (!size) return 0;
        if (((t->info >> 24) & 31) == 12 && !strcmp(kclf_btf_name(b, t->name), name)) {
            t = kclf_btf_resolve(b, t->size);
            return t && ((t->info >> 24) & 31) == 13 ? t : 0;
        }
        off += size;
    }
    return 0;
}

static inline int kclf_btf_is_bool(const struct kclf_btf_type *t)
{
    return t && ((t->info >> 24) & 31) == 1 && t->size == 1 &&
           (*(const uint32_t *)(t + 1) >> 24 & 4);
}

static inline int kclf_btf_points_to(const struct kclf_btf *b, const struct kclf_btf_type *t,
                                   const char *name)
{
    if (!t || ((t->info >> 24) & 31) != 2) return 0;
    t = kclf_btf_resolve(b, t->size);
    return t && ((t->info >> 24) & 31) == 4 && !strcmp(kclf_btf_name(b, t->name), name);
}

/* task_work_cancel has two incompatible ABIs under the SAME symbol name.
 * 0: no prototype; -1: unknown prototype; 1: function -> pointer; 2: work -> bool. */
static inline int kclf_btf_cancel_abi(const struct kclf_btf *b)
{
    const struct kclf_btf_type *p = kclf_btf_func_proto(b, "task_work_cancel"), *ret, *arg;
    const uint32_t *params;
    if (!p) return 0;
    if ((p->info & 0xffff) != 2) return -1;
    params = (const void *)(p + 1); /* name/type pairs */
    if (!kclf_btf_points_to(b, kclf_btf_resolve(b, params[1]), "task_struct")) return -1;
    ret = kclf_btf_resolve(b, p->size);
    arg = kclf_btf_resolve(b, params[3]);
    if (kclf_btf_is_bool(ret) && kclf_btf_points_to(b, arg, "callback_head")) return 2;
    if (!kclf_btf_points_to(b, ret, "callback_head") || !arg || ((arg->info >> 24) & 31) != 2) return -1;
    p = kclf_btf_resolve(b, arg->size);
    if (!p || ((p->info >> 24) & 31) != 13 || (p->info & 0xffff) != 1 || p->size) return -1;
    params = (const void *)(p + 1);
    return kclf_btf_points_to(b, kclf_btf_resolve(b, params[1]), "callback_head") ? 1 : -1;
}

/* -1 means unavailable/int ABI (use the upstream version baseline), -2 is
 * an incompatible prototype. BTF takes precedence over vendor version labels. */
static inline int kclf_btf_signal_abi(const struct kclf_btf *b)
{
    const struct kclf_btf_type *p = kclf_btf_func_proto(b, "task_work_add"), *t;
    const uint32_t *params, *values;
    unsigned int kind, i;
    int resume = -1, signal = -1;
    if (!p) return -1;
    if ((p->info & 0xffff) != 3) return -2;
    params = (const void *)(p + 1);
    t = kclf_btf_resolve(b, params[5]);
    if (kclf_btf_is_bool(t)) return 0;
    if (!t) return -2;
    kind = (t->info >> 24) & 31;
    if (kind == 1 && t->size == 4) return -1; /* 5.8-5.10 use int + macros */
    if (kind != 6 || t->size != 4) return -2;
    values = (const void *)(t + 1);
    for (i = 0; i < (t->info & 0xffff); i++) {
        const char *name = kclf_btf_name(b, values[2 * i]);
        if (!strcmp(name, "TWA_RESUME")) resume = (int)values[2 * i + 1];
        if (!strcmp(name, "TWA_SIGNAL")) signal = (int)values[2 * i + 1];
    }
    return resume == 1 && signal == 2 ? 1 : -2;
}
#endif
