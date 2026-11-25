/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Small valid BTF type graph for ABI selection tests, never target code. */
struct btf_fixture {
    unsigned char bytes[4096] __attribute__((aligned(4)));
    unsigned int used, ids, string_used;
    char strings[512];
};

static inline unsigned int bf_string(struct btf_fixture *f, const char *s)
{
    unsigned int off = f->string_used;
    size_t n = strlen(s) + 1;
    assert(off + n <= sizeof(f->strings));
    memcpy(f->strings + off, s, n);
    f->string_used += (unsigned int)n;
    return off;
}

static inline unsigned int bf_type(struct btf_fixture *f, const char *name, unsigned int kind,
                                  unsigned int size, unsigned int n, const unsigned int *extra,
                                  unsigned int words)
{
    struct kclf_btf_type t = {bf_string(f, name), (kind << 24) | n, size};
    assert(f->used + sizeof(t) + words * 4 < sizeof(f->bytes));
    memcpy(f->bytes + f->used, &t, sizeof(t));
    f->used += sizeof(t);
    if (words) memcpy(f->bytes + f->used, extra, words * 4);
    f->used += words * 4;
    return ++f->ids;
}

/* notify: 0 bool, 1 int, 2 enum, 3 invalid enum; cancel: 1 old, 2 new,
 * 3 incompatible. Extra qualifiers exercise typedef/const/type-tag peeling. */
static inline size_t bf_build(struct btf_fixture *f, int notify, int cancel)
{
    unsigned int e[6], task, cb, pt, pc, boolean, integer, mode, proto, fn, ret, arg;
    struct kclf_btf_header h = {0};
    memset(f, 0, sizeof(*f));
    f->used = sizeof(h);
    f->string_used = 1;
    task = bf_type(f, "task_struct", 4, 16, 0, 0, 0);
    cb = bf_type(f, "callback_head", 4, 16, 0, 0, 0);
    pt = bf_type(f, "", 2, task, 0, 0, 0);
    pc = bf_type(f, "", 2, cb, 0, 0, 0);
    e[0] = (4U << 24) | 8;
    boolean = bf_type(f, "_Bool", 1, 1, 0, e, 1);
    e[0] = (1U << 24) | 32;
    integer = bf_type(f, "int", 1, 4, 0, e, 1);
    e[0] = bf_string(f, "TWA_RESUME"); e[1] = 1;
    e[2] = bf_string(f, "TWA_SIGNAL"); e[3] = notify == 3 ? 3 : 2;
    mode = bf_type(f, "task_work_notify_mode", 6, 4, 2, e, 4);
    mode = notify == 0 ? boolean : notify == 1 ? integer : mode;
    mode = bf_type(f, "notify_t", 8, mode, 0, 0, 0);
    e[0] = e[2] = e[4] = 0; e[1] = pt; e[3] = pc; e[5] = mode;
    proto = bf_type(f, "", 13, integer, 3, e, 6);
    bf_type(f, "task_work_add", 12, proto, 1, 0, 0);
    e[0] = 0; e[1] = pc;
    proto = bf_type(f, "", 13, 0, 1, e, 2);
    fn = bf_type(f, "", 2, proto, 0, 0, 0);
    fn = bf_type(f, "task_work_func_t", 8, fn, 0, 0, 0);
    arg = cancel == 1 ? fn : pc;
    arg = bf_type(f, "", 10, arg, 0, 0, 0);
    arg = bf_type(f, "tag", 18, arg, 0, 0, 0);
    ret = cancel == 1 ? pc : cancel == 2 ? boolean : integer;
    e[0] = e[2] = 0; e[1] = pt; e[3] = arg;
    proto = bf_type(f, "", 13, ret, 2, e, 4);
    bf_type(f, "task_work_cancel", 12, proto, 1, 0, 0);
    h.magic = 0xeb9f; h.version = 1; h.hdr_len = sizeof(h);
    h.type_len = f->used - sizeof(h); h.str_off = h.type_len; h.str_len = f->string_used;
    memcpy(f->bytes, &h, sizeof(h));
    memcpy(f->bytes + f->used, f->strings, f->string_used);
    return f->used + f->string_used;
}
