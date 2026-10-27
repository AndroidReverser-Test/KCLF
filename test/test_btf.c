/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kclf_btf.h"

int main(int argc, char **argv)
{
    struct
    {
        struct kclf_btf_header h;
        struct kclf_btf_type t;
        struct kclf_btf_member m;
        char strings[11];
    } sample = { .h = { .magic = 0xeb9f, .version = 1, .hdr_len = 24, .type_len = 24, .str_off = 24, .str_len = 11 },
                 .t = { .name = 1, .info = (4U << 24) | 1, .size = 16 },
                 .m = { .name = 6, .offset = 64 },
                 .strings = "\0test\0slot" };
    struct kclf_btf b;
    size_t i;

    assert(!kclf_btf_open(&b, &sample, sizeof(sample)));
    assert(kclf_btf_member_offset(&b, "test", "slot") == 8);
    assert(kclf_btf_member_range(&b, "test", "slot", 8, 8) == 8);
    assert(kclf_btf_member_range(&b, "test", "slot", 16, 8) == -1);
    assert(kclf_btf_member_range(&b, "test", "slot", 8, 16) == -1);
    assert(kclf_btf_member_range(&b, "test", "slot", 8, 3) == -1);
    assert(kclf_btf_open(&b, (const char *)&sample + 1, sizeof(sample) - 1));
    assert(!kclf_btf_open(&b, &sample, sizeof(sample)));
    assert(kclf_btf_member_offset(&b, "test", "missing") == -1);
    assert(kclf_btf_member_offset(&b, "missing", "slot") == -1);
    for (i = 0; i < 59; i++)
        assert(kclf_btf_open(&b, &sample, i));
    sample.h.type_len = UINT32_MAX;
    assert(kclf_btf_open(&b, &sample, sizeof(sample)));
    sample.h.type_len = 24;
    sample.t.info = (4U << 24) | 65535;
    assert(!kclf_btf_open(&b, &sample, sizeof(sample)));
    assert(!kclf_btf_find(&b, "test", 0));
    sample.t.info = (31U << 24);
    assert(!kclf_btf_find(&b, "test", 0));
    sample.t.info = (4U << 24) | 1;
    sample.m.offset = 121;
    assert(kclf_btf_member_offset(&b, "test", "slot") == -1);
    sample.m.offset = 120;
    assert(kclf_btf_member_range(&b, "test", "slot", 8, 1) == -1);
    sample.m.offset = 64;
    /* Deterministic mutation smoke test under ASan/UBSan, not a fuzz proof. */
    for (i = 0; i < sizeof(sample) * 256; i++) {
        unsigned char copy[sizeof(sample)] __attribute__((aligned(4)));
        memcpy(copy, &sample, sizeof(copy));
        copy[i / 256] = (unsigned char)i;
        if (!kclf_btf_open(&b, copy, sizeof(copy))) {
            (void)kclf_btf_member_range(&b, "test", "slot", 8, 8);
            (void)kclf_btf_member_offset(&b, "missing", "missing");
        }
    }
    puts("synthetic BTF bounds/kinds/members: PASS");

    if (argc == 2) {
        FILE *f = fopen(argv[1], "rb");
        long len;
        void *data;
        const struct kclf_btf_type *t;
        assert(f);
        assert(!fseek(f, 0, SEEK_END));
        len = ftell(f);
        assert(len > 0 && len < 64 * 1024 * 1024);
        rewind(f);
        data = malloc((size_t)len);
        assert(data && fread(data, 1, (size_t)len, f) == (size_t)len);
        fclose(f);
        assert(!kclf_btf_open(&b, data, (size_t)len));
        t = kclf_btf_find(&b, "pt_regs", 0);
        assert(t);
        printf("pt_regs.size=%u orig_x0=%d syscallno=%d task.mm=%d mm.mmap_lock=%d vma.start=%d vma.end=%d\n", t->size,
               kclf_btf_member_offset(&b, "pt_regs", "orig_x0"), kclf_btf_member_offset(&b, "pt_regs", "syscallno"),
               kclf_btf_member_offset(&b, "task_struct", "mm"), kclf_btf_member_offset(&b, "mm_struct", "mmap_lock"),
               kclf_btf_member_offset(&b, "vm_area_struct", "vm_start"),
               kclf_btf_member_offset(&b, "vm_area_struct", "vm_end"));
        assert(kclf_btf_member_offset(&b, "pt_regs", "orig_x0") == 272);
        assert(kclf_btf_member_offset(&b, "pt_regs", "syscallno") == 280);
        free(data);
        puts("device BTF: PASS");
    }
    return 0;
}
