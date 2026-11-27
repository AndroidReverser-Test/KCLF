#!/usr/bin/env python3
"""Fault-inject the production TLS preparation and image rollback paths."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'kclf_manual.c').read_text()
prepare = source[source.index('static int prepare_tls_runtime('):source.index('static int read_hwcap(')]
finish = source[source.index('long kclf_manual_finish('):source.index('void kclf_manual_abandon(')]
defer = source[source.index('static int defer_ifunc('):source.index('static int defer_tlsdesc(')]
prelude = r'''
#include "kclf_elf.h"
#include "kclf_tls.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#define KCLF_MAX_RELRO 8
#define KCLF_F_UNLOAD 8
#define KM_NEW 1
#define KM_GET 2
#define KM_PUT 3
#define KM_DROP 4
#define KM_LIVE 2
#define KM_IFUNCS 64
#define KCLF_DONE 1
#define KCLF_FAILED 2
#define KCLF_ST_LOADER 3
#define __NR_mprotect 226
struct pid { int dummy; } owner;
struct file { int unused; } backing;
struct kclf_manual_image { u64 id, tls_map, tls_length, tls_code, tls_code_len, map, length; struct pid *owner; unsigned refs; int state; struct file *backing; };
struct kclf_req {
    struct kclf_manual_image *image;
    struct file *code_file;
    char path[32], code_path[32];
    unsigned flags, relro_count, ifunc_count;
    u64 relro[8][2], tls_init, tls_arg, handle, image_addr, image_len;
    unsigned image_refs;
    int state, saved_valid, unload_rc, image_action;
};
struct km_provider { struct ke_object object; struct ke_io io; };
struct km_tls_fixup { u64 where, offset; };
struct km_context {
    struct kclf_req *r;
    struct ke_object object;
    struct ke_io io;
    struct km_provider *providers;
    struct km_tls_fixup *tls_fixups;
    unsigned ntls;
    u64 values[2], fixups[64][3];
};
static unsigned char code[64], memory[262144], payload[8192], codepage[65536];
#define kclf_tls_start code
#define kclf_tls_end (code + sizeof(code))
#define kclf_tls_init code
#define kclf_tls_resolve (code + 16)
static u64 kclf_page_size;
static int lookup_error, map_error, code_error, copy_failure, copies, unmaps, unmap_error, locked, abandoned, puts_count, code_maps, file_puts;
static u64 requested_length;
static int select_provider(struct km_context *c, const char *path, const char *name) {
    (void)c; (void)path; assert(!strcmp(name, "libc.so")); return 0;
}
int ke_lookup(struct ke_io *io, const struct ke_object *o, const char *name, const char *version,
              u32 hash, struct ke_sym *s, u64 *value) {
    (void)io; (void)o; (void)name; (void)version; (void)hash;
    s->info = 2; *value = 0x1000; return lookup_error ? lookup_error : 1;
}
static void report(void *ctx, const char *why, const char *detail) { (void)ctx; (void)why; (void)detail; }
static int copy(void *out, const void *in, int bytes) {
    if (++copies == copy_failure) return -EFAULT;
    memcpy(out, in, (size_t)bytes); return 0;
}
static int kclf_uwr(u64 at, const void *from, int bytes) { return copy((void *)(uintptr_t)at, from, bytes); }
static int kclf_urds(u64 at, void *to, int bytes) { return copy(to, (void *)(uintptr_t)at, bytes); }
static u64 map(int fd, u64 addr, u64 size, int prot, int flags, int offset) {
    assert(!fd && !addr && prot == 3 && flags == 0x22 && !offset && size <= sizeof(memory));
    requested_length = size; return map_error ? (u64)(long)map_error : (uintptr_t)memory;
}
static long unmap(u64 at, u64 size) {
    assert(at && size); unmaps++;
    if (unmap_error) { unmap_error = 0; return -EAGAIN; }
    return 0;
}
static void put(struct pid *p) { assert(p == &owner); puts_count++; }
static void put_file(struct file *f) { assert(f == &backing && !locked); file_puts++; }
static struct { u64 (*vm_mmap)(int,u64,u64,int,int,int); long (*vm_munmap)(u64,u64); void (*put_pid)(struct pid *); void (*fput)(struct file *); } kclf_ks = {map, unmap, put, put_file};
/* The production helper maps one page of the payload file and copies the EL0
 * runtime into it; here it hands back a fixed page and counts the calls. */
static long kclf_map_file_code(struct file *file, const char *path, const void *from, u64 page, u64 *addr) {
    code_maps++;
    (void)path;
    assert(file == &backing);
    assert(from == kclf_tls_start && page == kclf_page_size);
    if (code_error) return code_error;
    *addr = (uintptr_t)codepage;
    return 0;
}
static int kclf_state_load(struct kclf_req *r) { return r->state; }
static int lock_registry(void) { return !locked; }
static void unlock_registry(void) {}
static void kclf_manual_abandon(struct kclf_req *r) { abandoned++; r->image = NULL; }
static void kclf_fail(struct kclf_req *r, int state, int stage, int rc, const char *fmt, ...) {
    (void)stage; (void)rc; (void)fmt; r->state = state;
}
'''
main = r'''
static struct km_context c;
static struct kclf_req request;
static struct kclf_manual_image image;
static struct km_provider provider;
static struct km_tls_fixup fixup;
static void reset(unsigned page) {
    memset(&c, 0, sizeof(c)); memset(&request, 0, sizeof(request)); memset(&image, 0, sizeof(image));
    memset(memory, 0, sizeof(memory)); memset(payload, 0, sizeof(payload));
    kclf_page_size = page; c.r = &request; request.image = &image; request.image_action = KM_NEW;
    image.id = 7; image.map = (uintptr_t)payload; image.length = sizeof(payload); image.owner = &owner;
    image.backing = request.code_file = &backing; file_puts = 0;
    c.providers = &provider; c.io.limit = 1ULL << 48; provider.io = c.io;
    c.object.tls = 1; c.object.phnum = 1;
    c.object.bias = (uintptr_t)payload;
    c.object.ph[0] = (struct ke_phdr){.type=7, .vaddr=128, .offset=512, .filesz=19, .memsz=8193, .align=65536};
    c.tls_fixups = &fixup; c.ntls = 1; fixup = (struct km_tls_fixup){(uintptr_t)(payload+1024), 8};
    /* The file offset differs from the mapped address, and the template holds
     * an already relocated pointer. Preparation must use the mapped bytes. */
    u64 value = (uintptr_t)(payload + 4096); memcpy(payload + 128, &value, 8); payload[146] = 99;
    lookup_error = map_error = code_error = copy_failure = copies = unmaps = unmap_error = locked = abandoned = puts_count = code_maps = 0;
}
int main(void) {
    for (unsigned page = 4096; page <= 65536; page *= 4) {
        reset(page); assert(!prepare_tls_runtime(&c));
        /* The code page is a private mapping of the payload; the state block is
         * the separate anonymous mapping. The runtime finds the state through
         * the descriptor argument, not through its own page. */
        u64 *state = (void *)memory;
        assert(state[KT_MEMSZ/8] == 8193 && state[KT_ALIGN/8] == 65536 && state[KT_FIRSTBYTE/8] == 128);
        assert(!memcmp((void *)(uintptr_t)state[KT_TEMPLATE/8], payload + 128, 19));
        u64 *desc = (void *)(payload+1024);
        assert(desc[0] == (uintptr_t)codepage + 16 && desc[1] == (uintptr_t)memory + KT_SIZE);
        assert(image.tls_length == requested_length && request.relro_count == 1);
        assert(request.relro[0][0] == (uintptr_t)memory && request.relro[0][1] == requested_length);
        assert(image.tls_code == (uintptr_t)codepage && image.tls_code_len == page && code_maps == 1);
        assert(request.tls_init == (uintptr_t)codepage && request.tls_arg == (uintptr_t)memory);
        int count = copies;
        for (int failure = 1; failure <= count; failure++) {
            reset(page); copy_failure = failure; assert(prepare_tls_runtime(&c) == -EFAULT);
            assert(image.tls_code && image.tls_map && image.map); assert(!kclf_manual_finish(&request));
            assert(!request.image && !image.tls_code && !image.tls_map && !image.map && unmaps == 3 && puts_count == 1);
        }
    }
    reset(4096); lookup_error = -ENOENT; assert(prepare_tls_runtime(&c) == -ENOENT && !image.tls_map && !image.tls_code);
    reset(4096); map_error = -ENOMEM; assert(prepare_tls_runtime(&c) == -ENOMEM && !image.tls_map);
    reset(4096); code_error = -EPERM; assert(prepare_tls_runtime(&c) == -EPERM && image.tls_map && !image.tls_code);
    assert(!kclf_manual_finish(&request) && unmaps == 2);
    reset(4096); request.relro_count = 8; assert(prepare_tls_runtime(&c) == -E2BIG && image.tls_map && image.tls_code);
    assert(!kclf_manual_finish(&request) && unmaps == 3);
    reset(4096); assert(!prepare_tls_runtime(&c)); unmap_error = 1;
    assert(kclf_manual_finish(&request) == -EAGAIN && request.image && image.tls_code && image.tls_map && image.map);
    assert(!file_puts);
    assert(!kclf_manual_finish(&request) && unmaps == 4 && puts_count == 1 && file_puts == 1 && !request.code_file);
    reset(4096); assert(!prepare_tls_runtime(&c)); locked = 1;
    assert(kclf_manual_finish(&request) == -EAGAIN && request.image && !image.tls_code && !image.tls_map && !image.map);
    assert(!file_puts);
    locked = 0; assert(!kclf_manual_finish(&request) && unmaps == 3 && puts_count == 1 && file_puts == 1);
    reset(4096); assert(!prepare_tls_runtime(&c)); request.saved_valid = 1; request.unload_rc = -EAGAIN;
    assert(!kclf_manual_finish(&request) && !request.image && unmaps == 3 && !abandoned);
    reset(4096); assert(!prepare_tls_runtime(&c)); request.saved_valid = 1;
    assert(!kclf_manual_finish(&request) && abandoned == 1 && !unmaps);
    reset(4096); assert(!prepare_tls_runtime(&c)); request.state = KCLF_DONE; request.handle = image.id;
    assert(!kclf_manual_finish(&request) && !unmaps && image.refs == 1 && image.state == KM_LIVE);
    assert(!file_puts && image.backing == &backing && !request.code_file);
    reset(4096); assert(defer_ifunc(&c, (uintptr_t)payload + 128, 0, 0) == -EOPNOTSUPP);
    assert(defer_ifunc(&c, (uintptr_t)payload + 144, 0, 0) == -EOPNOTSUPP);
    assert(!defer_ifunc(&c, (uintptr_t)payload + 152, 0, 0));
    puts("PASS TLS preparation: file-backed code page, relocated template, copy/map/protection faults, ownership/retry, key failure, abandon, residency, IFUNC rejection");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='kclf-tls-prepare-') as directory:
    path = Path(directory)
    (path / 'test.c').write_text(prelude + defer + prepare + finish + main)
    subprocess.run(['gcc', '-std=gnu11', '-DKCLF_ELF_HOST', '-Wall', '-Wextra', '-Werror',
                    '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-I', str(ROOT),
                    str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
