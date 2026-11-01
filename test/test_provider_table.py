#!/usr/bin/env python3
"""Compile and exercise the manual loader's growable loaded-provider table."""
from pathlib import Path
import subprocess
import tempfile

MODULE = Path(__file__).resolve().parents[1]
manual = (MODULE / "kclf_manual.c").read_text()
start = manual.index("static int provider_reserve")
end = manual.index("/* Loaded providers are chosen")
provider_code = manual[start:end]

PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KM_PROVIDERS_INIT 64
#define KM_PROVIDERS_MAX 4096
#define KE_NAME 256
#define KCLF_PATH_MAX 256

typedef uint64_t u64;
typedef uint32_t u32;
struct ke_object { u64 bias, low, high; unsigned soname; };
struct ke_io { void *error; };
struct kclf_req {
    u64 mm;
    struct { u64 linker_base, linker_end; } ld;
};

struct km_provider {
    unsigned long marker;
    struct ke_object object;
    char name[KE_NAME], path[KCLF_PATH_MAX];
};
struct km_context {
    struct kclf_req *r;
    struct ke_io io;
    struct ke_object candidate;
    struct km_provider *providers;
    unsigned nproviders, provider_cap;
};
struct kclf_syms {
    void *(*vmalloc)(unsigned long);
    void (*vfree)(const void *);
} kclf_ks;

static int fail_next, allocation_calls;
static char last_error[128];
static void *test_vmalloc(unsigned long size)
{
    allocation_calls++;
    if (fail_next) { fail_next = 0; return NULL; }
    return malloc(size);
}
static void test_vfree(const void *p) { free((void *)p); }
static int kclf_urds(u64 address, void *out, int size)
{
    u32 magic = 0x464c457fU;
    (void)address;
    assert(size == 4);
    memcpy(out, &magic, 4);
    return 0;
}
static int own_mapping(u64 mm, u64 address)
{
    (void)mm; (void)address;
    return 0;
}
static int ke_open(struct ke_io *io, u64 address, struct ke_object *o, int payload)
{
    (void)io;
    assert(!payload);
    *o = (struct ke_object){address, 0, 0x1000, 1};
    return 0;
}
static int ke_string(struct ke_io *io, const struct ke_object *o, u32 offset, char *name)
{
    (void)io; (void)o;
    assert(offset == 1);
    strcpy(name, "libc++.so");
    return 0;
}
static void report(struct km_context *c, const char *why, const char *detail)
{
    (void)c; (void)detail;
    snprintf(last_error, sizeof(last_error), "%s", why);
}
'''

MAIN = r'''
static struct km_context c;
static struct kclf_req request;

static void reset(void)
{
    free(c.providers);
    memset(&c, 0, sizeof(c));
    c.r = &request;
    last_error[0] = 0;
    fail_next = 0;
}
static void fill_to(unsigned n)
{
    for (unsigned i = c.nproviders; i < n; i++) c.providers[i].marker = 0x1000 + i;
    c.nproviders = n;
}
static void check_markers(void)
{
    for (unsigned i = 0; i < c.nproviders; i++) assert(c.providers[i].marker == 0x1000 + i);
}
int main(void)
{
    kclf_ks.vmalloc = test_vmalloc;
    kclf_ks.vfree = test_vfree;
    reset();
    assert(!provider_reserve(&c, 1) && c.provider_cap == KM_PROVIDERS_INIT && c.nproviders == 0);
    for (unsigned n = 1; n <= 1200; n++) {
        if (n > c.provider_cap) {
            unsigned old = c.provider_cap;
            assert(!provider_reserve(&c, n));
            assert(c.provider_cap > old && c.provider_cap <= KM_PROVIDERS_MAX);
        }
        fill_to(n);
        check_markers();
    }
    assert(c.provider_cap == 2048);
    /* No growth when the request already fits. */
    assert(!provider_reserve(&c, c.provider_cap) && c.provider_cap == 2048);
    /* Requests above the bound must not claim success with too little room. */
    int allocations_before = allocation_calls;
    assert(provider_reserve(&c, 5000) == -ENOSPC && c.provider_cap == 2048);
    assert(allocation_calls == allocations_before);
    check_markers();
    assert(!provider_reserve(&c, KM_PROVIDERS_MAX) && c.provider_cap == KM_PROVIDERS_MAX);
    check_markers();
    /* At the bound a further grow reports the caller's overflow condition. */
    assert(provider_reserve(&c, KM_PROVIDERS_MAX + 1) == -ENOSPC);
    puts("provider table growth, capacity contract and marker preservation: PASS");

    reset();
    fail_next = 1;
    assert(provider_reserve(&c, 1) == -ENOMEM && !c.providers && !c.provider_cap);
    assert(!provider_reserve(&c, 1));
    fill_to(KM_PROVIDERS_INIT);
    struct km_provider *original = c.providers;
    fail_next = 1;
    assert(provider_reserve(&c, KM_PROVIDERS_INIT + 1) == -ENOMEM);
    assert(c.providers == original && c.provider_cap == KM_PROVIDERS_INIT);
    assert(c.nproviders == KM_PROVIDERS_INIT);
    check_markers();
    puts("initial and growth allocation failure preserve the prior table: PASS");

    reset();
    fail_next = 1;
    assert(collect(0x10000000, "/system/lib64/libc++.so", &c) == -ENOMEM);
    assert(!c.providers && !c.nproviders && !c.provider_cap);
    assert(strstr(last_error, "provider table allocation failed"));
    puts("first provider allocation failure aborts the mapping walk: PASS");

    reset();
    for (unsigned i = 0; i < KM_PROVIDERS_INIT; i++)
        assert(!collect(0x10000000ULL + i * 0x10000ULL, "/system/lib64/libc++.so", &c));
    original = c.providers;
    fail_next = 1;
    /* This later same-SONAME object would win an ART importer's origin match.
     * Dropping it and continuing would silently select a system provider. */
    assert(collect(0x20000000, "/apex/com.android.art/lib64/libc++.so", &c) == -ENOMEM);
    assert(c.providers == original && c.nproviders == KM_PROVIDERS_INIT);
    assert(strstr(last_error, "provider table allocation failed"));
    for (unsigned i = 0; i < c.nproviders; i++)
        assert(c.providers[i].object.bias == 0x10000000ULL + i * 0x10000ULL);
    puts("growth failure aborts instead of resolving an incomplete SONAME set: PASS");

    reset();
    for (unsigned i = 0; i < KM_PROVIDERS_MAX; i++)
        assert(!collect(0x10000000ULL + i * 0x10000ULL, "/system/lib64/libc++.so", &c));
    assert(c.nproviders == KM_PROVIDERS_MAX && c.provider_cap == KM_PROVIDERS_MAX);
    /* Repeated VMAs for one image do not consume an extra provider slot. */
    assert(!collect(0x10000000, "/system/lib64/libc++.so", &c));
    assert(collect(0x80000000, "/apex/com.android.art/lib64/libc++.so", &c) == -ENOSPC);
    assert(c.nproviders == KM_PROVIDERS_MAX && c.provider_cap == KM_PROVIDERS_MAX);
    assert(strstr(last_error, "provider table limit exceeded"));
    puts("provider hard limit aborts before a later preferred origin can be lost: PASS");
    reset();
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="kclf-provider-table-") as directory:
    source = Path(directory) / "test.c"
    executable = Path(directory) / "test"
    source.write_text(PRELUDE + provider_code + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", str(source), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
