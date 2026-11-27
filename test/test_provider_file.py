#!/usr/bin/env python3
"""Exercise the manual loader's file-backed provider view with a fake file.

The view must translate a loaded provider's virtual addresses back to file
positions (including APK-embedded entries), return zero for the .bss tail, and
reject malformed geometry without ever touching target memory.
"""
from pathlib import Path
import subprocess
import tempfile

MODULE = Path(__file__).resolve().parents[1]
manual = (MODULE / "kclf_manual.c").read_text()
start = manual.index("/* --- provider file view: begin --- */")
end = manual.index("/* --- provider file view: end --- */")
view = manual[start:end]

PRELUDE = r'''
#define KCLF_ELF_HOST
#include "kclf_elf.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int64_t loff_t;
typedef unsigned short umode_t;
#define KM_FILE_MAX (64UL * 1024 * 1024)
#define KM_STRING_BUDGET (256ULL * 1024 * 1024)
#define BASE_ADDR 0x70000000ULL
#define BASE2_ADDR 0x80000000ULL

struct file { int unused; };
struct km_context;
struct km_provider_view {
    struct km_context *owner;
    struct ke_object *object;
    struct file *file;
    u64 file_size;
    u64 header_addr;
    u64 header_off;
    u64 header_end;
    u64 file_base;
    u64 bias;
    u64 string_budget;
};
struct km_context {
    struct km_provider_view probe;
    struct ke_phdr probe_ph[KE_PHNUM];
};

static unsigned char file_data[1 << 20];
static size_t file_size;
static size_t max_read = 7;
static int fput_count;
static loff_t seek_error;
static struct file opened;

static struct file *fake_open(const char *path, int flags, umode_t mode)
{
    assert(!strcmp(path, "/system/lib64/libfake.so"));
    assert(!flags && !mode);
    return &opened;
}
static loff_t fake_llseek(struct file *f, loff_t offset, int whence)
{
    assert(f == &opened && !offset && whence == 2);
    return seek_error ? seek_error : (loff_t)file_size;
}
static long fake_read(struct file *f, void *buf, unsigned long n, loff_t *pos)
{
    size_t left;
    assert(f == &opened && pos && *pos >= 0);
    if ((size_t)*pos >= file_size) return 0;
    left = file_size - (size_t)*pos;
    if (n > left) n = left;
    if (n > max_read) n = max_read;
    memcpy(buf, file_data + (size_t)*pos, n);
    *pos += (loff_t)n;
    return (long)n;
}
static void fake_fput(struct file *f)
{
    assert(f == &opened);
    fput_count++;
}
static struct {
    struct file *(*filp_open)(const char *, int, umode_t);
    loff_t (*vfs_llseek)(struct file *, loff_t, int);
    long (*kernel_read)(struct file *, void *, unsigned long, loff_t *);
    void (*fput)(struct file *);
} kclf_ks = {fake_open, fake_llseek, fake_read, fake_fput};
static u64 kclf_user_limit = 1ULL << 48;

/* Build a minimal ELF64/AArch64 image at @base in the fake file. */
static void build_image(size_t base, u64 phnum, size_t fsize, int apk)
{
    struct ke_ehdr eh;
    struct ke_phdr ph[3];
    memset(file_data, 0, sizeof(file_data));
    memset(&eh, 0, sizeof(eh));
    memset(ph, 0, sizeof(ph));
    memcpy(eh.ident, "\177ELF\2\1\1", 7);
    eh.type = 3;
    eh.machine = 183;
    eh.version = 1;
    eh.ehsize = sizeof(eh);
    eh.phentsize = sizeof(struct ke_phdr);
    eh.phnum = (u16)phnum;
    eh.phoff = sizeof(eh);
    ph[0].type = 1; ph[0].flags = 4;
    ph[0].offset = 0; ph[0].vaddr = 0; ph[0].filesz = 0x400; ph[0].memsz = 0x400;
    ph[0].align = 0x1000;
    ph[1].type = 1; ph[1].flags = 5;
    ph[1].offset = 0x400; ph[1].vaddr = 0x400; ph[1].filesz = 0x200; ph[1].memsz = 0x300;
    ph[1].align = 0x1000;
    ph[2].type = 1; ph[2].flags = 4;
    ph[2].offset = 0; ph[2].vaddr = 0; ph[2].filesz = 0x400; ph[2].memsz = 0x400;
    memcpy(file_data + base, &eh, sizeof(eh));
    memcpy(file_data + base + sizeof(eh), ph, phnum * sizeof(ph[0]));
    for (size_t i = 0; i < 0x200; i++) file_data[base + 0x400 + i] = (unsigned char)(i * 7 + 3);
    file_size = fsize;
    (void)apk;
}
'''

MAIN = r'''
static struct km_context c;
static struct ke_object object;
static struct ke_io io;
static unsigned char buf[64];
static unsigned char pbuf[256];

static void bind_loaded(u16 phnum)
{
    object.phnum = phnum;
    memcpy(object.ph, c.probe_ph, phnum * sizeof(object.ph[0]));
    object.bias = c.probe.bias;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    /* Normal .so at file offset zero. */
    build_image(0, 2, 0x1000, 0);
    fput_count = 0;
    memset(&c, 0, sizeof(c));
    memset(&object, 0, sizeof(object));
    assert(!provider_view_open(&c, "/system/lib64/libfake.so", BASE_ADDR, 0, &io, &object));
    assert(c.probe.file == &opened && c.probe.file_base == 0 && c.probe.bias == BASE_ADDR);
    assert(io.read == provider_view_read && io.ctx == &c.probe && io.string_budget == &c.probe.string_budget);
    assert(!io.read(io.ctx, BASE_ADDR, buf, 16) && !memcmp(buf, "\177ELF\2\1\1", 7));
    assert(!io.read(io.ctx, BASE_ADDR + sizeof(struct ke_ehdr), pbuf, sizeof(struct ke_phdr) * 2));
    bind_loaded(2);
    assert(!io.read(io.ctx, BASE_ADDR + 0x410, buf, 8));
    for (unsigned i = 0; i < 8; i++) assert(buf[i] == (unsigned char)((0x10 + i) * 7 + 3));
    /* The final page of file data is followed by zero-filled .bss. */
    assert(!io.read(io.ctx, BASE_ADDR + 0x400 + 0x1fc, buf, 8));
    for (unsigned i = 0; i < 4; i++) assert(buf[i] == (unsigned char)((0x1fc + i) * 7 + 3));
    for (unsigned i = 4; i < 8; i++) assert(buf[i] == 0);
    /* Outside every PT_LOAD, or a read crossing the last one, must fail. */
    assert(io.read(io.ctx, BASE_ADDR + 0x700, buf, 8) == -ENOEXEC);
    assert(io.read(io.ctx, BASE_ADDR + 0x6ff, buf, 8) == -ENOEXEC);
    provider_view_close(&c.probe);
    assert(!provider_view_open(&c, "/system/lib64/libfake.so", BASE2_ADDR, 0, &io, &object));
    assert(c.probe.file == &opened);
    fput_count = 0;
    provider_view_close(&c.probe);
    assert(fput_count == 1 && !c.probe.file);
    puts("provider view: ELF64 header/phdr/data/.bss translation: PASS");

    /* APK-embedded library: the mapping's pgoff is the zip entry data offset. */
    build_image(0x1000, 2, 0x2000, 1);
    memset(&c, 0, sizeof(c));
    memset(&object, 0, sizeof(object));
    assert(!provider_view_open(&c, "/system/lib64/libfake.so", BASE2_ADDR, 0x1000, &io, &object));
    assert(c.probe.file_base == 0x1000 && c.probe.bias == BASE2_ADDR);
    bind_loaded(2);
    assert(!io.read(io.ctx, BASE2_ADDR + 0x410, buf, 8));
    for (unsigned i = 0; i < 8; i++) assert(buf[i] == (unsigned char)((0x10 + i) * 7 + 3));
    provider_view_close(&c.probe);
    puts("provider view: APK entry offset and dual-layout bias: PASS");

    /* Malformed geometry fails closed and releases the file. */
    memset(&c, 0, sizeof(c));
    build_image(0, 2, 0x1000, 0);
    file_data[0] = 0;
    fput_count = 0;
    puts("malformed: bad magic");
    assert(provider_view_open(&c, "/system/lib64/libfake.so", BASE_ADDR, 0, &io, &object) == -ENOEXEC);
    assert(fput_count == 1 && !c.probe.file);
    build_image(0, 2, 0x1000, 0);
    ((struct ke_ehdr *)file_data)->phoff = 0x1000;
    puts("malformed: phoff past EOF");
    assert(provider_view_open(&c, "/system/lib64/libfake.so", BASE_ADDR, 0, &io, &object) == -ENOEXEC);
    build_image(0, 2, 0x1000, 0);
    ((struct ke_phdr *)(file_data + sizeof(struct ke_ehdr)))[1].offset = 0xf00;
    puts("malformed: segment past EOF");
    assert(provider_view_open(&c, "/system/lib64/libfake.so", BASE_ADDR, 0, &io, &object) == -ENOEXEC);
    build_image(0, 2, 0x1000, 0);
    ((struct ke_phdr *)(file_data + sizeof(struct ke_ehdr)))[1].offset = 0;
    puts("malformed: duplicate base segment");
    assert(provider_view_open(&c, "/system/lib64/libfake.so", BASE_ADDR, 0, &io, &object) == -ENOEXEC);
    assert(provider_view_open(&c, "/system/lib64/libfake.so", 0, 0, &io, &object) == -ENOENT);
    assert(provider_view_open(&c, "relative.so", BASE_ADDR, 0, &io, &object) == -ENOENT);
    puts("provider view: malformed headers/segments, duplicate base, bad address: PASS");
    for (unsigned i = 0; i < 3; i++) {
        build_image(0, 2, i == 0 ? 0 : sizeof(struct ke_ehdr) - 1, 0);
        seek_error = i == 2 ? -EIO : 0;
        fput_count = 0;
        assert(provider_view_open(&c, "/system/lib64/libfake.so", BASE_ADDR, 0, &io, &object) < 0);
        assert(fput_count == 1 && !c.probe.file);
    }
    puts("provider view: empty/truncated files and failed llseek release exactly one reference: PASS");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="kclf-provider-file-") as directory:
    source = Path(directory) / "test.c"
    executable = Path(directory) / "test"
    source.write_text(PRELUDE + view + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", "-I", str(MODULE), str(source),
                    "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
