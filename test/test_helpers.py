#!/usr/bin/env python3
"""Exercise the actual portable C helpers with ASan/UBSan (WSL/Linux host).

This is not a substitute for kernel, task_work or ARM64 instruction tests.
"""
from pathlib import Path
import subprocess
import tempfile

MODULE = Path(__file__).resolve().parents[1]


def function(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for i in range(opening, len(source)):
        depth += (source[i] == "{") - (source[i] == "}")
        if depth == 0:
            return source[start:i + 1]
    raise AssertionError(signature)


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
static u64 kclf_user_limit = 1ULL << 48;
#define BASE 0x10000ULL
static unsigned char arena[4096] __attribute__((aligned(16)));
enum { KCLF_IDLE, KCLF_ARMED, KCLF_PREPARING, KCLF_READY, KCLF_RUNNING,
       KCLF_DONE, KCLF_FAILED, KCLF_CANCELLED };
struct kclf_req { int state, finished, pending, busy, completing; u64 map_addr; };
static int kclf_state_load(const struct kclf_req *r) {
    return __atomic_load_n(&r->state, __ATOMIC_ACQUIRE);
}
static int kclf_urds(u64 addr, void *out, int len) {
    if (len < 0 || addr < BASE || addr > BASE + sizeof(arena) ||
        (u64)len > BASE + sizeof(arena) - addr) return -EFAULT;
    memcpy(out, arena + addr - BASE, (size_t)len);
    return 0;
}
static int kclf_urds_u32(u64 addr, u32 *out) { return kclf_urds(addr, out, 4); }
'''

MAIN = r'''
int main(void) {
    struct { char buf[16]; char guard[8]; } output;
    memset(&output, 0x5a, sizeof(output));
    int off = 0;
    for (int i = 0; i < 100; i++) off += kclf_scnprintf(output.buf + off, 16 - off, "%s", "abcdefgh");
    assert(off == 15 && output.buf[15] == 0);
    for (int i = 0; i < 8; i++) assert(output.guard[i] == 0x5a);
    assert(kclf_scnprintf(NULL, 0, "%s", "bad") == 0);
    assert(kclf_scnprintf(NULL, -1, "%s", "bad") == 0);
    assert(kclf_scnprintf(output.buf, 1, "%s", "abc") == 0 && !output.buf[0]);
    puts("saturating diagnostics: PASS");

    char buffer[32], *tokens[4];
    assert(kclf_tokenize("inject,123,/x,unload", buffer, sizeof(buffer), tokens, 4) == 4);
    assert(!strcmp(tokens[2], "/x") && !strcmp(tokens[3], "unload"));
    assert(kclf_tokenize(" \t,\n", buffer, sizeof(buffer), tokens, 4) == 0);
    assert(kclf_tokenize("a,b,c,d,e", buffer, sizeof(buffer), tokens, 4) == -E2BIG);
    char boundary[33];
    memset(boundary, 'a', sizeof(boundary)); boundary[32] = 0;
    assert(kclf_tokenize(boundary, buffer, sizeof(buffer), tokens, 4) == -E2BIG);
    boundary[31] = 0;
    assert(kclf_tokenize(boundary, buffer, sizeof(buffer), tokens, 4) == 1);
    puts("tokenizer length and token limits: PASS");

    struct kclf_req request = {.state = KCLF_RUNNING};
    assert(!kclf_slot_reclaimable(&request));
    request.state = KCLF_DONE;
    assert(!kclf_slot_reclaimable(&request));
    request.pending = 1; request.finished = 1;
    assert(!kclf_slot_reclaimable(&request)); /* body finished, wrapper still executing */
    request.pending = 0;
    assert(kclf_slot_reclaimable(&request));
    request.map_addr = BASE;
    assert(!kclf_slot_reclaimable(&request));
    request.map_addr = 0; request.completing = 1;
    assert(!kclf_slot_reclaimable(&request));
    request.completing = 0; request.busy = 1;
    assert(!kclf_slot_reclaimable(&request));
    request.busy = 0; request.state = KCLF_CANCELLED;
    assert(kclf_slot_reclaimable(&request));
    puts("slot reclamation waits for completion AND callback release: PASS");

    struct kclf_ehdr *eh = (void *)arena;
    struct kclf_phdr *ph = (void *)(arena + 64);
    struct kclf_dyn *dyn = (void *)(arena + 256);
    struct kclf_sym *sym = (void *)(arena + 512);
    memcpy(eh->ident, "\177ELF\2\1\1", 7);
    eh->machine = EM_AARCH64; eh->type = ET_DYN; eh->version = 1;
    eh->ehsize = sizeof(*eh); eh->phentsize = sizeof(*ph); eh->phoff = 64; eh->phnum = 2;
    ph[0].type = PT_LOAD; ph[0].flags = 5; ph[0].memsz = sizeof(arena);
    ph[1].type = PT_DYNAMIC; ph[1].vaddr = 256; ph[1].memsz = 6 * sizeof(*dyn);
    dyn[0] = (struct kclf_dyn){DT_SYMTAB, 512};
    dyn[1] = (struct kclf_dyn){DT_STRTAB, 1024};
    dyn[2] = (struct kclf_dyn){DT_STRSZ, 32};
    dyn[3] = (struct kclf_dyn){DT_HASH, 1280};
    dyn[4] = (struct kclf_dyn){DT_SYMENT, sizeof(*sym)};
    u32 *hash = (void *)(arena + 1280);
    hash[0] = 1; hash[1] = 2;
    memcpy(arena + 1024, "\0loader\0", 8);
    sym[1].name = 1; sym[1].info = 2; sym[1].shndx = 1; sym[1].value = 2048;
    struct kclf_elf ei;
    struct kclf_dyninfo di;
    u64 fn;
    u32 count;
    assert(!kclf_elf_open(BASE, &ei));
    assert(!kclf_elf_dyninfo(&ei, &di));
    assert(!kclf_elf_lookup(&ei, &di, "loader", &fn) && fn == BASE + 2048);
    ph[0].flags = 4;
    assert(kclf_elf_lookup(&ei, &di, "loader", &fn));
    ph[0].flags = 5;
    hash[1] = UINT32_MAX;
    assert(kclf_elf_symcount(&ei, &di, &count));
    hash[1] = 2;
    di.hash = ei.end - 4;
    assert(kclf_elf_symcount(&ei, &di, &count));
    di.hash = 0; di.gnu_hash = BASE + 1280;
    hash[0] = 1; hash[1] = 1; hash[2] = 1; hash[3] = 0;
    hash[6] = 1; hash[7] = 1;
    assert(!kclf_elf_symcount(&ei, &di, &count) && count == 2);
    hash[2] = 4096;
    assert(kclf_elf_symcount(&ei, &di, &count));
    dyn[4].val++;
    assert(kclf_elf_dyninfo(&ei, &di));
    dyn[4].val = sizeof(*sym);
    dyn[2].val = UINT64_MAX;
    assert(kclf_elf_dyninfo(&ei, &di));
    dyn[2].val = 32;
    eh->phoff = UINT64_MAX;
    assert(kclf_elf_open(BASE, &ei));
    eh->phoff = 64;
    ph[0].memsz = UINT64_MAX;
    assert(kclf_elf_open(BASE, &ei));
    assert(!kclf_user_range(UINT64_MAX - 4, 8));
    assert(!kclf_user_range(0, 1));
    assert(kclf_user_range(kclf_user_limit - 4, 4));
    assert(!kclf_user_range(kclf_user_limit - 4, 5));
    puts("ELF range/hash/dynamic/symbol/executable checks: PASS");
    return 0;
}
'''

execution = (MODULE / "kclf_exec.c").read_text()
control = (MODULE / "kclf.c").read_text()
compat = (MODULE / "kclf_compat.c").read_text()
types = execution[execution.index("#define KCLF_USER_MAX"):execution.index("/* kernel pointers")]
parts = [function(execution, name) for name in (
    "static int kclf_user_range(", "static int kclf_elf_open(",
    "static int kclf_elf_range(", "static int kclf_elf_executable(",
    "static int kclf_elf_dyninfo(", "static int kclf_elf_symcount(",
    "static int kclf_elf_lookup(")]
reclaim = function(control, "static int kclf_slot_reclaimable(")
assert reclaim.index("&r->finished") < reclaim.index("&r->pending")
parts += [function(control, "static int kclf_tokenize("), function(compat, "int kclf_scnprintf("), reclaim]
with tempfile.TemporaryDirectory(prefix="kclf-helpers-") as directory:
    source = Path(directory) / "test.c"
    exe = Path(directory) / "test"
    source.write_text(PRELUDE + types + "\n" + "\n".join(parts) + MAIN)
    subprocess.run(["gcc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", str(source), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
