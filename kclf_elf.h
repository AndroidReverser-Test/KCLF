/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Bounded ELF64/AArch64 reader. No linker API or kernel layout knowledge. */
#ifndef KCLF_ELF_H
#define KCLF_ELF_H
#ifdef KCLF_ELF_HOST
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
#else
#include <ktypes.h>
#endif

#define KE_PHNUM 64
#define KE_NEEDED 64
#define KE_NAME 256 /* bounded SONAME/version/diagnostic buffers, not symbol names */
#define KE_SYMS 500000
#define KE_RELOCS 1000000
#define KE_IMAGE_MAX (256ULL * 1024 * 1024)

struct ke_ehdr {
    u8 ident[16];
    u16 type, machine;
    u32 version;
    u64 entry, phoff, shoff;
    u32 flags;
    u16 ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct ke_phdr { u32 type, flags; u64 offset, vaddr, paddr, filesz, memsz, align; };
struct ke_dyn { s64 tag; u64 val; };
struct ke_sym { u32 name; u8 info, other; u16 shndx; u64 value, size; };
struct ke_rela { u64 offset, info; s64 addend; };
struct ke_verneed { u16 version, cnt; u32 file, aux, next; };
struct ke_vernaux { u32 hash; u16 flags, other; u32 name, next; };
struct ke_verdef { u16 version, flags, ndx, cnt; u32 hash, aux, next; };
struct ke_verdaux { u32 name, next; };

struct ke_io {
    void *ctx;
    u64 limit;
    int (*read)(void *, u64, void *, unsigned long);
    int (*write)(void *, u64, const void *, unsigned long);
    void (*error)(void *, const char *, const char *);
    int (*defer_ifunc)(void *, u64 where, u32 symbol, s64 addend);
    u64 *string_budget; /* optional shared byte budget for string-table reads */
};

struct ke_object {
    struct ke_phdr ph[KE_PHNUM];
    u64 bias, low, high, alignment, header;
    u64 symtab, strtab, strsz, hash, gnu_hash;
    u64 rela, relasz, jmprel, pltsz, packed, packedsz, relr, relrsz;
    u64 init, fini, init_array, init_count, fini_array, fini_count;
    u64 versym, verneed, verneednum, verdef, verdefnum;
    u64 flags, flags1;
    u32 needed[KE_NEEDED], nneeded, soname, symcount;
    u16 phnum;
    u8 symbolic, tls;
};

/* All ranges refer to real PT_LOAD segments, not the envelope's holes. */
int ke_contains(const struct ke_object *, u64 address, u64 size, unsigned flags);
int ke_headers(struct ke_io *, u64 header, struct ke_object *);
int ke_file_layout(struct ke_io *, struct ke_object *, u64 file_size, u64 page_size);
/* payload=1: strict ET_DYN/EM_AARCH64/version validation (file or new image).
 * payload=0: structural parsing of a provider candidate in an AArch64 target.
 * e_ident[8..15], e_type, e_machine and e_version may have been rewritten;
 * their content is not an identity check or an instruction signature. ELF64/LE
 * encoding, structural fields and every table/range bound remain mandatory.
 * This mode does not prove linker provenance or original code architecture. */
int ke_open(struct ke_io *, u64 header, struct ke_object *, int payload);
int ke_string(struct ke_io *, const struct ke_object *, u32 offset, char out[KE_NAME]);
/* Full symbol names: bounded by DT_STRSZ/readable PT_LOAD, never truncated.
 * size includes NUL. copy requires capacity >= size; equal validates the entire
 * table string and returns 1/0/-errno without allocating a candidate buffer. */
int ke_string_size(struct ke_io *, const struct ke_object *, u32 offset, u64 *size);
int ke_string_copy(struct ke_io *, const struct ke_object *, u32 offset, char *out, u64 capacity);
int ke_string_equal(struct ke_io *, const struct ke_object *, u32 offset, const char *expected);
int ke_symbol(struct ke_io *, const struct ke_object *, u32 index, struct ke_sym *);
int ke_required_version(struct ke_io *, const struct ke_object *, u32 index, char out[KE_NAME], u32 *hash);
/* 1 = found; 0 = not found; negative = malformed/unsupported, never silent fallback. */
int ke_lookup(struct ke_io *, const struct ke_object *, const char *name,
              const char *version, u32 version_hash, struct ke_sym *, u64 *address);
typedef int (*ke_resolve_fn)(void *, u32 symbol_index, u64 *value);
int ke_relocate(struct ke_io *, const struct ke_object *, ke_resolve_fn, void *);
#endif
