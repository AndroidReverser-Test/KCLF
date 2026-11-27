/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KCLF_MAPS_H
#define KCLF_MAPS_H

/* The maps line buffer is bounded; a longer line is consumed but its pathname
 * suffix is truncated. Namespace selection only needs the stable prefix. */
#define KCLF_MAPS_LINE 512
#define KCLF_MAPS_PATH 256

/* Portable parser for the address prefix of /proc/thread-self/maps.
 * Caller supplies uint64_t and a NUL-terminated prefix. */
static int kclf_maps_hex(const char **cursor, uint64_t *value)
{
    const char *p = *cursor;
    uint64_t v = 0;
    unsigned int digits = 0;

    for (;;) {
        unsigned int digit;
        if (*p >= '0' && *p <= '9') digit = (unsigned int)(*p - '0');
        else if (*p >= 'a' && *p <= 'f') digit = (unsigned int)(*p - 'a') + 10;
        else if (*p >= 'A' && *p <= 'F') digit = (unsigned int)(*p - 'A') + 10;
        else break;
        if (++digits > 16) return -1;
        v = (v << 4) | digit;
        p++;
    }
    if (!digits) return -1;
    *value = v;
    *cursor = p;
    return 0;
}

static int kclf_maps_range(const char *line, uint64_t limit, uint64_t *start, uint64_t *end)
{
    uint64_t first, last;

    if (kclf_maps_hex(&line, &first) || *line++ != '-' || kclf_maps_hex(&line, &last) || *line != ' ' ||
        last <= first || last > limit)
        return -1;
    *start = first;
    *end = last;
    return 0;
}

/* Decode the permission field of a maps line. Bits match mmap PROT_* flags:
 * 1 = readable, 2 = writable, 4 = executable.  Returns -1 on a malformed
 * prefix, otherwise 0. */
static int kclf_maps_prot(const char *line, int *prot)
{
    int value = 0;

    while (*line && *line != ' ') line++;
    while (*line == ' ') line++;
    if (line[0] != 'r' && line[0] != '-') return -1;
    if (line[1] != 'w' && line[1] != '-') return -1;
    if (line[2] != 'x' && line[2] != '-') return -1;
    if (line[3] != 'p' && line[3] != 's') return -1;
    if (line[4] != ' ') return -1;
    if (line[0] == 'r') value |= 1;
    if (line[1] == 'w') value |= 2;
    if (line[2] == 'x') value |= 4;
    *prot = value;
    return 0;
}

/* Decode the file offset field (third field) of a maps line.  A provider's
 * ELF header is located by "mapping start + vm_pgoff", so the manual backend
 * needs this value to read metadata from the file page cache instead of
 * faulting the target's own library pages in through GUP.  Returns -1 on a
 * malformed prefix, otherwise 0. */
static int kclf_maps_offset(const char *line, uint64_t *offset)
{
    unsigned int field;

    for (field = 0; field < 2; field++) {
        while (*line && *line != ' ') line++;
        while (*line == ' ') line++;
    }
    if (kclf_maps_hex(&line, offset)) return -1;
    return (*line == ' ' || *line == 0) ? 0 : -1;
}

/* Extract the optional pathname from a maps line:
 *   start-end perms offset dev inode [pathname]
 * Anonymous mappings have no pathname. The result is always NUL-terminated and
 * empty when the pathname is absent or does not start at '/'. */
static int kclf_maps_path(const char *line, char *out, unsigned int capacity)
{
    unsigned int field, i;

    if (!capacity) return -1;
    out[0] = 0;
    for (field = 0; field < 5; field++) {
        while (*line && *line != ' ') line++;
        while (*line == ' ') line++;
    }
    if (*line != '/') return 0;
    for (i = 0; i + 1 < capacity && line[i]; i++) out[i] = line[i];
    out[i] = 0;
    return 0;
}
#endif
