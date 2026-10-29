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
