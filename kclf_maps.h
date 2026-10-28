/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KCLF_MAPS_H
#define KCLF_MAPS_H

/* Portable parser for the address prefix of /proc/thread-self/maps.
 * Pathnames are deliberately ignored (including arbitrarily long names).
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
#endif
