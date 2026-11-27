/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Target-credential tmpfs backing for readable /data/local/tmp payloads.
 * No inode layout, filesystem mutation, fd installation or LSM override. */
#include "kclf_internal.h"
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

int kclf_tmp_path(const char *path)
{
    return path && !strncmp(path, "/data/local/tmp/", 16) && path[16];
}

/* The caller owns the returned reference. VMAs acquire their own references;
 * the manual image keeps this one for later trampoline/TLS/release requests. */
int kclf_stage_tmp_file(const char *path, const void *data, unsigned long size, struct file **out)
{
    struct file *file;
    const char *base, *p;
    char name[KCLF_PATH_MAX];
    loff_t pos = 0;
    long rc;

    if (!out) return -EINVAL;
    *out = 0;
    if (!kclf_tmp_path(path) || !data || !size || size > 64UL * 1024 * 1024) return -EINVAL;
    if (!kclf_tmp_backing || !kclf_ks.shmem_file_setup || !kclf_ks.kernel_write || !kclf_ks.fput)
        return -EOPNOTSUPP;
    base = path + 16;
    for (p = base; *p; p++) if (*p == '/') base = p + 1;
    if (!*base) return -EINVAL;
    kclf_scnprintf(name, sizeof(name), "kclf:%s", base);
    /* Use the ordinary API, not shmem_kernel_file_setup/S_PRIVATE. The file
     * is created under the target credentials and vm_mmap still checks LSM. */
    file = kclf_ks.shmem_file_setup(name, (loff_t)size, 0);
    if (!file || (unsigned long)file >= (unsigned long)-4095)
        return file ? (int)(long)file : -ENOMEM;
    while ((unsigned long)pos < size) {
        loff_t before = pos;
        unsigned long n = size - (unsigned long)pos;
        if (n > 65536) n = 65536;
        rc = kclf_ks.kernel_write(file, (const u8 *)data + pos, n, &pos);
        if (rc <= 0 || (unsigned long)rc > n || pos != before + rc) {
            kclf_ks.fput(file);
            return rc < 0 ? (int)rc : -EIO;
        }
    }
    *out = file;
    return 0;
}
