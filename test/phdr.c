/* Dumps the target-visible library list (dl_iterate_phdr) so the KPM side
 * assumptions about link_map naming can be validated.
 */
#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <dlfcn.h>

static int cb(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;
    unsigned long base = 0;
    unsigned long dyn = 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_LOAD && info->dlpi_phdr[i].p_offset == 0)
            base = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) dyn = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
    }
    printf("phdr name=%s addr=%p base=%lx dyn=%lx phnum=%d\n", info->dlpi_name ? info->dlpi_name : "(null)",
           (void *)info->dlpi_addr, base, dyn, info->dlpi_phnum);
    return 0;
}

int main(void)
{
    dl_iterate_phdr(cb, NULL);
    void *h = dlopen("libdl.so", RTLD_NOW);
    printf("dlopen(libdl.so)=%p dlsym(dlopen)=%p\n", h, dlsym(h ? h : RTLD_DEFAULT, "dlopen"));
    return 0;
}
