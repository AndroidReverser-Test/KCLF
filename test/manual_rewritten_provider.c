/* Owned device fixture: a real AArch64 DSO rewrites its nonstructural header,
 * then a separately built manual payload imports and calls its exported code.
 * Build with KCLF_REWRITTEN_PAYLOAD for the importing payload instead. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef KCLF_REWRITTEN_PAYLOAD
#include <fcntl.h>
extern int kclf_rewritten_data;
extern int kclf_rewritten_value(void);

__attribute__((constructor)) static void verify_provider(void)
{
    const char *dir = getenv("KCLF_TEST_DIR");
    char path[512], text[128];
    if (!dir) return;
    snprintf(path, sizeof(path), "%s/provider_%d.log", dir, getpid());
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return;
    int n = snprintf(text, sizeof(text), "function=%x data=%x\n",
                     kclf_rewritten_value(), kclf_rewritten_data);
    if (write(fd, text, (size_t)n) < 0) { }
    close(fd);
}
#else
#include <dlfcn.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>

int kclf_rewritten_data = 0x13579bdf;
int kclf_rewritten_value(void) { return kclf_rewritten_data; }

__attribute__((constructor)) static void rewrite_header(void)
{
    const char *mode = getenv("KCLF_TEST_PROVIDER_REWRITE");
    Dl_info info;
    if (!mode || !dladdr((const void *)kclf_rewritten_value, &info)) _exit(90);
    Elf64_Ehdr *header = (Elf64_Ehdr *)info.dli_fbase;
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || mprotect(header, (size_t)page, PROT_READ | PROT_WRITE)) _exit(91);
    unsigned char *bytes = (unsigned char *)header;
    if (!strcmp(mode, "zero")) memset(bytes + 8, 0, 16);
    else if (!strcmp(mode, "fill")) memset(bytes + 8, 0xa5, 16);
    else if (!strcmp(mode, "machine")) header->e_machine = EM_X86_64;
    else if (!strcmp(mode, "mixed")) {
        for (unsigned i = 8; i < 24; i++) bytes[i] = (unsigned char)(i * 37 + 0x31);
    } else _exit(92);
    if (mprotect(header, (size_t)page, PROT_READ)) _exit(93);
    printf("provider-header-ready mode=%s value=%x\n", mode, kclf_rewritten_value());
    fflush(stdout);
}
#endif
