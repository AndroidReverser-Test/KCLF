/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Shared offsets for the persistent, per-image EL0 TLS runtime. */
#ifndef KCLF_TLS_H
#define KCLF_TLS_H

#define KT_KEY 0             /* pthread_key_t (32 bits) */
#define KT_MEMSZ 8
#define KT_FILESZ 16
#define KT_ALIGN 24
#define KT_FIRSTBYTE 32      /* original PT_TLS vaddr modulo alignment */
#define KT_TEMPLATE 40
#define KT_KEY_CREATE 48
#define KT_GETSPECIFIC 56
#define KT_SETSPECIFIC 64
#define KT_ABORT 72
#define KT_SIZE 80

#ifndef __ASSEMBLER__
extern const unsigned char kclf_tls_start[], kclf_tls_end[];
extern const unsigned char kclf_tls_init[], kclf_tls_resolve[];
#endif
#endif
