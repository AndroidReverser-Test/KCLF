/* Deliberately unsupported ELF TLS: rejected before redirecting the target. */
__thread int kclf_manual_tls = 7;
int kclf_tls_read(void) { return kclf_manual_tls; }
