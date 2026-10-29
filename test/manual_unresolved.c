extern int kclf_strong_missing_symbol(void);
int (*volatile kclf_unresolved_pointer)(void) = kclf_strong_missing_symbol;
