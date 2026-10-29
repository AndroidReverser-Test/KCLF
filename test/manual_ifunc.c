static int implementation(void) { return 7; }
__attribute__((used)) static void *resolver(void) { return (void *)implementation; }
int kclf_manual_ifunc(void) __attribute__((ifunc("resolver")));
int (*volatile kclf_manual_ifunc_pointer)(void) = kclf_manual_ifunc;
