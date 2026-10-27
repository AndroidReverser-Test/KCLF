ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif

ifndef KP_DIR
    KP_DIR = ../..
endif


CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := -I. $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# GCC 14+ emits calls to __aarch64_ldadd*_acq_rel for C11 atomics.  Those
# libcalls are not part of the KPM ABI on older KernelPatch builds, so keep the
# atomics inline (LDXR/STXR or LSE) instead.
ARCH_CFLAGS := -mno-outline-atomics

objs := kclf.o kclf_exec.o kclf_tramp.o

all: kclf.kpm

kclf.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(ARCH_CFLAGS) $(INCLUDE_FLAGS) -c -O2 -fno-stack-protector -fno-asynchronous-unwind-tables -o $@ $<

%.o: %.S
	${CC} $(CFLAGS) $(ARCH_CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm *.o
