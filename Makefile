ifneq ($(filter-out clean test,$(if $(MAKECMDGOALS),$(MAKECMDGOALS),all)),)
ifndef TARGET_COMPILE
    $(error TARGET_COMPILE not set)
endif
endif

ifndef KP_DIR
    KP_DIR = ../..
endif


CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld
PYTHON ?= python3

INCLUDE_DIRS := include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := -I. $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# GCC 14+ emits calls to __aarch64_ldadd*_acq_rel for C11 atomics.  Those
# libcalls are not part of the KPM ABI on older KernelPatch builds, so keep the
# atomics inline (LDXR/STXR or LSE) instead.
ARCH_CFLAGS := -mno-outline-atomics -mgeneral-regs-only -ffixed-x18
KPM_CFLAGS := -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter \
	-Wformat=2 -Wshadow -Wframe-larger-than=2048 -fno-strict-aliasing \
	-ffreestanding -fno-builtin -nostdinc -fno-pic -fno-pie \
	-fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -MMD -MP

objs := kclf.o kclf_exec.o kclf_compat.o kclf_elf.o kclf_manual.o kclf_codegen.o

all: kclf.kpm

$(objs): Makefile

kclf.kpm: ${objs}
	${LD} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(KPM_CFLAGS) $(ARCH_CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

%.o: %.S
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -MMD -MP -c -o $@ $<

-include $(objs:.o=.d)

.PHONY: all clean test
test:
	$(PYTHON) test/run_host_tests.py

clean:
	rm -f kclf.kpm $(objs) $(objs:.o=.d)
