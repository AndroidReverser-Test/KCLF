/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Randomized AArch64 EL0 trampoline generator.
 *
 * Every injection gets a different program.  The kernel side only relies on the
 * semantic contract:
 *
 *   - entered at code_addr + entry_off through an exception return;
 *   - every General Purpose register is preserved except the ones the kernel
 *     itself restores on completion (the kernel restores the full pt_regs);
 *   - on success the program restores the interrupted register file in EL0,
 *     publishes a per-request random token in the private page and branches
 *     back to the interrupted PC itself.  There is no completion syscall, no
 *     library call and no fault: the kernel notices the token when the thread
 *     enters an ordinary watched syscall, or from a controller poll callback.
 *     x16/IP0 cannot be restored because it carries the resume address; it is
 *     caller-saved scratch in the supported ABI.
 *
 * Randomization per request: the code page is filled with random words, the
 * entry offset is random, the callee-saved register roles are assigned to a
 * random permutation of x19..x28, the 32 FPSIMD registers are stored under a
 * random pairing into random 32-byte slots, random filler instructions are
 * inserted, and the register restore order is shuffled.  The generated page
 * contains no svc and no library call on the completion path.
 */
#include "kclf_codegen.h"
#include "kclf_param.h"
#ifdef KCLF_CODEGEN_HOST
#include <string.h>
#else
#include <linux/string.h>
#endif

#define KCE_MAX_LABEL 24
#define KCE_MAX_PATCH 96

enum
{
    KCE_P_B26 = 1,
    KCE_P_B19_CBZ = 2,
    KCE_P_B19_CBNZ = 3,
    KCE_P_B19_COND = 4,
};

struct kce_patch
{
    u16 at;
    u16 label;
    u8 kind;
    u8 aux;
};

struct kce
{
    u32 *code;
    int n, cap;
    u64 rng;
    int labels[KCE_MAX_LABEL];
    int nlabels;
    struct kce_patch patch[KCE_MAX_PATCH];
    int npatch;
    int overflow;
};

struct kce_roles
{
    int p; /* parameter page base */
    int pb; /* private parameter page base */
    int v; /* vector cursor */
    int c; /* loop counter */
    int rc; /* loader result (image id / negative errno) */
    int t0, t1, t2; /* temporaries */
};

/* ------------------------------------------------------------------ */
/* deterministic helper RNG (splitmix64)                                */
/* ------------------------------------------------------------------ */

static u64 kce_random(struct kce *c)
{
    u64 z = (c->rng += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static int kce_below(struct kce *c, int n)
{
    return (int)(kce_random(c) % (u64)n);
}

/* ------------------------------------------------------------------ */
/* instruction encoding                                                 */
/* ------------------------------------------------------------------ */

static void kce_emit(struct kce *c, u32 insn)
{
    if (c->n >= c->cap) {
        c->overflow = 1;
        return;
    }
    c->code[c->n++] = insn;
}

static int kce_label(struct kce *c)
{
    int id = c->nlabels++;
    if (id >= KCE_MAX_LABEL) {
        c->overflow = 1;
        return 0;
    }
    c->labels[id] = -1;
    return id;
}

static void kce_bind(struct kce *c, int id)
{
    if (id >= 0 && id < KCE_MAX_LABEL) c->labels[id] = c->n;
}

static void kce_patch_here(struct kce *c, int kind, int aux, int label)
{
    if (c->npatch >= KCE_MAX_PATCH) {
        c->overflow = 1;
        return;
    }
    c->patch[c->npatch].at = (u16)c->n;
    c->patch[c->npatch].label = (u16)label;
    c->patch[c->npatch].kind = (u8)kind;
    c->patch[c->npatch].aux = (u8)aux;
    c->npatch++;
}

static void kce_b(struct kce *c, int label)
{
    kce_patch_here(c, KCE_P_B26, 0, label);
    kce_emit(c, 0x14000000u);
}

static void kce_bcond(struct kce *c, int cond, int label)
{
    kce_patch_here(c, KCE_P_B19_COND, cond, label);
    kce_emit(c, 0x54000000u);
}

static void kce_cbnz(struct kce *c, int rt, int is64, int label)
{
    kce_patch_here(c, KCE_P_B19_CBNZ, rt, label);
    kce_emit(c, (is64 ? 0xB5000000u : 0x35000000u));
}

static void kce_cbz(struct kce *c, int rt, int is64, int label)
{
    kce_patch_here(c, KCE_P_B19_CBZ, rt, label);
    kce_emit(c, (is64 ? 0xB4000000u : 0x34000000u));
}

static u32 kce_movz(int rd, u32 imm, int hw)
{
    return 0xD2800000u | ((u32)hw << 21) | ((imm & 0xffffu) << 5) | (u32)rd;
}

static u32 kce_movk(int rd, u32 imm, int hw)
{
    return 0xF2800000u | ((u32)hw << 21) | ((imm & 0xffffu) << 5) | (u32)rd;
}

static u32 kce_movn(int rd, u32 imm, int hw)
{
    return 0x92800000u | ((u32)hw << 21) | ((imm & 0xffffu) << 5) | (u32)rd;
}

static u32 kce_mov_reg(int rd, int rm)
{
    return 0xAA0003E0u | ((u32)rm << 16) | (u32)rd;
}

static u32 kce_add_imm12(int rd, int rn, u32 imm, int shift)
{
    return 0x91000000u | ((shift ? 1u : 0u) << 22) | ((imm & 0xfffu) << 10) | ((u32)rn << 5) | (u32)rd;
}

static u32 kce_sub_imm12(int rd, int rn, u32 imm, int shift)
{
    return 0xD1000000u | ((shift ? 1u : 0u) << 22) | ((imm & 0xfffu) << 10) | ((u32)rn << 5) | (u32)rd;
}

static u32 kce_cmp_reg(int rn, int rm)
{
    return 0xEB00001Fu | ((u32)rm << 16) | ((u32)rn << 5);
}

static u32 kce_ldr_x(int rt, int rn, u32 off)
{
    return 0xF9400000u | ((off / 8u) << 10) | ((u32)rn << 5) | (u32)rt;
}

static u32 kce_str_x(int rt, int rn, u32 off)
{
    return 0xF9000000u | ((off / 8u) << 10) | ((u32)rn << 5) | (u32)rt;
}

static u32 kce_ldr_w(int rt, int rn, u32 off)
{
    return 0xB9400000u | ((off / 4u) << 10) | ((u32)rn << 5) | (u32)rt;
}

static u32 kce_stp_xzr_post(int rn, u32 imm)
{
    return 0xA8800000u | (((imm / 8u) & 0x7fu) << 15) | (31u << 10) | ((u32)rn << 5) | 31u;
}

static u32 kce_stp_q(int rt, int rt2, int rn, u32 off)
{
    return 0xAD000000u | (((off / 16u) & 0x7fu) << 15) | ((u32)rt2 << 10) | ((u32)rn << 5) | (u32)rt;
}

static u32 kce_ldp_q(int rt, int rt2, int rn, u32 off)
{
    return 0xAD400000u | (((off / 16u) & 0x7fu) << 15) | ((u32)rt2 << 10) | ((u32)rn << 5) | (u32)rt;
}

static u32 kce_blr(int rn)
{
    return 0xD63F0000u | ((u32)rn << 5);
}

static u32 kce_br(int rn)
{
    return 0xD61F0000u | ((u32)rn << 5);
}

static u32 kce_eor_x(int rd, int rn, int rm)
{
    return 0xCA000000u | ((u32)rm << 16) | ((u32)rn << 5) | (u32)rd;
}

static u32 kce_and_x(int rd, int rn, int rm)
{
    return 0x8A000000u | ((u32)rm << 16) | ((u32)rn << 5) | (u32)rd;
}

static u32 kce_orr_x(int rd, int rn, int rm)
{
    return 0xAA000000u | ((u32)rm << 16) | ((u32)rn << 5) | (u32)rd;
}

static u32 kce_add_reg(int rd, int rn, int rm)
{
    return 0x8B000000u | ((u32)rm << 16) | ((u32)rn << 5) | (u32)rd;
}

/* movz/movk x<rd>, #value: always the full four instructions */
static void kce_mov64(struct kce *c, int rd, u64 value)
{
    int hw;
    for (hw = 0; hw < 4; hw++) {
        u32 chunk = (u32)((value >> (16 * hw)) & 0xffffu);
        kce_emit(c, hw ? kce_movk(rd, chunk, hw) : kce_movz(rd, chunk, hw));
    }
}

static void kce_mov_const(struct kce *c, int rd, u64 value)
{
    if (value <= 0xffffu)
        kce_emit(c, kce_movz(rd, (u32)value, 0));
    else
        kce_mov64(c, rd, value);
}

static void kce_add_imm(struct kce *c, int rd, int rn, u64 value)
{
    int first = 1;
    while (value > 0xfffu) {
        kce_emit(c, kce_add_imm12(rd, first ? rn : rd, 0xfffu, 0));
        value -= 0xfffu;
        first = 0;
    }
    kce_emit(c, kce_add_imm12(rd, first ? rn : rd, (u32)value, 0));
}

static u32 kce_mrs(int rt, int reg)
{
    static const u32 base[3] = { 0xD53B4400u, 0xD53B4420u, 0xD53B4200u };
    return base[reg] | (u32)rt;
}

static u32 kce_msr(int reg, int rt)
{
    static const u32 base[3] = { 0xD51B4400u, 0xD51B4420u, 0xD51B4200u };
    return base[reg] | (u32)rt;
}

#define KCE_FPCR 0
#define KCE_FPSR 1
#define KCE_NZCV 2

/* ------------------------------------------------------------------ */
/* random pieces                                                        */
/* ------------------------------------------------------------------ */

static void kce_shuffle(struct kce *c, int *values, int n)
{
    int i;
    for (i = n - 1; i > 0; i--) {
        int j = kce_below(c, i + 1);
        int tmp = values[i];
        values[i] = values[j];
        values[j] = tmp;
    }
}

static void kce_roles_pick(struct kce *c, struct kce_roles *r)
{
    int pool[8] = { 19, 20, 21, 22, 23, 24, 25, 26 };
    kce_shuffle(c, pool, 8);
    r->p = pool[0];
    r->pb = pool[1];
    r->v = pool[2];
    r->c = pool[3];
    r->rc = pool[4];
    r->t0 = pool[5];
    r->t1 = pool[6];
    r->t2 = pool[7];
}

/* Filler instructions: they only touch dead temporaries, so they never change
 * the register/flag/stack state observed by the target. */
static void kce_junk(struct kce *c, const struct kce_roles *r, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        switch (kce_below(c, 7)) {
        case 0:
            kce_emit(c, kce_movz(r->t1, (u32)kce_random(c) & 0xffffu, 0));
            break;
        case 1:
            kce_mov64(c, r->t2, kce_random(c));
            break;
        case 2:
            kce_add_imm(c, r->t1, r->t1, kce_below(c, 4096));
            break;
        case 3:
            kce_emit(c, kce_eor_x(r->t1, r->t1, r->t1));
            break;
        case 4:
            kce_emit(c, kce_mov_reg(r->t1, r->t2));
            break;
        case 5:
            kce_emit(c, kce_orr_x(r->t2, r->t2, r->t1));
            break;
        default:
            kce_emit(c, 0xD503201Fu); /* nop */
            break;
        }
    }
}

static int kce_resolve(struct kce *c)
{
    int i;
    for (i = 0; i < c->npatch; i++) {
        const struct kce_patch *p = &c->patch[i];
        int target = (p->label < KCE_MAX_LABEL) ? c->labels[p->label] : -1;
        int off;
        if (target < 0) return -1;
        off = target - (int)p->at;
        if (p->kind == KCE_P_B26) {
            if (off < -(1 << 25) || off >= (1 << 25)) return -1;
            c->code[p->at] |= (u32)(off & 0x03ffffff);
        } else {
            if (off < -(1 << 18) || off >= (1 << 18)) return -1;
            c->code[p->at] |= ((u32)(off & 0x7ffff) << 5) | (u32)p->aux;
        }
    }
    return 0;
}

int kclf_prog_build(u8 *page, int page_size, u64 param_addr, u64 priv_addr,
                    const struct kclf_priv_layout *pl, u64 seed, struct kclf_prog *out)
{
    struct kce c;
    struct kce_roles r;
    u64 state = seed ? seed : 0x6b636c66deadbeefULL;
    u32 *words = (u32 *)page;
    int qreg[32], qslot[16], order[31];
    int entry_off, i;
    int l_entry, l_manual, l_lok, l_lzero, l_ifunc, l_ifunc_err;
    int l_init, l_init_loop, l_fini, l_fini_loop, l_man_done, l_man_err, l_tail, l_wipe;

    if (!page || !out || !pl) return -1;
    if (page_size < 2048 || (page_size & (page_size - 1))) return -1;
    if (pl->end > page_size) return -1;
    memset(&c, 0, sizeof(c));

    /* Random code-page contents first: the machine code no longer sits in an
     * otherwise zero page, so a scanner cannot delimit it by zero runs. */
    for (i = 0; i < page_size / 4; i++) {
        state += 0x9e3779b97f4a7c15ULL;
        {
            u64 z = state;
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
            z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
            words[i] = (u32)(z ^ (z >> 31));
        }
    }
    c.rng = state;

    entry_off = 16 + 16 * kce_below(&c, 8);
    c.code = (u32 *)(page + entry_off - 4);
    c.cap = (page_size - (entry_off - 4)) / 4;

    kce_roles_pick(&c, &r);
    for (i = 0; i < 32; i++) qreg[i] = i;
    for (i = 0; i < 16; i++) qslot[i] = i;
    kce_shuffle(&c, qreg, 32);
    kce_shuffle(&c, qslot, 16);

    l_entry = kce_label(&c);
    l_manual = kce_label(&c);
    l_lok = kce_label(&c);
    l_lzero = kce_label(&c);
    l_ifunc = kce_label(&c);
    l_ifunc_err = kce_label(&c);
    l_init = kce_label(&c);
    l_init_loop = kce_label(&c);
    l_fini = kce_label(&c);
    l_fini_loop = kce_label(&c);
    l_man_done = kce_label(&c);
    l_man_err = kce_label(&c);
    l_tail = kce_label(&c);
    l_wipe = kce_label(&c);

    /* restart pad: a syscall restart may rewind the return PC by 4.  Emit one
     * random fall-through instruction that only touches a dead temporary, so
     * the entry does not start with a recognizable fixed branch. */
    switch (kce_below(&c, 5)) {
    case 0:
        kce_emit(&c, 0xD503201Fu); /* nop */
        break;
    case 1:
        kce_emit(&c, kce_movz(r.t2, (u32)kce_random(&c) & 0xffffu, 0));
        break;
    case 2:
        kce_emit(&c, kce_eor_x(r.t2, r.t2, r.t2));
        break;
    case 3:
        kce_emit(&c, kce_add_imm12(r.t2, r.t2, (u32)kce_random(&c) & 0xfffu, 0));
        break;
    default:
        kce_emit(&c, kce_orr_x(r.t2, r.t1, r.t2));
        break;
    }
    kce_bind(&c, l_entry);
    kce_emit(&c, 0xD503245Fu); /* bti c, a NOP without BTI */

    /* Resolve both parameter pages first.  They are separate blocks in the
     * transient mapping, so the 1.4.3 "private = ABI + page" relation is gone.
     * The FPSIMD file lives in the private page, not on the interrupted
     * thread's stack, so a signal frame cannot overwrite it and the trampoline
     * does not need a private stack of its own. */
    kce_junk(&c, &r, kce_below(&c, 3));
    kce_mov64(&c, r.p, param_addr);
    kce_mov64(&c, r.pb, priv_addr);
    kce_add_imm(&c, r.t0, r.pb, (u64)pl->qregs);
    for (i = 0; i < 16; i++)
        kce_emit(&c, kce_stp_q(qreg[2 * i], qreg[2 * i + 1], r.t0, (u32)qslot[i] * 32u));
    kce_emit(&c, kce_mrs(r.t1, KCE_FPCR));
    kce_emit(&c, kce_str_x(r.t1, r.pb, pl->fpcr));
    kce_emit(&c, kce_mrs(r.t1, KCE_FPSR));
    kce_emit(&c, kce_str_x(r.t1, r.pb, pl->fpsr));
    kce_junk(&c, &r, kce_below(&c, 3));

    kce_emit(&c, kce_ldr_w(r.t0, r.p, KCLF_P_MANUAL));
    kce_cbnz(&c, r.t0, 0, l_manual);

    /* ---- legacy linker backend ---- */
    kce_add_imm(&c, 0, r.p, KCLF_P_PATH);
    kce_emit(&c, kce_ldr_w(1, r.p, KCLF_P_FLAGS));
    kce_emit(&c, kce_ldr_x(2, r.p, KCLF_P_CALLER));
    kce_emit(&c, kce_ldr_x(r.t0, r.p, KCLF_P_FN));
    kce_emit(&c, kce_blr(r.t0));
    kce_emit(&c, kce_str_x(0, r.p, KCLF_P_HANDLE));
    kce_cbnz(&c, 0, 1, l_lok);

    kce_emit(&c, kce_ldr_x(r.t0, r.p, KCLF_P_DLERROR));
    kce_cbz(&c, r.t0, 1, l_lzero);
    kce_emit(&c, kce_blr(r.t0));
    kce_emit(&c, kce_str_x(0, r.p, KCLF_P_ERRPTR));
    kce_mov_const(&c, r.rc, 0);
    kce_b(&c, l_tail);
    kce_bind(&c, l_lzero);
    kce_mov_const(&c, r.rc, 0);
    kce_b(&c, l_tail);

    kce_bind(&c, l_lok);
    kce_emit(&c, kce_ldr_w(r.t0, r.p, KCLF_P_UNLOAD));
    kce_cbz(&c, r.t0, 0, l_lzero);
    kce_emit(&c, kce_ldr_x(r.t0, r.p, KCLF_P_DLCLOSE));
    kce_cbz(&c, r.t0, 1, l_lzero);
    kce_emit(&c, kce_ldr_x(0, r.p, KCLF_P_HANDLE));
    kce_emit(&c, kce_blr(r.t0));
    kce_emit(&c, kce_mov_reg(r.rc, 0));
    kce_b(&c, l_tail);

    /* ---- manual backend: IFUNC, constructors, finalizers ---- */
    kce_bind(&c, l_manual);
    kce_junk(&c, &r, kce_below(&c, 2));
    kce_emit(&c, kce_ldr_x(r.v, r.p, KCLF_P_IFUNCV));
    kce_emit(&c, kce_ldr_x(r.c, r.p, KCLF_P_IFUNCN));
    kce_bind(&c, l_ifunc);
    kce_cbz(&c, r.c, 1, l_init);
    kce_emit(&c, kce_ldr_x(r.t0, r.v, 0));
    kce_emit(&c, kce_ldr_x(0, r.p, KCLF_P_IFARG + 8));
    kce_mov64(&c, r.t1, 0x4000000000000000ULL);
    kce_emit(&c, kce_orr_x(0, 0, r.t1));
    kce_add_imm(&c, 1, r.p, KCLF_P_IFARG);
    kce_emit(&c, kce_blr(r.t0));
    kce_cbz(&c, 0, 1, l_ifunc_err);
    kce_mov_const(&c, r.t1, 3);
    kce_emit(&c, kce_and_x(r.t1, 0, r.t1));
    kce_cbnz(&c, r.t1, 1, l_ifunc_err);
    kce_emit(&c, kce_ldr_x(r.t1, r.v, 8));
    kce_emit(&c, kce_ldr_x(r.t2, r.v, 16));
    kce_emit(&c, kce_add_reg(0, 0, r.t2));
    kce_emit(&c, kce_str_x(0, r.t1, 0));
    kce_add_imm(&c, r.v, r.v, 24);
    kce_emit(&c, kce_sub_imm12(r.c, r.c, 1, 0));
    kce_b(&c, l_ifunc);
    kce_bind(&c, l_ifunc_err);
    kce_emit(&c, kce_movn(0, 7, 0)); /* -ENOEXEC */
    kce_emit(&c, kce_str_x(31, r.p, KCLF_P_HANDLE));
    kce_emit(&c, kce_mov_reg(r.rc, 0));
    kce_b(&c, l_tail);

    kce_bind(&c, l_init);
    kce_junk(&c, &r, kce_below(&c, 2));
    kce_emit(&c, kce_ldr_x(r.v, r.p, KCLF_P_INITV));
    kce_emit(&c, kce_ldr_x(r.c, r.p, KCLF_P_INITN));
    kce_bind(&c, l_init_loop);
    kce_cbz(&c, r.c, 1, l_fini);
    kce_emit(&c, kce_ldr_x(r.t0, r.v, 0));
    kce_add_imm(&c, r.v, r.v, 8);
    kce_mov_const(&c, r.t1, 0);
    kce_emit(&c, kce_mov_reg(0, r.t1));
    kce_emit(&c, kce_mov_reg(1, r.t1));
    kce_emit(&c, kce_mov_reg(2, r.t1));
    kce_emit(&c, kce_blr(r.t0));
    kce_emit(&c, kce_sub_imm12(r.c, r.c, 1, 0));
    kce_b(&c, l_init_loop);

    kce_bind(&c, l_fini);
    kce_emit(&c, kce_ldr_x(r.v, r.p, KCLF_P_FINIV));
    kce_emit(&c, kce_ldr_x(r.c, r.p, KCLF_P_FININ));
    kce_bind(&c, l_fini_loop);
    kce_cbz(&c, r.c, 1, l_man_done);
    kce_emit(&c, kce_ldr_x(r.t0, r.v, 0));
    kce_add_imm(&c, r.v, r.v, 8);
    kce_emit(&c, kce_blr(r.t0));
    kce_emit(&c, kce_sub_imm12(r.c, r.c, 1, 0));
    kce_b(&c, l_fini_loop);
    kce_bind(&c, l_man_done);
    kce_mov_const(&c, r.rc, 0);
    kce_b(&c, l_tail);

    kce_bind(&c, l_man_err);
    kce_emit(&c, kce_str_x(31, r.p, KCLF_P_HANDLE));
    kce_emit(&c, kce_mov_reg(r.rc, 0));
    kce_b(&c, l_tail);

    /* ---- common tail ---- */
    kce_bind(&c, l_tail);
    kce_junk(&c, &r, kce_below(&c, 2));
    kce_emit(&c, kce_ldr_x(r.t0, r.p, KCLF_P_HANDLE));
    kce_emit(&c, kce_str_x(r.t0, r.pb, pl->handle));
    kce_emit(&c, kce_ldr_x(r.t0, r.p, KCLF_P_ERRPTR));
    kce_emit(&c, kce_str_x(r.t0, r.pb, pl->errptr));
    kce_emit(&c, kce_str_x(r.rc, r.pb, pl->rc));

    /* Scrub the whole ABI page.  There is no fixed "used length" field to
     * trust, and the generated program has already copied everything it needs
     * (results, completion token) into the private page. */
    kce_emit(&c, kce_mov_reg(r.t0, r.p));
    kce_add_imm(&c, r.t1, r.p, (u64)page_size);
    kce_bind(&c, l_wipe);
    kce_emit(&c, kce_stp_xzr_post(r.t0, 16));
    kce_emit(&c, kce_cmp_reg(r.t0, r.t1));
    kce_bcond(&c, 0x3, l_wipe); /* b.lo */

    /* Restore the caller's FPSIMD file from the private page.  The file is not
     * on the interrupted stack, so a signal frame cannot corrupt it. */
    kce_add_imm(&c, 9, r.pb, (u64)pl->qregs);
    for (i = 0; i < 16; i++)
        kce_emit(&c, kce_ldp_q(qreg[2 * i], qreg[2 * i + 1], 9, (u32)qslot[i] * 32u));
    kce_emit(&c, kce_ldr_x(11, r.pb, pl->fpcr));
    kce_emit(&c, kce_msr(KCE_FPCR, 11));
    kce_emit(&c, kce_ldr_x(11, r.pb, pl->fpsr));
    kce_emit(&c, kce_msr(KCE_FPSR, 11));
    kce_junk(&c, &r, kce_below(&c, 3));

    /* Restore SP and NZCV first, then the general register file.  After the
     * final restore only the token store and the return loads remain, so the
     * thread cannot be observed inside a half-restored frame. */
    kce_emit(&c, kce_ldr_x(11, r.pb, pl->saved + KCLF_SAVED_SP));
    kce_emit(&c, kce_add_imm12(31, 11, 0, 0)); /* mov sp, x11 */
    kce_emit(&c, kce_ldr_x(11, r.pb, pl->saved + KCLF_SAVED_NZCV));
    kce_emit(&c, kce_msr(KCE_NZCV, 11));

    /* x10 carries the private page base through the final sequence.  x16 is
     * the one GPR that cannot be restored: it must hold the resume address for
     * the final indirect branch.  It is caller-saved scratch in this ABI. */
    kce_emit(&c, kce_mov_reg(10, r.pb));
    for (i = 0; i < 31; i++) order[i] = i;
    kce_shuffle(&c, order, 31);
    for (i = 0; i < 31; i++) {
        int reg = order[i];
        if (reg == 10 || reg == 16) continue;
        kce_emit(&c, kce_ldr_x(reg, 10, pl->saved + (u32)reg * 8u));
    }

    /* Publish the per-request random token.  This is the only completion
     * event: an ordinary watched target syscall or the controller's poll
     * callback compares it with the value exported by the kernel. */
    kce_emit(&c, kce_ldr_x(16, 10, pl->donetok));
    kce_emit(&c, kce_str_x(16, 10, pl->done));

    /* Resume the interrupted PC from EL0.  No syscall, signal or fault is
     * generated by the framework's completion path. */
    kce_emit(&c, kce_ldr_x(16, 10, pl->saved + KCLF_SAVED_PC));
    kce_emit(&c, kce_ldr_x(10, 10, pl->saved + 10u * 8u));
    kce_emit(&c, kce_br(16));

    if (c.overflow) return -1;
    if (kce_resolve(&c)) return -1;

    out->entry_off = (u32)entry_off;
    out->length = (u32)c.n * 4u;
    return 0;
}
