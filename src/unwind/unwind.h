/* -*- linux-c -*-
 *
 * dwarf unwinder header file
 * Copyright (C) 2008-2010, 2013 Red Hat Inc.
 * Copyright (C) 2002-2006 Novell, Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _STP_UNWIND_H_
#define _STP_UNWIND_H_

#include <asm/ptrace.h>
#include <linux/uaccess.h>

#ifdef CONFIG_COMPAT

/* x86_64 has a different flag name from all other arches and s390... */
#include <linux/thread_info.h>
#if defined (__x86_64__)
  #define TIF_32BIT TIF_IA32
#endif
#if defined(__s390__) || defined(__s390x__)
  #define TIF_32BIT TIF_31BIT
#endif
#if !defined(TIF_32BIT)
#error architecture not supported, no TIF_32BIT flag
#endif

/* _stp_is_compat_task - returns true if this is a 32-on-64 bit user task.
   Note that some kernels/architectures define a function called
   is_compat_task(), but that just tests for being inside a 32bit compat
   syscall. We want to test whether the current task is a 32 bit compat
   task itself.*/
static inline int _stp_is_compat_task(void)
{
  return test_thread_flag(TIF_32BIT);
}

#else

static inline int _stp_is_compat_task(void)
{
  return 0;
}

#endif /* CONFIG_COMPAT */

struct section {
	unsigned long offset;	/* offset from vma start */
	u8 __user *ubuf;	/* original virtual address of the section */
	u8 *kbuf;		/* accessible buffer mapped in kernel */
	uint32_t size;		/* buffer size in bytes */
};

struct _stp_module {
	int is_dynamic;
	unsigned long static_addr;

	struct section ehf_hdr;	/* eh_frame_hdr */
	struct section ehf;	/* eh_frame */

	// The .eh_frame unwind data for this module.
	void *eh_frame;
	void *unwind_hdr;
	uint32_t eh_frame_len;
	uint32_t unwind_hdr_len;
	unsigned long eh_frame_addr; /* Orig load address (offset) .eh_frame */
	unsigned long unwind_hdr_addr; /* same for .eh_frame_hdr */
};

/** Safely read from userspace or kernelspace.
 * On success, returns 0. Returns -EFAULT on error.
 *
 * This uses __get_user() to read from userspace or
 * kernelspace.  Will not sleep or cause pagefaults when
 * called from within a kprobe context.
 *
 * @param segment . KERNEL_DS for kernel access
 *                  USER_DS for userspace.
 */

/* XXX: duplicates _stp_deref() in loc2c-runtime.h */
/* NB: lookup_bad_addr cannot easily be called from here due to header
 * file ordering. */
/* XXX: no error signalling */
#define _stp_read_address(x, ptr, segment)    \
	({				      \
		long ret;		      \
		mm_segment_t ofs = get_fs();  \
		set_fs(segment);	      \
                pagefault_disable();          \
                if (!access_ok(VERIFY_READ, (char __user *)ptr, sizeof(x))) \
                     ret = -EFAULT;           \
                else                          \
                     ret = __get_user(x, ptr);                          \
                pagefault_enable();           \
		set_fs(ofs);		      \
		ret;   			      \
	})


struct unwind_frame_info
{
    struct pt_regs regs;
    unsigned call_frame:1;
};

#if defined (__x86_64__)
#include "x86_64.h"
#elif  defined (__i386__)
#include "i386.h"
#elif defined (__powerpc64__)
#include "ppc64.h"
#elif defined (__s390x__)
#include "s390x.h"
#elif defined (__arm__)
#include "arm.h"
#elif defined (__aarch64__)
#include "arm64.h"
#else
#error "Unsupported dwarf unwind architecture"
#endif

#define DW_EH_PE_absptr   0x00
#define DW_EH_PE_leb128   0x01
#define DW_EH_PE_data2    0x02
#define DW_EH_PE_data4    0x03
#define DW_EH_PE_data8    0x04
#define DW_EH_PE_FORM     0x07 /* mask */
#define DW_EH_PE_signed   0x08 /* signed versions of above have this bit set */

#define DW_EH_PE_pcrel    0x10
#define DW_EH_PE_textrel  0x20
#define DW_EH_PE_datarel  0x30
#define DW_EH_PE_funcrel  0x40
#define DW_EH_PE_aligned  0x50
#define DW_EH_PE_ADJUST   0x70 /* mask */
#define DW_EH_PE_indirect 0x80
#define DW_EH_PE_omit     0xff

typedef unsigned long uleb128_t;
typedef   signed long sleb128_t;

/* Used for DW_CFA_remember_state and DW_CFA_restore_state. */
#define STP_MAX_STACK_DEPTH 4

#ifndef BUILD_BUG_ON_ZERO
#define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)
#endif

#ifndef FIELD_SIZEOF
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#endif


#define EXTRA_INFO(f) { \
		BUILD_BUG_ON_ZERO(offsetof(struct unwind_frame_info, f) \
		                  % FIELD_SIZEOF(struct unwind_frame_info, f)) \
		+ offsetof(struct unwind_frame_info, f) \
		  / FIELD_SIZEOF(struct unwind_frame_info, f), \
		FIELD_SIZEOF(struct unwind_frame_info, f) \
	}
#define PTREGS_INFO(f) EXTRA_INFO(regs.f)

static const struct {
	unsigned offs:BITS_PER_LONG / 2;
	unsigned width:BITS_PER_LONG / 2;
} reg_info[] = {
	UNW_REGISTER_INFO
};

#undef PTREGS_INFO
#undef EXTRA_INFO

/* The reg_info array assumes dwarf register numbers start at zero and
   are consecutive.  If that isn't the case for some architecture (e.g. ppc)
   then redefine to map the given dwarf register number to the actual
   reg_info index.  */
#ifndef DWARF_REG_MAP
#define DWARF_REG_MAP(r) r
#endif

/* COMPAT_REG_MAP is the mapping from 32bit to 64bit DWARF registers.  In
   the case where they're not the same (e.g. x86_64 and i386) the alternate
   mapping will be located in the 64bit header file */
#ifndef COMPAT_REG_MAP
#define COMPAT_REG_MAP(r) r
#endif

/* The number of real registers in the register map. These are all assumed
   to be the Same in the new frame. All others will be Unknown untill they
   have been explictly set. (e.g. the x86 return register). */
#ifndef UNW_NR_REAL_REGS
#define UNW_NR_REAL_REGS ARRAY_SIZE(reg_info)
#endif

#ifndef REG_INVALID
#define REG_INVALID(r) (reg_info[r].width == 0)
#endif

/* Whether the stack pointer should be set from the CFA.
   If this isn't what the architecture wants, then it should define
   this as zero.  */
#ifndef UNW_SP_FROM_CFA
#define UNW_SP_FROM_CFA 1
#endif

/* Whether the instruction pointer should be set from the return address
   column.  If this isn't what the architecture wants, then it should
   define this as zero.  */
#ifndef UNW_PC_FROM_RA
#define UNW_PC_FROM_RA 1
#endif

#define DW_CFA_nop                          0x00
#define DW_CFA_set_loc                      0x01
#define DW_CFA_advance_loc1                 0x02
#define DW_CFA_advance_loc2                 0x03
#define DW_CFA_advance_loc4                 0x04
#define DW_CFA_offset_extended              0x05
#define DW_CFA_restore_extended             0x06
#define DW_CFA_undefined                    0x07
#define DW_CFA_same_value                   0x08
#define DW_CFA_register                     0x09
#define DW_CFA_remember_state               0x0a
#define DW_CFA_restore_state                0x0b
#define DW_CFA_def_cfa                      0x0c
#define DW_CFA_def_cfa_register             0x0d
#define DW_CFA_def_cfa_offset               0x0e
#define DW_CFA_def_cfa_expression           0x0f
#define DW_CFA_expression                   0x10
#define DW_CFA_offset_extended_sf           0x11
#define DW_CFA_def_cfa_sf                   0x12
#define DW_CFA_def_cfa_offset_sf            0x13
#define DW_CFA_val_offset                   0x14
#define DW_CFA_val_offset_sf                0x15
#define DW_CFA_val_expression               0x16
#define DW_CFA_lo_user                      0x1c
#define DW_CFA_GNU_window_save              0x2d
#define DW_CFA_GNU_args_size                0x2e
#define DW_CFA_GNU_negative_offset_extended 0x2f
#define DW_CFA_hi_user                      0x3f

#define	DW_OP_addr		0x03
#define	DW_OP_deref		0x06
#define	DW_OP_const1u		0x08
#define	DW_OP_const1s		0x09
#define	DW_OP_const2u		0x0a
#define	DW_OP_const2s		0x0b
#define	DW_OP_const4u		0x0c
#define	DW_OP_const4s		0x0d
#define	DW_OP_const8u		0x0e
#define	DW_OP_const8s		0x0f
#define	DW_OP_constu		0x10
#define	DW_OP_consts		0x11
#define	DW_OP_dup		0x12
#define	DW_OP_drop		0x13
#define	DW_OP_over		0x14
#define	DW_OP_pick		0x15
#define	DW_OP_swap		0x16
#define	DW_OP_rot		0x17
#define	DW_OP_xderef		0x18
#define	DW_OP_abs		0x19
#define	DW_OP_and		0x1a
#define	DW_OP_div		0x1b
#define	DW_OP_minus		0x1c
#define	DW_OP_mod		0x1d
#define	DW_OP_mul		0x1e
#define	DW_OP_neg		0x1f
#define	DW_OP_not		0x20
#define	DW_OP_or		0x21
#define	DW_OP_plus		0x22
#define	DW_OP_plus_uconst	0x23
#define	DW_OP_shl		0x24
#define	DW_OP_shr		0x25
#define	DW_OP_shra		0x26
#define	DW_OP_xor		0x27
#define	DW_OP_bra		0x28
#define	DW_OP_eq		0x29
#define	DW_OP_ge		0x2a
#define	DW_OP_gt		0x2b
#define	DW_OP_le		0x2c
#define	DW_OP_lt		0x2d
#define	DW_OP_ne		0x2e
#define	DW_OP_skip		0x2f
#define	DW_OP_lit0		0x30
#define	DW_OP_lit1		0x31
#define	DW_OP_lit2		0x32
#define	DW_OP_lit3		0x33
#define	DW_OP_lit4		0x34
#define	DW_OP_lit5		0x35
#define	DW_OP_lit6		0x36
#define	DW_OP_lit7		0x37
#define	DW_OP_lit8		0x38
#define	DW_OP_lit9		0x39
#define	DW_OP_lit10		0x3a
#define	DW_OP_lit11		0x3b
#define	DW_OP_lit12		0x3c
#define	DW_OP_lit13		0x3d
#define	DW_OP_lit14		0x3e
#define	DW_OP_lit15		0x3f
#define	DW_OP_lit16		0x40
#define	DW_OP_lit17		0x41
#define	DW_OP_lit18		0x42
#define	DW_OP_lit19		0x43
#define	DW_OP_lit20		0x44
#define	DW_OP_lit21		0x45
#define	DW_OP_lit22		0x46
#define	DW_OP_lit23		0x47
#define	DW_OP_lit24		0x48
#define	DW_OP_lit25		0x49
#define	DW_OP_lit26		0x4a
#define	DW_OP_lit27		0x4b
#define	DW_OP_lit28		0x4c
#define	DW_OP_lit29		0x4d
#define	DW_OP_lit30		0x4e
#define	DW_OP_lit31		0x4f
#define	DW_OP_reg0		0x50
#define	DW_OP_reg1		0x51
#define	DW_OP_reg2		0x52
#define	DW_OP_reg3		0x53
#define	DW_OP_reg4		0x54
#define	DW_OP_reg5		0x55
#define	DW_OP_reg6		0x56
#define	DW_OP_reg7		0x57
#define	DW_OP_reg8		0x58
#define	DW_OP_reg9		0x59
#define	DW_OP_reg10		0x5a
#define	DW_OP_reg11		0x5b
#define	DW_OP_reg12		0x5c
#define	DW_OP_reg13		0x5d
#define	DW_OP_reg14		0x5e
#define	DW_OP_reg15		0x5f
#define	DW_OP_reg16		0x60
#define	DW_OP_reg17		0x61
#define	DW_OP_reg18		0x62
#define	DW_OP_reg19		0x63
#define	DW_OP_reg20		0x64
#define	DW_OP_reg21		0x65
#define	DW_OP_reg22		0x66
#define	DW_OP_reg23		0x67
#define	DW_OP_reg24		0x68
#define	DW_OP_reg25		0x69
#define	DW_OP_reg26		0x6a
#define	DW_OP_reg27		0x6b
#define	DW_OP_reg28		0x6c
#define	DW_OP_reg29		0x6d
#define	DW_OP_reg30		0x6e
#define	DW_OP_reg31		0x6f
#define	DW_OP_breg0		0x70
#define	DW_OP_breg1		0x71
#define	DW_OP_breg2		0x72
#define	DW_OP_breg3		0x73
#define	DW_OP_breg4		0x74
#define	DW_OP_breg5		0x75
#define	DW_OP_breg6		0x76
#define	DW_OP_breg7		0x77
#define	DW_OP_breg8		0x78
#define	DW_OP_breg9		0x79
#define	DW_OP_breg10		0x7a
#define	DW_OP_breg11		0x7b
#define	DW_OP_breg12		0x7c
#define	DW_OP_breg13		0x7d
#define	DW_OP_breg14		0x7e
#define	DW_OP_breg15		0x7f
#define	DW_OP_breg16		0x80
#define	DW_OP_breg17		0x81
#define	DW_OP_breg18		0x82
#define	DW_OP_breg19		0x83
#define	DW_OP_breg20		0x84
#define	DW_OP_breg21		0x85
#define	DW_OP_breg22		0x86
#define	DW_OP_breg23		0x87
#define	DW_OP_breg24		0x88
#define	DW_OP_breg25		0x89
#define	DW_OP_breg26		0x8a
#define	DW_OP_breg27		0x8b
#define	DW_OP_breg28		0x8c
#define	DW_OP_breg29		0x8d
#define	DW_OP_breg30		0x8e
#define	DW_OP_breg31		0x8f
#define	DW_OP_regx		0x90
#define	DW_OP_fbreg		0x91
#define	DW_OP_bregx		0x92
#define	DW_OP_deref_size	0x94
#define	DW_OP_xderef_size	0x95
#define	DW_OP_nop		0x96

struct unwind_item {
	enum item_location {
		Same,     /* no state */
		Nowhere,  /* no state */
		Memory,   /* signed offset from CFA */
		Register, /* unsigned register number */
		Value,    /* signed offset from CFA */
		Expr,     /* DWARF expression */
		ValExpr   /* DWARF expression */
	} where;
	union {
		uleb128_t reg;
		sleb128_t off;
		const u8 *expr;
	} state;
};

struct unwind_reg_state {
	union {
		struct cfa {
			uleb128_t reg;
			sleb128_t off;
		} cfa;
		const u8 *cfa_expr;
	};
	struct unwind_item regs[ARRAY_SIZE(reg_info)];
	unsigned cfa_is_expr:1;
};

struct unwind_state {
	uleb128_t loc;						/* instruction address */
	uleb128_t codeAlign;
	sleb128_t dataAlign;
	unsigned stackDepth:8;
	struct unwind_reg_state reg[STP_MAX_STACK_DEPTH];
	struct unwind_item cie_regs[ARRAY_SIZE(reg_info)];
};

struct unwind_context {
    struct unwind_frame_info info;
    struct unwind_state state;
};

static const struct cfa badCFA = { ARRAY_SIZE(reg_info), 1 };

#ifndef MAXBACKTRACE
#define MAXBACKTRACE 20
#endif

struct unwind_cache {
	enum uwcache_state {
		uwcache_uninitialized,
		uwcache_partial,
		uwcache_finished
	} state;
	unsigned depth; /* pc[0..(depth-1)] contains valid entries */
	unsigned long pc[MAXBACKTRACE];
};

struct kunwind_proc_modules;

int unwind_full(struct unwind_context *context,
		struct kunwind_proc_modules *proc,
		struct kunwind_backtrace *bt);

int eh_frame_from_hdr(void *base, unsigned long vma_start, unsigned long vma_end, int compat,
		      u8 *hdr, unsigned long hdr_addr, unsigned long hdr_len,
		      u8 **eh_frame, unsigned long *eh_frame_addr, unsigned long *eh_frame_len);
#endif /*_STP_UNWIND_H_*/
