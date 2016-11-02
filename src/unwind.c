/* -*- linux-c -*-
 * kernel stack unwinding
 * Copyright (C) 2008-2011, 2014 Red Hat Inc.
 *
 * Based on old kernel code that is
 * Copyright (C) 2002-2006 Novell, Inc.
 *	Jan Beulich <jbeulich@novell.com>
 *
 * This code is released under version 2 of the GNU GPL.
 *
 * This code currently does stack unwinding in the kernel and modules.
 * It has been extended to handle userspace unwinding using systemtap
 * data structures.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/kallsyms.h>

#include "modules.h"
#include "debug.h"
#include "unwind/unwind.h"

static uleb128_t get_uleb128(const u8 **pcur, const u8 *end)
{
	const u8 *cur = *pcur;
	uleb128_t value = 0;
	unsigned shift;

	for (shift = 0; cur < end; shift += 7) {
		if (shift + 7 > 8 * sizeof(value)
		    && (*cur & 0x7fU) >= (1U << (8 * sizeof(value) - shift))) {
			cur = end + 1;
			break;
		}
		value |= (uleb128_t)(*cur & 0x7f) << shift;
		if (!(*cur++ & 0x80))
			break;
	}
	*pcur = cur;

	return value;
}

static sleb128_t get_sleb128(const u8 **pcur, const u8 *end)
{
	const u8 *cur = *pcur;
	sleb128_t value = 0;
	unsigned shift;

	for (shift = 0; cur < end; shift += 7) {
    const u8 cur_val = *cur++;
		if (shift + 7 > 8 * sizeof(value)
		    && (cur_val & 0x7fU) >= (1U << (8 * sizeof(value) - shift))) {
			cur = end + 1;
			break;
		}
		value |= (sleb128_t)(cur_val & 0x7f) << shift;
		if (!(cur_val & 0x80)) {
			value |= -(cur_val & 0x40) << shift;
			break;
		}
	}
	*pcur = cur;

	return value;
}

/* read an encoded pointer and increment *pLoc past the end of the
 * data read. */
static unsigned long read_ptr_sect(const u8 **pLoc, const void *end,
				   signed ptrType, unsigned long textAddr,
				   unsigned long dataAddr, int user, int compat_task, int tableSize)
{
	unsigned long value = 0;
	union {
		const u8 *p8;
		const u16 *p16u;
		const s16 *p16s;
		const u32 *p32u;
		const s32 *p32s;
		const unsigned long *pul;
		const unsigned int *pui;
	} ptr;

	if (ptrType < 0 || ptrType == DW_EH_PE_omit)
		return 0;

	ptr.p8 = *pLoc;
	switch (ptrType & DW_EH_PE_FORM) {
	case DW_EH_PE_data2:
		if (end < (const void *)(ptr.p16u + 1))
			return 0;
		if (ptrType & DW_EH_PE_signed)
			value = _stp_get_unaligned(ptr.p16s++);
		else
			value = _stp_get_unaligned(ptr.p16u++);
		break;
	case DW_EH_PE_data4:
#ifdef CONFIG_64BIT

		/* If the tableSize matches the length of data we're trying to return
		 * or if specifically set to 0 in the call it means we actually want a
		 * DW_EH_PE_data4 and not a DW_EH_PE_absptr.  If this is not the case
		 * then we want to fall through to DW_EH_PE_absptr */
		if (!compat_task || (compat_task && (tableSize == 4 || tableSize == 0)))
		{
			if (end < (const void *)(ptr.p32u + 1))
				return 0;

			if (ptrType & DW_EH_PE_signed)
				value = _stp_get_unaligned(ptr.p32s++);
			else
				value = _stp_get_unaligned(ptr.p32u++);
			break;
		}
	case DW_EH_PE_data8:
		BUILD_BUG_ON(sizeof(u64) != sizeof(value));
#else
		BUILD_BUG_ON(sizeof(u32) != sizeof(value));
#endif
	/* fallthrough, see above. */
	case DW_EH_PE_absptr:
		if (compat_task)
		{
			if (end < (const void *)(ptr.pui + 1))
				return 0;
			value = _stp_get_unaligned(ptr.pui++);
		} else {
			if (end < (const void *)(ptr.pul + 1))
				return 0;
			value = _stp_get_unaligned(ptr.pul++);
		}

		break;
	case DW_EH_PE_leb128:
		BUILD_BUG_ON(sizeof(uleb128_t) > sizeof(value));
		value = ptrType & DW_EH_PE_signed ? get_sleb128(&ptr.p8, end)
		    : get_uleb128(&ptr.p8, end);
		if ((const void *)ptr.p8 > end)
			return 0;
		break;
	default:
		return 0;
	}
	switch (ptrType & DW_EH_PE_ADJUST) {
	case DW_EH_PE_absptr:
		break;
	case DW_EH_PE_pcrel:
		value += (unsigned long)*pLoc;
		break;
	case DW_EH_PE_textrel:
		value += textAddr;
		break;
	case DW_EH_PE_datarel:
		value += dataAddr;
		break;
	default:
		return 0;
	}
	if ((ptrType & DW_EH_PE_indirect)
	    && _stp_read_address(value, (unsigned long *)value,
				 (user ? USER_DS : KERNEL_DS)))
		return 0;
	*pLoc = ptr.p8;

	return value;
}

static unsigned long read_pointer(const u8 **pLoc, const void *end, signed ptrType,
				  int user, int compat_task)
{
	return read_ptr_sect(pLoc, end, ptrType, 0, 0, user, compat_task, 0);
}

static inline unsigned long
get_pc(struct unwind_frame_info *info)
{
	return UNW_PC(info) - info->call_frame;
}

static struct kunwind_stp_module
*kunw_mod_lookup(unsigned long pc, struct kunwind_proc_modules *proc)
{
	struct kunwind_stp_module *kunw_mod = NULL, *pos;
	list_for_each_entry(pos, &(proc->stp_modules), list) {
		if (pc >= pos->elf_vma->vm_start && pc <= pos->elf_vma->vm_end) {
			kunw_mod = pos;
			break;
		}
	}
	return kunw_mod;
}

/* Whether this is a real CIE. Assumes CIE (length) sane. */
static int has_cie_id(const u32 *cie, int is_ehframe)
{
	/* CIE id for eh_frame is 0, otherwise 0xffffffff */
	if (is_ehframe && cie[1] == 0)
		return 1;
	else if (cie[1] == 0xffffffff)
		return 1;
	else
		return 0;
}

/* whether this is a real fde or not */
static int is_fde(const u32 *fde, void *table, uint32_t table_len,
			int is_ehframe)
{
	const u8 *end;

	/* check that length is proper */
	if (!*fde || (*fde & (sizeof(*fde) - 1))) {
		_stp_warn("bad fde\n");
		return 0;
	}

	if (has_cie_id(fde, is_ehframe))
		return 0;

	end = (const u8 *)(fde + 1) + *fde;

        /* end should fall within unwind table. */
        if (((void*)end) < table
            || ((void *)end) > ((void *)(table + table_len))) {
		_stp_warn("bad fde length\n");
		return 0;
	}

	return 1;
}

/* given an FDE, find its CIE and sanity check */
static const u32 *cie_for_fde(const u32 *fde, void *unwind_data,
			      uint32_t table_len, int is_ehframe)
{
	const u32 *cie;
	unsigned version;
	const u8 *end;

	/* CIE_pointer must be a proper offset */
	if ((fde[1] & (sizeof(*fde) - 1)) || fde[1] > (unsigned long)(fde + 1) - (unsigned long)unwind_data) {
		_stp_warn("invalid fde[1]=%lx fde+1=%lx, unwind_data=%lx  %lx\n",
			    (unsigned long)fde[1], (unsigned long)(fde + 1),
			    (unsigned long)unwind_data, (unsigned long)(fde + 1) - (unsigned long)unwind_data);
		return NULL;	/* this is not a valid FDE */
	}

	/* cie pointer field is different in eh_frame vs debug_frame */
	if (is_ehframe)
		cie = fde + 1 - fde[1] / sizeof(*fde);
	else
		cie = unwind_data + fde[1];

	/* Make sure address falls in the table */
	if (((void *)cie) < ((void*)unwind_data)
	    || ((void*)cie) > ((void*)(unwind_data + table_len))) {
		_stp_warn("cie address falls outside table\n");
		return NULL;
	}

	if (*cie <= sizeof(*cie) + 4 || *cie >= fde[1] - sizeof(*fde)
	    || ! has_cie_id(cie, is_ehframe)) {
		_stp_warn("cie is not valid %lx %x %x %x\n", (unsigned long)cie, *cie, fde[1], cie[1]);
		return NULL;	/* this is not a (valid) CIE */
	}

	version = *(const u8 *)(cie + 2);
	if (version != 1 && version != 3 && version != 4) {
		_stp_warn ("Unsupported CIE version: %d\n", version);
		return NULL;
	}

	end = (const u8 *)(cie + 1) + *cie;

        /* end should fall within unwind table. */
        if (((void *)end) < (void *)unwind_data
            || ((void *)end) > ((void *)(unwind_data + table_len))) {
		_stp_warn ("CIE end falls outside table\n");
		return NULL;
	}

	return cie;
}


/* Parse FDE and CIE content. Basic sanity checks should already have
   been done start/end/version/id (done by is_fde and cie_for_fde).
   Returns -1 if FDE or CIE cannot be parsed.*/
static int parse_fde_cie(const u32 *fde, const u32 *cie,
			 void *unwind_data, uint32_t table_len,
			 unsigned *ptrType, int user,
			 unsigned long *startLoc, unsigned long *locRange,
			 const u8 **fdeStart, const u8 **fdeEnd,
			 const u8 **cieStart, const u8 **cieEnd,
			 uleb128_t *codeAlign, sleb128_t *dataAlign,
			 uleb128_t *retAddrReg, unsigned *call_frame, int compat_task)
{
	const u8 *ciePtr = (const u8 *)(cie + 2);
	const u8 *fdePtr = (const u8 *)(fde + 2);
	unsigned version = *ciePtr++;
	const char *aug = (const void *)ciePtr;
	uleb128_t augLen = 0;	/* Set to non-zero if cie aug starts with z */

	*cieEnd = (const u8 *)(cie + 1) + *cie;
	*fdeEnd = (const u8 *)(fde + 1) + *fde;

	/* check if augmentation string is nul-terminated */
	if ((ciePtr = memchr(aug, 0, *cieEnd - ciePtr)) == NULL) {
		_stp_warn("Unterminated augmentation string\n");
		return -1;
	}
	ciePtr++;	/* skip aug terminator */

	*codeAlign = get_uleb128(&ciePtr, *cieEnd);
	*dataAlign = get_sleb128(&ciePtr, *cieEnd);
	dbug_unwind(2, "codeAlign=%lx, dataAlign=%lx\n",
		    *codeAlign, *dataAlign);
	if (*codeAlign == 0 || *dataAlign == 0) {
		_stp_warn("zero codeAlign or dataAlign values\n");
		return -1;
	}

	*retAddrReg = ((version <= 1)
		       ? *ciePtr++ : get_uleb128(&ciePtr, *cieEnd));
	if(compat_task){
		dbug_unwind(1, "map retAddrReg value %ld to reg_info idx %ld\n",
			    *retAddrReg, COMPAT_REG_MAP(DWARF_REG_MAP(*retAddrReg)));
		*retAddrReg = COMPAT_REG_MAP(DWARF_REG_MAP(*retAddrReg));
	} else {
		dbug_unwind(1, "map retAddrReg value %ld to reg_info idx %ld\n",
			    *retAddrReg, DWARF_REG_MAP(*retAddrReg));
		*retAddrReg = DWARF_REG_MAP(*retAddrReg);
	}

	if (*aug == 'z') {
		augLen = get_uleb128(&ciePtr, *cieEnd);
		if (augLen > (const u8 *)cie - *cieEnd
		    || ciePtr + augLen > *cieEnd) {
			_stp_warn("Bogus CIE augmentation length\n");
			return -1;
		}
	}
	*cieStart = ciePtr + augLen;

	/* Read augmentation string to determine frame_call and ptrType. */
	*call_frame = 1;
	*ptrType = DW_EH_PE_absptr;
	while (*aug) {
		if (ciePtr > *cieStart) {
			_stp_warn("Augmentation data runs past end\n");
			return -1;
		}
		switch (*aug) {
			case 'z':
				break;
			case 'L':
				ciePtr++;
				break;
			case 'P': {
				/* We are not actually interested in
				   the value, so don't try to deref.
				   Mask off DW_EH_PE_indirect. */
				signed pType = *ciePtr++ & 0x7F;
				if (!read_pointer(&ciePtr, *cieStart, pType, user, compat_task)) {
					_stp_warn("couldn't read personality routine handler\n");
					return -1;
				}
				break;
			}
			case 'R':
				*ptrType = *ciePtr++;
				break;
			case 'S':
				*call_frame = 0;
				break;
			default:
				_stp_warn("Unknown augmentation char '%c'\n", *(aug - 1));
				return -1;
		}
		aug++;
	}
	if (ciePtr != *cieStart) {
		_stp_warn("Bogus CIE augmentation data\n");
		return -1;
	}

	/* Now we finally know the type encoding and whether or not the
	   augmentation string starts with 'z' indicating the FDE might also
	   have some augmentation data, so we can parse the FDE. */
	*startLoc = read_pointer(&fdePtr, *fdeEnd, *ptrType, user, compat_task);
	*locRange = read_pointer(&fdePtr, *fdeEnd,
				 *ptrType & (DW_EH_PE_FORM | DW_EH_PE_signed),
				 user, compat_task);
	dbug_unwind(2, "startLoc: %lx, locrange: %lx\n",
		    *startLoc, *locRange);

	/* Skip FDE augmentation length (not interested in data). */
	if (augLen != 0) {
		augLen = get_uleb128(&fdePtr, *fdeEnd);
		if (augLen > (const u8 *)fde - *fdeEnd
		    || fdePtr + augLen > *fdeEnd) {
			_stp_warn("Bogus FDE augmentation length\n");
			return -1;
		}
	}
	*fdeStart = fdePtr + augLen;

	return 0;
}

#define REG_STATE state->reg[state->stackDepth]

static int advance_loc(unsigned long delta, struct unwind_state *state)
{
	state->loc += delta * state->codeAlign;
	dbug_unwind(1, "state->loc=%lx\n", state->loc);
	return delta > 0;
}

/* Set Same or Nowhere rule for register. */
static void set_no_state_rule(uleb128_t reg, enum item_location where,
                              struct unwind_state *state)
{
	dbug_unwind(1, "reg=%lx, where=%d\n", reg, where);
	if (reg < ARRAY_SIZE(REG_STATE.regs)) {
		REG_STATE.regs[reg].where = where;
	}
}

/* Memory or Value rule */
static void set_offset_rule(uleb128_t reg, enum item_location where,
                            sleb128_t svalue, struct unwind_state *state)
{
	dbug_unwind(1, "reg=%lx, where=%d, svalue=%lx\n", reg, where, svalue);
	if (reg < ARRAY_SIZE(REG_STATE.regs)) {
		REG_STATE.regs[reg].where = where;
		REG_STATE.regs[reg].state.off = svalue;
	}
}

/* Register rule. */
static void set_register_rule(uleb128_t reg, uleb128_t value,
                              struct unwind_state *state)
{
	dbug_unwind(1, "reg=%lx, value=%lx\n", reg, value);
	if (reg < ARRAY_SIZE(REG_STATE.regs)) {
		REG_STATE.regs[reg].where = Register;
		REG_STATE.regs[reg].state.reg = value;
	}
}

/* Expr or ValExpr rule. */
static void set_expr_rule(uleb128_t reg, enum item_location where,
			  const u8 **expr, const u8 *end,
			  struct unwind_state *state)
{
	const u8 *const start = *expr;
	uleb128_t len = get_uleb128(expr, end);
	dbug_unwind(1, "reg=%lx, where=%d, expr=%lu@%p\n",
		    reg, where, len, *expr);
	/* Sanity check that expr falls completely inside known data. */
	if (end - *expr >= len && reg < ARRAY_SIZE(REG_STATE.regs)) {
		REG_STATE.regs[reg].where = where;
		REG_STATE.regs[reg].state.expr = start;
		*expr += len;
	}
}

/* Limit the number of instructions we process. Arbitrary limit.
   512 should be enough for anybody... */
#define MAX_CFI 512

static int run_cfi_program(const u8 *start, const u8 *end, unsigned long targetLoc,
		      signed ptrType, int user, struct unwind_state *state, int compat_task)
{
	union {
		const u8 *p8;
		const u16 *p16;
		const u32 *p32;
	} ptr;
	int result = 1;

	if (end - start > MAX_CFI) {
		_stp_warn("Too many CFI instuctions\n");
		return 0;
	}

	dbug_unwind(1, "targetLoc=%lx state->loc=%lx\n", targetLoc, state->loc);
	for (ptr.p8 = start; result && ptr.p8 < end;) {
		switch (*ptr.p8 >> 6) {
			uleb128_t value;
			uleb128_t value2;
			sleb128_t svalue;
		case 0:
			switch (*ptr.p8++) {
			case DW_CFA_nop:
				dbug_unwind(1, "DW_CFA_nop\n");
				break;
			case DW_CFA_set_loc:
				if ((state->loc = read_pointer(&ptr.p8, end, ptrType, user, compat_task)) == 0)
					result = 0;
				dbug_unwind(1, "DW_CFA_set_loc %lx (result=%d)\n", state->loc, result);
				break;
			case DW_CFA_advance_loc1:
				result = ptr.p8 < end && advance_loc(*ptr.p8++, state);
				dbug_unwind(1, "DW_CFA_advance_loc1 (result=%d)\n", result);
				break;
			case DW_CFA_advance_loc2:
				result = ptr.p8 <= end + 2 && advance_loc(*ptr.p16++, state);
				dbug_unwind(1, "DW_CFA_advance_loc2 (result=%d)\n", result);
				break;
			case DW_CFA_advance_loc4:
				result = ptr.p8 <= end + 4 && advance_loc(*ptr.p32++, state);
				dbug_unwind(1, "DW_CFA_advance_loc4 (result=%d)\n", result);
				break;
			case DW_CFA_offset_extended:
				value = get_uleb128(&ptr.p8, end);
				value2 = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_offset_extended value %ld to reg_info idx %ld, with offset %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)), value2);
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_offset_extended value %ld to reg_info idx %ld, with offset %ld\n",
						    value, DWARF_REG_MAP(value), value2);
					value = DWARF_REG_MAP(value);
				}
				set_offset_rule(value, Memory,
                                                value2 * state->dataAlign,
                                                state);
				break;
			case DW_CFA_val_offset:
				value = get_uleb128(&ptr.p8, end);
				value2 = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_val_offset value %ld to reg_info idx %ld\n, with offset: %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)), value2);
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_val_offset value %ld to reg_info idx %ld\n, with offset: %ld\n",
						    value, DWARF_REG_MAP(value), value2);
					value = DWARF_REG_MAP(value);
				}
				set_offset_rule(value, Value,
                                                value2 * state->dataAlign,
                                                state);
				break;
			case DW_CFA_offset_extended_sf:
				value = get_uleb128(&ptr.p8, end);
				svalue = get_sleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_offset_extended_sf value %ld to reg_info idx %ld, with offset: %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)), svalue);
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_offset_extended_sf value %ld to reg_info idx %ld, with offset: %ld\n",
						    value, DWARF_REG_MAP(value), svalue);
					value = DWARF_REG_MAP(value);
				}
				set_offset_rule(value, Memory,
						svalue * state->dataAlign,
						state);
				break;
			case DW_CFA_val_offset_sf:
				value = get_uleb128(&ptr.p8, end);
				svalue = get_sleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_val_offset_sf value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_val_offset_sf value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_offset_rule(value, Value,
						svalue * state->dataAlign,
						state);
				break;
			case DW_CFA_same_value:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_same_value value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_same_value value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_no_state_rule(value, Same, state);
				break;
			case DW_CFA_restore_extended:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_restore_extended value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_restore_extended value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				if (value < ARRAY_SIZE(REG_STATE.regs))
					memcpy(&REG_STATE.regs[value], &state->cie_regs[value], sizeof(struct unwind_item));
				break;
			case DW_CFA_undefined:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_undefined value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_undefined value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_no_state_rule(value, Nowhere, state);
				break;
			case DW_CFA_register: {
				uleb128_t reg_value;
				value = get_uleb128(&ptr.p8, end);
				reg_value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_register value %ld to reg_info idx %ld (reg_value %ld to reg_info idx %ld)\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)), reg_value, COMPAT_REG_MAP(DWARF_REG_MAP(reg_value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
					reg_value = DWARF_REG_MAP(reg_value);
				} else {
					dbug_unwind(1, "map DW_CFA_register value %ld to reg_info idx %ld (reg_value %ld to reg_info idx %ld)\n",
						    value, DWARF_REG_MAP(value), reg_value, DWARF_REG_MAP(reg_value));
					value = DWARF_REG_MAP(value);
					reg_value = DWARF_REG_MAP(reg_value);
				}
				set_register_rule(value, reg_value, state);
				break;
			}
			case DW_CFA_expression:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_expression value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_expression value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_expr_rule(value, Expr, &ptr.p8, end, state);
				break;
			case DW_CFA_val_expression:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_val_expression value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_val_expression value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_expr_rule(value, ValExpr, &ptr.p8, end,
					      state);
				break;
			case DW_CFA_remember_state:
				state->stackDepth++;
				if (state->stackDepth >= STP_MAX_STACK_DEPTH) {
					_stp_warn("Too many stacked DW_CFA_remember_state\n");
					return 0;
				}
				memcpy(&REG_STATE,
				       &state->reg[state->stackDepth - 1],
				       sizeof (REG_STATE));
				dbug_unwind(1, "DW_CFA_remember_state (stackDepth=%d)\n", state->stackDepth);
				break;
			case DW_CFA_restore_state:
				if (state->stackDepth == 0) {
					_stp_warn("Unbalanced DW_CFA_restore_state\n");
					return 0;
				}
				state->stackDepth--;
				dbug_unwind(1, "DW_CFA_restore_state (stackDepth=%d)\n", state->stackDepth);
				break;
			case DW_CFA_def_cfa:
				value = get_uleb128(&ptr.p8, end);
				REG_STATE.cfa_is_expr = 0;
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_def_cfa value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					REG_STATE.cfa.reg = COMPAT_REG_MAP(value);
					dbug_unwind(1, "DW_CFA_def_cfa reg=%ld\n", COMPAT_REG_MAP(REG_STATE.cfa.reg));
				} else {
					dbug_unwind(1, "map DW_CFA_def_cfa value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					REG_STATE.cfa.reg = value;
					dbug_unwind(1, "DW_CFA_def_cfa reg=%ld\n", REG_STATE.cfa.reg);
				}
				/*nobreak */
			case DW_CFA_def_cfa_offset:
				if (REG_STATE.cfa_is_expr != 0) {
					_stp_warn("Unexpected DW_CFA_def_cfa_offset\n");
				} else {
					/* non-factored uleb128 */
					REG_STATE.cfa.off = get_uleb128(&ptr.p8, end);
					dbug_unwind(1, "DW_CFA_def_cfa_offset offs=%lx\n", REG_STATE.cfa.off);
				}
				break;
			case DW_CFA_def_cfa_sf:
				value = get_uleb128(&ptr.p8, end);
				REG_STATE.cfa_is_expr = 0;
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_def_cfa_sf value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					REG_STATE.cfa.reg = COMPAT_REG_MAP(value);
				} else {
					dbug_unwind(1, "map DW_CFA_def_cfa_sf value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					REG_STATE.cfa.reg = value;
				}
				/*nobreak */
			case DW_CFA_def_cfa_offset_sf:
				if (REG_STATE.cfa_is_expr != 0) {
					_stp_warn("Unexpected DW_CFA_def_cfa_offset_sf\n");
				} else {
					/* factored sleb128 */
					REG_STATE.cfa.off = get_sleb128(&ptr.p8, end) * state->dataAlign;
					dbug_unwind(1, "DW_CFA_def_cfa_offset_sf offs=%lx\n", REG_STATE.cfa.off);
				}
				break;
			case DW_CFA_def_cfa_register:
				if (REG_STATE.cfa_is_expr != 0) {
					_stp_warn("Unexpected DW_CFA_def_cfa_register\n");
				} else {
					value = get_uleb128(&ptr.p8, end);
					if (compat_task) {
						dbug_unwind(1, "map DW_CFA_def_cfa_register value %ld to reg_info idx %ld (%ld)\n",
							    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)), DWARF_REG_MAP(value));
						REG_STATE.cfa.reg = COMPAT_REG_MAP(value);
					} else {
						dbug_unwind(1, "map DW_CFA_def_cfa_register value %ld to reg_info idx %ld (%ld)\n",
							    value, DWARF_REG_MAP(value), DWARF_REG_MAP(value));
						REG_STATE.cfa.reg = value;
					}
				}
				break;
			case DW_CFA_def_cfa_expression: {
				const u8 *cfa_expr = ptr.p8;
				value = get_uleb128(&ptr.p8, end);
				/* Sanity check that cfa_expr falls completely
				   inside known data. */
				if (ptr.p8 < end && end - ptr.p8 >= value) {
					REG_STATE.cfa_is_expr = 1;
					REG_STATE.cfa_expr = cfa_expr;
					ptr.p8 += value;
					dbug_unwind(1, "DW_CFA_def_cfa_expression %lu@%p\n", value, cfa_expr);
				}
				else
					_stp_warn("BAD DW_CFA_def_cfa_expression value %lu\n", value);
				break;
			}
			/* Size of all arguments pushed on the stack. */
			case DW_CFA_GNU_args_size:
				get_uleb128(&ptr.p8, end);
				dbug_unwind(1, "DW_CFA_GNU_args_size\n");
				break;
			/* This is only produced by GCC before 2002.
			   Like DW_CFA_offset_extended_sf but using an
			   uleb128 that is subtracted from CFA.  */
			case DW_CFA_GNU_negative_offset_extended:
				value = get_uleb128(&ptr.p8, end);
				if (compat_task) {
					dbug_unwind(1, "map DW_CFA_GNU_negative_offset_extended value %ld to reg_info idx %ld\n",
						    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
					value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
				} else {
					dbug_unwind(1, "map DW_CFA_GNU_negative_offset_extended value %ld to reg_info idx %ld\n",
						    value, DWARF_REG_MAP(value));
					value = DWARF_REG_MAP(value);
				}
				set_offset_rule(value, Memory,
						(uleb128_t)0 - get_uleb128(&ptr.p8, end), state);
				break;
			case DW_CFA_GNU_window_save:
			default:
				_stp_warn("unimplemented call frame instruction: 0x%x\n", *(ptr.p8 - 1));
				result = 0;
				break;
			}
			break;
		case 1:
			result = advance_loc(*ptr.p8++ & 0x3f, state);
			dbug_unwind(1, "DW_CFA_advance_loc\n");
			break;
		case 2:
			value = *ptr.p8++ & 0x3f;
			if (compat_task) {
				dbug_unwind(1, "map DW_CFA_offset value %ld to reg_info idx %ld\n",
					    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
				value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
			} else {
				dbug_unwind(1, "map DW_CFA_offset value %ld to reg_info idx %ld\n",
					    value, DWARF_REG_MAP(value));
				value = DWARF_REG_MAP(value);
			}
			value2 = get_uleb128(&ptr.p8, end);
			set_offset_rule(value, Memory,
					value2 * state->dataAlign, state);
			break;
		case 3:
			value = *ptr.p8++ & 0x3f;
			if (compat_task) {
				dbug_unwind(1, "map DW_CFA_restore value %ld to reg_info idx %ld\n",
					    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
				value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
			} else {
				dbug_unwind(1, "map DW_CFA_restore value %ld to reg_info idx %ld\n",
					    value, DWARF_REG_MAP(value));
				value = DWARF_REG_MAP(value);
			}
			if (value < ARRAY_SIZE(REG_STATE.regs))
				memcpy(&REG_STATE.regs[value], &state->cie_regs[value], sizeof(struct unwind_item));
			break;
		}
		dbug_unwind(1, "targetLoc=%lx state->loc=%lx\n", targetLoc, state->loc);
		dbug_unwind(1, "result: %d\n", result);
		if (ptr.p8 > end)
			result = 0;
		if (result && targetLoc != 0 && targetLoc < state->loc)
			return 1;
	}
	return result && ptr.p8 == end;
}

#ifdef DEBUG_UNWIND
static const char *_stp_enc_hi_name[] = {
	"DW_EH_PE",
	"DW_EH_PE_pcrel",
	"DW_EH_PE_textrel",
	"DW_EH_PE_datarel",
	"DW_EH_PE_funcrel",
	"DW_EH_PE_aligned"
};
static const char *_stp_enc_lo_name[] = {
	"_absptr",
	"_uleb128",
	"_udata2",
	"_udata4",
	"_udata8",
	"_sleb128",
	"_sdata2",
	"_sdata4",
	"_sdata8"
};
static char *_stp_eh_enc_name(signed type)
{
	static char buf[64];
	int hi, low;
	if (type == DW_EH_PE_omit)
		return "DW_EH_PE_omit";

	hi = (type & DW_EH_PE_ADJUST) >> 4;
	low = type & DW_EH_PE_FORM;
	if (hi > 5 || low > 4 || (low == 0 && (type & DW_EH_PE_signed))) {
	    snprintf(buf, sizeof(buf), "ERROR:encoding=0x%x", type);
		return buf;
	}

	buf[0] = 0;
	if (type & DW_EH_PE_indirect)
		strlcpy(buf, "DW_EH_PE_indirect|", sizeof(buf));
	strlcat(buf, _stp_enc_hi_name[hi], sizeof(buf));

	if (type & DW_EH_PE_signed)
		low += 4;
	strlcat(buf, _stp_enc_lo_name[low], sizeof(buf));
	return buf;
}
#endif /* DEBUG_UNWIND */

// If this is an address inside a module, adjust for section relocation
// and the elfutils base relocation done during loading of the .dwarf_frame
// in translate.cxx.
static unsigned long
adjust_start_loc(unsigned long start_loc,
		 struct _stp_module *m, unsigned ptr_type, int is_ehframe,
		 int user, struct kunwind_stp_module *kunw_mod)
{
	unsigned long new_start_loc = start_loc;
	unsigned long temp = start_loc;

	/* XXX - some, or all, of this should really be done by
	 _stp_module_relocate and/or read_pointer. */
	dbug_unwind(2, "adjust_start_loc parameters: start_loc=%lx ptr_type=%s file=%pD1 dynamic=%d is_ehframe=%d\n",
			start_loc, _stp_eh_enc_name(ptr_type),
			kunw_mod->elf_vma->vm_file, m->is_dynamic, is_ehframe);

	if (start_loc == 0 || !is_ehframe) {
		new_start_loc = 0;
		goto out;
	}

	/*
	 * eh_frame data has been loaded in the kernel.
	 * Adjust the offset in the case start_loc is pcrel
	 */
	dbug_unwind(2, "eh_frame=%lx, eh_frame_offset=%lx\n",
			(unsigned long) m->ehf.kbuf, m->ehf.offset);
	if ((ptr_type & DW_EH_PE_ADJUST) == DW_EH_PE_pcrel) {
		temp = new_start_loc - (unsigned long) m->ehf.kbuf + m->ehf.offset;
		dbug_unwind(2, "DW_EH_PE_pcrel  %lx -> %lx\n", new_start_loc, temp);
		new_start_loc = temp;
	}

	if (m->is_dynamic) {
		temp = new_start_loc + kunw_mod->elf_vma->vm_start;
		dbug_unwind(2, "is_dynamic  %lx -> %lx\n", new_start_loc, temp);
		new_start_loc = temp;
	}
out:
	dbug_unwind(1, "adjust_start_loc: %lx -> %lx\n", start_loc, new_start_loc);
	return new_start_loc;
}

/* If we previously created an unwind header, then use it now to binary search */
/* for the FDE corresponding to pc. */
static u32 *_stp_search_fde(unsigned long pc, struct _stp_module *m,
			    int is_ehframe, int user, int compat_task,
			    struct kunwind_stp_module *kunw_mod)
{
	const u8 *ptr, *end, *hdr = m->ehf_hdr.kbuf;
	uint32_t hdr_len = m->ehf_hdr.size;
	unsigned long start_loc, start_loc_adj;
	u32 *fde = NULL;
	unsigned num, table_size;
	unsigned long eh_hdr_addr = m->ehf_hdr.offset;

	if (hdr == NULL || hdr_len < 4 || hdr[0] != 1) {
		_stp_warn("no or bad debug frame hdr\n");
		return NULL;
	}

	dbug_unwind(1, "binary search for %lx\n", pc);

	/* table_enc */
	switch (hdr[3] & DW_EH_PE_FORM) {
	case DW_EH_PE_absptr:
		if (!compat_task)
			table_size = sizeof(unsigned long);
		else
			table_size = sizeof(unsigned int);
		break;
	case DW_EH_PE_data2:
		table_size = 2;
		break;
	case DW_EH_PE_data4:
		table_size = 4;
		break;
	case DW_EH_PE_data8:
		table_size = 8;
		break;
	default:
		_stp_warn("bad unwind table encoding");
		return NULL;
	}
	ptr = hdr + 4;
	end = hdr + hdr_len;
	{
		// XXX Can the header validity be checked just once?
		unsigned long eh = read_ptr_sect(&ptr, end, hdr[1], 0,
						 eh_hdr_addr, user, compat_task, table_size);
		if ((hdr[1] & DW_EH_PE_ADJUST) == DW_EH_PE_pcrel)
			eh = eh - (unsigned long)hdr + eh_hdr_addr;
		if ((is_ehframe && eh != (unsigned long)m->ehf.offset)) {
			_stp_warn("eh_frame_ptr in eh_frame_hdr 0x%lx not valid; eh_frame_offset = 0x%lx", eh, (unsigned long)m->ehf.offset);
			return NULL;
		}
	}
	num = read_ptr_sect(&ptr, end, hdr[2], 0, eh_hdr_addr, user, compat_task, table_size);
	if (num == 0 || num != (end - ptr) / (2 * table_size)
	    || (end - ptr) % (2 * table_size)) {
		_stp_warn("unwind Bad num=%d end-ptr=%ld 2*tableSize=%d",
			    num, (long)(end - ptr), 2 * table_size);
		return NULL;
	}

	do {
		const u8 *cur = ptr + (num / 2) * (2 * table_size);
		start_loc = read_ptr_sect(&cur, cur + table_size, hdr[3], 0,
					 eh_hdr_addr, user, compat_task, table_size);
		start_loc_adj = adjust_start_loc(start_loc, m, hdr[3],
					  is_ehframe, user, kunw_mod);
		if (!start_loc_adj) {
			_stp_warn("error: bad adjusted_start_loc %lx -> %lx\n", start_loc, start_loc_adj);
			return NULL;
		}
		start_loc = start_loc_adj;
		if (pc < start_loc)
			num /= 2;
		else {
			ptr = cur - table_size;
			num = (num + 1) / 2;
		}
	} while (start_loc && num > 1);

	if (num == 1
	    && (start_loc = adjust_start_loc(read_ptr_sect(&ptr, ptr + table_size, hdr[3], 0,
							eh_hdr_addr, user, compat_task, table_size),
					  m, hdr[3], is_ehframe, user, kunw_mod)) != 0 && pc >= start_loc) {
		unsigned long off;
		off = read_ptr_sect(&ptr, ptr + table_size, hdr[3],
				    0, eh_hdr_addr, user, compat_task, table_size);
		dbug_unwind(1, "fde off=%lx\n", off);
		/* For real eh_frame_hdr the actual fde address is at the
		   new eh_frame load address. For our own debug_hdr created
		   table the fde is an offset into the debug_frame table. */
		if (is_ehframe)
			fde = (u32 *) (off - m->ehf.offset + m->ehf.kbuf);
		else
			fde = (u32 *) (m->ehf.kbuf + off);
	}

	dbug_unwind(1, "returning fde=%p start_loc=%lx\n", fde, start_loc);
	return fde;
}

/*
TODO refactoring
static u32 *_stp_search_cie(void)
{
	return NULL;
}
*/

#define FRAME_REG(r, t) (((t *)frame)[reg_info[r].offs])

#ifndef CONFIG_64BIT
# define CASES CASE(8); CASE(16); CASE(32)
#else
# define CASES CASE(8); CASE(16); CASE(32); CASE(64)
#endif

#define MAX_EXPR_STACK	8	/* arbitrary */

static int compute_expr(const u8 *expr, struct unwind_frame_info *frame,
			unsigned long *result, int user, int compat_task)
{
	/*
	 * We previously validated the length, so we won't read off the end.
	 * See sanity checks in set_expr() and for DW_CFA_def_cfa_expression.
	 */
	uleb128_t len = get_uleb128(&expr, (const u8 *) -1UL);
	const u8 *const start = expr;
	const u8 *const end = expr + len;

	long stack[MAX_EXPR_STACK]; /* stack slots are signed */
	unsigned int sp = 0;
#define PUSH(val) do { \
		if (sp == MAX_EXPR_STACK) \
			goto overflow; \
		stack[sp++] = (val); \
	} while (0)
#define POP ({ \
		if (sp == 0) \
			goto underflow; \
		stack[--sp]; \
	})
#define NEED(n)	do { \
		if (end - expr < (n)) \
			goto truncated; \
	} while (0)

	while (expr < end) {
		uleb128_t value;
		union {
			u8 u8;
			s8 s8;
			u16 u16;
			s16 s16;
			u32 u32;
			s32 s32;
			u64 u64;
			s64 s64;
		} u;
		const u8 op = *expr++;
		dbug_unwind(3, " expr op 0x%x (%ld left)\n", op, (long)(end - expr));
		switch (op) {
		case DW_OP_nop:
			break;

		case DW_OP_bra:
			if (POP == 0)
				break;
			/* Fall through.  */
		case DW_OP_skip:
			NEED(sizeof(u.s16));
			memcpy(&u.s16, expr, sizeof(u.s16));
			expr += sizeof(u.s16);
			if (u.s16 < 0 ?
			    unlikely(expr - start < -u.s16) :
			    unlikely(end - expr < u.s16)) {
				_stp_warn("invalid skip %d in CFI expression\n", (int) u.s16);
				return 1;
			}
			/*
			 * A backward branch could lead to an infinite loop.
			 * So punt it until we find we actually need it.
			 */
			if (u.s16 < 0) {
				_stp_warn("backward branch in CFI expression not supported\n");
				return 1;
			}
			expr += u.s16;
			break;

		case DW_OP_dup:
			value = POP;
			PUSH(value);
			PUSH(value);
			break;
		case DW_OP_drop:
			POP;
			break;
		case DW_OP_swap: {
			unsigned long tos = POP;
			unsigned long nos = POP;
			PUSH(tos);
			PUSH(nos);
			break;
		};

		case DW_OP_over:
			value = 1;
			goto pick;
		case DW_OP_pick:
			NEED(1);
			value = *expr++;
		pick:
			if (value >= sp)
				goto underflow;
			value = stack[sp - value];
			PUSH(value);
			break;

#define CONSTANT(type) \
			NEED(sizeof(u.type)); \
			memcpy(&u.type, expr, sizeof(u.type)); \
			expr += sizeof(u.type); \
			value = u.type; \
			PUSH(value); \
			break

		case DW_OP_addr:
			if (sizeof(unsigned long) == 8) { /* XXX 32/64!! */
				CONSTANT(u64);
			} else {
				CONSTANT(u32);
			}
			break;

		case DW_OP_const1u: CONSTANT(u8);
		case DW_OP_const1s: CONSTANT(s8);
		case DW_OP_const2u: CONSTANT(u16);
		case DW_OP_const2s: CONSTANT(s16);
		case DW_OP_const4u: CONSTANT(u32);
		case DW_OP_const4s: CONSTANT(s32);
		case DW_OP_const8u: CONSTANT(u64);
		case DW_OP_const8s: CONSTANT(s64);

#undef	CONSTANT

		case DW_OP_constu:
			value = get_uleb128(&expr, end);
			PUSH(value);
			break;
		case DW_OP_consts:
			value = get_sleb128(&expr, end);
			PUSH(value);
			break;

		case DW_OP_lit0 ... DW_OP_lit31:
			PUSH(op - DW_OP_lit0);
			break;

		case DW_OP_plus_uconst:
			value = get_uleb128(&expr, end);
			PUSH(value + POP);
			break;

#define BINOP(name, operator)				\
			case DW_OP_##name: {		\
				long b = POP;		\
				long a = POP;		\
				PUSH(a operator b);	\
			} break

			BINOP(eq, ==);
			BINOP(ne, !=);
			BINOP(ge, >=);
			BINOP(gt, >);
			BINOP(le, <=);
			BINOP(lt, <);

			BINOP(and, &);
			BINOP(or, |);
			BINOP(xor, ^);
			BINOP(plus, +);
			BINOP(minus, -);
			BINOP(mul, *);
			BINOP(shl, <<);
			BINOP(shra, >>);
#undef	BINOP

		case DW_OP_mod: {
			unsigned long b = POP;
			unsigned long a = POP;
			if (b == 0)
				goto divzero;
			PUSH (a % b);
			break;
		}

		case DW_OP_div: {
			long b = POP;
			long a = POP;
			if (b == 0)
				goto divzero;
			PUSH (a / b);
			break;
		}

		case DW_OP_shr: {
			unsigned long b = POP;
			unsigned long a = POP;
			PUSH (a >> b);
			break;
		}

		case DW_OP_not:
			PUSH(~ POP);
			break;
		case DW_OP_neg:
			PUSH(- POP);
			break;
		case DW_OP_abs:
			value = POP;
			value = abs(value);
			PUSH(value);
			break;

		case DW_OP_bregx:
			value = get_uleb128(&expr, end);
			goto breg;
		case DW_OP_breg0 ... DW_OP_breg31:
			value = op - DW_OP_breg0;
		breg:
			if (compat_task) {
				dbug_unwind(1, "map DW_OP_breg value %ld to reg_info idx %ld\n",
					    value, COMPAT_REG_MAP(DWARF_REG_MAP(value)));
				value = COMPAT_REG_MAP(DWARF_REG_MAP(value));
			} else {
				dbug_unwind(1, "map DW_OP_breg value %ld to reg_info idx %ld\n",
					    value, DWARF_REG_MAP(value));
				value = DWARF_REG_MAP(value);
			}
			if (unlikely(value >= ARRAY_SIZE(reg_info))) {
				_stp_warn("invalid register number %lu in CFI expression\n", value);
				return 1;
			} else {
				sleb128_t offset = get_sleb128(&expr, end);
				value = FRAME_REG(value, unsigned long);
				PUSH(value + offset);
			}
			break;

		case DW_OP_deref:
			value = sizeof(long); /* XXX 32/64!! */
			goto deref;
		case DW_OP_deref_size:
			NEED(1);
			value = *expr++;
			if (unlikely(value > sizeof(stack[0]))) {
			bad_deref_size:
				_stp_warn("invalid DW_OP_deref_size %lu in CFI expression\n", value);
				return 1;
			}
		deref: {
				unsigned long addr = POP;
				switch (value) {
#define CASE(n)     		case sizeof(u##n):			\
					if (unlikely(_stp_read_address(value, (u##n *)addr, \
						                       (user ? USER_DS : KERNEL_DS)))) \
						goto copy_failed;	\
					break
					CASES;
#undef CASE
				default:
					goto bad_deref_size;
				}
			}
			break;

		case DW_OP_rot:
		default:
			_stp_warn("unimplemented CFI expression operation: 0x%x\n", op);
			return 1;
		}
	}

	*result = POP;
	return 0;

copy_failed:
	_stp_warn("_stp_read_address failed to access memory for deref\n");
	return 1;
truncated:
	_stp_warn("invalid (truncated) DWARF expression in CFI\n");
	return 1;
overflow:
	_stp_warn("DWARF expression stack overflow in CFI\n");
	return 1;
underflow:
	_stp_warn("DWARF expression stack underflow in CFI\n");
	return 1;
divzero:
	_stp_warn("DWARF expression stack divide by zero in CFI\n");
	return 1;

#undef	NEED
#undef	PUSH
#undef	POP
}


/*
struct cfi {
	u32 *addr;
	u8 *inst;
	u8 *end;
};

struct ctx {
	u32 *fde;
	u32 *cie;
};
*/

static void (*show_regs_fn)(struct pt_regs *, int all) = NULL;
void dump_context(struct unwind_context *ctx)
{
	struct unwind_frame_info *info = &ctx->info;
	struct unwind_state *state = &ctx->state;
	(void) state;

	if (!show_regs_fn)
		show_regs_fn = (void *) kallsyms_lookup_name("__show_regs");
	if (show_regs_fn)
		show_regs_fn(&info->regs, 0);
}

/*
 * Unwind to previous frame.  Returns 0 if successful, negative
 * number in case of an error.  A positive return means unwinding is finished;
 * don't try to fallback to dumping addresses on the stack.
 */
static int
__unwind_frame(struct unwind_context *context,
	       struct kunwind_stp_module *kunw_mod,
	       int compat_task)
{
	struct _stp_module *m;

	void *table;
	uint32_t table_len;
	const int user = 1;
	const int is_ehframe = 1;

	const u32 *fde = NULL, *cie = NULL;
	/* The start and end of the CIE CFI instructions. */
	const u8 *cieStart = NULL, *cieEnd = NULL;
	/* The start and end of the FDE CFI instructions. */
	const u8 *fdeStart = NULL, *fdeEnd = NULL;
	struct unwind_frame_info *frame = &context->info;
	unsigned long pc = UNW_PC(frame) - frame->call_frame;
	unsigned long startLoc = 0, endLoc = 0, locRange = 0, cfa;
	unsigned i;
	signed ptrType = -1, call_frame = 1;
	uleb128_t retAddrReg = 0;
	struct unwind_state *state = &context->state;
	unsigned long addr;
	unsigned long frame_size;
	int ret;

	m = &kunw_mod->stp_mod;
	table = m->ehf.kbuf;
	table_len = m->ehf.size;

	if (unlikely(table_len == 0)) {
		// Don't _stp_warn about this, debug_frame and/or eh_frame
		// might actually not be there.
		dbug_unwind(1, "file %pD1: no unwind frame data\n", kunw_mod->elf_vma->vm_file);
		goto err;
	}
	if (unlikely(table_len & (sizeof(*fde) - 1))) {
		_stp_warn("file %pD1: frame_len=%d", kunw_mod->elf_vma->vm_file, table_len);
		goto err;
	}

	/* Sets all rules to default Same value. */
	memset(state, 0, sizeof(*state));

	/* All "fake" dwarf registers should start out Nowhere. */
	for (i = UNW_NR_REAL_REGS; i < ARRAY_SIZE(REG_STATE.regs); ++i)
		set_no_state_rule(i, Nowhere, state);

	/* DEBUG */
	printk("UNWIND step 1\n");
	dump_context(context);

	fde = _stp_search_fde(pc, m, is_ehframe, user, compat_task, kunw_mod);
	dbug_unwind(1, "file %pD1: fde=%lx\n", kunw_mod->elf_vma->vm_file, (unsigned long) fde);

	/* found the fde, now set startLoc and endLoc */
	if (fde != NULL && is_fde(fde, table, table_len, is_ehframe)) {
		cie = cie_for_fde(fde, table, table_len, is_ehframe);
		dbug_unwind(1, "%pD1: cie=%lx\n", kunw_mod->elf_vma->vm_file, (unsigned long) cie);
		if (unlikely(cie == NULL)) {
			_stp_warn("fde found in header, but cie is bad!\n");
			fde = NULL;
		}

		ret = parse_fde_cie(fde, cie, table, table_len, &ptrType, user,
				&startLoc, &locRange, &fdeStart, &fdeEnd,
				&cieStart, &cieEnd, &state->codeAlign,
				&state->dataAlign, &retAddrReg, &call_frame,
				compat_task);
		if (ret < 0) {
			_stp_warn("error: parse_fde_cie returned %d\n", ret);
			goto err;
		}
		startLoc = adjust_start_loc(startLoc, m, ptrType, is_ehframe, user, kunw_mod);
		if (!startLoc) {
			_stp_warn("error: bad adjust_start_loc: %lx", startLoc);
			goto err;
		}
		endLoc = startLoc + locRange;
		dbug_unwind(1, "startLoc: %lx, endLoc: %lx\n", startLoc, endLoc);
		if (pc > endLoc) {
			dbug_unwind(1, "pc (%lx) > endLoc(%lx)\n", pc, endLoc);
			goto done;
		}
	}

	dbug_unwind(1, "cie=%lx fde=%lx startLoc=%lx endLoc=%lx, pc=%lx\n",
                    (unsigned long) cie, (unsigned long)fde, (unsigned long) startLoc, (unsigned long) endLoc, pc);
	if (cie == NULL || fde == NULL)
		goto err;

	/* found the CIE and FDE */

	// Sanity check return address register value.
	if (retAddrReg >= ARRAY_SIZE(reg_info)
	    || REG_INVALID(retAddrReg)
	    || reg_info[retAddrReg].width != sizeof(unsigned long)) {
		_stp_warn("Bad retAddrReg value\n");
		goto err;
	}

	frame->call_frame = call_frame;
	state->stackDepth = 0;
	state->loc = startLoc;
	memcpy(&REG_STATE.cfa, &badCFA, sizeof(REG_STATE.cfa));

	/* Common Information Entry (CIE) instructions. */
	dbug_unwind (1, "processCFI for CIE\n");
	if (!run_cfi_program(cieStart, cieEnd, 0, ptrType, user, state, compat_task))
		goto err;

	/* Store initial state registers for use with DW_CFA_restore... */
	memcpy(&state->cie_regs, &REG_STATE.regs, sizeof (REG_STATE.regs));

	/* Process Frame Description Entry (FDE) instructions. */
	dbug_unwind (1, "processCFI for FDE\n");
	if (!run_cfi_program(fdeStart, fdeEnd, pc, ptrType, user, state, compat_task)
	    || state->loc > endLoc)
		goto err;
	if (REG_STATE.regs[retAddrReg].where == Nowhere)
		goto bottom;

	/* DEBUG */
	printk("UNWIND step 2\n");
	dump_context(context);

	/* update frame */
	if (REG_STATE.cfa_is_expr) {
		if (compute_expr(REG_STATE.cfa_expr, frame, &cfa, user, compat_task))
			goto err;
	}
	else {
		// We expect the offset to be a multiple of the address size
		if(REG_STATE.cfa.reg >= ARRAY_SIZE(reg_info)
		   || reg_info[REG_STATE.cfa.reg].width != sizeof(unsigned long)
		   || REG_STATE.cfa.off % (sizeof(unsigned long)/2))
			goto err;

		dbug_unwind(1, "cfa reg=%ld, off=%lx\n",
			    REG_STATE.cfa.reg, REG_STATE.cfa.off);
		cfa = FRAME_REG(REG_STATE.cfa.reg, unsigned long) + REG_STATE.cfa.off;
	}

	/* DEBUG */
	printk("UNWIND step 3\n");
	dump_context(context);

	/* Here, the CFA value is known */
	frame_size = abs(cfa - UNW_SP(frame));
	dbug_unwind(1, "recovered cfa=%lx, rsp=%lx (frame size=%lu)\n", cfa, UNW_SP(frame), frame_size);

	dbug_unwind(1, "check RSP invalid=%d UNW_RSP=%lu RSP=%llu where=%d\n",
			REG_INVALID(RSP),
			UNW_SP(frame),
			FRAME_REG(RSP, const u64),
			REG_STATE.regs[RSP].where);

	for (i = 0; i < ARRAY_SIZE(REG_STATE.regs); ++i) {
		if (REG_INVALID(i)) {
			if (REG_STATE.regs[i].where == Nowhere)
				continue;
			_stp_warn("REG_INVALID %d\n", i);
			goto err;
		}
		dbug_unwind(2, "register %d. where=%d\n", i, REG_STATE.regs[i].where);
		switch (REG_STATE.regs[i].where) {
		default:
			break;
		case Register:
			if (REG_STATE.regs[i].state.reg >= ARRAY_SIZE(reg_info)
			    || REG_INVALID(REG_STATE.regs[i].state.reg)
			    || reg_info[i].width > reg_info[REG_STATE.regs[i].state.reg].width) {
				_stp_warn("case Register bad\n");
				goto err;
			}
			switch (reg_info[REG_STATE.regs[i].state.reg].width) {
#define CASE(n) \
			case sizeof(u##n): \
				REG_STATE.regs[i].state.reg = FRAME_REG(REG_STATE.regs[i].state.reg, \
				                                const u##n); \
				break
				CASES;
#undef CASE
			default:
				_stp_warn("bad Register size\n");
				goto err;
			}
			break;
		}
	}
	for (i = 0; i < ARRAY_SIZE(REG_STATE.regs); ++i) {
		dbug_unwind(2, "register %d. invalid=%d\n", i, REG_INVALID(i));
		if (REG_INVALID(i))
			continue;
		dbug_unwind(2, "register %d. where=%d\n", i, REG_STATE.regs[i].where);

#if (UNW_SP_FROM_CFA == 1)
		if (i == UNW_SP_IDX) {
			UNW_SP(frame) = cfa;
			continue;
		}
#endif

#if (UNW_PC_FROM_RA == 1)
		if (i == UNW_PC_IDX) {
			UNW_PC(frame) = FRAME_REG(retAddrReg, unsigned long);
			continue;
		}
#endif

		switch (REG_STATE.regs[i].where) {
		case Same:
			/* Preserve register from current frame. */
			break;
		case Nowhere:
			switch (reg_info[i].width) {
#define CASE(n) case sizeof(u##n): \
				FRAME_REG(i, u##n) = 0; \
				break
				CASES;
#undef CASE
			default:
				_stp_warn("bad Register size (Nowhere)\n");
				goto err;
			}
			break;
		case Register:
			switch (reg_info[i].width) {
#define CASE(n) case sizeof(u##n): \
				FRAME_REG(i, u##n) = REG_STATE.regs[i].state.reg; \
				break
				CASES;
#undef CASE
			default:
				_stp_warn("bad Register size (Register)\n");
				goto err;
			}
			break;
		case Expr:
			if (compute_expr(REG_STATE.regs[i].state.expr, frame, &addr, user, compat_task))
				goto err;
			goto memory;
		case ValExpr:
			if (compute_expr(REG_STATE.regs[i].state.expr, frame, &addr, user, compat_task))
				goto err;
			goto value;
		case Value:
			addr = cfa + REG_STATE.regs[i].state.off;
		value:
			if (reg_info[i].width != sizeof(unsigned long)) {
				_stp_warn("bad Register width for value state\n");
				goto err;
			}
			FRAME_REG(i, unsigned long) = addr;
			break;
		case Memory:
			addr = cfa + REG_STATE.regs[i].state.off;
		memory:
			dbug_unwind(2, "addr=%lx width=%d\n", addr, reg_info[i].width);
			/* We only want the lower half of the address defined, however
			   _stp_read_address will sometimes return garbage in the top half.
			   for 32-on-64 bit unwinding we need to ensure this is 0xFFFFFFFF */
			switch (reg_info[i].width) {
#define CASE(n)     case sizeof(u##n):					\
				if (unlikely(_stp_read_address(FRAME_REG(i, u##n), (u##n *)addr, \
							       (user ? USER_DS : KERNEL_DS)))) \
					goto copy_failed;		\
				if (compat_task) FRAME_REG(i, u##n) &= 0xFFFFFFFF; \
				dbug_unwind(1, "set register %d to %lx\n", i, (long)FRAME_REG(i,u##n)); \
				break
				CASES;
#undef CASE
			default:
				_stp_warn("bad Register width\n");
				goto err;
			}
			break;
		}
	}

	/* DEBUG */
	printk("UNWIND step 4\n");
	dump_context(context);

	dbug_unwind(1, "returning 0 (%llx)\n",
		    (unsigned long long) UNW_PC(frame));
	return 0;

copy_failed:
	_stp_warn("_stp_read_address failed to access memory location\n");
err:
	return -EIO;

done:
	/* PC was in a range convered by a module but no unwind info */
	/* found for the specific PC. This seems to happen only for kretprobe */
	/* trampolines and at the end of interrupt backtraces. */
	return 1;
bottom:
	/* It seems that an undefined returned address register means
	 * that we have reached the end of the stack. */
	return 2;
#undef CASES
#undef FRAME_REG
}

//int is_standard_frame(struct unwind_reg_state *rs)
//{
//	return ((rs->regs[DWARF_CFA_REG_COLUMN].where == Register)
//		&& (rs->regs[DWARF_CFA_REG_COLUMN].state.reg == RBP
//			|| rs->regs[DWARF_CFA_REG_COLUMN].val == RSP)
//		&& labs((long) rs->regs[DWARF_CFA_OFF_COLUMN].val) < (1 << 29)
//		&& DWARF_GET_LOC(d->loc[d->ret_addr_column]) == d->cfa-8
//		&& (rs->reg[RBP].where == DWARF_WHERE_UNDEF
//			|| rs->reg[RBP].where == DWARF_WHERE_SAME
//			|| (rs->reg[RBP].where == DWARF_WHERE_CFAREL
//				&& labs((long) rs->reg[RBP].val) < (1 << 14)
//				&& rs->reg[RBP].val+1 != 0))
//		&& (rs->reg[RSP].where == DWARF_WHERE_UNDEF
//			|| rs->reg[RSP].where == DWARF_WHERE_SAME
//			|| (rs->reg[RSP].where == DWARF_WHERE_CFAREL
//				&& labs((long) rs->reg[RSP].val) < (1 << 14)
//				&& rs->reg[RSP].val+1 != 0)));
//}

int unwind_frame(struct unwind_context *context, int user,
		 struct kunwind_proc_modules *proc)
{
	struct kunwind_stp_module *mod = NULL;
	struct unwind_frame_info *frame = &context->info;
	unsigned long pc = get_pc(frame);
        int res;

	/*
	 * compat_task is a flag for 32bit process unwinding on a 64-bit
	 * architecture.  If this flag is set, it means a mapping of
	 * register numbers is required, as well as being aware of 32-bit
	 * values on 64-bit registers.
	 */
	int compat_task = _stp_is_compat_task();

	dbug_unwind(1, "pc=%lx compat_task=%d\n", pc, compat_task);

	if (!pc || !user)
		return -EINVAL;

	mod = kunw_mod_lookup(pc, proc);

	if (mod == NULL)
		return -EINVAL;

	res = __unwind_frame(context, mod, compat_task);

	dbug_unwind (2, "unwind_frame returned: %d\n", res);
	return res;
}


int unwind_full(struct unwind_context *context,
		struct kunwind_proc_modules *proc,
		struct kunwind_backtrace *bt)
{
	int ret;
	unsigned long pc;

	if (!bt->entries || !bt->max_entries)
		return -EINVAL;

	bt->nr_entries = 0;

	while (bt->nr_entries < bt->max_entries) {
		pc = get_pc(&context->info);

		if (pc == 0)
			break;

		bt->entries[bt->nr_entries++] = pc;
		dbug_unwind(1, "nr_entries %u, ip %p\n", bt->nr_entries, (void *) pc);

		ret = unwind_frame(context, 1, proc);

		if (ret != 0)
			break;
	}

	/* The return code 2 indicates that the unwind is completed */
	if (ret == 2)
		ret = 0;
	return ret;
}
EXPORT_SYMBOL_GPL(unwind_full);

int eh_frame_from_hdr(void *base, unsigned long vma_start,
		unsigned long vma_end, int compat, struct section *ehf_hdr,
		struct section *ehf)
{
	unsigned long eh_addr, eh_off, eh_len, cie_fde_size = 0;
	const u8* pos;
	u8 *eh, *ptr, *prev_ptr;
	u8 *hdr = ehf_hdr->kbuf;
	unsigned long hdr_addr = ehf_hdr->offset;
	unsigned long hdr_len = ehf_hdr->size;

	// FIXME -1 tablesize might not be right in following call
	pos = hdr + 4;
	eh_addr = read_ptr_sect(&pos, hdr + hdr_len, hdr[1], vma_start, hdr_addr, 1, compat, -1);
	eh_off = eh_addr - (unsigned long)base;
	eh = (u8 *) eh_addr;
	dbug_unwind(3, "eh: 0x%lx\n", (unsigned long)eh);
	dbug_unwind(3, "offset: 0x%lx\n", eh_off);

	// Find eh_frame size
	ptr = prev_ptr = eh;
	do {
		cie_fde_size = *((u32 *) ptr);
		ptr += 4;
		if (cie_fde_size == 0xffffffff) {
			cie_fde_size = *((u64 *) ptr);
			ptr += 8;
		}
		ptr += cie_fde_size;
		eh_len = (unsigned long) ptr - (unsigned long) eh;
		if (eh_len + vma_start + hdr_addr > vma_end)
			return -EINVAL;
		if (prev_ptr >= ptr)
			return -EINVAL;
		prev_ptr = ptr;
	} while (cie_fde_size);

	ehf->kbuf = eh;
	ehf->offset = eh_off;
	ehf->size = eh_len;
	ehf->ubuf = ehf_hdr->ubuf - ehf_hdr->offset + ehf->offset; // FIXME: verify

	return 0;
}
