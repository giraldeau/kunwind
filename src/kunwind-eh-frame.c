/*
 * Copyright (C) 2009 Matt Fleming <matt@console-pimps.org>
 * Copyright (C) 2016 Jean-Alexandre Barszcz <jalex_b@hotmail.com>
 *
 * This file contains parts copied from the kernel source file
 * linux/arch/sh/kernel/dwarf.c originally written by Matt Fleming.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.
 *
 * This is an implementation of a DWARF (eh_frame) unwinder. Its main
 * purpose is for generating stacktrace information. Based on the
 * DWARF 4 specification from http://www.dwarfstd.org.
 *
 * TODO:
 *	- DWARF64 doesn't work.
 *	- Registers with DWARF_VAL_OFFSET rules aren't handled properly.
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <asm/unaligned.h>

#include "kunwind-eh-frame.h"
#include "kunwind-bug.h"

/**
 *	dwarf_read_uleb128 - read unsigned LEB128 data
 *	@addr: the address where the ULEB128 data is stored
 *	@ret: address to store the result
 *
 *	Decode an unsigned LEB128 encoded datum. The algorithm is
 *	taken from Appendix C of the DWARF 3 spec. For information on
 *	the encodings refer to section "7.6 - Variable Length
 *	Data". Return the number of bytes read on success or -EFAULT
 *	on error. On error *ret is left changed.
 *
 *	Calls get_user() to read data so the same context applies.
 *	Context: User context only. This function may sleep if
 *		pagefaults are enabled.
 */
static inline int dwarf_read_uleb128(char *addr, unsigned int *ret)
{
	unsigned int result;
	unsigned char byte;
	int shift, count;
	int err = 0;

	result = 0;
	shift = 0;
	count = 0;

	while (1) {
		err = get_user(byte, addr);
		if (err)
			return err;
		addr++;
		count++;

		result |= (byte & 0x7f) << shift;
		shift += 7;

		if (!(byte & 0x80))
			break;
	}

	*ret = result;

	return count;
}

/**
 *	dwarf_read_leb128 - read signed LEB128 data
 *	@addr: the address of the LEB128 encoded data
 *	@ret: address to store the result
 *
 *	Decode signed LEB128 data. The algorithm is taken from
 *	Appendix C of the DWARF 3 spec. Return the number of bytes
 *	read on success or -EFAULT on error. On error *ret is left
 *	unchanged.
 *
 *	Calls get_user() to read data so the same context applies.
 *	Context: User context only. This function may sleep if
 *		pagefaults are enabled.
 */
static inline int dwarf_read_leb128(char *addr, int *ret)
{
	unsigned char byte;
	int result, shift;
	int num_bits;
	int count;
	int err;

	result = 0;
	shift = 0;
	count = 0;

	while (1) {
		err = get_user(byte, addr);
		if (err)
			return err;
		addr++;
		result |= (byte & 0x7f) << shift;
		shift += 7;
		count++;

		if (!(byte & 0x80))
			break;
	}

	/* The number of bits in a signed integer. */
	num_bits = 8 * sizeof(result);

	if ((shift < num_bits) && (byte & 0x40))
		result |= (-1 << shift);

	*ret = result;

	return count;
}

/**
 *	dwarf_read_encoded_value - return the decoded value at @addr
 *	@addr: the address of the encoded value
 *	@base: base added to the decoded value
 *	@val: where to write the decoded value
 *	@encoding: the encoding with which we can decode @addr
 *
 *	GCC emits encoded address in the .eh_frame FDE entries. Decode
 *	the value at @addr using @encoding. The decoded value is
 *	written to @val and the number of bytes read is returned. In
 *	case of error, negative error code is returned. Addresses are
 *	unsigned, so the resulting value is unsigned, but the encoded
 *	value can be signed in case of relative addressing. Thus, the
 *	base must be given before decoding, perhaps with the help of
 *	DW_EH_PE_ADJUST(). The base might depend on the context
 *	anyway, so it has to be calculated by caller.
 */
static int dwarf_read_encoded_value(unsigned long addr,
				    unsigned long base,
				    unsigned long *val,
				    char encoding)
{
	unsigned long decoded = 0;
	int count = 0, err = 0;
	char issigned;

	if (DW_EH_PE_OMITTED(encoding))
		return -ENODATA;

	switch (DW_EH_PE_FORMAT(encoding)) {
	case DW_EH_PE_absptr:
		count = sizeof(unsigned long);
		err = get_user(decoded, (unsigned long *) addr);
		addr += count;
		break;
	case DW_EH_PE_sdata4:
	case DW_EH_PE_udata4:
		count = 4;
		err = get_user(decoded, (u32 *)addr);
		addr += count;
		break;
	default:
		KUNWIND_BUGM("encoding=0x%x\n", encoding);
	}
	if (err)
		return err;

	issigned = ((encoding & 0x08) != 0);

	if (issigned)
		// This cast might not be necessary, signed + unsigned
		// is tricky and might have som eimplementation
		// dependent elements
		*val = base + *((signed long *) &decoded);
	else
		*val = base + decoded;

	return count;
}

int parse_eh_frame_hdr_section(unsigned long eh_frame_start,
			       struct eh_frame_hdr * const dest)

{
	volatile //debug
		unsigned long addr = eh_frame_start;
	int ret = 0, err = 0;

	err |= get_user(dest->version, (char *) addr); ++addr;
	err |= get_user(dest->eh_frame_ptr_enc, (char *) addr); ++addr;
	err |= get_user(dest->fde_count_enc, (char *) addr); ++addr;
	err |= get_user(dest->table_enc, (char *) addr); ++addr;
	if (err) return err;

	if (dest->eh_frame_ptr_enc != DW_EH_PE_selfrel) {
		KUNWIND_BUGM("eh_frame_ptr_enc unexpected: %#04X",
			     dest->eh_frame_ptr_enc);
		return -EUNIMPL;
	}
	ret = dwarf_read_encoded_value(addr, addr,
				       &(dest->eh_frame_ptr),
				       dest->eh_frame_ptr_enc);
	if (ret < 0)
		return ret;
	else
		addr += ret;

	ret = dwarf_read_encoded_value(addr, 0, &(dest->fde_count),
				       dest->fde_count_enc);
	if (ret < 0)
		return ret;
	else
		addr += ret;

	dest->table = addr;
	return 0;
}
