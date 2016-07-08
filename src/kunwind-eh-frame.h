/*
 * Copyright (C) 2009 Matt Fleming <matt@console-pimps.org>
 * Copyright (C) 2016 Jean-Alexandre Barszcz <jalex_b@hotmail.com>
 *
 * This file contains parts copied from the kernel source file
 * linux/arch/sh/include/asm/dwarf.h originally written by Matt Fleming.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.
 *
 */


#ifndef KUNWIND_EH_FRAME_H_
#define KUNWIND_EH_FRAME_H_

/*
 * Addresses used in FDE entries in the .eh_frame section may be encoded
 * using one of the following encodings.
 */
#define DW_EH_PE_absptr	0x00
#define DW_EH_PE_uleb128	0x01
#define DW_EH_PE_udata2	0x02
#define DW_EH_PE_udata4	0x03
#define DW_EH_PE_udata8	0x04
#define DW_EH_PE_sleb128	0x09
#define DW_EH_PE_sdata2	0x0a
#define DW_EH_PE_sdata4	0x0b
#define DW_EH_PE_sdata8	0x0c

#define DW_EH_PE_pcrel	0x10
#define DW_EH_PE_textrel	0x20
#define DW_EH_PE_datarel	0x30
#define DW_EH_PE_funcrel	0x40
#define DW_EH_PE_aligned	0x50

#define DW_EH_PE_omit	0xff
#define DW_EH_PE_selfrel	0x1b // not in LSB or ABI, see
				     // http://www.hexblog.com/wp-content/uploads/2012/06/Recon-2012-Skochinsky-Compiler-Internals.pdf#42

#define DW_EH_PE_FORMAT(encoding)	((encoding) & 0x0f)
//#define DW_EH_PE_ADJUST(encoding)	((encoding) & 0x70)
#define DW_EH_PE_OMITTED(encoding)	((encoding)==DW_EH_PE_omit)


struct eh_frame_hdr {
	char version;
	char eh_frame_ptr_enc;
	char fde_count_enc;
	char table_enc;
	unsigned long eh_frame_ptr;
	unsigned long fde_count;
	unsigned long table;
};


#include <proc_info.h>

int parse_eh_frame_hdr_section(unsigned long eh_frame_start,
			       struct eh_frame_hdr * const dest);


#endif // KUNWIND_EH_FRAME_H_
