/* Debug and bug Macros
 * Copyright 2016 Jean-Alexandre Barszcz
 * Copyright (C) 2014 Red Hat Inc.
 *
 * This file is copied from systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */
#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <linux/bug.h>

#define KUNWIND_BUG()	BUG()

#define KUNWIND_BUGM(message, args...) ({		\
		printk(message, ##args);		\
		KUNWIND_BUG();				\
	})

#define EUNIMPL	1

#define _stp_warn(fmt, args...) printk(fmt "\n", ##args);

#define _stp_dbug(func, line, fmt, args...) ({				\
			printk("stp_dbug in [%s] at line %d : ",	\
			       func, line);				\
			printk(fmt, ##args);				\
		})

#define _dbug(args...) _stp_dbug(__FUNCTION__, __LINE__, args)

#ifdef DEBUG_UNWIND /* stack unwinder */
#define dbug_unwind(level, args...) do {					\
		if ((level) <= DEBUG_UNWIND)				\
			_stp_dbug(__FUNCTION__, __LINE__, args);	\
	} while (0)
#else
#define dbug_unwind(level, args...) ;
#endif

#endif /* _DEBUG_H_ */
