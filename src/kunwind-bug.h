#ifndef KUNWIND_BUG_H_
#define KUNWIND_BUG_H_

#include <linux/bug.h>

#define KUNWIND_BUG()	BUG()

#define KUNWIND_BUGM(message, args...) ({		\
		printk(message, ##args);		\
		KUNWIND_BUG();				\
	})

#define EUNIMPL	1

#endif /* KUNWIND_BUG_H_ */
