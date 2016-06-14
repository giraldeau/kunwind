#include <linux/module.h>
#include <linux/printk.h>

static int __init kunwind_init(void)
{
    printk("kunwind init\n");
    return 0;
}

module_init(kunwind_init);

static void __exit kunwind_exit(void)
{
    printk("kunwind exit\n");
}

module_exit(kunwind_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau <francis.giraldeau@gmail.com>");
MODULE_DESCRIPTION("Kernel Unwind");

