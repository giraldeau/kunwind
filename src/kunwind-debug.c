#include <linux/module.h>
#include <linux/printk.h>

static int __init kunwind_debug_init(void)
{
    printk(KERN_INFO "kunwind_debug init\n");
    return 0;
}

module_init(kunwind_debug_init);

static void __exit kunwind_debug_exit(void)
{
    printk(KERN_INFO "kunwind_debug exit\n");
}

module_exit(kunwind_debug_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Jean-Alexandre Barszcz <jalex_b@hotmail.com>");
MODULE_DESCRIPTION("Kernel Unwind Debugging");

