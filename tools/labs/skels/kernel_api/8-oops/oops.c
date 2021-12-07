#include <linux/module.h>


MODULE_DESCRIPTION("Oops");
MODULE_AUTHOR("SO2");
MODULE_LICENSE("GPL");

static noinline void do_oops(void)
{
    *(int*)0x42 = 'a';
}

static int so2_oops_init(void)
{
    pr_info("oops_init\n");
    do_oops();

    return 0;
}

static void so2_oops_exit(void)
{
    pr_info("oops exit\n");
}

module_init(so2_oops_init);
module_exit(so2_oops_exit);