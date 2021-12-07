#include "linux/printk.h"
#include "linux/sched.h"
#include "linux/sched/signal.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_DESCRIPTION("List current processes");
MODULE_AUTHOR("Kernel Hacker");
MODULE_LICENSE("GPL");

static int my_proc_init(void)
{
	struct task_struct *p;

    pr_info("Current process: pid=%d, comm = %s\n", current->pid, current->comm);

    pr_info("\nProcess list:\n\n");
    for_each_process(p)
        pr_info("pid = %d; comm = %s\n", p->pid, p->comm);
	return 0;
}

static void my_proc_exit(void)
{
    pr_info("Current process: pid = %d; comm = %s\n", current->pid, current->comm);
}

module_init(my_proc_init);
module_exit(my_proc_exit);
