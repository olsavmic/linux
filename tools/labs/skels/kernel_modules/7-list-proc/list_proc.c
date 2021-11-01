#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

MODULE_DESCRIPTION("List current processes");
MODULE_AUTHOR("Kernel Hacker");
MODULE_LICENSE("GPL");

static int my_proc_init(void)
{
	struct task_struct *p;

	/* TODO: print current process pid and its name */
	pr_info("Current process: pid = %d; comm = %s\n", current->pid, current->comm);

	/* TODO: print the pid and name of all processes */
	pr_info("\nProcess list:\n");

	for_each_process(p)
		pr_info("pid = %d; comm = %s\n", p->pid, p->comm);

	return 0;
}

static void my_proc_exit(void)
{
	/* TODO: print current process pid and name */
	pr_info("Current process: pid = %d; comm = %s\n", current->pid, current->comm);
}

module_init(my_proc_init);
module_exit(my_proc_exit);
