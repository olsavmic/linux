#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm_types.h>

MODULE_DESCRIPTION("List current processes");
MODULE_AUTHOR("Kernel Hacker");
MODULE_LICENSE("GPL");

static int my_memory_init(void)
{
	struct task_struct *p;
    struct vm_area_struct *current_area;

	pr_info("Current process: pid = %d; comm = %s\n", current->pid, current->comm);

	pr_info("\nMemory areas list:\n");


    for (current_area = current->active_mm->mmap; current_area != NULL; current_area = current_area->vm_next) {
        printk("Area start: %lu, end: %lu", current_area->vm_start, current_area->vm_end);
    }

	return 0;
}

static void my_memory_exit(void)
{
	/* TODO: print current process pid and name */
	pr_info("Current process: pid = %d; comm = %s\n", current->pid, current->comm);
}

module_init(my_memory_init);
module_exit(my_memory_exit);
