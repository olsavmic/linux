#include "tracer.h"
#include <asm/current.h>
#include <linux/gfp.h>
#include <linux/kern_levels.h>
#include <linux/rwlock_types.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define LOG_LEVEL KERN_DEBUG
#define PROC_OUTPUT_FILE "tracer"

MODULE_AUTHOR("olsavmic");
MODULE_DESCRIPTION("Tracer");
MODULE_LICENSE("GPL");

DEFINE_HASHTABLE(proc_table, 10);

static struct proc_dir_entry *proc_output;

struct kmalloc_probe_data {
	struct hlist_node node;
	void *address;
	int size;
};

struct kfree_probe_data {
	void *address;
};

struct my_proc_entry {
	struct hlist_node node;
	int pid;
	int up_interruptible_counter;
	int down_interruptible_counter;
	int mutex_lock_counter;
	int mutex_unlock_counter;
	int kfree_counter;
	int kmalloc_counter;
	int schedule_counter;

	int kmalloc_allocated;
	int kmalloc_freed;
	struct hlist_head mem[1 << 10];
};

static void init_entry_data(struct my_proc_entry *entry, int pid)
{
	entry->pid = pid;
	entry->up_interruptible_counter = 0;
	entry->down_interruptible_counter = 0;
	entry->mutex_lock_counter = 0;
	entry->mutex_unlock_counter = 0;
	entry->kfree_counter = 0;
	entry->schedule_counter = 0;
	entry->kmalloc_counter = 0;
	entry->kmalloc_freed = 0;
	entry->kmalloc_allocated = 0;

	hash_init(entry->mem);
}

static void delete_entry_data(struct my_proc_entry *entry)
{
	int bkt;
	struct kmalloc_probe_data *proc;
	struct hlist_node *tmp;

	hash_for_each_safe (entry->mem, bkt, tmp, proc, node) {
		hash_del(&proc->node);
		kfree(proc);
	}
}

static char kmalloc_func_name[] = "__kmalloc";
static char kfree_func_name[] = "kfree";
static char up_interrupt_func_name[] = "up";
static char down_interrupt_func_name[] = "down_interruptible";
static char mutex_lock_func_name[] = "mutex_lock_nested";
static char mutex_unlock_func_name[] = "mutex_unlock";
static char schedule_func_name[] = "schedule";
static char do_exit_func_name[] = "do_exit";

static rwlock_t my_device_lock = __RW_LOCK_UNLOCKED(my_device_lock);

static int my_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int my_release(struct inode *inode, struct file *file)
{
	return 0;
}

static int delete_proc_by_pid(unsigned int pid)
{
	struct my_proc_entry *entry;
	struct my_proc_entry *found = NULL;
	struct hlist_node *tmp;

	write_lock(&my_device_lock);
	hash_for_each_possible_safe (proc_table, entry, tmp, node, pid) {
		if (entry->pid == pid) {
			found = entry;
			hash_del(&entry->node);
			break;
		}
	}

	write_unlock(&my_device_lock);

	if (found != NULL) {
		delete_entry_data(found);
	}

	return 0;
}

static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct my_proc_entry *entry;
	unsigned int selected_pid = arg;

	unsigned long flags;

	printk(LOG_LEVEL "IOCTL called");

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (entry == NULL) {
			return -ENOMEM;
		}

		init_entry_data(entry, selected_pid);

		write_lock_irqsave(&my_device_lock, flags);
		hash_add(proc_table, &entry->node, selected_pid);
		write_unlock_irqrestore(&my_device_lock, flags);

		printk(LOG_LEVEL "Process %d added to list", selected_pid);

		break;
	case TRACER_REMOVE_PROCESS:
		delete_proc_by_pid(selected_pid);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static struct my_proc_entry *find_entry_in_proc_table(int pid)
{
	struct my_proc_entry *proc = NULL;

	read_lock(&my_device_lock);
	hash_for_each_possible (proc_table, proc, node, pid) {
		if (proc->pid == pid) {
			break;
		}
	}
	read_unlock(&my_device_lock);

	return proc;
}

static int kmalloc_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kmalloc_probe_data *data;

	data = (struct kmalloc_probe_data *)ri->data;
	data->size = regs->ax;

	return 0;
}

static int kmalloc_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_proc_entry *proc;
	struct kmalloc_probe_data *data;

	proc = find_entry_in_proc_table(current->pid);
	if (proc == NULL) {
		return 0;
	}

	data = kmalloc(sizeof(*data), GFP_ATOMIC);
	memcpy(data, ri->data, sizeof(*data));

	data->address = (void *)regs_return_value(regs);
	printk(LOG_LEVEL "kmalloc returned address %px with size %d", data->address, data->size);

	proc->kmalloc_counter++;
	proc->kmalloc_allocated += data->size;

	hash_add(proc->mem, &data->node, (unsigned int)data->address);

	return 0;
}

static int kfree_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kfree_probe_data *data;

	data = (struct kfree_probe_data *)ri->data;
	data->address = (void *)regs->ax;

	return 0;
}

static int kfree_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_proc_entry *proc;
	struct kmalloc_probe_data *alloc;
	struct kfree_probe_data *kfree_data;
	struct hlist_node *tmp;

	proc = find_entry_in_proc_table(current->pid);
	if (proc == NULL) {
		return 0;
	}

	kfree_data = (struct kfree_probe_data *)ri->data;

	printk(LOG_LEVEL "kfree returned address %px", kfree_data->address);

	proc->kfree_counter++;

	hash_for_each_possible_safe (proc->mem, alloc, tmp, node, (unsigned int)kfree_data->address) {
		if (alloc->address == kfree_data->address) {
			proc->kmalloc_freed += alloc->size;
			hash_del(&alloc->node);
			kfree(alloc);
			break;
		}
	}

	return 0;
}

static int up_interruptible_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_proc_entry *proc;

	proc = find_entry_in_proc_table(current->pid);
	if (proc != NULL) {
		proc->up_interruptible_counter++;
	}

	return 0;
}

static int down_interruptible_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_proc_entry *proc;

	proc = find_entry_in_proc_table(current->pid);
	if (proc != NULL) {
		proc->down_interruptible_counter++;
	}

	return 0;
}

static int mutex_lock_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_proc_entry *proc;

	proc = find_entry_in_proc_table(current->pid);
	if (proc != NULL) {
		proc->mutex_lock_counter++;
	}

	return 0;
}

static int mutex_unlock_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_proc_entry *proc;

	proc = find_entry_in_proc_table(current->pid);
	if (proc != NULL) {
		proc->mutex_unlock_counter++;
	}

	return 0;
}

static int schedule_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_proc_entry *proc;

	proc = find_entry_in_proc_table(current->pid);
	if (proc != NULL) {
		proc->schedule_counter++;
	}

	return 0;
}

static int do_exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return delete_proc_by_pid(current->pid);
}

static int show_output(struct seq_file *m, void *v)
{
	struct my_proc_entry *entry;
	int bkt;

	seq_puts(m, "PID kmalloc kfree kmalloc_mem kfree_mem sched up down lock unlock\n");

	read_lock(&my_device_lock);
	hash_for_each (proc_table, bkt, entry, node) {
		pr_debug("Listing results for process %d", entry->pid);
		pr_debug("%d %d %d %d %d %d %d %d %d %d\n", entry->pid, entry->kmalloc_counter, entry->kfree_counter, entry->kmalloc_allocated, entry->kmalloc_freed, entry->schedule_counter,
			 entry->up_interruptible_counter, entry->down_interruptible_counter, entry->mutex_lock_counter, entry->mutex_unlock_counter);

		seq_printf(m, "%d %d %d %d %d %d %d %d %d %d\n", entry->pid, entry->kmalloc_counter, entry->kfree_counter, entry->kmalloc_allocated, entry->kmalloc_freed, entry->schedule_counter,
			   entry->up_interruptible_counter, entry->down_interruptible_counter, entry->mutex_lock_counter, entry->mutex_unlock_counter);
	}
	read_unlock(&my_device_lock);

	return 0;
}

static int my_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, show_output, NULL);
}

static const struct file_operations my_fops = {
	.owner = THIS_MODULE,
	.open = my_open,
	.release = my_release,
	.unlocked_ioctl = my_ioctl,
};

static struct miscdevice my_device = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &my_fops,
};

static struct kretprobe kmalloc_probe = {
	.entry_handler = kmalloc_probe_entry_handler,
	.handler = kmalloc_probe_handler,
	.data_size = sizeof(struct kmalloc_probe_data),
	.maxactive = 32,
};

static struct kretprobe kfree_probe = {
	.handler = kfree_probe_handler,
	.data_size = sizeof(struct kmalloc_probe_data),
	.maxactive = 32,
	.entry_handler = kfree_probe_entry_handler,
};

static struct kretprobe up_probe = {
	.handler = up_interruptible_handler,
	.maxactive = 32,
};

static struct kretprobe down_probe = {
	.handler = down_interruptible_handler,
	.maxactive = 32,
};

static struct kretprobe mutex_lock_probe = {
	.handler = mutex_lock_handler,
	.maxactive = 32,
};

static struct kretprobe mutex_unlock_probe = {
	.handler = mutex_unlock_handler,
	.maxactive = 32,
};

static struct kretprobe do_exit_probe = {
	.handler = do_exit_handler,
	.maxactive = 32,
};

static struct kretprobe schedule_probe = {
	.entry_handler = schedule_entry_handler,
    .maxactive = 128,
};

static struct proc_ops proc_output_ops = {
	.proc_open = my_proc_open,
	.proc_release = single_release,
	.proc_read = seq_read,
};

static int __init tracer_init(void)
{
	int err;
	err = misc_register(&my_device);

	if (err != 0) {
		pr_err("misc_register failed");
		return err;
	}

	printk(LOG_LEVEL "Misc device registered");

	proc_output = proc_create(PROC_OUTPUT_FILE, 0000, NULL, &proc_output_ops);
	if (proc_output == NULL) {
		pr_err("Unable to create record in /proc directory");
		goto out_misc;
	}

	kmalloc_probe.kp.symbol_name = kmalloc_func_name;
	err = register_kretprobe(&kmalloc_probe);
	if (err != 0) {
		pr_err("Unable to register kretprobe for kmalloc");
		goto out_proc;
	}
	printk(LOG_LEVEL "kmalloc probe registered");

	kfree_probe.kp.symbol_name = kfree_func_name;
	err = register_kretprobe(&kfree_probe);
	if (err != 0) {
		pr_err("Unable to register kretprobe for kfree");
		goto out_kmalloc;
	}
	printk(LOG_LEVEL "kfree probe registered");

	up_probe.kp.symbol_name = up_interrupt_func_name;
	err = register_kretprobe(&up_probe);
	if (err != 0) {
		pr_err("Unable to register kprobe for up");
		goto out_kfree;
	}
	printk(LOG_LEVEL "up probe registered");

	down_probe.kp.symbol_name = down_interrupt_func_name;
	err = register_kretprobe(&down_probe);
	if (err != 0) {
		pr_err("Unable to register kretprobe for down_interruptible");
		goto out_up_interruptible;
	}
	printk(LOG_LEVEL "down_interruptible probe registered");

	mutex_lock_probe.kp.symbol_name = mutex_lock_func_name;
	err = register_kretprobe(&mutex_lock_probe);
	if (err != 0) {
		pr_err("Unable to register kretprobe for mutex_lock");
		goto out_down_interruptible;
	}
	printk(LOG_LEVEL "mutex_lock probe registered");

	mutex_unlock_probe.kp.symbol_name = mutex_unlock_func_name;
	err = register_kretprobe(&mutex_unlock_probe);
	if (err != 0) {
		pr_err("Unable to register kretprobe for mutex_unlock");
		goto out_mutex_lock;
	}
	printk(LOG_LEVEL "mutex_unlock probe registered");

	schedule_probe.kp.symbol_name = schedule_func_name;
	err = register_kretprobe(&schedule_probe);
	if (err != 0) {
		pr_err("Unable to register kretprobe for schedule");
		goto out_mutex_unlock;
	}
	printk(LOG_LEVEL "schedule probe registered");

	do_exit_probe.kp.symbol_name = do_exit_func_name;
	err = register_kretprobe(&do_exit_probe);
	if (err != 0) {
		pr_err("Unable to register kretprobe for do_exit");
		goto out_schedule;
	}
	printk(LOG_LEVEL "do_exit probe registered");

	return 0;

out_schedule:
	unregister_kretprobe(&schedule_probe);
out_mutex_unlock:
	unregister_kretprobe(&mutex_unlock_probe);
out_mutex_lock:
	unregister_kretprobe(&mutex_lock_probe);
out_down_interruptible:
	unregister_kretprobe(&down_probe);
out_up_interruptible:
	unregister_kretprobe(&up_probe);
out_kfree:
	unregister_kretprobe(&kfree_probe);
out_kmalloc:
	unregister_kretprobe(&kmalloc_probe);
out_proc:
	proc_remove(proc_output);
out_misc:
	misc_deregister(&my_device);
	return err;
}

static void __exit tracer_exit(void)
{
	struct my_proc_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	unregister_kretprobe(&kmalloc_probe);
	unregister_kretprobe(&kfree_probe);
	unregister_kretprobe(&up_probe);
	unregister_kretprobe(&down_probe);
	unregister_kretprobe(&mutex_lock_probe);
	unregister_kretprobe(&mutex_unlock_probe);
	unregister_kretprobe(&schedule_probe);
	unregister_kretprobe(&do_exit_probe);

	proc_remove(proc_output);
	misc_deregister(&my_device);

	hash_for_each_safe (proc_table, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		delete_entry_data(entry);
	}
}

module_init(tracer_init);
module_exit(tracer_exit);
