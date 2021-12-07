// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Michael Olsavsky <olsavmic@cvut.cz>
 */
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROCFS_MAX_SIZE 512

#define procfs_dir_name "list"
#define procfs_file_read "preview"
#define procfs_file_write "management"

#define ADD_LAST_COMMAND "adde"
#define ADD_FIRST_COMMAND "addf"
#define DELETE_ALL_COMMAND "dela"
#define DELETE_FIRST_COMMAND "delf"

#define COMMAND_LEN 4

#define DATA_NAME_MAX_SIZE (PROCFS_MAX_SIZE - COMMAND_LEN)

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

LIST_HEAD(proc_data_list);

struct data_entry {
	char name[DATA_NAME_MAX_SIZE];
	struct list_head list;
};

enum add_to_list_mode {
	ADD_TO_LIST_MODE_PREPEND = 0,
	ADD_TO_LIST_MODE_APPEND = 1,
};

enum delete_from_list_mode {
	DELETE_FROM_LIST_MODE_FIRST = 0,
	DELETE_FROM_LIST_MODE_ALL = 1,
};

static int __add_list_entry(char *name, int len, enum add_to_list_mode mode)
{
	struct data_entry *entry = kmalloc(sizeof(*entry), GFP_KERNEL);

	if (!entry) {
		return -ENOMEM;
	}

	strncpy(entry->name, name, sizeof(entry->name));

	switch (mode) {
	case ADD_TO_LIST_MODE_PREPEND:
		list_add(&entry->list, &proc_data_list);
		break;
	case ADD_TO_LIST_MODE_APPEND:
		list_add_tail(&entry->list, &proc_data_list);
		break;
	}

	return 0;
}

static int __delete_list_entry(char *name, int len,
			       enum delete_from_list_mode mode)
{
	struct list_head *i, *tmp;
	struct data_entry *entry;

	list_for_each_safe (i, tmp, &proc_data_list) {
		entry = list_entry(i, struct data_entry, list);

		if (strncmp(entry->name, name, sizeof(entry->name)) == 0) {
			list_del(i);
			kfree(entry);

			if (mode == DELETE_FROM_LIST_MODE_FIRST) {
				return 0;
			}
		}
	}

	return 0;
}

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *i;

	list_for_each (i, &proc_data_list) {
		seq_puts(m, list_entry(i, struct data_entry, list)->name);
	}

	return 0;
}

static int list_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0, entry_len;
	char *entry_name;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	entry_name = (local_buffer + COMMAND_LEN);
	entry_len = local_buffer_size - COMMAND_LEN;

	if (strncmp(local_buffer, ADD_FIRST_COMMAND, COMMAND_LEN) == 0) {
		pr_debug("Received `ADD_FIRST_COMMAND`");
		__add_list_entry(entry_name, entry_len, ADD_TO_LIST_MODE_PREPEND);

	} else if (strncmp(local_buffer, ADD_LAST_COMMAND, COMMAND_LEN) == 0) {
		pr_debug("Received `ADD_LAST_COMMAND`");
		__add_list_entry(entry_name, entry_len, ADD_TO_LIST_MODE_APPEND);

	} else if (strncmp(local_buffer, DELETE_FIRST_COMMAND, COMMAND_LEN) == 0) {
		pr_debug("Received `DELETE_FIRST_COMMAND`");
		__delete_list_entry(entry_name, entry_len, DELETE_FROM_LIST_MODE_FIRST);

	} else if (strncmp(local_buffer, DELETE_ALL_COMMAND, COMMAND_LEN) == 0) {
		pr_debug("Received `DELETE_ALL_COMMAND`");
		__delete_list_entry(entry_name, entry_len, DELETE_FROM_LIST_MODE_ALL);

	} else {
		pr_err("Unsupported command provided to proc_list module: %s",
		       local_buffer);
	}

	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open = list_read_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

static const struct proc_ops w_pops = {
	.proc_open = list_write_open,
	.proc_write = list_write,
	.proc_release = single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read =
		proc_create(procfs_file_read, 0000, proc_list, &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write =
		proc_create(procfs_file_write, 0000, proc_list, &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
    struct list_head *i, *tmp;
    struct data_entry *entry;

	proc_remove(proc_list);

    list_for_each_safe(i, tmp, &proc_data_list) {
        entry = list_entry(i, struct data_entry, list);
        list_del(i);
        kfree(entry);
    }
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Michael Olsavsky <olsavmic@cvut.cz>");
MODULE_LICENSE("GPL v2");
