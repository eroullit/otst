/*
 * otst: one-time stacktrace module
 * Copyright (C) 2011 Daniel Borkmann <borkmann@iogearbox.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * cat /proc/driver/otst ... to show currently traced syms
 * echo "netif_rx" > /proc/driver/otst ... to add a symbol for trace
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>

#define MODULE_NAME "otst"
#define MODULE_DESC "one-time stacktrace driver"

struct otst_kprobes_elem {
	char *symname;
	struct kprobe probe;
	struct list_head list;
};

static LIST_HEAD(otst_kprobes);
static DEFINE_SPINLOCK(otst_kprobes_lock);

static int otst_handler(struct kprobe *kp, struct pt_regs *regs)
{
	printk(KERN_INFO "%s: triggered stacktrace for symbol %s at 0x%p:\n",
	       MODULE_NAME, kp->symbol_name, kp->addr);
	dump_stack();
	return 0;
}

static void otst_handler_post_work(struct kprobe *kp, struct pt_regs *regs,
				   unsigned long flags)
{
	disable_kprobe(kp);
}

static void otst_collect_garbage(void)
{
	int found;
	unsigned long flags;
	struct otst_kprobes_elem *elem;

	do {
		found = 0;
		rcu_read_lock();
		list_for_each_entry_rcu(elem, &otst_kprobes, list) {
			if (kprobe_disabled(&elem->probe)) {
				found = 1;
				unregister_kprobe(&elem->probe);
				break;
			}
		}
		rcu_read_unlock();
		if (found) {
			spin_lock_irqsave(&otst_kprobes_lock, flags);
			list_del_rcu(&elem->list);
			spin_unlock_irqrestore(&otst_kprobes_lock, flags);
			synchronize_rcu();
			printk(KERN_INFO
			       "%s: symbol %s unregistered!\n",
			       MODULE_NAME, elem->symname);
			kfree(elem->symname);
			kfree(elem);
		}
	} while (found);
}

static int otst_proc_show(struct seq_file *m, void *v)
{
	struct otst_kprobes_elem *elem;
	rcu_read_lock();
	list_for_each_entry_rcu(elem, &otst_kprobes, list) {
		seq_printf(m, "%s\n", elem->probe.symbol_name);
	}
	rcu_read_unlock();
	return 0;
}

static int otst_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, otst_proc_show, NULL);
}

static ssize_t otst_proc_write(struct file *file, const char __user * buffer,
			       size_t count, loff_t * pos)
{
	int ret;
	unsigned long flags;
	struct otst_kprobes_elem *elem;

	otst_collect_garbage();

	if (count > 0 && count < 256) {
		elem = kzalloc(sizeof(*elem), GFP_KERNEL);
		if (!elem)
			return -ENOMEM;
		elem->probe.pre_handler = otst_handler;
		elem->probe.post_handler = otst_handler_post_work;
		elem->symname = kzalloc(count, GFP_KERNEL);
		if (!elem->symname) {
			ret = -ENOMEM;
			goto err;
		}
		if (copy_from_user(elem->symname, buffer, count)) {
			ret = -EFAULT;
			goto err_sym;
		}
		elem->symname[count - 1] = 0;
		elem->probe.symbol_name = elem->symname;
		if (!kallsyms_lookup_name(elem->probe.symbol_name)) {
			printk(KERN_INFO "%s: %s is no symbol!\n",
			       MODULE_NAME, elem->probe.symbol_name);
			ret = -EINVAL;
			goto err_sym;
		}
		ret = register_kprobe(&elem->probe);
		if (ret < 0) {
			printk(KERN_INFO "%s: register_kprobe for %s failed "
			       "with %d\n", MODULE_NAME,
			       elem->probe.symbol_name, ret);
			goto err_sym;
		} else
			printk(KERN_INFO "%s: symbol %s registered!\n",
			       MODULE_NAME, elem->probe.symbol_name);

		spin_lock_irqsave(&otst_kprobes_lock, flags);
		list_add_rcu(&elem->list, &otst_kprobes);
		spin_unlock_irqrestore(&otst_kprobes_lock, flags);
	}

	return count;
 err_sym:
	kfree(elem->symname);
 err:
	kfree(elem);
	return ret;
}

static const struct file_operations otst_fops = {
	.owner = THIS_MODULE,
	.open = otst_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = otst_proc_write,
	.release = single_release,
};

static int __init otst_init(void)
{
	struct proc_dir_entry *otst_file;
	otst_file = proc_create("driver/otst", S_IWUSR | S_IRUSR,
				NULL, &otst_fops);
	if (!otst_file)
		return -ENOMEM;
	printk(KERN_INFO "%s: %s loaded!\n", MODULE_NAME, MODULE_DESC);
	return 0;
}

static void __exit otst_exit(void)
{
	otst_collect_garbage();
	remove_proc_entry("driver/otst", NULL);
	printk(KERN_INFO "%s: removed!\n", MODULE_NAME);
}

module_init(otst_init);
module_exit(otst_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(MODULE_DESC);
MODULE_AUTHOR("Daniel Borkmann <borkmann@iogearbox.net>");
