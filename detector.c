#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");

#define PAGE_SIZE 4096;

struct module_memory_rbnode {
	struct module_memory mem;
	struct rb_node node;
};

struct detector_kallsyms {
	struct vmap_area *(*find_vmap_area)(unsigned long addr);
	struct module *(*mod_find)(unsigned long addr, void *tree);
	void *mod_tree;
	struct ftrace_ops __rcu *ftrace_ops_list;
	struct execmem_info *execmem_info;
};

static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {.symbol_name = name};
	unsigned long retval;

	if (register_kprobe(&kp) < 0)
		return 0;
	retval = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return retval;
}

struct detector_kallsyms detector_kallsyms_constructor(void)
{
	unsigned long (*kallsyms_lookup_name)(const char *name) =
	    (unsigned long (*)(const char *))lookup_name(
		"kallsyms_lookup_name");

	struct detector_kallsyms ret;

	ret.find_vmap_area = (struct vmap_area * (*)(unsigned long))
	    lookup_name("find_vmap_area");

	ret.mod_find = (struct module * (*)(unsigned long, void *))
	    kallsyms_lookup_name("mod_find");

	ret.mod_tree = (void *)kallsyms_lookup_name("mod_tree");

	ret.ftrace_ops_list = *(struct ftrace_ops __rcu **)kallsyms_lookup_name(
	    "ftrace_ops_list");

	ret.execmem_info =
	    (struct execmem_info *)kallsyms_lookup_name("execmem_info");

	return ret;
}

int rbtree_mod_insert(struct rb_root *root, struct module_memory_rbnode *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct module_memory_rbnode *this =
		    container_of(*new, struct module_memory_rbnode, node);

		parent = *new;
		if (data->mem.base < this->mem.base)
			new = &((*new)->rb_left);
		else if (data->mem.base > this->mem.base)
			new = &((*new)->rb_right);
		else
			return 0;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	return 1;
}

struct module_memory_rbnode module_memtype_to_rbnode(struct module *mod,
						     enum mod_mem_type memtype)
{
	struct module_memory_rbnode ret = {.mem = mod->mem[memtype]};
	pr_info("Module addr: %px", ret.mem.base);
	return ret;
}

int insert_module_to_rbtree(struct rb_root *modtree, struct module *mod)
{
	int ret = 0;
	struct module_memory_rbnode *ins;
	struct module_memory_rbnode temp;
	for (int i = MOD_TEXT; i < MOD_MEM_NUM_TYPES; i++) {
		temp = module_memtype_to_rbnode(mod, i);
		if (temp.mem.base) {
			ins = kzalloc(sizeof(struct module_memory_rbnode),
				      GFP_KERNEL);
			*ins = temp;
			ret = rbtree_mod_insert(modtree, ins);
		} else {
			pr_info("null ptr!");
		}
	}
	return ret;
}

static void detector_work(struct work_struct *work)
{
	struct detector_kallsyms dk = detector_kallsyms_constructor();
	struct module_memory_rbnode *ins;
	struct rb_root modtree = RB_ROOT;
	struct module *this = THIS_MODULE;
	int gap = 0;
	int count = 0;

	list_for_each_entry(this, THIS_MODULE->list.prev, list)
	{
		pr_info("Module name: %s", this->name);
		count++;
		pr_info("Module count: %d", count);

		insert_module_to_rbtree(&modtree, this);
	}
	count = 0;
	struct rb_node *current_node = rb_first(&modtree);
	struct module_memory_rbnode *current_mod =
	    container_of(current_node, struct module_memory_rbnode, node);
	struct module_memory_rbnode *to_free;
	void *previous_module_end =
	    (void *)dk.execmem_info->ranges[EXECMEM_MODULE_TEXT].start;

	struct ftrace_ops __rcu *ops;
	while (current_node) {
		pr_info("Area %d: %px + %d", count++, current_mod->mem.base,
			current_mod->mem.size);
		to_free = current_mod;
		current_node = rb_next(current_node);
		if (!current_node) {
			kfree(to_free);
			break;
		}

		current_mod = container_of(current_node,
					   struct module_memory_rbnode, node);
		gap = current_mod->mem.base - previous_module_end;
		if (to_free && gap > 0) {

			struct vmap_area *gap_allocation = dk.find_vmap_area(
			    (unsigned long)previous_module_end);
			while (!gap_allocation) {
				previous_module_end += PAGE_SIZE;
				gap_allocation = dk.find_vmap_area(
				    (unsigned long)previous_module_end);
			}
			while (gap_allocation &&
			       (void *)gap_allocation->va_start <
				   current_mod->mem.base) {

				// Try to find the allocation in mod_tree
				struct module *temp_mod = dk.mod_find(
				    gap_allocation->va_start, dk.mod_tree);
				if (temp_mod) {
					pr_info("mod addr: %px", temp_mod);
					// Slice the name to bypass hooks
					pr_info("Mod name: %c %s",
						temp_mod->name[0],
						temp_mod->name + 1);
				}
				// Check if a tracer exists in the area
				rcu_read_lock();
				pr_info("list: %px",
					rcu_dereference(dk.ftrace_ops_list));
				for (ops = rcu_dereference(dk.ftrace_ops_list);
				     ops; ops = rcu_dereference(ops->next)) {
					pr_info("ops: %px tramp: %lx", ops,
						ops->trampoline);

					if (ops->trampoline ==
					    gap_allocation->va_start)
						pr_info("tramp in place");
				}
				rcu_read_unlock();
				/* ------------------------ */
				pr_info("STH FISHY!: %px --- %px",
					(void *)gap_allocation->va_start,
					(void *)gap_allocation->va_end);
				pr_info("flags: %lx",
					gap_allocation->vm->flags);
				previous_module_end =
				    (void *)gap_allocation->va_end;
				gap_allocation = dk.find_vmap_area(
				    (unsigned long)previous_module_end);
			}
		}
		previous_module_end =
		    to_free->mem.base + to_free->mem.size + PAGE_SIZE;

		kfree(to_free);
	}
}
static DECLARE_DELAYED_WORK(detect_delayed, detector_work);

int init_module(void)
{
	struct module_memory text_area = THIS_MODULE->mem[MOD_TEXT];
	struct module_memory data_area = THIS_MODULE->mem[MOD_DATA];
	pr_info("Text Address is: %px\n", text_area.base);
	pr_info("Data Address is: %px\n", data_area.base);
	pr_info("Some Address is: %px\n", THIS_MODULE->mem[2]);
	pr_info("Some Address is: %px\n", THIS_MODULE->mem[3]);
	pr_info("Module text size is: %u\n", text_area.size);
	pr_info("Module data size is: %u\n", data_area.size);
	pr_info("Instruction is: %x %x %x %x %x %x %x %x %x\n", instr[0],
		instr[1], instr[2], instr[3], instr[4], instr[5], instr[6],
		instr[7], instr[8], instr[9]);
	schedule_delayed_work(&detect_delayed, msecs_to_jiffies(1000));

	return 0;
}

void cleanup_module(void)
{
	pr_info("Unloading module!");
	return;
}
