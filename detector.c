#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");

#define PAGE_SIZE 4096

struct module_memory_rbnode {
	struct module_memory mem;
	struct rb_node node;
};

struct detector_kallsyms {
	struct vmap_area *(*find_vmap_area)(unsigned long addr);
	struct module *(*mod_find)(unsigned long addr, void *tree);
	void *mod_tree;
	struct list_head *ftrace_ops_trampoline_list;
	// struct execmem_info is not exported in kernel, so walk the struct
	// manually
	unsigned long **execmem_info;
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

	ret.ftrace_ops_trampoline_list =
	    (struct list_head *)kallsyms_lookup_name(
		"ftrace_ops_trampoline_list");

	ret.execmem_info = (void *)kallsyms_lookup_name("execmem_info");

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

struct module_memory_rbnode module_memory_to_rbnode(struct module_memory *mem)
{
	struct module_memory_rbnode ret = {.mem = *mem};
	return ret;
}

struct module_memory module_to_module_memory(struct module *mod,
					     enum mod_mem_type memtype)
{
	struct module_memory ret = mod->mem[memtype];
	pr_info("Module addr: %px", ret.base);
	return ret;
}

int insert_module_memory_to_rbtree(struct rb_root *modtree,
				   struct module_memory *mem)
{
	int ret = 0;
	struct module_memory_rbnode *ins;
	struct module_memory_rbnode temp;
	temp = module_memory_to_rbnode(mem);
	if (temp.mem.base) {
		ins = kzalloc(sizeof(struct module_memory_rbnode), GFP_KERNEL);
		*ins = temp;
		ret = rbtree_mod_insert(modtree, ins);
	} else {
		pr_info("null ptr!");
	}
	return ret;
}

int insert_module_to_rbtree(struct rb_root *modtree, struct module *mod)
{
	int ret = 0;
	struct module_memory temp;
	for (int i = MOD_TEXT; i < MOD_MEM_NUM_TYPES; i++) {
		temp = module_to_module_memory(mod, i);
		insert_module_memory_to_rbtree(modtree, &temp);
	}
	return ret;
}

struct module_memory
trampoline_alloc_to_module_memory(unsigned long trampoline,
				  unsigned long trampoline_size)
{
	int size = ((int)trampoline_size) / PAGE_SIZE + PAGE_SIZE;
	struct module_memory ret = {.base = (void *)trampoline, .size = size};
	return ret;
}

int insert_ftrace_ops_to_rbtree(struct rb_root *modtree, struct ftrace_ops *ops)
{
	int ret = 0;
	struct module_memory temp;
	temp = trampoline_alloc_to_module_memory(ops->trampoline,
						 ops->trampoline_size);
	insert_module_memory_to_rbtree(modtree, &temp);
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
	struct ftrace_ops *current_ops;

	list_for_each_entry(this, THIS_MODULE->list.prev, list)
	{
		insert_module_to_rbtree(&modtree, this);
	}
	list_for_each_entry(current_ops, dk.ftrace_ops_trampoline_list, list)
	{
		insert_ftrace_ops_to_rbtree(&modtree, current_ops);
		pr_info("ops: %px tramp: %lx", current_ops,
			current_ops->trampoline);
	}
	count = 0;
	struct rb_node *current_node = rb_first(&modtree);
	struct module_memory_rbnode *current_mod =
	    container_of(current_node, struct module_memory_rbnode, node);
	struct module_memory_rbnode *to_free;
	void *previous_module_end =
	    current_mod->mem.base + current_mod->mem.size + PAGE_SIZE;

	struct ftrace_ops __rcu *ops;
	while (current_node = rb_next(current_node)) {
		to_free = current_mod;
		previous_module_end =
		    to_free->mem.base + to_free->mem.size + PAGE_SIZE;

		current_mod = container_of(current_node,
					   struct module_memory_rbnode, node);
		pr_info("Area %d: %px + %d", count++, current_mod->mem.base,
			current_mod->mem.size);
		gap = current_mod->mem.base - previous_module_end;
		if (to_free && gap > 0) {

			struct vmap_area *gap_allocation = dk.find_vmap_area(
			    (unsigned long)previous_module_end);

			while (previous_module_end < current_mod->mem.base) {
				while (gap_allocation &&
				       previous_module_end <
					   current_mod->mem.base) {

					// Try to find the allocation in
					// mod_tree
					struct module *temp_mod = dk.mod_find(
					    gap_allocation->va_start,
					    dk.mod_tree);
					if (temp_mod) {
						pr_info("mod addr: %px",
							temp_mod);
						// Slice the name to bypass
						// hooks
						pr_info("Mod addr: %px\nMod "
							"name: %c %s\nMod "
							"state: %d",
							temp_mod,
							temp_mod->name[0],
							temp_mod->name + 1,
							temp_mod->state);
					}
					pr_info(
					    "Unknown allocation: %px --- %px",
					    (void *)gap_allocation->va_start,
					    (void *)gap_allocation->va_end);
					previous_module_end =
					    (void *)gap_allocation->va_end;
					gap_allocation = dk.find_vmap_area(
					    (unsigned long)previous_module_end);
				}
				while (!gap_allocation) {
					pr_info("Unallocated: %px --- %px",
						previous_module_end,
						previous_module_end +
						    PAGE_SIZE);

					previous_module_end += PAGE_SIZE;
					gap_allocation = dk.find_vmap_area(
					    (unsigned long)previous_module_end);
				}
			}
		}
		kfree(to_free);
	}
}
static DECLARE_DELAYED_WORK(detect_delayed, detector_work);

int init_module(void)
{
	struct module_memory text_area = THIS_MODULE->mem[MOD_TEXT];
	struct module_memory data_area = THIS_MODULE->mem[MOD_DATA];
	schedule_delayed_work(&detect_delayed, msecs_to_jiffies(1000));

	return 0;
}

void cleanup_module(void)
{
	pr_info("Unloading module!");
	return;
}
