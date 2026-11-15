#include <linux/errno.h>
#include <linux/ftrace.h>
#include <linux/gfp_types.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "mod_array.h"
#include "mod_helpers.h"
#include "mod_kallsyms.h"
#include "mod_rbtree.h"

MODULE_LICENSE("GPL");

#define MODULE_MEMORY_ARRAY_INIT_SIZE 2

static void check_gap(const struct detector_kallsyms *dk, void *current_base,
		      void *previous_end)
{
	unsigned long gap = 0;
	gap = current_base - previous_end;

	if (gap > 0) {
		struct vmap_area *gap_allocation =
		    dk->find_vmap_area((unsigned long)previous_end);

		while (previous_end < current_base) {
			if (gap_allocation) {
				// Try to find the allocation in
				// mod_tree
				struct module *temp_mod = dk->mod_find(
				    gap_allocation->va_start, dk->mod_tree);
				if (temp_mod) {
					// Slice the name to bypass
					// hooks
					pr_info("Mod addr: %px\nMod "
						"name: %c %s\nMod "
						"state: %d\n",
						temp_mod, temp_mod->name[0],
						temp_mod->name + 1,
						temp_mod->state);
				} else {
					pr_warn(
					    "Unknown allocation: %px --- %px\n",
					    (void *)gap_allocation->va_start,
					    (void *)gap_allocation->va_end);
				}
				previous_end = (void *)gap_allocation->va_end;
			} else {
				pr_info("Unallocated: %px --- %px\n",
					previous_end,
					previous_end + MODDECT_PAGE_SIZE);

				previous_end += MODDECT_PAGE_SIZE;
			}
			gap_allocation =
			    dk->find_vmap_area((unsigned long)previous_end);
		}
	}
}

static void module_memory_array_check(const struct detector_kallsyms *dk,
				      const struct module_memory_array *array)
{
	int i;
	void *previous_module_end;
	struct module_memory *prev;

	for (i = 1; i < array->size; i++) {
		prev = &array->modules[i - 1];
		previous_module_end =
		    prev->base + prev->size + MODDECT_PAGE_SIZE;

		pr_info("area %d: %px + %u\n", i - 1, prev->base, prev->size);
		check_gap(dk, array->modules[i].base, previous_module_end);
	}
}

static void module_memory_rbtree_check(const struct detector_kallsyms *dk,
				       struct rb_root *module_rbtree)
{
	int count = 0;
	struct rb_node *current_node = rb_first(module_rbtree);
	struct module_memory_rbnode *current_mod =
	    container_of(current_node, struct module_memory_rbnode, node);
	struct module_memory_rbnode *to_free;
	void *previous_module_end;

	while ((current_node = rb_next(current_node))) {
		to_free = current_mod;
		previous_module_end =
		    to_free->mem.base + to_free->mem.size + MODDECT_PAGE_SIZE;

		current_mod = container_of(current_node,
					   struct module_memory_rbnode, node);
		pr_info("area %d: %px + %u\n", count++, to_free->mem.base,
			to_free->mem.size);
		check_gap(dk, current_mod->mem.base, previous_module_end);
		kfree(to_free);
	}
}

static void detector_work(struct work_struct *work)
{
	struct detector_kallsyms dk = detector_kallsyms_constructor();
	struct rb_root modtree = RB_ROOT;

	struct module_memory *mem = (struct module_memory *)kcalloc(
	    MODULE_MEMORY_ARRAY_INIT_SIZE, sizeof(*mem), GFP_KERNEL);
	if (!mem)
		return;

	struct module_memory_array modarray = {
	    .limit = MODULE_MEMORY_ARRAY_INIT_SIZE, .size = 0, .modules = mem};
	struct module *this = THIS_MODULE;
	struct ftrace_ops *current_ops;

	list_for_each_entry(this, THIS_MODULE->list.prev, list)
	{
		for (int i = MOD_TEXT; i < MOD_MEM_NUM_TYPES; i++) {
			if (this->mem[i].base) {
				module_memory_array_append(&modarray,
							   this->mem + i);
				insert_module_memory_to_rbtree(&modtree,
							       this->mem + i);
			}
		}
	}

	list_for_each_entry(current_ops, dk.ftrace_ops_trampoline_list, list)
	{
		struct module_memory temp;
		temp = trampoline_alloc_to_module_memory(
		    current_ops->trampoline, current_ops->trampoline_size);
		pr_info("ops: %px tramp: %lx\n", current_ops,
			current_ops->trampoline);
		module_memory_array_append(&modarray, &temp);
		insert_module_memory_to_rbtree(&modtree, &temp);
	}

	pr_info("--------------------TREE CHECK--------------------\n");
	module_memory_rbtree_check(&dk, &modtree);

	pr_info("--------------------ARRAY CHECK--------------------\n");
	module_memory_array_sort(&modarray);
	module_memory_array_check(&dk, &modarray);
	kfree(modarray.modules);
}
static DECLARE_DELAYED_WORK(detect_delayed, detector_work);

int init_module(void)
{
	schedule_delayed_work(&detect_delayed, msecs_to_jiffies(2000));

	return 0;
}

void cleanup_module(void)
{
	pr_info("Unloading module!\n");
	return;
}
