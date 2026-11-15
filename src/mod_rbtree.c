#include "mod_rbtree.h"
#include <linux/module.h>

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
		pr_info("null ptr!\n");
	}
	return ret;
}
