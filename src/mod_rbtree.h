#ifndef MODDECT_RBTREE_H
#define MODDECT_RBTREE_H

#include <linux/module.h>

#define MODDECT_PAGE_SIZE 4096

struct module_memory_rbnode {
	struct module_memory mem;
	struct rb_node node;
};

int rbtree_mod_insert(struct rb_root *root, struct module_memory_rbnode *data);

struct module_memory_rbnode module_memory_to_rbnode(struct module_memory *mem);

int insert_module_memory_to_rbtree(struct rb_root *modtree,
				   struct module_memory *mem);

#endif // !MODDECT_RBTREE_H
