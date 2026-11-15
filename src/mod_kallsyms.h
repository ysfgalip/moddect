#ifndef MODDECT_KALLSYMS_H
#define MODDECT_KALLSYMS_H

struct detector_kallsyms {
	struct vmap_area *(*find_vmap_area)(unsigned long addr);
	struct module *(*mod_find)(unsigned long addr, void *tree);
	void *mod_tree;
	struct list_head *ftrace_ops_trampoline_list;
	// struct execmem_info is not exported in kernel, so walk the struct
	// manually
	unsigned long **execmem_info;
};

struct detector_kallsyms detector_kallsyms_constructor(void);

#endif // !MODDECT_KALLSYMS_H
