#include "mod_helpers.h"
#include <linux/module.h>

struct module_memory module_to_module_memory(struct module *mod,
					     enum mod_mem_type memtype)
{
	struct module_memory ret = mod->mem[memtype];
	pr_info("Module addr: %px\n", ret.base);
	return ret;
}

struct module_memory
trampoline_alloc_to_module_memory(unsigned long trampoline,
				  unsigned long trampoline_size)
{
	int size =
	    ((int)trampoline_size) / MODDECT_PAGE_SIZE + MODDECT_PAGE_SIZE;
	struct module_memory ret = {.base = (void *)trampoline, .size = size};
	return ret;
}
