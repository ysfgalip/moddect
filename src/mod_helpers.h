#ifndef MODDECT_HELPERS_H
#define MODDECT_HELPERS_H

#include <linux/module.h>

#define MODDECT_PAGE_SIZE 4096

struct module_memory module_to_module_memory(struct module *mod,
					     enum mod_mem_type memtype);

struct module_memory
trampoline_alloc_to_module_memory(unsigned long trampoline,
				  unsigned long trampoline_size);

#endif // !MODDECT_HELPERS_H
