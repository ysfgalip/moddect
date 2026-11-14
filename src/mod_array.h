#ifndef MODDECT_ARRAY_H
#define MODDECT_ARRAY_H

#include <linux/module.h>

// Array for the modules as an alternative to rbtree
struct module_memory_array {
	struct module_memory *modules;
	size_t size;
	size_t limit;
};

int module_memory_array_append(struct module_memory_array *a,
			       const struct module_memory *m);

void module_memory_array_sort(struct module_memory_array *array);

#endif // !MODDECT_ARRAY_H
