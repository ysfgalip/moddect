#include <linux/module.h>
#include <linux/sort.h>

#include "mod_array.h"

int module_memory_array_append(struct module_memory_array *a,
			       const struct module_memory *m)
{
	struct module_memory *new;
	struct module_memory temp = *m;

	if (a->size == a->limit) {
		new = (struct module_memory *)krealloc_array(
		    a->modules, a->limit * 2, sizeof(temp), GFP_KERNEL);
		if (!new)
			return -ENOMEM;

		a->modules = new;
		a->limit *= 2;
	}
	a->modules[a->size] = temp;
	a->size++;
	return 0;
}

static int module_memory_compare(const void *a, const void *b)
{
	const struct module_memory *l = a;
	const struct module_memory *r = b;
	unsigned long x = (unsigned long)l->base;
	unsigned long y = (unsigned long)r->base;

	return (x > y) - (x < y);
}

void module_memory_array_sort(struct module_memory_array *array)
{
	sort(array->modules, array->size, sizeof(array->modules[0]),
	     module_memory_compare, NULL);
}
