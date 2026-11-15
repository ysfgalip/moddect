#include "mod_kallsyms.h"
#include "linux/kprobes.h"

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
