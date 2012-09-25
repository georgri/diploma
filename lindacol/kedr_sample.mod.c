#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xe68a66b1, "module_layout" },
	{ 0xe83ea961, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x8d4aace0, "call_usermodehelper_setfns" },
	{ 0xe817635e, "call_usermodehelper_exec" },
	{ 0x8daa2cd, "debugfs_create_dir" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x59d696b6, "register_module_notifier" },
	{ 0x3ec8886f, "param_ops_int" },
	{ 0xd0d8621b, "strlen" },
	{ 0xc7ec6c27, "strspn" },
	{ 0x4ff1c9bc, "populate_rootfs_wait" },
	{ 0x7c904ded, "unregister_module_notifier" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x1c307a5a, "kallsyms_on_each_symbol" },
	{ 0x13f13805, "mutex_unlock" },
	{ 0x999e8297, "vfree" },
	{ 0x132b1f14, "debugfs_create_file" },
	{ 0x47c7b0d2, "cpu_number" },
	{ 0x6c1ce5ce, "strcspn" },
	{ 0x6fbf3206, "nonseekable_open" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x63319466, "mutex_lock_killable" },
	{ 0x72aa82c6, "param_ops_charp" },
	{ 0x2bc95bd4, "memset" },
	{ 0xf97456ea, "_raw_spin_unlock_irqrestore" },
	{ 0xac2e972e, "current_task" },
	{ 0x50eedeb8, "printk" },
	{ 0x62cd8754, "__tracepoint_module_get" },
	{ 0x2f287f0d, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0xf56c1dd0, "debugfs_remove" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0x310917fe, "sort" },
	{ 0x51ef33b8, "kstrndup" },
	{ 0xedbb2c10, "module_put" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x2a78b2ca, "kmem_cache_alloc_trace" },
	{ 0x21fb443e, "_raw_spin_lock_irqsave" },
	{ 0x74509349, "call_usermodehelper_setup" },
	{ 0x1f6f8095, "find_module" },
	{ 0x37a0cba, "kfree" },
	{ 0x2e60bace, "memcpy" },
	{ 0xedbb03b2, "module_mutex" },
	{ 0xb81960ca, "snprintf" },
	{ 0x8235805b, "memmove" },
	{ 0x362ef408, "_copy_from_user" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "797628DB5C00380773A06DB");
