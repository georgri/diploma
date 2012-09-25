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
	{ 0xf6628fc9, "module_layout" },
	{ 0x53822150, "kmalloc_caches" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x26b64321, "call_usermodehelper_setfns" },
	{ 0x4c4fef19, "kernel_stack" },
	{ 0xdb347c7a, "call_usermodehelper_exec" },
	{ 0x4d8309dc, "debugfs_create_dir" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0x3ec8886f, "param_ops_int" },
	{ 0xc996d097, "del_timer" },
	{ 0x25ec1b28, "strlen" },
	{ 0x3fa913da, "strspn" },
	{ 0x4ff1c9bc, "populate_rootfs_wait" },
	{ 0xe06f50b8, "register_wide_hw_breakpoint" },
	{ 0x7e5e301f, "unregister_kprobe" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0x93260715, "register_kprobe" },
	{ 0xd2f1b260, "interruptible_sleep_on" },
	{ 0x20000329, "simple_strtoul" },
	{ 0x3f9c3419, "kallsyms_on_each_symbol" },
	{ 0xfb0e29f, "init_timer_key" },
	{ 0x59f300eb, "mutex_unlock" },
	{ 0x999e8297, "vfree" },
	{ 0x8e63fbf6, "debugfs_create_file" },
	{ 0x47c7b0d2, "cpu_number" },
	{ 0xafe82e10, "strcspn" },
	{ 0xfdff9bb2, "nonseekable_open" },
	{ 0x7d11c268, "jiffies" },
	{ 0x7f69aa23, "mutex_lock_killable" },
	{ 0xb33b95f2, "unregister_wide_hw_breakpoint" },
	{ 0x4f8b5ddb, "_copy_to_user" },
	{ 0x72aa82c6, "param_ops_charp" },
	{ 0xde0bdcff, "memset" },
	{ 0x8f64aa4, "_raw_spin_unlock_irqrestore" },
	{ 0xf5d0b8cb, "current_task" },
	{ 0x51d3d8f1, "mutex_lock_interruptible" },
	{ 0x27e1a049, "printk" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xb4390f9a, "mcount" },
	{ 0x945859cf, "debugfs_remove" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0x8834396c, "mod_timer" },
	{ 0x9ca95a0e, "sort" },
	{ 0xbaa2782a, "kstrndup" },
	{ 0xc6cbbc89, "capable" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x3bd1b1f6, "msecs_to_jiffies" },
	{ 0x4b5814ef, "kmalloc_order_trace" },
	{ 0x4a21112a, "kmem_cache_alloc_trace" },
	{ 0x9327f5ce, "_raw_spin_lock_irqsave" },
	{ 0xcf21d241, "__wake_up" },
	{ 0x659a64d0, "call_usermodehelper_setup" },
	{ 0x9fb71de5, "find_module" },
	{ 0x37a0cba, "kfree" },
	{ 0x236c8c64, "memcpy" },
	{ 0xf9bd4aea, "module_mutex" },
	{ 0x50720c5f, "snprintf" },
	{ 0xa3a5be95, "memmove" },
	{ 0x4f6b400b, "_copy_from_user" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "034BA22F094A40F39207461");
