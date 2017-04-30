/*
 * Openkirin's hook module
 *
 * Copyright (C) 2017 OpenKirin
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kallsyms.h>

static void *bfmr_ptr = NULL;
static void *old_ptr = NULL;
static int foo(void)
{
	pr_info("Prevented a kpanic");
	return 0;
}

static int __init init_hook(void)
{
	pr_info("Openkirin's Injector loaded.\n");
	bfmr_ptr = (void *)kallsyms_lookup_name("bfmr_process_boot_fail_err");
	old_ptr = bfmr_ptr;
	pr_info("Found our function at %p\n", bfmr_ptr);
	bfmr_ptr = foo;
	return 0;
}

static void __exit stop_hook(void)
{
	bfmr_ptr = old_ptr;	
	pr_info("Unloading OpenKirin's Injector, the hook has been removed");
}

module_init(init_hook);
module_exit(stop_hook);
MODULE_AUTHOR("OpenKirin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("This module prevent's auto induced kpanics on HiSilicon SoCs");
MODULE_INFO(vermagic, "4.1.18-gaa01840 SMP preempt mod_unload aarch64");

