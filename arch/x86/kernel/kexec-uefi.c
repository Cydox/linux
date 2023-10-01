// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kexec UEFI loader
 *
 * Copyright (C) Jan Hendrik Farr
 * Authors:
 *      Jan Hendrik Farr <kernel@jfarr.cc>
 */

#define pr_fmt(fmt)	"kexec-uefi: " fmt
#include "linux/wait_bit.h"
#include "linux/completion.h"

#include "asm-generic/set_memory.h"
#include "asm/page_types.h"
#include "linux/compiler_attributes.h"
#include "linux/sched.h"

#include <asm/kexec-uefi.h>

#include <linux/efi.h>
#include <asm/efi.h>

#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/err.h>
#include <linux/errno.h>

#include <linux/parse_pefile.h>

#include "../../../drivers/firmware/efi/libstub/efistub.h"
#include "../../../drivers/firmware/efi/libstub/x86-stub.h"



static efi_status_t _not_implemented(const char * fn)
{
	pr_err("%s not implemented\n", fn);
	return EFI_NOT_FOUND;
}

static efi_status_t __efiapi _allocate_pages(int Type, int MemoryType, unsigned long Pages, efi_physical_addr_t *Memory)
{
	return _not_implemented("allocate_pages");
}

static efi_status_t __noreturn __efiapi _exit(efi_handle_t ImageHandle, efi_status_t ExitStatus, unsigned long ExitDataSize, efi_char16_t *ExitData)
{
	pr_info("exit status is %lu\n", ExitStatus);
	pr_info("expecting %lu\n", EFI_INVALID_PARAMETER);
	_not_implemented("exit");

	kthread_exit(ExitStatus);
}

struct efi_bs_table {
	efi_table_hdr_t hdr;
	void *raise_tpl;
	void *restore_tpl;
	efi_status_t (__efiapi *allocate_pages)(int, int, unsigned long, efi_physical_addr_t *);
	efi_status_t (__efiapi *free_pages)(efi_physical_addr_t,
					    unsigned long);
	efi_status_t (__efiapi *get_memory_map)(unsigned long *, void *,
						unsigned long *,
						unsigned long *, u32 *);
	efi_status_t (__efiapi *allocate_pool)(int, unsigned long,
					       void **);
	efi_status_t (__efiapi *free_pool)(void *);
	efi_status_t (__efiapi *create_event)(u32, unsigned long,
					      efi_event_notify_t, void *,
					      efi_event_t *);
	efi_status_t (__efiapi *set_timer)(efi_event_t,
					  EFI_TIMER_DELAY, u64);
	efi_status_t (__efiapi *wait_for_event)(unsigned long,
						efi_event_t *,
						unsigned long *);
	void *signal_event;
	efi_status_t (__efiapi *close_event)(efi_event_t);
	void *check_event;
	void *install_protocol_interface;
	void *reinstall_protocol_interface;
	void *uninstall_protocol_interface;
	efi_status_t (__efiapi *handle_protocol)(efi_handle_t,
						 efi_guid_t *, void **);
	void *__reserved;
	void *register_protocol_notify;
	efi_status_t (__efiapi *locate_handle)(int, efi_guid_t *,
					       void *, unsigned long *,
					       efi_handle_t *);
	efi_status_t (__efiapi *locate_device_path)(efi_guid_t *,
						    efi_device_path_protocol_t **,
						    efi_handle_t *);
	efi_status_t (__efiapi *install_configuration_table)(efi_guid_t *,
							     void *);
	efi_status_t (__efiapi *load_image)(bool, efi_handle_t,
					    efi_device_path_protocol_t *,
					    void *, unsigned long,
					    efi_handle_t *);
	efi_status_t (__efiapi *start_image)(efi_handle_t, unsigned long *,
					     efi_char16_t **);
	efi_status_t __noreturn (__efiapi *exit)(efi_handle_t,
						 efi_status_t,
						 unsigned long,
						 efi_char16_t *);
	efi_status_t (__efiapi *unload_image)(efi_handle_t);
	efi_status_t (__efiapi *exit_boot_services)(efi_handle_t,
						    unsigned long);
	void *get_next_monotonic_count;
	efi_status_t (__efiapi *stall)(unsigned long);
	void *set_watchdog_timer;
	void *connect_controller;
	efi_status_t (__efiapi *disconnect_controller)(efi_handle_t,
						       efi_handle_t,
						       efi_handle_t);
	void *open_protocol;
	void *close_protocol;
	void *open_protocol_information;
	void *protocols_per_handle;
	void *locate_handle_buffer;
	efi_status_t (__efiapi *locate_protocol)(efi_guid_t *, void *,
						 void **);
	efi_status_t (__efiapi *install_multiple_protocol_interfaces)(efi_handle_t *, ...);
	efi_status_t (__efiapi *uninstall_multiple_protocol_interfaces)(efi_handle_t, ...);
	void *calculate_crc32;
	void (__efiapi *copy_mem)(void *, const void *, unsigned long);
	void (__efiapi *set_mem)(void *, unsigned long, unsigned char);
	void *create_event_ex;
};

static struct efi_bs_table bs_table;

static void setup_efi_bs_table(void)
{
	memset(&bs_table, 0, sizeof(bs_table));
	bs_table.allocate_pages = _allocate_pages;
	bs_table.exit = _exit;
}

static int uefi_probe(const char *buf, unsigned long len)
{
	int ret = -ENOEXEC;

	pr_info("Assuming it's an EFI application right now");
	return 0;

	return ret;
}

struct thread_test_t {
	efi_status_t (__efiapi *efi_entry)(efi_handle_t handle,
				   efi_system_table_t *sys_table_arg);
	efi_handle_t handle;
	efi_system_table_t sys_table;
	struct completion started;
};

static int call_entry(void *data)
{
	struct thread_test_t *d = data;
	complete(&d->started);
	unsigned long r = d->efi_entry(d->handle, &d->sys_table);
	kthread_exit(r);
	return 0;
}

static void *uefi_load(struct kimage *image, char *kernel,
			    unsigned long kernel_len, char *initrd,
			    unsigned long initrd_len, char *cmdline,
			    unsigned long cmdline_len)
{
	setup_efi_bs_table();

	efi_system_table_t sys_table;
	memset(&sys_table, 0, sizeof(sys_table));
	sys_table.boottime = (union efi_boot_services *) &bs_table;

	char foo = 123;
	efi_handle_t handle = &foo;

	struct pefile_context pe_ctx;
	memset(&pe_ctx, 0, sizeof(pe_ctx));
	pr_info("about to parse pe file\n");
	int r = pefile_parse_binary(kernel, kernel_len, &pe_ctx);

	if (r) {
		pr_info("error parsing pe file\n");
		return ERR_PTR(r);
	}

	set_memory_ro((unsigned long) kernel, kernel_len >> PAGE_SHIFT);
	set_memory_x((unsigned long) kernel, kernel_len >> PAGE_SHIFT);


	efi_status_t (__efiapi *efi_entry)(efi_handle_t handle,
				   efi_system_table_t *sys_table_arg) = (void *)(kernel + pe_ctx.entry_point);

	struct thread_test_t *tt = kmalloc(sizeof(struct thread_test_t), GFP_KERNEL);
	tt->efi_entry = efi_entry;
	tt->handle = handle;
	tt->sys_table = sys_table;
	init_completion(&tt->started);

	struct task_struct *kth = kthread_run(call_entry, (void *)tt, "test uefi kthread");

	wait_for_completion(&tt->started);
	kthread_stop(kth);

	set_memory_nx((unsigned long) kernel, kernel_len >> PAGE_SHIFT);
	set_memory_rw((unsigned long) kernel, kernel_len >> PAGE_SHIFT);
	kfree(tt);

	return ERR_PTR(-ENOEXEC);
}

/* This cleanup function is called after various segments have been loaded */
static int uefi_cleanup(void *loader_data)
{
	return 0;
}

const struct kexec_file_ops kexec_uefi_ops = {
	.probe = uefi_probe,
	.load = uefi_load,
	.cleanup = uefi_cleanup,
#ifdef CONFIG_KEXEC_BZIMAGE_VERIFY_SIG
	.verify_sig = kexec_kernel_verify_pe_sig,
#endif
};
