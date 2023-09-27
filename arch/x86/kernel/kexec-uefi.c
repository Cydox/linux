// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kexec UEFI loader
 *
 * Copyright (C) Jan Hendrik Farr
 * Authors:
 *      Jan Hendrik Farr <kernel@jfarr.cc>
 */

#define pr_fmt(fmt)	"kexec-uefi: " fmt

#include <asm/kexec-uefi.h>

#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/err.h>
#include <linux/errno.h>


static int uefi_probe(const char *buf, unsigned long len)
{
	int ret = -ENOEXEC;

	return ret;
}

static void *uefi_load(struct kimage *image, char *kernel,
			    unsigned long kernel_len, char *initrd,
			    unsigned long initrd_len, char *cmdline,
			    unsigned long cmdline_len)
{
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
