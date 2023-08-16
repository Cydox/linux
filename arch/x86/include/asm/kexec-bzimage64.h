/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_KEXEC_BZIMAGE64_H
#define _ASM_KEXEC_BZIMAGE64_H

extern const struct kexec_file_ops kexec_bzImage64_ops;

#include <linux/string.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/kexec.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/efi.h>
#include <linux/random.h>

#include <asm/bootparam.h>
#include <asm/setup.h>
#include <asm/crash.h>
#include <asm/efi.h>
#include <asm/e820/api.h>

void *bzImage64_load(struct kimage *image, char *kernel,
			    unsigned long kernel_len, char *initrd,
			    unsigned long initrd_len, char *cmdline,
			    unsigned long cmdline_len);

int bzImage64_cleanup(void *loader_data);

#endif  /* _ASM_KEXE_BZIMAGE64_H */
