// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kexec UKI loader
 *
 * Copyright (C) 2023 Jan Hendrik Farr
 * Authors:
 *      Jan Hendrik Farr <kernel@jfarr.cc>
 */

#define pr_fmt(fmt)	"kexec-uki: " fmt

#include <linux/kernel.h>
#include "linux/pe.h"
#include <linux/kexec.h>

#include <asm/kexec-uki.h>
#include <asm/kexec-bzimage64.h>
#include <asm/parse_pefile.h>


static int uki_probe(const char *buf, unsigned long len)
{
	int ret = -ENOEXEC;

	pr_warn("Assuming it's a UKI in every case rn\n");
	ret = 0;

	return ret;
}

static void *uki_load(struct kimage *image, char *kernel,
			    unsigned long kernel_len, char *initrd,
			    unsigned long initrd_len, char *cmdline,
			    unsigned long cmdline_len)
{
	struct pefile_context pe_ctx;
	int r = pefile_parse_binary(kernel, kernel_len, &pe_ctx);

	if (r)
		return ERR_PTR(r);

	pr_debug("pefile_parse_binary return %d, number of sections: %d",
	         r, pe_ctx.n_sections);

	char *_kernel, *_initrd, *_cmdline;
	uint32_t _kernel_len, _initrd_len, _cmdline_len;

	for (int i = 0; i < pe_ctx.n_sections; i++) {
		struct section_header sec = pe_ctx.secs[i];
		
		if (!strncmp(sec.name, ".linux", ARRAY_SIZE(sec.name))) {
			_kernel = kernel + pe_ctx.secs[i].data_addr;
			_kernel_len = pe_ctx.secs[i].raw_data_size;
		} else if (!strncmp(sec.name, ".initrd", ARRAY_SIZE(sec.name))) {
			_initrd = kernel + pe_ctx.secs[i].data_addr;
			_initrd_len = pe_ctx.secs[i].raw_data_size;
		} else if (!strncmp(sec.name, ".cmdline", ARRAY_SIZE(sec.name))) {
			_cmdline = kernel + pe_ctx.secs[i].data_addr;
			_cmdline_len = pe_ctx.secs[i].raw_data_size;
		}
	}

	void *ret = bzImage64_load(
		image,
		_kernel,
		_kernel_len,
		_initrd,
		_initrd_len,
		_cmdline,
	        _cmdline_len
	);

	if (IS_ERR(ret)) {
		pr_warn("bzImage64_load error");
	}

	return ret;
}

static int uki_cleanup(void *loader_data)
{
	return bzImage64_cleanup(loader_data);
}

const struct kexec_file_ops kexec_uki_ops = {
	.probe = uki_probe,
	.load = uki_load,
	.cleanup = uki_cleanup,
#ifdef CONFIG_KEXEC_BZIMAGE_VERIFY_SIG
	.verify_sig = kexec_kernel_verify_pe_sig,
#endif
};
