// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kexec UKI loader
 *
 * Copyright (C) 2023 Jan Hendrik Farr
 *
 * Authors:
 *      Jan Hendrik Farr <kernel@jfarr.cc>
 */

#define pr_fmt(fmt)	"kexec-uki: " fmt

#include <linux/kernel.h>
#include "linux/pe.h"
#include <linux/kexec.h>
#include <linux/err.h>

#include <asm/kexec-uki.h>
#include <asm/kexec-bzimage64.h>
#include <asm/parse_pefile.h>

static int find_section(struct pefile_context *ctx, const char *name,
			const struct section_header **sec)
{
	for (int i = 0; i < ctx->n_sections; i++) {
		const struct section_header *cur_sec = &ctx->secs[i];

		if (!strncmp(cur_sec->name, name, ARRAY_SIZE(cur_sec->name))) {
			*sec = cur_sec;
			return 0;
		}
	}

	return -EINVAL;
}

static int uki_probe(const char *buf, unsigned long len)
{
	int ret = -ENOEXEC;
	struct pefile_context pe_ctx;

	int r = pefile_parse_binary(buf, len, &pe_ctx);

	if (r) {
		pr_info("Not a UKI. Not a valid PE file\n");
		return ret;
	}

	const struct section_header *_;

	if (find_section(&pe_ctx, ".linux", &_) ||
	    find_section(&pe_ctx, ".initrd", &_) ||
	    find_section(&pe_ctx, ".cmdline", &_)) {
		pr_info("Not a UKI. Missing .linux, .initrd, or .cmdline\n");
		return ret;
	}


	pr_info("It's a UKI\n");
	return 0;
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

	pr_debug("pefile_parse_binary return %d, number of sections: %d\n",
		 r, pe_ctx.n_sections);

	const struct section_header *sec_linux, *sec_initrd, *sec_cmdline;
	int r_linux = find_section(&pe_ctx, ".linux", &sec_linux);
	int r_initrd = find_section(&pe_ctx, ".initrd", &sec_initrd);
	int r_cmdline = find_section(&pe_ctx, ".cmdline", &sec_cmdline);

	if (r_linux || r_initrd || r_cmdline)
		return ERR_PTR(-EINVAL);

	void *ret = kexec_bzImage64_ops.load(
		image,
		kernel + sec_linux->data_addr,
		sec_linux->raw_data_size,
		kernel + sec_initrd->data_addr,
		sec_initrd->raw_data_size,
		kernel + sec_cmdline->data_addr,
		sec_cmdline->raw_data_size
	);

	if (IS_ERR(ret))
		pr_warn("bzImage64_load error\n");

	return ret;
}

static int uki_cleanup(void *loader_data)
{
	return kexec_bzImage64_ops.cleanup(loader_data);
}

const struct kexec_file_ops kexec_uki_ops = {
	.probe = uki_probe,
	.load = uki_load,
	.cleanup = uki_cleanup,
#ifdef CONFIG_KEXEC_BZIMAGE_VERIFY_SIG
	.verify_sig = kexec_kernel_verify_pe_sig,
#endif
};
