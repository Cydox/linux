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
#include <linux/parse_pefile.h>

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
	int r = 0;
	struct pefile_context pe_ctx;
	const struct section_header *s;

	memset(&pe_ctx, 0, sizeof(pe_ctx));
	r = pefile_parse_binary(buf, len, &pe_ctx);

	if (r) {
		pr_info("Not a UKI. Not a valid PE file\n");
		return ret;
	}

	if (find_section(&pe_ctx, ".linux", &s) ||
	    find_section(&pe_ctx, ".initrd", &s)) {
		pr_info("Not a UKI. Missing .linux, or .initrd\n");
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
	const struct section_header *sec_linux, *sec_initrd, *sec_cmdline;
	int r_linux, r_initrd, r_cmdline, r = 0;
	void *ret;

	if (initrd_len || strcmp(cmdline, "") || cmdline_len != 1) {
		pr_err("No manual cmdline or initrd allowed for UKIs");
		return ERR_PTR(-EPERM);
	}

	memset(&pe_ctx, 0, sizeof(pe_ctx));
	r = pefile_parse_binary(kernel, kernel_len, &pe_ctx);

	if (r)
		return ERR_PTR(r);

	r_linux   = find_section(&pe_ctx, ".linux", &sec_linux);
	r_initrd  = find_section(&pe_ctx, ".initrd", &sec_initrd);
	r_cmdline = find_section(&pe_ctx, ".cmdline", &sec_cmdline);

	if (r_linux || r_initrd)
		return ERR_PTR(-EINVAL);

	if (r_cmdline)
		cmdline_len = 0;
	else
		cmdline_len = sec_cmdline->raw_data_size;

	ret = kexec_bzImage64_ops.load(
		image,
		kernel + sec_linux->data_addr,
		sec_linux->raw_data_size,
		kernel + sec_initrd->data_addr,
		sec_initrd->raw_data_size,
		kernel + sec_cmdline->data_addr,
		cmdline_len
	);

	if (IS_ERR(ret))
		pr_err("bzImage64_load error\n");

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
