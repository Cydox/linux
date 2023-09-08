// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kexec UKI loader
 *
 * Copyright (C) 2023 Jan Hendrik Farr
 * Authors:
 *      Jan Hendrik Farr <kernel@jfarr.cc>
 */

#define pr_fmt(fmt)	"kexec-uki: " fmt

#include <linux/kexec.h>
#include <asm/kexec-uki.h>

#include <asm/kexec-bzimage64.h>
#include <asm/kexec-uki.h>\

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
	pr_info("first two bytes: %x%x", kernel[0], kernel[1]);

	struct pefile_context pe_ctx;
	int r = pefile_parse_binary(kernel, kernel_len, &pe_ctx);
	
	pr_info("pefile_parse_binary return %d, number of sections: %d", r,pe_ctx.n_sections);
	char *ke, *in, *cm;
	uint32_t kl, il, cl;
	for (int i = 0; i < pe_ctx.n_sections; i++) {
		char name[9];
		memcpy(name, pe_ctx.secs[i].name, 8);
		pr_info("section name: %s", name);
		
		if (!strcmp(name, ".linux")) {
			ke = kernel + pe_ctx.secs[i].data_addr;
			kl = pe_ctx.secs[i].raw_data_size;
		} else if (!strcmp(name, ".initrd")) {
			in = kernel + pe_ctx.secs[i].data_addr;
			il = pe_ctx.secs[i].raw_data_size;
		} else if (!strcmp(name, ".cmdline")) {
			cm = kernel + pe_ctx.secs[i].data_addr;
			cl = pe_ctx.secs[i].raw_data_size;
		}

		
	}

	char cmd[1024];
	memset(cmd, 0, 1024);
	memcpy(cmd, cm, cl);
	
	//return bzImage64_load(image, ke, kl, in, il, cmd, cl + 1);
	void *ret = bzImage64_load(image, ke, kl, in, il, cm, cl);
	if (IS_ERR(ret)) {
		pr_info("bzImage64_load error");
	}

	return ret;

    // pr_err("Always failing for now\n");
	// return ERR_PTR(-EINVAL);

    // return 0;
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
