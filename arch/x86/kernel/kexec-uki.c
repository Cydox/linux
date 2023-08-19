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

#include <linux/pe.h>

#define kenter(FMT, ...)					\
	pr_devel("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_devel("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)
struct pefile_context {
	unsigned	header_size;
	unsigned	image_checksum_offset;
	unsigned	cert_dirent_offset;
	unsigned	n_data_dirents;
	unsigned	n_sections;
	unsigned	certs_size;
	unsigned	sig_offset;
	unsigned	sig_len;
	const struct section_header *secs;

	/* PKCS#7 MS Individual Code Signing content */
	const void	*digest;		/* Digest */
	unsigned	digest_len;		/* Digest length */
	const char	*digest_algo;		/* Digest algorithm */
};
/*
 * Parse a PE binary.
 */
static int pefile_parse_binary(const void *pebuf, unsigned int pelen,
			       struct pefile_context *ctx)
{
	const struct mz_hdr *mz = pebuf;
	const struct pe_hdr *pe;
	const struct pe32_opt_hdr *pe32;
	const struct pe32plus_opt_hdr *pe64;
	const struct data_directory *ddir;
	const struct data_dirent *dde;
	const struct section_header *secs, *sec;
	size_t cursor, datalen = pelen;

	kenter("");

#define chkaddr(base, x, s)						\
	do {								\
		if ((x) < base || (s) >= datalen || (x) > datalen - (s)) \
			return -ELIBBAD;				\
	} while (0)

	chkaddr(0, 0, sizeof(*mz));
	if (mz->magic != MZ_MAGIC)
		return -ELIBBAD;
	cursor = sizeof(*mz);

	chkaddr(cursor, mz->peaddr, sizeof(*pe));
	pe = pebuf + mz->peaddr;
	pr_info("pe header location: 0x%x", mz->peaddr);
	pr_info("pe header n sections: 0x%x", pe->sections);
	if (pe->magic != PE_MAGIC)
		return -ELIBBAD;
	cursor = mz->peaddr + sizeof(*pe);

	chkaddr(0, cursor, sizeof(pe32->magic));
	pe32 = pebuf + cursor;
	pe64 = pebuf + cursor;

	pr_info("pe magic: 0x%x", pe32->magic);

	switch (pe32->magic) {
	case PE_OPT_MAGIC_PE32:
		chkaddr(0, cursor, sizeof(*pe32));
		ctx->image_checksum_offset =
			(unsigned long)&pe32->csum - (unsigned long)pebuf;
		ctx->header_size = pe32->header_size;
		cursor += sizeof(*pe32);
		ctx->n_data_dirents = pe32->data_dirs;
		break;

	case PE_OPT_MAGIC_PE32PLUS:
		chkaddr(0, cursor, sizeof(*pe64));
		ctx->image_checksum_offset =
			(unsigned long)&pe64->csum - (unsigned long)pebuf;
		ctx->header_size = pe64->header_size;
		cursor += sizeof(*pe64);
		ctx->n_data_dirents = pe64->data_dirs;
		break;

	default:
		pr_warn("Unknown PEOPT magic = %04hx\n", pe32->magic);
		return -ELIBBAD;
	}

	pr_debug("checksum @ %x\n", ctx->image_checksum_offset);
	pr_debug("header size = %x\n", ctx->header_size);

	if (cursor >= ctx->header_size || ctx->header_size >= datalen)
		return -ELIBBAD;

	if (ctx->n_data_dirents > (ctx->header_size - cursor) / sizeof(*dde))
		return -ELIBBAD;

	ddir = pebuf + cursor;
	cursor += sizeof(*dde) * ctx->n_data_dirents;

	ctx->cert_dirent_offset =
		(unsigned long)&ddir->certs - (unsigned long)pebuf;
	ctx->certs_size = ddir->certs.size;

	if (!ddir->certs.virtual_address || !ddir->certs.size) {
		pr_warn("Unsigned PE binary\n");
		// return -ENODATA;
	}
	// pr_info("hello");

	// chkaddr(ctx->header_size, ddir->certs.virtual_address,
	// 	ddir->certs.size);
	// ctx->sig_offset = ddir->certs.virtual_address;
	// ctx->sig_len = ddir->certs.size;
	// pr_debug("cert = %x @%x [%*ph]\n",
	// 	 ctx->sig_len, ctx->sig_offset,
	// 	 ctx->sig_len, pebuf + ctx->sig_offset);

	ctx->n_sections = pe->sections;
	// pr_info("ctx->n_sections: %x", ctx->n_sections);
	if (ctx->n_sections > (ctx->header_size - cursor) / sizeof(*sec))
		return -ELIBBAD;
	ctx->secs = secs = pebuf + cursor;

	return 0;
}


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
