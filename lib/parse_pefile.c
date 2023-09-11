// SPDX-License-Identifier: GPL-2.0-only
/* Parse a PE binary
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 *
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/parse_pefile.h>
#include <linux/err.h>

#define pr_fmt(fmt)	"parse_pefile: " fmt
#include <linux/module.h>
/*
 * Parse a PE binary.
 */
int pefile_parse_binary(const void *pebuf, unsigned int pelen,
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
	if (pe->magic != PE_MAGIC)
		return -ELIBBAD;
	cursor = mz->peaddr + sizeof(*pe);

	chkaddr(0, cursor, sizeof(pe32->magic));
	pe32 = pebuf + cursor;
	pe64 = pebuf + cursor;

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

	if (ddir->certs.virtual_address && ddir->certs.size) {

		chkaddr(ctx->header_size, ddir->certs.virtual_address,
			ddir->certs.size);
		ctx->sig_offset = ddir->certs.virtual_address;
		ctx->sig_len = ddir->certs.size;
		pr_debug("cert = %x @%x [%*ph]\n",
			 ctx->sig_len, ctx->sig_offset,
			 ctx->sig_len, pebuf + ctx->sig_offset);

	}

	ctx->n_sections = pe->sections;
	if (ctx->n_sections > (ctx->header_size - cursor) / sizeof(*sec))
		return -ELIBBAD;
	ctx->secs = secs = pebuf + cursor;

	return 0;
}
