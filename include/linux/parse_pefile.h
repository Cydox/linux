/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 *
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _ASM_PARSE_PEFILE_H
#define _ASM_PARSE_PEFILE_H

#include <linux/pe.h>

struct pefile_context {
	unsigned	header_size;
	unsigned	image_checksum_offset;
	unsigned	cert_dirent_offset;
	unsigned	n_data_dirents;
	unsigned	n_sections;
	unsigned	certs_size;
	unsigned	sig_offset;
	unsigned	sig_len;
	uint32_t entry_point;	/* file offset of entry point */

	const struct section_header *secs;

	/* PKCS#7 MS Individual Code Signing content */
	const void	*digest;		/* Digest */
	unsigned	digest_len;		/* Digest length */
	const char	*digest_algo;		/* Digest algorithm */
};
int pefile_parse_binary(const void *pebuf, unsigned int pelen,
			       struct pefile_context *ctx);

#endif // _ASM_PARSE_PEFILE_H
