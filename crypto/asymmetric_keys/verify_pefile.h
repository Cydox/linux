/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PE Binary parser bits
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <crypto/pkcs7.h>
#include <crypto/hash_info.h>


#define kenter(FMT, ...)					\
	pr_devel("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_devel("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

/*
 * mscode_parser.c
 */
extern int mscode_parse(void *_ctx, const void *content_data, size_t data_len,
			size_t asn1hdrlen);
