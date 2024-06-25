/*
 * Copyright (C) SandboxAQ and deSEC.
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include <dst/xmss.h>

int
xmss_name_to_oid(const char *name) {
	for (int i = 0; alg_xmss_name[i] != NULL; i++) {
		if (strcmp(name, alg_xmss_name[i]) == 0) {
			return alg_xmss_oid[i];
		}
	}
	return -1;
}

const char *
xmss_oid_to_name(const uint32_t oid) {
	for (int i = 0; alg_xmss_oid[i] != 0; i++) {
		if (oid == alg_xmss_oid[i]) {
			return alg_xmss_name[i];
		}
	}
	return NULL;
}

const char *
xmss_bindname_to_name(const char *bindname) {
	for (int i = 0; alg_xmss_bindname[i] != NULL; i++) {
		if (strcmp(bindname, alg_xmss_bindname[i]) == 0) {
			return alg_xmss_name[i];
		}
	}
	return NULL;
}

int
xmss_name_to_bits(const char *name) {
	int	      size;
	OQS_SIG_STFL *ctx = OQS_SIG_STFL_new(name);
	if (ctx != NULL) {
		size = ctx->length_public_key * 8;
		OQS_SIG_STFL_free(ctx);
		return size;
	}
	return -1;
}

#define XMSS_OID_LEN 4

uint32_t
xmss_key_to_oid(const unsigned char *key, size_t key_len) {
	uint32_t i;
	uint32_t oid = 0;
	if (XMSS_OID_LEN > key_len) {
		return 0;
	}
	for (i = 0; i < XMSS_OID_LEN; i++) {
		oid |= key[XMSS_OID_LEN - i - 1] << (i * 8);
	}
	return oid;
}

int
xmssmt_name_to_oid(const char *name) {
	for (int i = 0; alg_xmssmt_name[i] != NULL; i++) {
		if (strcmp(name, alg_xmssmt_name[i]) == 0) {
			return alg_xmssmt_oid[i];
		}
	}
	return -1;
}

const char *
xmssmt_oid_to_name(const uint32_t oid) {
	for (int i = 0; alg_xmssmt_oid[i] != 0; i++) {
		if (oid == alg_xmssmt_oid[i]) {
			return alg_xmssmt_name[i];
		}
	}
	return NULL;
}

const char *
xmssmt_bindname_to_name(const char *bindname) {
	for (int i = 0; alg_xmssmt_bindname[i] != NULL; i++) {
		if (strcmp(bindname, alg_xmssmt_bindname[i]) == 0) {
			return alg_xmssmt_name[i];
		}
	}
	return NULL;
}

int
xmssmt_name_to_bits(const char *name) {
	return xmss_name_to_bits(name);
}

uint32_t
xmssmt_key_to_oid(const unsigned char *key, size_t key_len) {
	return xmss_key_to_oid(key, key_len);
}
