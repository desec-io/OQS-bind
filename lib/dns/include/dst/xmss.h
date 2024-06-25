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

/*
 * This header file exposes some internal liboqs values
 * that we need to support all parameter sets for XMSS
 * and XMSS^MT
 */

#pragma once

#include <oqs/oqs.h>

/***
 *** XMSS OIDs
 ***/

#define OQS_SIG_STFL_alg_xmss_sha256_h10_oid   0x01
#define OQS_SIG_STFL_alg_xmss_sha256_h16_oid   0x02
#define OQS_SIG_STFL_alg_xmss_sha256_h20_oid   0x03
#define OQS_SIG_STFL_alg_xmss_sha512_h10_oid   0x04
#define OQS_SIG_STFL_alg_xmss_sha512_h16_oid   0x05
#define OQS_SIG_STFL_alg_xmss_sha512_h20_oid   0x06
#define OQS_SIG_STFL_alg_xmss_shake128_h10_oid 0x07
#define OQS_SIG_STFL_alg_xmss_shake128_h16_oid 0x08
#define OQS_SIG_STFL_alg_xmss_shake128_h20_oid 0x09
#define OQS_SIG_STFL_alg_xmss_shake256_h10_oid 0x0a
#define OQS_SIG_STFL_alg_xmss_shake256_h16_oid 0x0b
#define OQS_SIG_STFL_alg_xmss_shake256_h20_oid 0x0c

/***
 *** XMSSMT OIDs
 ***/

#define OQS_SIG_STFL_alg_xmssmt_sha256_h20_2_oid    0x01
#define OQS_SIG_STFL_alg_xmssmt_sha256_h20_4_oid    0x02
#define OQS_SIG_STFL_alg_xmssmt_sha256_h40_2_oid    0x03
#define OQS_SIG_STFL_alg_xmssmt_sha256_h40_4_oid    0x04
#define OQS_SIG_STFL_alg_xmssmt_sha256_h40_8_oid    0x05
#define OQS_SIG_STFL_alg_xmssmt_sha256_h60_3_oid    0x06
#define OQS_SIG_STFL_alg_xmssmt_sha256_h60_6_oid    0x07
#define OQS_SIG_STFL_alg_xmssmt_sha256_h60_12_oid   0x08
#define OQS_SIG_STFL_alg_xmssmt_shake128_h20_2_oid  0x11
#define OQS_SIG_STFL_alg_xmssmt_shake128_h20_4_oid  0x12
#define OQS_SIG_STFL_alg_xmssmt_shake128_h40_2_oid  0x13
#define OQS_SIG_STFL_alg_xmssmt_shake128_h40_4_oid  0x14
#define OQS_SIG_STFL_alg_xmssmt_shake128_h40_8_oid  0x15
#define OQS_SIG_STFL_alg_xmssmt_shake128_h60_3_oid  0x16
#define OQS_SIG_STFL_alg_xmssmt_shake128_h60_6_oid  0x17
#define OQS_SIG_STFL_alg_xmssmt_shake128_h60_12_oid 0x18

/***
 *** XMSS Functions
 ***/

int
xmss_name_to_oid(const char *name);

/*!<
 * \brief Returns the internal oid for a given XMSS name.
 *
 * Requires:
 *\li	"name" is a non-NULL cstring and valid XMSS name.
 */

const char *
xmss_oid_to_name(const uint32_t oid);

/*!<
 * \brief Returns the XMSS name associated with the given internal oid.
 *
 * Requires:
 *\li	"oid" is a valid XMSS oid.
 */

const char *
xmss_bindname_to_name(const char *bindname);

/*!<
 * \brief Returns the XMSS name associated Bind formated XMSS name.
 *
 * Requires:
 *\li	"bindname" is a non-NULL cstring and valid Bind formatted XMSS name.
 */

int
xmss_name_to_bits(const char *name);

/*!<
 * \brief Returns the number of bits associated with keys generated by the
 * associated XMSS name.
 *
 * Requires:
 *\li	"name" is a non-NULL cstring and valid XMSS name.
 */

uint32_t
xmss_key_to_oid(const unsigned char *key, size_t key_len);

/*!<
 * \brief Returns the oid associated with the byte encoded XMSS key.
 *
 * Requires:
 *\li	"key" is a valid XMSS public or private key encoded as a byte string.
 */

/***
 *** XMSSMT Functions
 ***/

int
xmssmt_name_to_oid(const char *name);

/*!<
 * \brief Returns the internal oid for a given XMSSMT name.
 *
 * Requires:
 *\li	"name" is a non-NULL cstring and valid XMSSMT name.
 */

const char *
xmssmt_oid_to_name(const uint32_t oid);

/*!<
 * \brief Returns the XMSSMT name associated with the given internal oid.
 *
 * Requires:
 *\li	"oid" is a valid XMSS oid.
 */

const char *
xmssmt_bindname_to_name(const char *bindname);

/*!<
 * \brief Returns the XMSSMT name associated Bind formated XMSS name.
 *
 * Requires:
 *\li	"bindname" is a non-NULL cstring and valid Bind formatted XMSSMT name.
 */

int
xmssmt_name_to_bits(const char *name);

/*!<
 * \brief Returns the number of bits associated with keys generated by the
 * associated XMSSMT name.
 *
 * Requires:
 *\li	"name" is a non-NULL cstring and valid XMSSMT name.
 */

uint32_t
xmssmt_key_to_oid(const unsigned char *key, size_t key_len);

/*!<
 * \brief Returns the oid associated with the byte encoded XMSSMT key.
 *
 * Requires:
 *\li	"key" is a valid XMSSMT public or private key encoded as a byte string.
 */

