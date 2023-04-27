/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
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

#pragma once

#include <isc/util.h>

/* when urcu is not installed in a system header location */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/* Inline small (less than 10 lines) functions */
#define URCU_INLINE_SMALL_FUNCTIONS

#if defined(RCU_MEMBARRIER) || defined(RCU_MB) || defined(RCU_SIGNAL)
#include <urcu.h>
#elif defined(RCU_QSBR)
#include <urcu-qsbr.h>
#elif defined(RCU_BP)
#include <urcu-bp.h>
#endif

#include <urcu/compiler.h>
#include <urcu/rculfhash.h>
#include <urcu/rculist.h>

#pragma GCC diagnostic pop

#if defined(RCU_QSBR)

/*
 * Define wrappers that allows us to make the thread online without any extra
 * heavy tooling around libuv callbacks.
 */

#define isc_qsbr_read_lock()                       \
	{                                          \
		if (!urcu_qsbr_read_ongoing()) {   \
			urcu_qsbr_thread_online(); \
		}                                  \
		urcu_qsbr_read_lock();             \
	}

#undef rcu_read_lock
#define rcu_read_lock() isc_qsbr_read_lock()

#define isc_qsbr_call_rcu(rcu_head, func)           \
	{                                           \
		if (!urcu_qsbr_read_ongoing()) {    \
			urcu_qsbr_thread_online();  \
		}                                   \
		urcu_qsbr_call_rcu(rcu_head, func); \
	}

#undef call_rcu
#define call_rcu(rcu_head, func) isc_qsbr_call_rcu(rcu_head, func)

#define isc_qsbr_synchronize_rcu()                 \
	{                                          \
		if (!urcu_qsbr_read_ongoing()) {   \
			urcu_qsbr_thread_online(); \
		}                                  \
		urcu_qsbr_synchronize_rcu();       \
	}

#undef synchronize_rcu
#define synchronize_rcu() isc_qsbr_syncronize_rcu()

#define isc_qsbr_rcu_dereference(ptr)              \
	{                                          \
		if (!urcu_qsbr_read_ongoing()) {   \
			urcu_qsbr_thread_online(); \
		}                                  \
		urcu_qsbr_dereference(ptr);        \
	}

#undef rcu_dereference
#define rcu_dereference(ptr) isc_qsbr_rcu_dereference(ptr)

#endif /* RCU_QSBR */
