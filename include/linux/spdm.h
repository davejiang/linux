/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Copyright (C) 2021-22 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-23 Intel Corporation
 */

#ifndef _SPDM_H_
#define _SPDM_H_

#include <linux/types.h>

struct key;
struct device;
struct spdm_state;

typedef int (spdm_transport)(void *priv, struct device *dev,
			     const void *request, size_t request_sz,
			     void *response, size_t response_sz);

struct spdm_state *spdm_create(struct device *dev, spdm_transport *transport,
			       void *transport_priv, u32 transport_sz,
			       struct key *keyring);

int spdm_authenticate(struct spdm_state *spdm_state);

void spdm_await(struct spdm_state *spdm_state);

void spdm_destroy(struct spdm_state *spdm_state);

#endif
