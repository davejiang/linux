/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2018 Intel Corporation. All rights reserved. */

#include <linux/device.h>
#include <linux/ndctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/cred.h>
#include <linux/key.h>
#include <keys/user-type.h>
#include "nd-core.h"
#include "nd.h"

/*
 * Find key that's cached with nvdimm.
 */
struct key *nvdimm_get_key(struct device *dev)
{
	struct nvdimm *nvdimm = to_nvdimm(dev);

	if (!nvdimm->key)
		return NULL;

	if (key_validate(nvdimm->key) < 0)
		return NULL;

	dev_dbg(dev, "%s: key found: %#x\n", __func__,
			key_serial(nvdimm->key));
	return nvdimm->key;
}

/*
 * Retrieve kernel key for DIMM and request from user space if necessary.
 */
static struct key *nvdimm_request_key(struct device *dev)
{
	struct nvdimm *nvdimm = to_nvdimm(dev);
	struct key *key = NULL;
	char desc[NVDIMM_KEY_DESC_LEN + sizeof(NVDIMM_PREFIX)];

	sprintf(desc, "%s%s", NVDIMM_PREFIX, nvdimm->dimm_id);
	key = request_key(&key_type_logon, desc, "");
	if (IS_ERR(key))
		key = NULL;

	return key;
}

static int nvdimm_check_key_len(unsigned short len)
{
	if (len == NVDIMM_PASSPHRASE_LEN)
		return 0;

	return -EINVAL;
}

int nvdimm_security_get_state(struct device *dev)
{
	struct nvdimm *nvdimm = to_nvdimm(dev);
	struct nvdimm_bus *nvdimm_bus = walk_to_nvdimm_bus(dev);

	if (!nvdimm->security_ops)
		return 0;

	return nvdimm->security_ops->state(nvdimm_bus, nvdimm,
			&nvdimm->state);
}

int nvdimm_security_unlock_dimm(struct device *dev)
{
	struct nvdimm *nvdimm = to_nvdimm(dev);
	struct nvdimm_bus *nvdimm_bus = walk_to_nvdimm_bus(dev);
	struct key *key;
	struct user_key_payload *payload;
	int rc;
	bool cached_key = false;

	if (!nvdimm->security_ops)
		return 0;

	if (nvdimm->state == NVDIMM_SECURITY_UNLOCKED ||
			nvdimm->state == NVDIMM_SECURITY_UNSUPPORTED ||
			nvdimm->state == NVDIMM_SECURITY_DISABLED)
		return 0;

	mutex_lock(&nvdimm->key_mutex);
	key = nvdimm_get_key(dev);
	if (!key)
		key = nvdimm_request_key(dev);
	else
		cached_key = true;
	if (!key) {
		mutex_unlock(&nvdimm->key_mutex);
		return -ENXIO;
	}

	if (!cached_key) {
		rc = nvdimm_check_key_len(key->datalen);
		if (rc < 0) {
			key_put(key);
			mutex_unlock(&nvdimm->key_mutex);
			return rc;
		}
	}

	dev_dbg(dev, "%s: key: %#x\n", __func__, key_serial(key));
	down_read(&key->sem);
	payload = key->payload.data[0];
	rc = nvdimm->security_ops->unlock(nvdimm_bus, nvdimm,
			(const void *)payload->data);
	up_read(&key->sem);

	if (rc == 0) {
		if (!cached_key)
			nvdimm->key = key;
		nvdimm->state = NVDIMM_SECURITY_UNLOCKED;
		dev_dbg(dev, "DIMM %s unlocked\n", dev_name(dev));
	} else {
		key_invalidate(key);
		key_put(key);
		nvdimm->key = NULL;
		dev_warn(dev, "Failed to unlock dimm: %s\n", dev_name(dev));
	}

	mutex_unlock(&nvdimm->key_mutex);
	nvdimm_security_get_state(dev);
	return rc;
}
