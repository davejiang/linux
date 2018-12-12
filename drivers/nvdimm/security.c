// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2018 Intel Corporation. All rights reserved. */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/ndctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/cred.h>
#include <linux/key.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <keys/encrypted-type.h>
#include "nd-core.h"
#include "nd.h"

static bool key_revalidate = true;
module_param(key_revalidate, bool, 0444);
MODULE_PARM_DESC(key_revalidate, "Require key validation at init.");

static void *key_data(struct key *key)
{
	struct encrypted_key_payload *epayload = dereference_key_locked(key);

	lockdep_assert_held_read(&key->sem);

	return epayload->decrypted_data;
}

static void nvdimm_put_key(struct key *key)
{
	up_read(&key->sem);
	key_put(key);
}

/*
 * Retrieve kernel key for DIMM and request from user space if
 * necessary. Returns a key held for read and must be put by
 * nvdimm_put_key() before the usage goes out of scope.
 */
static struct key *nvdimm_request_key(struct nvdimm *nvdimm)
{
	struct key *key = NULL;
	static const char NVDIMM_PREFIX[] = "nvdimm:";
	char desc[NVDIMM_KEY_DESC_LEN + sizeof(NVDIMM_PREFIX)];
	struct device *dev = &nvdimm->dev;

	sprintf(desc, "%s%s", NVDIMM_PREFIX, nvdimm->dimm_id);
	key = request_key(&key_type_encrypted, desc, "");
	if (IS_ERR(key)) {
		if (PTR_ERR(key) == -ENOKEY)
			dev_warn(dev, "request_key() found no key\n");
		else
			dev_warn(dev, "request_key() upcall failed\n");
		key = NULL;
	} else {
		struct encrypted_key_payload *epayload;

		down_read(&key->sem);
		epayload = dereference_key_locked(key);
		if (epayload->decrypted_datalen != NVDIMM_PASSPHRASE_LEN) {
			up_read(&key->sem);
			key_put(key);
			key = NULL;
		}
	}

	return key;
}

static struct key *nvdimm_key_revalidate(struct nvdimm *nvdimm)
{
	struct key *key;
	int rc;

	if (!nvdimm->sec.ops->change_key)
		return NULL;

	key = nvdimm_request_key(nvdimm);
	if (!key)
		return NULL;

	/*
	 * Send the same key to the hardware as new and old key to
	 * verify that the key is good.
	 */
	rc = nvdimm->sec.ops->change_key(nvdimm, key_data(key), key_data(key));
	if (rc < 0) {
		nvdimm_put_key(key);
		key = NULL;
	}
	return key;
}

static int __nvdimm_security_unlock(struct nvdimm *nvdimm)
{
	struct device *dev = &nvdimm->dev;
	struct nvdimm_bus *nvdimm_bus = walk_to_nvdimm_bus(dev);
	struct key *key = NULL;
	int rc;

	/* The bus lock should be held at the top level of the call stack */
	lockdep_assert_held(&nvdimm_bus->reconfig_mutex);

	if (!nvdimm->sec.ops || !nvdimm->sec.ops->unlock
			|| nvdimm->sec.state < 0)
		return -EIO;

	/*
	 * If the pre-OS has unlocked the DIMM, attempt to send the key
	 * from request_key() to the hardware for verification.  Failure
	 * to revalidate the key against the hardware results in a
	 * freeze of the security configuration. I.e. if the OS does not
	 * have the key, security is being managed pre-OS.
	 */
	if (nvdimm->sec.state == NVDIMM_SECURITY_UNLOCKED) {
		if (!key_revalidate)
			return 0;

		key = nvdimm_key_revalidate(nvdimm);
		if (!key)
			return nvdimm_security_freeze(nvdimm);
	} else
		key = nvdimm_request_key(nvdimm);

	if (!key)
		return -ENOKEY;

	rc = nvdimm->sec.ops->unlock(nvdimm, key_data(key));
	dev_dbg(dev, "key: %d unlock: %s\n", key_serial(key),
			rc == 0 ? "success" : "fail");

	nvdimm_put_key(key);
	nvdimm->sec.state = nvdimm_security_state(nvdimm);
	return rc;
}

int nvdimm_security_unlock(struct device *dev)
{
	struct nvdimm *nvdimm = to_nvdimm(dev);
	int rc;

	nvdimm_bus_lock(dev);
	rc = __nvdimm_security_unlock(nvdimm);
	nvdimm_bus_unlock(dev);
	return rc;
}
