/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2018 Intel Corporation. All rights reserved. */

#include <linux/device.h>
#include <linux/ndctl.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/cred.h>
#include <linux/key.h>
#include <linux/key-type.h>
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
 * Replacing the user key with a kernel key. The function expects that
 * we hold the sem for the key passed in. The function will release that
 * sem when done process. We will also hold the sem for the valid new key
 * returned.
 */
static struct key *nvdimm_replace_key(struct key *key)
{
	struct key *new_key;
	struct user_key_payload *payload;
	int rc;

	new_key = key_alloc(&key_type_logon, key->description,
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, current_cred(),
			KEY_POS_SEARCH, KEY_ALLOC_NOT_IN_QUOTA, NULL);
	if (IS_ERR(new_key))
		return NULL;

	payload = key->payload.data[0];
	rc = key_instantiate_and_link(new_key, payload->data,
			payload->datalen, NULL, NULL);
	up_read(&key->sem);
	if (rc < 0) {
		key_put(new_key);
		return NULL;
	}

	key_put(key);

	down_read(&new_key->sem);
	return new_key;
}

/*
 * Retrieve user injected key
 */
static struct key *nvdimm_lookup_user_key(struct device *dev,
		key_serial_t id)
{
	key_ref_t keyref;
	struct key *key;

	keyref = lookup_user_key(id, 0, 0);
	if (IS_ERR(keyref))
		return NULL;

	key = key_ref_to_ptr(keyref);
	dev_dbg(dev, "%s: key found: %#x\n", __func__, key_serial(key));

	return key;
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

struct key *nvdimm_get_and_verify_key(struct device *dev,
		unsigned int user_key_id)
{
	struct key *user_key, *key;
	struct user_key_payload *upayload, *payload;
	int rc = 0;

	key = nvdimm_get_key(dev);
	/* we don't have a cached key */
	if (!key) {
		dev_dbg(dev, "No cached kernel key\n");
		return NULL;
	}
	dev_dbg(dev, "cached_key: %#x\n", key_serial(key));

	user_key = nvdimm_lookup_user_key(dev, user_key_id);
	if (!user_key) {
		dev_dbg(dev, "Old user key lookup failed\n");
		rc = -EINVAL;
		goto out;
	}
	dev_dbg(dev, "user_key: %#x\n", key_serial(user_key));

	down_read(&key->sem);
	down_read(&user_key->sem);
	payload = key->payload.data[0];
	upayload = user_key->payload.data[0];

	if (memcmp(payload->data, upayload->data,
				NVDIMM_PASSPHRASE_LEN) != 0) {
		rc = -EINVAL;
		dev_warn(dev, "Supplied old user key fails check.\n");
	}

	up_read(&user_key->sem);
	key_put(user_key);
	up_read(&key->sem);

out:
	if (rc < 0)
		key = ERR_PTR(rc);
	return key;
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

int nvdimm_security_erase(struct device *dev, unsigned int keyid)
{
	struct nvdimm *nvdimm = to_nvdimm(dev);
	struct nvdimm_bus *nvdimm_bus = walk_to_nvdimm_bus(dev);
	struct key *key;
	struct user_key_payload *payload;
	int rc = 0;
	bool is_userkey = false;

	if (!nvdimm->security_ops)
		return -EOPNOTSUPP;

	nvdimm_bus_lock(&nvdimm_bus->dev);
	mutex_lock(&nvdimm->key_mutex);
	if (atomic_read(&nvdimm->busy)) {
		dev_warn(dev, "Unable to secure erase while DIMM active.\n");
		rc = -EBUSY;
		goto out;
	}

	if (dev_get_drvdata(dev)) {
		dev_warn(dev, "Unable to secure erase while DIMM enabled.\n");
		rc = -EBUSY;
		goto out;
	}

	if (nvdimm->state == NVDIMM_SECURITY_UNSUPPORTED) {
		dev_warn(dev, "Attempt to secure erase in wrong state.\n");
		rc = -EOPNOTSUPP;
		goto out;
	}

	/* look for a key from cached key if exists */
	key = nvdimm_get_and_verify_key(dev, keyid);
	if (IS_ERR(key)) {
		dev_dbg(dev, "Unable to get and verify key\n");
		rc = PTR_ERR(key);
		goto out;
	}
	if (!key) {
		dev_dbg(dev, "No cached key found\n");
		/* get old user key */
		key = nvdimm_lookup_user_key(dev, keyid);
		if (!key) {
			dev_dbg(dev, "Unable to retrieve user key: %#x\n",
					keyid);
			rc = -ENOKEY;
			goto out;
		}
		is_userkey = true;
	}

	down_read(&key->sem);
	payload = key->payload.data[0];
	rc = nvdimm->security_ops->erase(nvdimm_bus, nvdimm,
			(void *)payload->data);
	up_read(&key->sem);

	/* remove key since secure erase kills the passphrase */
	if (!is_userkey) {
		key_invalidate(key);
		nvdimm->key = NULL;
	}
	key_put(key);

 out:
	mutex_unlock(&nvdimm->key_mutex);
	nvdimm_bus_unlock(&nvdimm_bus->dev);
	nvdimm_security_get_state(dev);
	return rc;
}

int nvdimm_security_freeze_lock(struct device *dev)
{
	struct nvdimm *nvdimm = to_nvdimm(dev);
	struct nvdimm_bus *nvdimm_bus = walk_to_nvdimm_bus(dev);
	int rc;

	if (!nvdimm->security_ops)
		return -EOPNOTSUPP;

	if (nvdimm->state == NVDIMM_SECURITY_UNSUPPORTED)
		return -EOPNOTSUPP;

	rc = nvdimm->security_ops->freeze_lock(nvdimm_bus, nvdimm);
	if (rc < 0)
		return rc;

	nvdimm_security_get_state(dev);
	return 0;
}

int nvdimm_security_disable(struct device *dev, unsigned int keyid)
{
	struct nvdimm *nvdimm = to_nvdimm(dev);
	struct nvdimm_bus *nvdimm_bus = walk_to_nvdimm_bus(dev);
	struct key *key;
	int rc;
	struct user_key_payload *payload;
	bool is_userkey = false;

	if (!nvdimm->security_ops)
		return -EOPNOTSUPP;

	if (nvdimm->state == NVDIMM_SECURITY_UNSUPPORTED)
		return -EOPNOTSUPP;

	mutex_lock(&nvdimm->key_mutex);
	/* look for a key from cached key */
	key = nvdimm_get_and_verify_key(dev, keyid);
	if (IS_ERR(key)) {
		mutex_unlock(&nvdimm->key_mutex);
		return PTR_ERR(key);
	}
	if (!key) {
		/* get old user key */
		key = nvdimm_lookup_user_key(dev, keyid);
		if (!key) {
			mutex_unlock(&nvdimm->key_mutex);
			return -ENOKEY;
		}
		is_userkey = true;
	}

	down_read(&key->sem);
	payload = key->payload.data[0];

	rc = nvdimm->security_ops->disable(nvdimm_bus, nvdimm,
			(void *)payload->data);
	up_read(&key->sem);
	if (rc < 0) {
		dev_warn(dev, "unlock failed\n");
		goto out;
	}

	/* If we succeed then remove the key */
	if (!is_userkey) {
		key_invalidate(key);
		nvdimm->key = NULL;
	}
	key_put(key);

 out:
	mutex_unlock(&nvdimm->key_mutex);
	nvdimm_security_get_state(dev);
	return rc;
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

int nvdimm_security_change_key(struct device *dev,
		unsigned int old_keyid, unsigned int new_keyid)
{
	struct nvdimm *nvdimm = to_nvdimm(dev);
	struct nvdimm_bus *nvdimm_bus = walk_to_nvdimm_bus(dev);
	struct key *key, *old_key;
	int rc;
	void *old_data = NULL, *new_data;
	bool update = false;
	struct user_key_payload *payload, *old_payload;

	if (!nvdimm->security_ops)
		return -EOPNOTSUPP;

	if (nvdimm->state == NVDIMM_SECURITY_FROZEN)
		return -EBUSY;

	mutex_lock(&nvdimm->key_mutex);
	/* look for a key from cached key if exists */
	old_key = nvdimm_get_and_verify_key(dev, old_keyid);
	if (IS_ERR(old_key)) {
		mutex_unlock(&nvdimm->key_mutex);
		return PTR_ERR(old_key);
	}
	if (old_key) {
		dev_dbg(dev, "%s: old key: %#x\n",
				__func__, key_serial(old_key));
		update = true;
	}

	/* request new key from userspace */
	key = nvdimm_lookup_user_key(dev, new_keyid);
	if (!key) {
		dev_dbg(dev, "%s: failed to acquire new key\n", __func__);
		rc = -ENXIO;
		goto out;
	}

	dev_dbg(dev, "%s: new key: %#x\n", __func__, key_serial(key));

	down_read(&key->sem);
	payload = key->payload.data[0];
	rc = nvdimm_check_key_len(payload->datalen);
	if (rc < 0) {
		up_read(&key->sem);
		goto out;
	}

	if (!update)
		key = nvdimm_replace_key(key);

	/*
	 * We don't need to release key->sem here because
	 * nvdimm_replace_key() will.
	 */
	if (!key)
		goto out;

	payload = key->payload.data[0];

	if (old_key) {
		down_read(&old_key->sem);
		old_payload = old_key->payload.data[0];
		old_data = old_payload->data;
	}

	new_data = payload->data;

	rc = nvdimm->security_ops->change_key(nvdimm_bus, nvdimm, old_data,
			new_data);
	/* copy new payload to old payload */
	if (rc == 0) {
		if (update)
			key_update(make_key_ref(old_key, 1), new_data,
					old_key->datalen);
	} else
		dev_warn(dev, "key update failed\n");
	if (old_key)
		up_read(&old_key->sem);
	up_read(&key->sem);

	if (!update) {
		if (rc == 0) {
			dev_dbg(dev, "key cached: %#x\n", key_serial(key));
			nvdimm->key = key;
		} else
			key_invalidate(key);
	}
	nvdimm_security_get_state(dev);

 out:
	mutex_unlock(&nvdimm->key_mutex);
	return rc;
}
