// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2018 Intel Corporation. All rights reserved. */
#include <linux/libnvdimm.h>
#include <linux/ndctl.h>
#include <linux/acpi.h>
#include "intel.h"
#include "nfit.h"

static enum nvdimm_security_state intel_security_state(struct nvdimm *nvdimm)
{
	struct nfit_mem *nfit_mem = nvdimm_provider_data(nvdimm);
	struct {
		struct nd_cmd_pkg pkg;
		struct nd_intel_get_security_state cmd;
	} nd_cmd = {
		.pkg = {
			.nd_command = NVDIMM_INTEL_GET_SECURITY_STATE,
			.nd_family = NVDIMM_FAMILY_INTEL,
			.nd_size_out =
				sizeof(struct nd_intel_get_security_state),
			.nd_fw_size =
				sizeof(struct nd_intel_get_security_state),
		},
	};
	int rc;

	if (!test_bit(NVDIMM_INTEL_GET_SECURITY_STATE, &nfit_mem->dsm_mask))
		return -ENXIO;

	rc = nvdimm_ctl(nvdimm, ND_CMD_CALL, &nd_cmd, sizeof(nd_cmd), NULL);
	if (rc < 0)
		return rc;
	if (nd_cmd.cmd.status)
		return -EIO;

	/* check and see if security is enabled and locked */
	if (nd_cmd.cmd.state & ND_INTEL_SEC_STATE_UNSUPPORTED)
		return -ENXIO;
	else if (nd_cmd.cmd.state & ND_INTEL_SEC_STATE_ENABLED) {
		if (nd_cmd.cmd.state & ND_INTEL_SEC_STATE_LOCKED)
			return NVDIMM_SECURITY_LOCKED;
		else if (nd_cmd.cmd.state & ND_INTEL_SEC_STATE_FROZEN ||
				nd_cmd.cmd.state & ND_INTEL_SEC_STATE_PLIMIT)
			return NVDIMM_SECURITY_FROZEN;
		else
			return NVDIMM_SECURITY_UNLOCKED;
	}
	return NVDIMM_SECURITY_DISABLED;
}

static int intel_security_freeze(struct nvdimm *nvdimm)
{
	struct nfit_mem *nfit_mem = nvdimm_provider_data(nvdimm);
	struct {
		struct nd_cmd_pkg pkg;
		struct nd_intel_freeze_lock cmd;
	} nd_cmd = {
		.pkg = {
			.nd_command = NVDIMM_INTEL_FREEZE_LOCK,
			.nd_family = NVDIMM_FAMILY_INTEL,
			.nd_size_out = ND_INTEL_STATUS_SIZE,
			.nd_fw_size = ND_INTEL_STATUS_SIZE,
		},
	};
	int rc;

	if (!test_bit(NVDIMM_INTEL_FREEZE_LOCK, &nfit_mem->dsm_mask))
		return -ENOTTY;

	rc = nvdimm_ctl(nvdimm, ND_CMD_CALL, &nd_cmd, sizeof(nd_cmd), NULL);
	if (rc < 0)
		return rc;
	if (nd_cmd.cmd.status)
		return -EIO;
	return 0;
}

static int intel_security_change_key(struct nvdimm *nvdimm,
		const struct nvdimm_key_data *old_data,
		const struct nvdimm_key_data *new_data)
{
	struct nfit_mem *nfit_mem = nvdimm_provider_data(nvdimm);
	struct {
		struct nd_cmd_pkg pkg;
		struct nd_intel_set_passphrase cmd;
	} nd_cmd = {
		.pkg = {
			.nd_command = NVDIMM_INTEL_SET_PASSPHRASE,
			.nd_family = NVDIMM_FAMILY_INTEL,
			.nd_size_in = ND_INTEL_PASSPHRASE_SIZE * 2,
			.nd_size_out = ND_INTEL_STATUS_SIZE,
			.nd_fw_size = ND_INTEL_STATUS_SIZE,
		},
	};
	int rc;

	if (!test_bit(NVDIMM_INTEL_SET_PASSPHRASE, &nfit_mem->dsm_mask))
		return -ENOTTY;

	if (old_data)
		memcpy(nd_cmd.cmd.old_pass, old_data->data,
				sizeof(nd_cmd.cmd.old_pass));
	memcpy(nd_cmd.cmd.new_pass, new_data->data,
			sizeof(nd_cmd.cmd.new_pass));
	rc = nvdimm_ctl(nvdimm, ND_CMD_CALL, &nd_cmd, sizeof(nd_cmd), NULL);
	if (rc < 0)
		return rc;

	switch (nd_cmd.cmd.status) {
	case 0:
		return 0;
	case ND_INTEL_STATUS_INVALID_PASS:
		return -EINVAL;
	case ND_INTEL_STATUS_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	case ND_INTEL_STATUS_INVALID_STATE:
	default:
		return -EIO;
	}
}

static void nvdimm_invalidate_cache(void);

static int intel_security_unlock(struct nvdimm *nvdimm,
		const struct nvdimm_key_data *key_data)
{
	struct nfit_mem *nfit_mem = nvdimm_provider_data(nvdimm);
	struct {
		struct nd_cmd_pkg pkg;
		struct nd_intel_unlock_unit cmd;
	} nd_cmd = {
		.pkg = {
			.nd_command = NVDIMM_INTEL_UNLOCK_UNIT,
			.nd_family = NVDIMM_FAMILY_INTEL,
			.nd_size_in = ND_INTEL_PASSPHRASE_SIZE,
			.nd_size_out = ND_INTEL_STATUS_SIZE,
			.nd_fw_size = ND_INTEL_STATUS_SIZE,
		},
	};
	int rc;

	if (!test_bit(NVDIMM_INTEL_UNLOCK_UNIT, &nfit_mem->dsm_mask))
		return -ENOTTY;

	memcpy(nd_cmd.cmd.passphrase, key_data->data,
			sizeof(nd_cmd.cmd.passphrase));
	rc = nvdimm_ctl(nvdimm, ND_CMD_CALL, &nd_cmd, sizeof(nd_cmd), NULL);
	if (rc < 0)
		return rc;
	switch (nd_cmd.cmd.status) {
	case 0:
		break;
	case ND_INTEL_STATUS_INVALID_PASS:
		return -EINVAL;
	default:
		return -EIO;
	}

	/* DIMM unlocked, invalidate all CPU caches before we read it */
	nvdimm_invalidate_cache();

	return 0;
}

static int intel_security_disable(struct nvdimm *nvdimm,
		const struct nvdimm_key_data *key_data)
{
	int rc;
	struct nfit_mem *nfit_mem = nvdimm_provider_data(nvdimm);
	struct {
		struct nd_cmd_pkg pkg;
		struct nd_intel_disable_passphrase cmd;
	} nd_cmd = {
		.pkg = {
			.nd_command = NVDIMM_INTEL_DISABLE_PASSPHRASE,
			.nd_family = NVDIMM_FAMILY_INTEL,
			.nd_size_in = ND_INTEL_PASSPHRASE_SIZE,
			.nd_size_out = ND_INTEL_STATUS_SIZE,
			.nd_fw_size = ND_INTEL_STATUS_SIZE,
		},
	};

	if (!test_bit(NVDIMM_INTEL_DISABLE_PASSPHRASE, &nfit_mem->dsm_mask))
		return -ENOTTY;

	memcpy(nd_cmd.cmd.passphrase, key_data->data,
			sizeof(nd_cmd.cmd.passphrase));
	rc = nvdimm_ctl(nvdimm, ND_CMD_CALL, &nd_cmd, sizeof(nd_cmd), NULL);
	if (rc < 0)
		return rc;

	switch (nd_cmd.cmd.status) {
	case 0:
		break;
	case ND_INTEL_STATUS_INVALID_PASS:
		return -EINVAL;
	case ND_INTEL_STATUS_INVALID_STATE:
	default:
		return -ENXIO;
	}

	return 0;
}

/*
 * TODO: define a cross arch wbinvd equivalent when/if
 * NVDIMM_FAMILY_INTEL command support arrives on another arch.
 */
#ifdef CONFIG_X86
static void nvdimm_invalidate_cache(void)
{
	wbinvd_on_all_cpus();
}
#else
static void nvdimm_invalidate_cache(void)
{
	WARN_ON_ONCE("cache invalidation required after unlock\n");
}
#endif

static const struct nvdimm_security_ops __intel_security_ops = {
	.state = intel_security_state,
	.freeze = intel_security_freeze,
	.change_key = intel_security_change_key,
	.disable = intel_security_disable,
#ifdef CONFIG_X86
	.unlock = intel_security_unlock,
#endif
};

const struct nvdimm_security_ops *intel_security_ops = &__intel_security_ops;
