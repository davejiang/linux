// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2018 Intel Corporation. All rights reserved. */
/*
 * Intel specific NFIT ops
 */
#include <linux/libnvdimm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/ndctl.h>
#include <linux/sysfs.h>
#include <linux/delay.h>
#include <linux/acpi.h>
#include <linux/io.h>
#include <linux/nd.h>
#include <asm/cacheflush.h>
#include <asm/smp.h>
#include <acpi/nfit.h>
#include "intel.h"
#include "nfit.h"

static int intel_dimm_security_freeze_lock(struct nvdimm_bus *nvdimm_bus,
		struct nvdimm *nvdimm)
{
	struct nvdimm_bus_descriptor *nd_desc = to_nd_desc(nvdimm_bus);
	int cmd_rc, rc = 0;
	struct nfit_mem *nfit_mem = nvdimm_provider_data(nvdimm);
	struct {
		struct nd_cmd_pkg pkg;
		struct nd_intel_freeze_lock cmd;
	} nd_cmd = {
		.pkg = {
			.nd_command = NVDIMM_INTEL_FREEZE_LOCK,
			.nd_family = NVDIMM_FAMILY_INTEL,
			.nd_size_in = 0,
			.nd_size_out = ND_INTEL_STATUS_SIZE,
			.nd_fw_size = ND_INTEL_STATUS_SIZE,
		},
		.cmd = {
			.status = 0,
		},
	};

	if (!test_bit(NVDIMM_INTEL_FREEZE_LOCK, &nfit_mem->dsm_mask))
		return -ENOTTY;

	rc = nd_desc->ndctl(nd_desc, nvdimm, ND_CMD_CALL, &nd_cmd,
			sizeof(nd_cmd), &cmd_rc);
	if (rc < 0)
		goto out;
	if (cmd_rc < 0) {
		rc = cmd_rc;
		goto out;
	}

	switch (nd_cmd.cmd.status) {
	case 0:
		break;
	case ND_INTEL_STATUS_INVALID_STATE:
	default:
		rc = -ENXIO;
		goto out;
	}

 out:
	return rc;
}

static int intel_dimm_security_disable(struct nvdimm_bus *nvdimm_bus,
		struct nvdimm *nvdimm, const struct nvdimm_key_data *nkey)
{
	struct nvdimm_bus_descriptor *nd_desc = to_nd_desc(nvdimm_bus);
	int cmd_rc, rc = 0;
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
		.cmd = {
			.status = 0,
		},
	};

	if (!test_bit(NVDIMM_INTEL_DISABLE_PASSPHRASE, &nfit_mem->dsm_mask))
		return -ENOTTY;

	memcpy(nd_cmd.cmd.passphrase, nkey->data,
			sizeof(nd_cmd.cmd.passphrase));
	rc = nd_desc->ndctl(nd_desc, nvdimm, ND_CMD_CALL, &nd_cmd,
			sizeof(nd_cmd), &cmd_rc);
	if (rc < 0)
		goto out;
	if (cmd_rc < 0) {
		rc = cmd_rc;
		goto out;
	}

	switch (nd_cmd.cmd.status) {
	case 0:
		break;
	case ND_INTEL_STATUS_INVALID_PASS:
		rc = -EINVAL;
		goto out;
	case ND_INTEL_STATUS_INVALID_STATE:
	default:
		rc = -ENXIO;
		goto out;
	}

 out:
	return rc;
}

/*
 * The update passphrase takes the old passphrase and the new passphrase
 * and send those to the nvdimm. The nvdimm will verify the old
 * passphrase and then update it with the new passphrase if pending
 * verification. The function will pass in a zeroed passphrase field
 * if the old passphrase is NULL. This typically happens when we are
 * enabling security from the disabled state.
 */
static int intel_dimm_security_update_passphrase(
		struct nvdimm_bus *nvdimm_bus, struct nvdimm *nvdimm,
		const struct nvdimm_key_data *old_data,
		const struct nvdimm_key_data *new_data)
{
	struct nvdimm_bus_descriptor *nd_desc = to_nd_desc(nvdimm_bus);
	int cmd_rc, rc = 0;
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
		.cmd = {
			.status = 0,
		},
	};

	if (!test_bit(NVDIMM_INTEL_SET_PASSPHRASE, &nfit_mem->dsm_mask))
		return -ENOTTY;

	if (old_data)
		memcpy(nd_cmd.cmd.old_pass, old_data->data,
				sizeof(nd_cmd.cmd.old_pass));
	else
		memset(nd_cmd.cmd.old_pass, 0, sizeof(nd_cmd.cmd.old_pass));
	memcpy(nd_cmd.cmd.new_pass, new_data->data,
			sizeof(nd_cmd.cmd.new_pass));
	rc = nd_desc->ndctl(nd_desc, nvdimm, ND_CMD_CALL, &nd_cmd,
			sizeof(nd_cmd), &cmd_rc);
	if (rc < 0)
		goto out;
	if (cmd_rc < 0) {
		rc = cmd_rc;
		goto out;
	}

	switch (nd_cmd.cmd.status) {
	case 0:
		break;
	case ND_INTEL_STATUS_INVALID_PASS:
		rc = -EINVAL;
		goto out;
	case ND_INTEL_STATUS_INVALID_STATE:
	default:
		rc = -ENXIO;
		goto out;
	}

 out:
	return rc;
}

static int intel_dimm_security_unlock(struct nvdimm_bus *nvdimm_bus,
		struct nvdimm *nvdimm, const struct nvdimm_key_data *nkey)
{
	struct nvdimm_bus_descriptor *nd_desc = to_nd_desc(nvdimm_bus);
	int cmd_rc, rc = 0;
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
		.cmd = {
			.status = 0,
		},
	};

	if (!test_bit(NVDIMM_INTEL_UNLOCK_UNIT, &nfit_mem->dsm_mask))
		return -ENOTTY;

	memcpy(nd_cmd.cmd.passphrase, nkey->data,
			sizeof(nd_cmd.cmd.passphrase));
	rc = nd_desc->ndctl(nd_desc, nvdimm, ND_CMD_CALL, &nd_cmd,
			sizeof(nd_cmd), &cmd_rc);
	if (rc < 0)
		goto out;
	if (cmd_rc < 0) {
		rc = cmd_rc;
		goto out;
	}

	switch (nd_cmd.cmd.status) {
	case 0:
		break;
	case ND_INTEL_STATUS_INVALID_PASS:
		rc = -EINVAL;
		goto out;
	case ND_INTEL_STATUS_INVALID_STATE:
	default:
		rc = -ENXIO;
		goto out;
	}

	/*
	 * TODO: define a cross arch wbinvd when/if NVDIMM_FAMILY_INTEL
	 * support arrives on another arch.
	 */
	/* DIMM unlocked, invalidate all CPU caches before we read it */
	wbinvd_on_all_cpus();

 out:
	return rc;
}

static int intel_dimm_security_state(struct nvdimm_bus *nvdimm_bus,
		struct nvdimm *nvdimm, enum nvdimm_security_state *state)
{
	struct nvdimm_bus_descriptor *nd_desc = to_nd_desc(nvdimm_bus);
	int cmd_rc, rc = 0;
	struct nfit_mem *nfit_mem = nvdimm_provider_data(nvdimm);
	struct {
		struct nd_cmd_pkg pkg;
		struct nd_intel_get_security_state cmd;
	} nd_cmd = {
		.pkg = {
			.nd_command = NVDIMM_INTEL_GET_SECURITY_STATE,
			.nd_family = NVDIMM_FAMILY_INTEL,
			.nd_size_in = 0,
			.nd_size_out =
				sizeof(struct nd_intel_get_security_state),
			.nd_fw_size =
				sizeof(struct nd_intel_get_security_state),
		},
		.cmd = {
			.status = 0,
			.state = 0,
		},
	};

	if (!test_bit(NVDIMM_INTEL_GET_SECURITY_STATE, &nfit_mem->dsm_mask)) {
		*state = NVDIMM_SECURITY_UNSUPPORTED;
		return 0;
	}

	*state = NVDIMM_SECURITY_DISABLED;
	rc = nd_desc->ndctl(nd_desc, nvdimm, ND_CMD_CALL, &nd_cmd,
			sizeof(nd_cmd), &cmd_rc);
	if (rc < 0)
		goto out;
	if (cmd_rc < 0) {
		rc = cmd_rc;
		goto out;
	}

	switch (nd_cmd.cmd.status) {
	case 0:
		break;
	case ND_INTEL_STATUS_RETRY:
		rc = -EAGAIN;
		goto out;
	case ND_INTEL_STATUS_NOT_READY:
	default:
		rc = -ENXIO;
		goto out;
	}

	/* check and see if security is enabled and locked */
	if (nd_cmd.cmd.state & ND_INTEL_SEC_STATE_UNSUPPORTED)
		*state = NVDIMM_SECURITY_UNSUPPORTED;
	else if (nd_cmd.cmd.state & ND_INTEL_SEC_STATE_ENABLED) {
		if (nd_cmd.cmd.state & ND_INTEL_SEC_STATE_LOCKED)
			*state = NVDIMM_SECURITY_LOCKED;
		else if (nd_cmd.cmd.state & ND_INTEL_SEC_STATE_FROZEN ||
				nd_cmd.cmd.state & ND_INTEL_SEC_STATE_PLIMIT)
			*state = NVDIMM_SECURITY_FROZEN;
		else
			*state = NVDIMM_SECURITY_UNLOCKED;
	} else
		*state = NVDIMM_SECURITY_DISABLED;

 out:
	if (rc < 0)
		*state = NVDIMM_SECURITY_INVALID;
	return rc;
}

const struct nvdimm_security_ops intel_security_ops = {
	.state = intel_dimm_security_state,
	.unlock = intel_dimm_security_unlock,
	.change_key = intel_dimm_security_update_passphrase,
	.disable = intel_dimm_security_disable,
	.freeze_lock = intel_dimm_security_freeze_lock,
};
