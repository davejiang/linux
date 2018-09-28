/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2018 Intel Corporation. All rights reserved. */
/*
 * Intel specific definitions for NVDIMM Firmware Interface Table - NFIT
 */
#ifndef _NFIT_INTEL_H_
#define _NFIT_INTEL_H_

#ifdef CONFIG_X86

extern const struct nvdimm_security_ops intel_security_ops;

#define ND_INTEL_STATUS_SIZE		4
#define ND_INTEL_PASSPHRASE_SIZE	32

#define ND_INTEL_STATUS_RETRY		5
#define ND_INTEL_STATUS_NOT_READY	9
#define ND_INTEL_STATUS_INVALID_STATE	10
#define ND_INTEL_STATUS_INVALID_PASS	11

#define ND_INTEL_SEC_STATE_ENABLED	0x02
#define ND_INTEL_SEC_STATE_LOCKED	0x04
#define ND_INTEL_SEC_STATE_FROZEN	0x08
#define ND_INTEL_SEC_STATE_PLIMIT	0x10
#define ND_INTEL_SEC_STATE_UNSUPPORTED	0x20

struct nd_intel_get_security_state {
	u32 status;
	u32 reserved;
	u8 state;
	u8 reserved1[3];
} __packed;

struct nd_intel_set_passphrase {
	u8 old_pass[ND_INTEL_PASSPHRASE_SIZE];
	u8 new_pass[ND_INTEL_PASSPHRASE_SIZE];
	u32 status;
} __packed;

struct nd_intel_unlock_unit {
	u8 passphrase[ND_INTEL_PASSPHRASE_SIZE];
	u32 status;
} __packed;

struct nd_intel_disable_passphrase {
	u8 passphrase[ND_INTEL_PASSPHRASE_SIZE];
	u32 status;
} __packed;

struct nd_intel_freeze_lock {
	u32 status;
} __packed;

struct nd_intel_secure_erase {
	u8 passphrase[ND_INTEL_PASSPHRASE_SIZE];
	u32 status;
} __packed;

struct nd_intel_overwrite {
	u8 passphrase[ND_INTEL_PASSPHRASE_SIZE];
	u32 status;
} __packed;

struct nd_intel_query_overwrite {
	u32 status;
} __packed;
#endif /* CONFIG_X86 */

static inline const struct nvdimm_security_ops *
acpi_nfit_get_security_ops(int family)
{
	switch (family) {
#ifdef CONFIG_X86
	case NVDIMM_FAMILY_INTEL:
		return &intel_security_ops;
#endif
	default:
		return NULL;
	}
}

#endif
