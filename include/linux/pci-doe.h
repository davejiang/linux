/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Data Object Exchange
 *	PCIe r6.0, sec 6.30 DOE
 *
 * Copyright (C) 2021 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022 Intel Corporation
 *	Ira Weiny <ira.weiny@intel.com>
 */

#ifndef LINUX_PCI_DOE_H
#define LINUX_PCI_DOE_H

struct pci_doe_mb;

/* Max data object length is 2^18 dwords (including 2 dwords for header) */
#define PCI_DOE_MAX_LENGTH	(1 << 18)
#define PCI_DOE_MAX_PAYLOAD	((PCI_DOE_MAX_LENGTH - 2) * sizeof(u32))

struct pci_doe_mb *pci_find_doe_mailbox(struct pci_dev *pdev, u16 vendor,
					u8 type);

int pci_doe(struct pci_doe_mb *doe_mb, u16 vendor, u8 type,
	    const void *request, size_t request_sz,
	    void *response, size_t response_sz);

#endif
