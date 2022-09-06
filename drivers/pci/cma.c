// SPDX-License-Identifier: GPL-2.0
/*
 * Component Measurement and Authentication (CMA-SPDM, PCIe r6.1 sec 6.31)
 *
 * Copyright (C) 2021 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-23 Intel Corporation
 */

#define dev_fmt(fmt) "CMA: " fmt

#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/pm_runtime.h>
#include <linux/spdm.h>

#include "pci.h"

#define PCI_DOE_PROTOCOL_CMA 1

/* Keyring that userspace can poke certs into */
static struct key *cma_keyring;

static int spdm_doe_transport(void *priv, struct device *dev,
			      const void *request, size_t request_sz,
			      void *response, size_t response_sz)
{
	struct pci_doe_mb *doe = priv;
	int rc;

	/*
	 * CMA-SPDM operation in non-D0 states is optional (PCIe r6.1
	 * sec 6.31.3).  The spec does not define a way to determine
	 * if it's supported, so resume to D0 unconditionally.
	 */
	rc = pm_runtime_resume_and_get(dev);
	if (rc)
		return rc;

	rc = pci_doe(doe, PCI_VENDOR_ID_PCI_SIG, PCI_DOE_PROTOCOL_CMA,
		     request, request_sz, response, response_sz);

	pm_runtime_put(dev);

	return rc;
}

void pci_cma_init(struct pci_dev *pdev)
{
	struct pci_doe_mb *doe;
	int rc;

	if (!pci_is_pcie(pdev))
		return;

	doe = pci_find_doe_mailbox(pdev, PCI_VENDOR_ID_PCI_SIG,
				   PCI_DOE_PROTOCOL_CMA);
	if (!doe)
		return;

	pdev->spdm_state = spdm_create(&pdev->dev, spdm_doe_transport, doe,
				       PCI_DOE_MAX_PAYLOAD, cma_keyring);
	if (!pdev->spdm_state) {
		return;
	}

	rc = spdm_authenticate(pdev->spdm_state);
	if (rc)
		return;

	set_bit(PCI_CMA_AUTHENTICATED, &pdev->priv_flags);
}

void pci_cma_destroy(struct pci_dev *pdev)
{
	spdm_destroy(pdev->spdm_state);
}

__init static int cma_keyring_init(void)
{
	cma_keyring = keyring_alloc("_cma",
				    KUIDT_INIT(0), KGIDT_INIT(0),
				    current_cred(),
				    (KEY_POS_ALL & ~KEY_POS_SETATTR) |
				    KEY_USR_VIEW | KEY_USR_READ | KEY_USR_WRITE | KEY_USR_SEARCH,
				    KEY_ALLOC_NOT_IN_QUOTA | KEY_ALLOC_SET_KEEP, NULL, NULL);
	if (IS_ERR(cma_keyring))
		pr_err("Could not allocate cma keyring\n");

	return 0;
}
device_initcall(cma_keyring_init);
