// SPDX-License-Identifier: GPL-2.0
/*
 * Component Measurement and Authentication (CMA-SPDM, PCIe r6.1 sec 6.31)
 *
 * Copyright (C) 2023 Intel Corporation
 */

#include <linux/pci.h>
#include <linux/sysfs.h>

#include "pci.h"

static ssize_t authenticated_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	ssize_t rc;

	if (!pdev->cma_capable &&
	    (pdev->cma_init_failed || pdev->doe_init_failed))
		return -ENOTTY;

	rc = pci_cma_reauthenticate(pdev);
	if (rc)
		return rc;

	return count;
}

static ssize_t authenticated_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	if (!pdev->cma_capable &&
	    (pdev->cma_init_failed || pdev->doe_init_failed))
		return -ENOTTY;

	return sysfs_emit(buf, "%u\n", test_bit(PCI_CMA_AUTHENTICATED,
						&pdev->priv_flags));
}
static DEVICE_ATTR_RW(authenticated);

static struct attribute *pci_cma_attrs[] = {
	&dev_attr_authenticated.attr,
	NULL
};

static umode_t pci_cma_attrs_are_visible(struct kobject *kobj,
					 struct attribute *a, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct pci_dev *pdev = to_pci_dev(dev);

	/*
	 * If CMA or DOE initialization failed, CMA attributes must be visible
	 * and return an error on access.  This prevents downgrade attacks
	 * where an attacker disturbs memory allocation or DOE communication
	 * in order to create the appearance that CMA is unsupported.
	 * The attacker may achieve that by simply hogging memory.
	 */
	if (!pdev->cma_capable &&
	    !pdev->cma_init_failed && !pdev->doe_init_failed)
		return 0;

	return a->mode;
}

const struct attribute_group pci_cma_attr_group = {
	.attrs  = pci_cma_attrs,
	.is_visible = pci_cma_attrs_are_visible,
};
