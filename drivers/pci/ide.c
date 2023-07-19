// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/pci.h>
#include "pci.h"

/*
 * The verification function assumes the devices are passed in with pdev1
 * upstream of pdev2 if the link is not P2P.
 */
static int pcie_ide_stream_validate(struct pci_dev *pdev1, struct pci_dev *pdev2,
				    enum pci_ide_stream_type type)
{
	if (!pci_is_pcie(pdev1) || !pci_is_pcie(pdev2))
		return -EINVAL;

	if (!pdev1->ide_support || !pdev2->ide_support)
		return -EOPNOTSUPP;

	if (!test_bit(PCI_CMA_AUTHENTICATED, &pdev2->priv_flags))
		return -ENXIO;

	if (pci_pcie_type(pdev1) != PCI_EXP_TYPE_ROOT_PORT &&
	    !test_bit(PCI_CMA_AUTHENTICATED, &pdev1->priv_flags))
			return -EOPNOTSUPP;

	/*
	 * If the pdev1 is an upstream port, then a stream cannot be formed. The
	 * upstream port should be passed in as pdev2 in order to form a link stream
	 * with a downstream port (not of the same switch) or a root port.
	 */
	if (pci_pcie_type(pdev1) == PCI_EXP_TYPE_UPSTREAM)
		return -EINVAL;

	/*
	 * Cannot form a link if the second device is a downstream port or a root
	 * port.
	 */
	if (pci_pcie_type(pdev2) == PCI_EXP_TYPE_ROOT_PORT ||
	    pci_pcie_type(pdev2) == PCI_EXP_TYPE_DOWNSTREAM)
		return -EINVAL;

	return 0;
}

static bool is_pci_endpoint(struct pci_dev *pdev)
{
	return pci_pcie_type(pdev) == PCI_EXP_TYPE_ENDPOINT ||
	       pci_pcie_type(pdev) == PCI_EXP_TYPE_RC_END;
}

static bool is_stream_p2p(struct pci_dev *pdev1, struct pci_dev *pdev2)
{
	return is_pci_endpoint(pdev1) && is_pci_endpoint(pdev2);
}

/**
 * pcie_ide_stream_shutdown() - teardown an IDE stream between the two PCIe devices
 *
 * @pdev1: device 1 for the IDE stream, typically the Root Port
 * @pdev2: device 2 for the IDE stream, typically the End Point
 * @ep: the endpoint device for the IDE stream
 * @type: link or selective IDE stream
 *
 * Returns 0 on sucess or -errno for failures.
 */
void pcie_ide_stream_shutdown(struct pci_dev *pdev1, struct pci_dev *pdev2,
			      struct pci_dev *ep, enum pci_ide_stream_type type)
{
	struct pci_dev *itr, *prev;
	struct device *parent_dev;

	/* Reject p2p until support is implemented */
	if (is_stream_p2p(pdev1, pdev2))
		return;

	if (pcie_ide_stream_validate(pdev1, pdev2, pdev2->ide.stream_type))
		return;

	prev = pdev2;
	itr = to_pci_dev(pdev2->dev.parent);
	while (itr && dev_is_pci(&itr->dev)) {
		if (!itr->ide.ops || !itr->ide.ops->stream_shutdown)
			return;

		if (!itr->ide.secure)
			continue;

		itr->ide.ops->stream_shutdown(itr, prev, ep, type);

		prev = itr;
		parent_dev = itr->dev.parent;
		if (!dev_is_pci(parent_dev))
			break;
		itr = to_pci_dev(parent_dev);
	}
}
EXPORT_SYMBOL_GPL(pcie_ide_stream_shutdown);

/**
 * pcie_ide_stream_create() - Create an IDE stream between the two PCIe devices
 *
 * @pdev1: device 1 for the IDE stream, typically the Root Port
 * @pdev2: device 2 for the IDE stream, typically the End Point
 * @ep: the endpoint device for the IDE stream
 * @type: link or selective IDE stream
 *
 * Returns 0 on sucess or -errno for failures.
 */
int pcie_ide_stream_create(struct pci_dev *pdev1, struct pci_dev *pdev2,
			   struct pci_dev *ep, enum pci_ide_stream_type type)
{
	struct pci_dev *itr, *prev;
	struct device *parent_dev;
	int rc;

	/* Reject now until support is implemented */
	if (type == PCI_IDE_STREAM_TYPE_LINK)
		return -EOPNOTSUPP;

	/* Reject p2p until support is implemented */
	if (is_stream_p2p(pdev1, pdev2))
		return -EOPNOTSUPP;

	rc = pcie_ide_stream_validate(pdev1, pdev2, type);
	if (rc)
		return rc;

	prev = pdev2;
	itr = to_pci_dev(pdev2->dev.parent);
	while (itr && dev_is_pci(&itr->dev)) {
		if (!itr->ide.ops || !itr->ide.ops->stream_create) {
			rc = -ENXIO;
			goto err;
		}

		rc = itr->ide.ops->stream_create(itr, prev, ep, type);
		if (rc) {
			rc = -ENXIO;
			goto err;
		}

		prev = itr;
		parent_dev = itr->dev.parent;
		if (!dev_is_pci(parent_dev))
			break;
		itr = to_pci_dev(parent_dev);
	}

	return 0;

err:
	pcie_ide_stream_shutdown(pdev1, pdev2, ep, type);
	return rc;
}
EXPORT_SYMBOL_GPL(pcie_ide_stream_create);

void pci_ide_init(struct pci_dev *pdev)
{
	int link_num = 0, select_num = 0, pos;
	u32 cap;
	int rc;

	if (!pci_is_pcie(pdev))
		return;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_IDE);
	if (!pos)
		return;

	pci_read_config_dword(pdev, pos + PCI_IDE_CAP, &cap);
	if (!(cap & (PCI_IDE_CAP_LNK | PCI_IDE_CAP_SEL)))
		return;

	if (cap & PCI_IDE_CAP_LNK)
		link_num = 1 + FIELD_GET(PCI_IDE_CAP_LNK_NUM, cap);

	if (cap & PCI_IDE_CAP_SEL)
		select_num = 1 + FIELD_GET(PCI_IDE_CAP_SEL_NUM, cap);

	pdev->ide_support = true;
	pdev->ide.link_num = link_num;
	pdev->ide.select_num = select_num;
	pdev->ide.stream_min = 0;
	pdev->ide.stream_max = link_num + select_num;
	ida_init(&pdev->ide.stream_pos_ids);
	ida_init(&pdev->ide.stream_ids);
	mutex_init(&pdev->ide.lock);

	/* No CMA established, just exit */
	if (!test_bit(PCI_CMA_AUTHENTICATED, &pdev->priv_flags))
		return;

	if (is_pci_endpoint(pdev)) {
		struct pci_dev *rp = pcie_find_root_port(pdev);

		rc = pcie_ide_stream_create(rp, pdev, pdev,
					    PCI_IDE_STREAM_TYPE_SELECTIVE);
		if (rc) {
			dev_dbg(&pdev->dev,
				"Failed to establish IDE stream.\n");
			return;
		}
	}
}

void pci_ide_release(struct pci_dev *pdev)
{
	if (is_pci_endpoint(pdev)) {
		struct pci_dev *rp = pcie_find_root_port(pdev);

		pcie_ide_stream_shutdown(rp, pdev, pdev,
					 PCI_IDE_STREAM_TYPE_SELECTIVE);
	}

	guard(mutex)(&pdev->ide.lock);
	ida_destroy(&pdev->ide.stream_ids);
	ida_destroy(&pdev->ide.stream_pos_ids);
}
