// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/pci.h>
#include <linux/pci-ide.h>
#include <linux/cleanup.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include "pci.h"

static int pci_ide_get_reg_block_pos(struct pci_dev *pdev, int id);

static int pcie_ide_link_stream_validate(struct pci_dev *pdev1,
					 struct pci_dev *pdev2,
					 enum pci_ide_stream_type type)
{
	if ((pci_pcie_type(pdev1) == PCI_EXP_TYPE_ROOT_PORT ||
	     pci_pcie_type(pdev1) == PCI_EXP_TYPE_DOWNSTREAM) &&
	    (pci_pcie_type(pdev2) != PCI_EXP_TYPE_ENDPOINT ||
	     pci_pcie_type(pdev2) != PCI_EXP_TYPE_RC_END ||
	     pci_pcie_type(pdev2) != PCI_EXP_TYPE_UPSTREAM))
		return -EINVAL;

	return 0;
}

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

	if (type == PCI_IDE_STREAM_TYPE_LINK) {
		int rc = pcie_ide_link_stream_validate(pdev1, pdev2, type);

		if (rc)
			return -EINVAL;
	}

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


static int pcie_ep_ide_stream_create(struct pci_dev *pdev1, struct pci_dev *pdev2,
				     struct pci_dev *ep, enum pci_ide_stream_type type)
{
	/* Unless this is a P2P stream setup, there's nothing to do */
	return 0;
}

static void pcie_ep_ide_stream_shutdown(struct pci_dev *pdev1, struct pci_dev *pdev2,
					struct pci_dev *ep, enum pci_ide_stream_type type)
{
}

static const struct pci_ide_ops pcie_ep_ide_ops = {
	.stream_create = pcie_ep_ide_stream_create,
	.stream_shutdown = pcie_ep_ide_stream_shutdown,
};

DEFINE_FREE(keyset_free, struct key_package *, if (_T) ide_km_keyset_free(_T))
static void pcie_usp_ide_stream_key_refresh(struct work_struct *work)
{
	struct pci_ide *ide = container_of(work, struct pci_ide, dwork.work);
	struct pci_dev *pdev2 = container_of(ide, struct pci_dev, ide);
	struct pci_dev *pdev1 = to_pci_dev(pdev2->dev.parent);
	struct key_package *pkg __free(keyset_free) = ide_km_keyset_alloc();
	int keyset, rc, stream_id;

	if (!pkg)
		return;

	guard(mutex)(&pdev1->ide.lock);
	guard(mutex)(&pdev2->ide.lock);

	keyset = next_keyset(pdev2->ide.keyset);
	stream_id = pdev2->ide.stream_id;

	rc = ide_km_set_keyset(pdev1, stream_id, keyset, pkg, IDE_DEV_UPSTREAM);
	if (rc)
		return;

	rc = ide_km_set_keyset(pdev2, stream_id, keyset, pkg, IDE_DEV_DOWNSTREAM);
	if (rc)
		return;

	rc = ide_km_enable_keyset(pdev1, stream_id, keyset, IDE_STREAM_RX);
	if (rc)
		return;

	rc = ide_km_enable_keyset(pdev2, stream_id, keyset, IDE_STREAM_RX);
	if (rc)
		return;

	rc = ide_km_enable_keyset(pdev1, stream_id, keyset, IDE_STREAM_TX);
	if (rc)
		return;

	rc = ide_km_enable_keyset(pdev2, stream_id, keyset, IDE_STREAM_TX);
	if (rc)
		return;

	pdev2->ide.keyset = keyset;

	queue_delayed_work(system_wq, &pdev2->ide.dwork, msecs_to_jiffies(30) * 1000);
}

static int pcie_usp_ide_stream_create(struct pci_dev *pdev1, struct pci_dev *pdev2,
				      struct pci_dev *ep, enum pci_ide_stream_type type)
{
	u32 ctrl;
	int pos;

	guard(mutex)(&pdev1->ide.lock);
	if (type == PCI_IDE_STREAM_TYPE_SELECTIVE) {
		pos = pci_find_ext_capability(pdev1, PCI_EXT_CAP_ID_IDE);
		if (!pos)
			return pos;

		if (is_pci_endpoint(pdev1))
			return -EINVAL;

		/* Set Flow-Through IDE Stream Enabled */
		ctrl = PCI_IDE_CTRL_FLOWTH;
		pci_write_config_dword(pdev1, pos + PCI_IDE_CTRL, ctrl);

		return 0;
	}

	return 0;
}

static void pcie_usp_ide_stream_shutdown(struct pci_dev *pdev1, struct pci_dev *pdev2,
					 struct pci_dev *ep, enum pci_ide_stream_type type)
{
	int pos;

	guard(mutex)(&pdev1->ide.lock);
	if (type == PCI_IDE_STREAM_TYPE_SELECTIVE) {
		pos = pci_find_ext_capability(pdev1, PCI_EXT_CAP_ID_IDE);
		if (!pos)
			return;

		if (is_pci_endpoint(pdev1))
			return;

		/* Clear Flow-Through IDE Stream Enabled */
		pci_write_config_dword(pdev1, pos + PCI_IDE_CTRL, 0);
	}
}

static const struct pci_ide_ops pcie_usp_ide_ops = {
	.stream_create = pcie_usp_ide_stream_create,
	.stream_shutdown = pcie_usp_ide_stream_shutdown,
};

static int pcie_dsp_ide_stream_create(struct pci_dev *pdev1, struct pci_dev *pdev2,
				      struct pci_dev *ep, enum pci_ide_stream_type type)
{
	int pos, stream_id, keyset, rc;
	u32 ctrl;

	guard(mutex)(&pdev1->ide.lock);
	if (type == PCI_IDE_STREAM_TYPE_SELECTIVE) {
		pos = pci_find_ext_capability(pdev1, PCI_EXT_CAP_ID_IDE);
		if (!pos)
			return pos;

		/* Set Flow-Through IDE Stream Enabled */
		ctrl = PCI_IDE_CTRL_FLOWTH;
		pci_write_config_dword(pdev1, pos + PCI_IDE_CTRL, ctrl);

		return 0;
	}

	guard(mutex)(&pdev2->ide.lock);
	rc = pci_ide_stream_setup(pdev1, pdev2, type);
	if (rc)
		return rc;

	struct key_package *pkg __free(keyset_free) = ide_km_keyset_alloc();

	if (!pkg)
		return -ENOMEM;

	stream_id = ep->ide.stream_id;
	keyset = pdev2->ide.keyset;

	rc = ide_km_send_query(pdev1);
	if (rc)
		return rc;

	rc = ide_km_send_query(pdev2);
	if (rc)
		return rc;

	rc = ide_km_set_keyset(pdev1, stream_id, keyset, pkg,
			       IDE_DEV_UPSTREAM);
	if (rc)
		return rc;

	rc = ide_km_set_keyset(pdev2, stream_id, keyset, pkg,
			       IDE_DEV_DOWNSTREAM);
	if (rc)
		return rc;

	rc = ide_km_enable_keyset(pdev1, stream_id, keyset, IDE_STREAM_RX);
	if (rc)
		return rc;

	rc = ide_km_enable_keyset(pdev2, stream_id, keyset, IDE_STREAM_RX);
	if (rc)
		goto pdev2_rx_keyerr;

	rc = ide_km_enable_keyset(pdev1, stream_id, keyset, IDE_STREAM_TX);
	if (rc)
		goto pdev1_tx_keyerr;

	rc = ide_km_enable_keyset(pdev2, stream_id, keyset, IDE_STREAM_TX);
	if (rc)
		goto pdev2_tx_keyerr;

	rc = pci_ide_stream_enable(pdev1, pdev2, type);
	if (rc)
		goto stream_en_err;

	if (!ide_stream_is_secure(pdev2, true)) {
		rc = -ENXIO;
		goto stream_err;
	}

	pdev2->ide.stream_type = type;
	pdev2->ide.secure = true;

	queue_delayed_work(system_wq, &pdev2->ide.dwork, msecs_to_jiffies(30) * 1000);

	return 0;

stream_err:
	pci_ide_stream_disable(pdev1, pdev2, type);
stream_en_err:
	ide_km_disable_keyset(pdev2, stream_id, keyset, IDE_STREAM_TX);
pdev2_tx_keyerr:
	ide_km_disable_keyset(pdev1, stream_id, keyset, IDE_STREAM_TX);
pdev1_tx_keyerr:
	ide_km_disable_keyset(pdev2, stream_id, keyset, IDE_STREAM_RX);
pdev2_rx_keyerr:
	ide_km_disable_keyset(pdev1, stream_id, keyset, IDE_STREAM_RX);
	return rc;
}

static void pcie_dsp_ide_stream_shutdown(struct pci_dev *pdev1, struct pci_dev *pdev2,
					 struct pci_dev *ep, enum pci_ide_stream_type type)
{
	int pos, stream_id, keyset;

	guard(mutex)(&pdev1->ide.lock);
	if (type == PCI_IDE_STREAM_TYPE_SELECTIVE) {
		pos = pci_find_ext_capability(pdev1, PCI_EXT_CAP_ID_IDE);
		if (!pos)
			return;

		/* Clear Flow-Through IDE Stream Enabled */
		pci_write_config_dword(pdev1, pos + PCI_IDE_CTRL, 0);
		return;
	}

	guard(mutex)(&pdev2->ide.lock);
	stream_id = ep->ide.stream_id;
	keyset = pdev2->ide.keyset;

	cancel_delayed_work_sync(&pdev2->ide.dwork);

	ide_km_disable_keyset(pdev1, stream_id, keyset, IDE_STREAM_TX);
	ide_km_disable_keyset(pdev2, stream_id, keyset, IDE_STREAM_TX);
	ide_km_disable_keyset(pdev1, stream_id, keyset, IDE_STREAM_RX);
	ide_km_disable_keyset(pdev2, stream_id, keyset, IDE_STREAM_RX);
	pci_ide_stream_disable(pdev1, pdev2, PCI_IDE_STREAM_TYPE_LINK);
	pdev2->ide.stream_type = PCI_IDE_STREAM_TYPE_NONE;
	pdev2->ide.secure = false;
}

static const struct pci_ide_ops pcie_dsp_ide_ops = {
	.stream_create = pcie_dsp_ide_stream_create,
	.stream_shutdown = pcie_dsp_ide_stream_shutdown,
};

static int pci_ide_stream_id_alloc(struct pci_dev *pdev)
{
	if (!pci_is_pcie(pdev))
		return -EOPNOTSUPP;

	return ida_alloc_range(&pdev->ide.stream_ids, pdev->ide.stream_min,
			       pdev->ide.stream_max, GFP_KERNEL);
}

static void pci_ide_stream_id_free(struct pci_dev *pdev, int id)
{
	ida_free(&pdev->ide.stream_ids, id);
}

static int pci_ide_id_alloc(struct pci_dev *pdev, enum pci_ide_stream_type type)
{
	int min, max;

	if (type == PCI_IDE_STREAM_TYPE_LINK) {
		max = pdev->ide.link_num - 1;
		min = 0;
	} else {
		max = pdev->ide.link_num + pdev->ide.select_num - 1;
		min = pdev->ide.link_num;
	}

	return ida_alloc_range(&pdev->ide.stream_pos_ids, min, max, GFP_KERNEL);
}

static void pci_ide_id_free(struct pci_dev *pdev, int id)
{
	ida_free(&pdev->ide.stream_pos_ids, id);
}

static int pci_ide_get_reg_block_pos(struct pci_dev *pdev, int id)
{
	int pos, i;
	u32 reg;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_IDE);
	if (!pos)
		return -ENODEV;

	pos += PCI_IDE_CTRL + 4;
	for (i = 0; i < id; i++) {
		if (i < pdev->ide.link_num) {
			pos += PCI_IDE_LNK_REG_BLOCK_SIZE;
			continue;
		}

		pci_read_config_dword(pdev, pos, &reg);
		pos += PCI_IDE_ADDR_ASSOC_REG_BLOCK_OFFSET;
		pos += PCI_IDE_ADDR_ASSOC_REG_BLOCK_SIZE *
			FIELD_GET(PCI_IDE_SEL_CAP_NUM_ASSOC_BLK, reg);
	}

	return pos;
}

static void pci_ide_config_sel_stream_rp(struct pci_dev *pdev, int pos, int stream_id)
{
	struct resource *r = &pdev->resource[PCI_BRIDGE_MEM_WINDOW];
	int addr_assoc_pos;
	u32 reg;

	reg = FIELD_PREP(PCI_IDE_RID_ASSOC1_LIMIT, pci_dev_id(pdev) + 1);
	pci_write_config_dword(pdev, pos + PCI_IDE_RID_ASSOC1, reg);

	reg = FIELD_PREP(PCI_IDE_RID_ASSOC2_VALID, 1) |
	      FIELD_PREP(PCI_IDE_RID_ASSOC2_BASE, pci_dev_id(pdev));
	pci_write_config_dword(pdev, pos + PCI_IDE_RID_ASSOC2, reg);

	addr_assoc_pos = pos + PCI_IDE_RID_ASSOC2 + 4;
	reg = FIELD_PREP(PCI_IDE_ADDR_ASSOC1_VALID, 1) |
	      FIELD_PREP(PCI_IDE_ADDR_ASSOC1_MEM_BASE_LOWER,
			 lower_32_bits(r->start)) |
	      FIELD_PREP(PCI_IDE_ADDR_ASSOC1_MEM_LIMIT_LOWER,
			 lower_32_bits(r->end));
	pci_write_config_dword(pdev, addr_assoc_pos + PCI_IDE_ADDR_ASSOC1, reg);

	reg = FIELD_PREP(PCI_IDE_ADDR_ASSOC2_MEM_LIMIT_UPPER,
			 upper_32_bits(r->end));
	pci_write_config_dword(pdev, addr_assoc_pos + PCI_IDE_ADDR_ASSOC2, reg);

	reg = FIELD_PREP(PCI_IDE_ADDR_ASSOC3_MEM_BASE_UPPER,
			 upper_32_bits(r->start));
	pci_write_config_dword(pdev, addr_assoc_pos + PCI_IDE_ADDR_ASSOC3, reg);

	reg = FIELD_PREP(PCI_IDE_SEL_CTRL_STREAM_ID, stream_id) |
	      FIELD_PREP(PCI_IDE_SEL_CTRL_ALGO,
			 PCI_IDE_ALGO_AES_GCM_256_96B_MAC);
	pci_write_config_dword(pdev, pos + PCI_IDE_SEL_CTRL, reg);
}

static void pci_ide_config_sel_stream_ep(struct pci_dev *pdev, int pos, int stream_id)
{
	int addr_assoc_pos;
	u32 reg;

	reg = FIELD_PREP(PCI_IDE_RID_ASSOC1_LIMIT, 0xffff);
	pci_write_config_dword(pdev, pos + PCI_IDE_RID_ASSOC1, reg);

	reg = FIELD_PREP(PCI_IDE_RID_ASSOC2_VALID, 1) |
	      FIELD_PREP(PCI_IDE_RID_ASSOC2_BASE, 0);
	pci_write_config_dword(pdev, pos + PCI_IDE_RID_ASSOC2, reg);

	addr_assoc_pos = pos + PCI_IDE_RID_ASSOC2 + 4;
	reg = FIELD_PREP(PCI_IDE_ADDR_ASSOC1_VALID, 1) |
	      FIELD_PREP(PCI_IDE_ADDR_ASSOC1_MEM_LIMIT_LOWER, 0xfff) |
	      FIELD_PREP(PCI_IDE_ADDR_ASSOC1_MEM_BASE_LOWER, 0);
	pci_write_config_dword(pdev, addr_assoc_pos + PCI_IDE_ADDR_ASSOC1, reg);

	reg = FIELD_PREP(PCI_IDE_ADDR_ASSOC2_MEM_LIMIT_UPPER, 0xffffffff);
	pci_write_config_dword(pdev, addr_assoc_pos + PCI_IDE_ADDR_ASSOC2, reg);

	reg = FIELD_PREP(PCI_IDE_ADDR_ASSOC3_MEM_BASE_UPPER, 0);
	pci_write_config_dword(pdev, addr_assoc_pos + PCI_IDE_ADDR_ASSOC3, reg);

	reg = FIELD_PREP(PCI_IDE_SEL_CTRL_STREAM_ID, stream_id) |
	      FIELD_PREP(PCI_IDE_SEL_CTRL_ALGO,
			 PCI_IDE_ALGO_AES_GCM_256_96B_MAC) |
	      FIELD_PREP(PCI_IDE_SEL_CTRL_DEFAULT, 1);
	pci_write_config_dword(pdev, pos + PCI_IDE_SEL_CTRL, reg);
}

static enum pci_ide_stream_type ide_stream_type(struct pci_dev *pdev, int id)
{
	if (id < pdev->ide.link_num)
		return PCI_IDE_STREAM_TYPE_LINK;

	return PCI_IDE_STREAM_TYPE_SELECTIVE;
}

/**
 * is_ide_stream_secure - Check IDE stream status
 * @pdev: the downstream PCI device for the IDE stream
 * @wait: set true to wait 10ms for key to start
 *
 * Return true if link is secure or false if unsecure or error
 */
bool ide_stream_is_secure(struct pci_dev *pdev, bool wait)
{
	int pos_id, pos;
	u32 reg;

	if (pci_pcie_type(pdev) == PCI_EXP_TYPE_DOWNSTREAM ||
	    pci_pcie_type(pdev) == PCI_EXP_TYPE_ROOT_PORT)
		return false;

	pos_id = pdev->ide.pdev2_stream_pos_id;
	pos = pci_ide_get_reg_block_pos(pdev, pos_id);
	if (pos < 0)
		return false;

	/*
	 * PCIe base spec r6.0.1 6.33.3
	 * Transmission of stream must start not more than 10ms after K_SET_GO
	 */
	if (wait)
		msleep(10);

	if (ide_stream_type(pdev, pos_id) == PCI_IDE_STREAM_TYPE_LINK)
		pci_read_config_dword(pdev, pos + PCI_IDE_LNK_STATUS, &reg);
	else
		pci_read_config_dword(pdev, pos + PCI_IDE_SEL_STATUS, &reg);

	return FIELD_GET(PCI_IDE_STM_STATUS_MASK, reg) == PCI_IDE_STM_STATUS_SECURE;
}
EXPORT_SYMBOL_GPL(ide_stream_is_secure);

static void pci_ide_config_link_stream(struct pci_dev *pdev, int pos, int stream_id)
{
	u32 reg;

	reg = FIELD_PREP(PCI_IDE_LNK_CTRL_STREAM_ID, stream_id) |
	      FIELD_PREP(PCI_IDE_LNK_CTRL_ALGO,
			 PCI_IDE_ALGO_AES_GCM_256_96B_MAC) |
	pci_write_config_dword(pdev, pos + PCI_IDE_LNK_CTRL, reg);
}

/**
 * pci_ide_stream_setup - Setup the PCIe IDE config registers
 * @pdev1: the first PCI device of the IDE stream
 * @pdev2: the second PCI device of the IDE stream
 * @type: type of IDE stream (selective or link)
 *
 * The position ID for the PCI device allocates the IDE stream slot under the
 * IDE config register stream block, depending on if the stream is a select
 * stream or a link stream.
 *
 * Return 0 if success or -errno if failure.
 *
 */
int pci_ide_stream_setup(struct pci_dev *pdev1, struct pci_dev *pdev2,
			 enum pci_ide_stream_type type)
{
	int rc, pdev1_id, pdev2_id, pdev1_stm_pos, pdev2_stm_pos, stream_id;

	lockdep_assert_held(&pdev1->ide.lock);
	lockdep_assert_held(&pdev2->ide.lock);

	rc = pcie_ide_stream_validate(pdev1, pdev2, type);
	if (rc)
		return -EINVAL;

	pdev1_id = pci_ide_id_alloc(pdev1, type);
	if (pdev1_id < 0)
		return pdev1_id;

	pdev2_id = pci_ide_id_alloc(pdev2, type);
	if (pdev2_id < 0) {
		rc = pdev2_id;
		goto pdev2_id_alloc_err;
	}

	pdev1_stm_pos = pci_ide_get_reg_block_pos(pdev1, pdev1_id);
	if (pdev1_stm_pos < 0) {
		rc = pdev1_stm_pos;
		goto pdev1_pos_err;
	}

	pdev2_stm_pos = pci_ide_get_reg_block_pos(pdev2, pdev2_id);
	if (pdev2_stm_pos < 0) {
		rc = pdev2_stm_pos;
		goto pdev2_pos_err;
	}

	stream_id = pci_ide_stream_id_alloc(pdev1);
	if (stream_id < 0) {
		rc = stream_id;
		goto stm_id_err;
	}

	if (type == PCI_IDE_STREAM_TYPE_SELECTIVE) {
		pci_ide_config_sel_stream_rp(pdev1, pdev1_stm_pos, stream_id);
		pci_ide_config_sel_stream_ep(pdev2, pdev2_stm_pos, stream_id);
	} else {
		pci_ide_config_link_stream(pdev1, pdev1_stm_pos, stream_id);
		pci_ide_config_link_stream(pdev2, pdev2_stm_pos, stream_id);
	}

	/*
	 * The IDs are stored in the endpoint pci_dev only because only 1
	 * stream is created from the endpoing to the rootport. However, the
	 * root port will have multiple streams since there are multiple
	 * endpoints. It's the most convenient to store this information in the
	 * endpoint.
	 */
	pdev2->ide.pdev1_stream_pos_id = pdev1_id;
	pdev2->ide.pdev2_stream_pos_id = pdev2_id;
	pdev2->ide.stream_id = stream_id;

	return 0;

stm_id_err:
pdev2_pos_err:
pdev1_pos_err:
	pci_ide_id_free(pdev2, pdev2_id);
pdev2_id_alloc_err:
	pci_ide_id_free(pdev1, pdev1_id);
	return rc;
}
EXPORT_SYMBOL_GPL(pci_ide_stream_setup);

static int pci_ide_stream_ctrl(struct pci_dev *pdev, int pos_id,
			       enum pci_ide_stream_type type, bool enable)
{
	int stm_pos;
	u32 reg;

	lockdep_assert_held(&pdev->ide.lock);

	stm_pos = pci_ide_get_reg_block_pos(pdev, pos_id);
	if (stm_pos < 0)
		return stm_pos;

	if (type == PCI_IDE_STREAM_TYPE_SELECTIVE) {
		pci_read_config_dword(pdev, stm_pos + PCI_IDE_SEL_CTRL, &reg);
		if (enable)
			reg |= PCI_IDE_SEL_CTRL_ENABLE;
		else
			reg &= ~PCI_IDE_SEL_CTRL_ENABLE;
		pci_write_config_dword(pdev, stm_pos + PCI_IDE_SEL_CTRL, reg);
		return 0;
	}

	pci_read_config_dword(pdev, stm_pos + PCI_IDE_LNK_CTRL, &reg);
	if (enable)
		reg |= PCI_IDE_LNK_CTRL_ENABLE;
	else
		reg &= ~PCI_IDE_LNK_CTRL_ENABLE;
	pci_write_config_dword(pdev, stm_pos + PCI_IDE_LNK_CTRL, reg);

	return 0;
}

/**
 * pci_ide_stream_disable - disables the PCIe IDE stream
 * @pdev1: the first PCI device of the IDE stream
 * @pdev2: the second PCI device of the IDE stream
 * @type: type of IDE stream (selective or link)
 *
 * Returns 0 if success or -errno if failed.
 */
int pci_ide_stream_disable(struct pci_dev *pdev1, struct pci_dev *pdev2,
			   enum pci_ide_stream_type type)
{
	int pdev1_id = pdev2->ide.pdev1_stream_pos_id;
	int pdev2_id = pdev2->ide.pdev2_stream_pos_id;
	int rc;

	lockdep_assert_held(&pdev1->ide.lock);
	lockdep_assert_held(&pdev2->ide.lock);
	rc = pci_ide_stream_ctrl(pdev2, pdev2_id, type, false);
	if (rc < 0)
		return rc;

	return pci_ide_stream_ctrl(pdev1, pdev1_id, type, false);
}
EXPORT_SYMBOL_GPL(pci_ide_stream_disable);

/**
 * pci_ide_stream_enable - Enables the PCIe IDE stream
 * @pdev1: the first PCI device of the IDE stream
 * @pdev2: the second PCI device of the IDE stream
 * @type: type of IDE stream (selective or link)
 *
 * Returns 0 if success or -errno if failed.
 */
int pci_ide_stream_enable(struct pci_dev *pdev1, struct pci_dev *pdev2,
			  enum pci_ide_stream_type type)
{
	int pdev1_id = pdev2->ide.pdev1_stream_pos_id;
	int pdev2_id = pdev2->ide.pdev2_stream_pos_id;
	int rc;

	lockdep_assert_held(&pdev1->ide.lock);
	lockdep_assert_held(&pdev2->ide.lock);
	rc = pci_ide_stream_ctrl(pdev2, pdev2_id, type, true);
	if (rc < 0)
		return rc;

	return pci_ide_stream_ctrl(pdev1, pdev1_id, type, true);
}
EXPORT_SYMBOL_GPL(pci_ide_stream_enable);

/**
 * pci_ide_stream_release - Release resources allocated by the stream
 * @pdev1: the first PCI device of the IDE stream
 * @pdev2: the second PCI device of the IDE stream
 *
 * Returns 0 if success or -errno if failed.
 */
void pci_ide_stream_release(struct pci_dev *pdev1, struct pci_dev *pdev2)
{
	lockdep_assert_held(&pdev1->ide.lock);
	lockdep_assert_held(&pdev2->ide.lock);
	pci_ide_stream_id_free(pdev1, pdev2->ide.stream_id);
}
EXPORT_SYMBOL_GPL(pci_ide_stream_release);

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


	switch (pci_pcie_type(pdev)) {
	case PCI_EXP_TYPE_DOWNSTREAM:
		pdev->ide.ops = &pcie_dsp_ide_ops;
		break;
	case PCI_EXP_TYPE_UPSTREAM:
		pdev->ide.ops = &pcie_usp_ide_ops;
		INIT_DELAYED_WORK(&pdev->ide.dwork, pcie_usp_ide_stream_key_refresh);
		break;
	case PCI_EXP_TYPE_ENDPOINT:
	case PCI_EXP_TYPE_RC_END:
		pdev->ide.ops = &pcie_ep_ide_ops;
		break;
	default:	/* Do nothing, RP should be already set */
		break;
	}

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
