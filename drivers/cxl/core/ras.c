// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2025 AMD Corporation. All rights reserved. */

#include <linux/pci.h>
#include <linux/aer.h>
#include <cxl/event.h>
#include <cxlmem.h>
#include <cxlpci.h>
#include "trace.h"

static void cxl_cper_trace_corr_port_prot_err(struct pci_dev *pdev,
					      struct cxl_ras_capability_regs ras_cap)
{
	u32 status = ras_cap.cor_status & ~ras_cap.cor_mask;

	trace_cxl_aer_correctable_error(&pdev->dev, status, 0);
}

static void cxl_cper_trace_uncorr_port_prot_err(struct pci_dev *pdev,
						struct cxl_ras_capability_regs ras_cap)
{
	u32 status = ras_cap.uncor_status & ~ras_cap.uncor_mask;
	u32 fe;

	if (hweight32(status) > 1)
		fe = BIT(FIELD_GET(CXL_RAS_CAP_CONTROL_FE_MASK,
				   ras_cap.cap_control));
	else
		fe = status;

	trace_cxl_aer_uncorrectable_error(&pdev->dev, status, fe,
					  ras_cap.header_log, 0);
}

static void cxl_cper_trace_corr_prot_err(struct cxl_memdev *cxlmd,
					 struct cxl_ras_capability_regs ras_cap)
{
	u32 status = ras_cap.cor_status & ~ras_cap.cor_mask;

	trace_cxl_aer_correctable_error(&cxlmd->dev, status, cxlmd->cxlds->serial);
}

static void
cxl_cper_trace_uncorr_prot_err(struct cxl_memdev *cxlmd,
			       struct cxl_ras_capability_regs ras_cap)
{
	u32 status = ras_cap.uncor_status & ~ras_cap.uncor_mask;
	struct cxl_dev_state *cxlds = cxlmd->cxlds;
	u32 fe;

	if (hweight32(status) > 1)
		fe = BIT(FIELD_GET(CXL_RAS_CAP_CONTROL_FE_MASK,
				   ras_cap.cap_control));
	else
		fe = status;

	trace_cxl_aer_uncorrectable_error(&cxlmd->dev, status, fe,
					  ras_cap.header_log,
					  cxlds->serial);
}

static int match_memdev_by_parent(struct device *dev, const void *uport)
{
	if (is_cxl_memdev(dev) && dev->parent == uport)
		return 1;
	return 0;
}

static void cxl_cper_handle_prot_err(struct cxl_cper_prot_err_work_data *data)
{
	unsigned int devfn = PCI_DEVFN(data->prot_err.agent_addr.device,
				       data->prot_err.agent_addr.function);
	struct pci_dev *pdev __free(pci_dev_put) =
		pci_get_domain_bus_and_slot(data->prot_err.agent_addr.segment,
					    data->prot_err.agent_addr.bus,
					    devfn);
	struct cxl_memdev *cxlmd;
	int port_type;

	if (!pdev)
		return;

	port_type = pci_pcie_type(pdev);
	if (port_type == PCI_EXP_TYPE_ROOT_PORT ||
	    port_type == PCI_EXP_TYPE_DOWNSTREAM ||
	    port_type == PCI_EXP_TYPE_UPSTREAM) {
		if (data->severity == AER_CORRECTABLE)
			cxl_cper_trace_corr_port_prot_err(pdev, data->ras_cap);
		else
			cxl_cper_trace_uncorr_port_prot_err(pdev, data->ras_cap);

		return;
	}

	guard(device)(&pdev->dev);
	if (!pdev->dev.driver)
		return;

	struct device *mem_dev __free(put_device) = bus_find_device(
		&cxl_bus_type, NULL, pdev, match_memdev_by_parent);
	if (!mem_dev)
		return;

	cxlmd = to_cxl_memdev(mem_dev);
	if (data->severity == AER_CORRECTABLE)
		cxl_cper_trace_corr_prot_err(cxlmd, data->ras_cap);
	else
		cxl_cper_trace_uncorr_prot_err(cxlmd, data->ras_cap);
}

static void cxl_cper_prot_err_work_fn(struct work_struct *work)
{
	struct cxl_cper_prot_err_work_data wd;

	while (cxl_cper_prot_err_kfifo_get(&wd))
		cxl_cper_handle_prot_err(&wd);
}
static DECLARE_WORK(cxl_cper_prot_err_work, cxl_cper_prot_err_work_fn);

static void cxl_dport_map_ras(struct cxl_dport *dport)
{
	struct cxl_register_map *map = &dport->reg_map;
	struct device *dev = dport->dport_dev;

	if (!map->component_map.ras.valid)
		dev_dbg(dev, "RAS registers not found\n");
	else if (cxl_map_component_regs(map, &dport->regs.component,
					BIT(CXL_CM_CAP_CAP_ID_RAS)))
		dev_dbg(dev, "Failed to map RAS capability.\n");
}

/**
 * devm_cxl_dport_ras_setup - Setup CXL RAS report on this dport
 * @dport: the cxl_dport that needs to be initialized
 */
void devm_cxl_dport_ras_setup(struct cxl_dport *dport)
{
	dport->reg_map.host = &dport->port->dev;
	cxl_dport_map_ras(dport);

	if (dport->rch) {
		struct pci_host_bridge *host_bridge =
			to_pci_host_bridge(dport->dport_dev);

		if (!host_bridge->native_aer)
			return;

		cxl_dport_map_rch_aer(dport);
		cxl_disable_rch_root_ints(dport);
	}
}
EXPORT_SYMBOL_NS_GPL(devm_cxl_dport_ras_setup, "CXL");

void devm_cxl_port_ras_setup(struct cxl_port *port)
{
	struct cxl_register_map *map = &port->reg_map;

	map->host = &port->dev;
	if (cxl_map_component_regs(map, &port->regs,
				   BIT(CXL_CM_CAP_CAP_ID_RAS)))
		dev_dbg(&port->dev, "Failed to map RAS capability\n");
}
EXPORT_SYMBOL_NS_GPL(devm_cxl_port_ras_setup, "CXL");

/*
 * Return 'struct cxl_port *' parent CXL Port of dev
 *
 * Reference count increments returned port on success
 *
 * @pdev: Find the parent CXL Port of this device
 */
static struct cxl_port *get_cxl_port(struct pci_dev *pdev)
{
	switch (pci_pcie_type(pdev)) {
	case PCI_EXP_TYPE_ROOT_PORT:
	case PCI_EXP_TYPE_DOWNSTREAM:
	{
		struct cxl_dport *dport;
		struct cxl_port *port = find_cxl_port(&pdev->dev, &dport);

		if (!port) {
			pci_err(pdev, "Failed to find the CXL device");
			return NULL;
		}
		return port;
	}
	case PCI_EXP_TYPE_UPSTREAM:
	case PCI_EXP_TYPE_ENDPOINT:
	{
		struct cxl_port *port = find_cxl_port_by_uport(&pdev->dev);

		if (!port) {
			pci_err(pdev, "Failed to find the CXL device");
			return NULL;
		}
		return port;
	}
	}
	pci_warn_once(pdev, "Error: Unsupported device type (%#x)", pci_pcie_type(pdev));
	return NULL;
}

static void __iomem *cxl_get_ras_base(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);

	switch (pci_pcie_type(pdev)) {
	case PCI_EXP_TYPE_ROOT_PORT:
	case PCI_EXP_TYPE_DOWNSTREAM:
	{
		struct cxl_dport *dport;
		struct cxl_port *port __free(put_cxl_port) = find_cxl_port(&pdev->dev, &dport);

		if (!dport) {
			pci_err(pdev, "Failed to find the CXL device");
			return NULL;
		}
		return dport->regs.ras;
	}
	case PCI_EXP_TYPE_UPSTREAM:
	case PCI_EXP_TYPE_ENDPOINT:
	{
		struct cxl_port *port __free(put_cxl_port) = find_cxl_port_by_uport(&pdev->dev);

		if (!port) {
			pci_err(pdev, "Failed to find the CXL device");
			return NULL;
		}
		return port->regs.ras;
	}
	}
	dev_warn_once(dev, "Error: Unsupported device type (%#x)", pci_pcie_type(pdev));
	return NULL;
}

static pci_ers_result_t cxl_port_error_detected(struct device *dev);

static void cxl_do_recovery(struct pci_dev *pdev)
{
	struct cxl_port *port __free(put_cxl_port) = get_cxl_port(pdev);
	pci_ers_result_t status;

	if (!port) {
		pci_err(pdev, "Failed to find the CXL device\n");
		return;
	}

	status = cxl_port_error_detected(&pdev->dev);
	if (status == PCI_ERS_RESULT_PANIC)
		panic("CXL cachemem error.");

	/*
	 * If we have native control of AER, clear error status in the device
	 * that detected the error.  If the platform retained control of AER,
	 * it is responsible for clearing this status.  In that case, the
	 * signaling device may not even be visible to the OS.
	 */
	if (pcie_aer_is_native(pdev)) {
		pcie_clear_device_status(pdev);
		pci_aer_clear_nonfatal_status(pdev);
		pci_aer_clear_fatal_status(pdev);
	}
}

void cxl_handle_cor_ras(struct device *dev, u64 serial, void __iomem *ras_base)
{
	void __iomem *addr;
	u32 status;

	if (!ras_base)
		return;

	addr = ras_base + CXL_RAS_CORRECTABLE_STATUS_OFFSET;
	status = readl(addr);
	if (!(status & CXL_RAS_CORRECTABLE_STATUS_MASK))
		return;
	writel(status & CXL_RAS_CORRECTABLE_STATUS_MASK, addr);

	if (is_cxl_memdev(dev))
		trace_cxl_aer_correctable_error(dev, status, serial);
	else
		trace_cxl_port_aer_correctable_error(dev, status);
}

/* CXL spec rev3.0 8.2.4.16.1 */
static void header_log_copy(void __iomem *ras_base, u32 *log)
{
	void __iomem *addr;
	u32 *log_addr;
	int i, log_u32_size = CXL_HEADERLOG_SIZE / sizeof(u32);

	addr = ras_base + CXL_RAS_HEADER_LOG_OFFSET;
	log_addr = log;

	for (i = 0; i < log_u32_size; i++) {
		*log_addr = readl(addr);
		log_addr++;
		addr += sizeof(u32);
	}
}

/*
 * Log the state of the RAS status registers and prepare them to log the
 * next error status. Return 1 if reset needed.
 */
pci_ers_result_t cxl_handle_ras(struct device *dev, u64 serial, void __iomem *ras_base)
{
	u32 hl[CXL_HEADERLOG_SIZE_U32];
	void __iomem *addr;
	u32 status;
	u32 fe;

	if (!ras_base) {
		dev_warn_once(dev, "CXL RAS register block is not mapped");
		return PCI_ERS_RESULT_NONE;
	}

	addr = ras_base + CXL_RAS_UNCORRECTABLE_STATUS_OFFSET;
	status = readl(addr);
	if (!(status & CXL_RAS_UNCORRECTABLE_STATUS_MASK))
		return PCI_ERS_RESULT_NONE;

	/* If multiple errors, log header points to first error from ctrl reg */
	if (hweight32(status) > 1) {
		void __iomem *rcc_addr =
			ras_base + CXL_RAS_CAP_CONTROL_OFFSET;

		fe = BIT(FIELD_GET(CXL_RAS_CAP_CONTROL_FE_MASK,
				   readl(rcc_addr)));
	} else {
		fe = status;
	}

	header_log_copy(ras_base, hl);

	if (is_cxl_memdev(dev))
		trace_cxl_aer_uncorrectable_error(dev, status, fe, hl, serial);
	else
		trace_cxl_port_aer_uncorrectable_error(dev, status, fe, hl);

	writel(status & CXL_RAS_UNCORRECTABLE_STATUS_MASK, addr);

	return PCI_ERS_RESULT_PANIC;
}

static void cxl_port_cor_error_detected(struct device *dev)
{
	cxl_handle_cor_ras(dev, 0, cxl_get_ras_base(dev));
}

static pci_ers_result_t cxl_port_error_detected(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct cxl_port *port __free(put_cxl_port) = get_cxl_port(pdev);
	u64 serial = 0;

	if (is_cxl_endpoint(port)) {
		struct cxl_memdev *cxlmd = to_cxl_memdev(port->uport_dev);
		struct cxl_dev_state *cxlds = cxlmd->cxlds;

		guard(device)(&cxlmd->dev);

		if (!dev->driver) {
			dev_warn(&pdev->dev,
				 "%s: memdev disabled, abort error handling\n",
				 dev_name(dev));
			return PCI_ERS_RESULT_NONE;
		}

		if (cxlds->rcd)
			cxl_handle_rdport_errors(cxlds);

		serial = cxlds->serial;
	}

	return cxl_handle_ras(dev, serial, cxl_get_ras_base(dev));
}

void cxl_cor_error_detected(struct pci_dev *pdev)
{
	struct cxl_dev_state *cxlds = pci_get_drvdata(pdev);
	struct cxl_memdev *cxlmd = cxlds->cxlmd;
	struct device *dev = &cxlds->cxlmd->dev;

	guard(device)(dev);

	if (!dev->driver) {
		dev_warn(&pdev->dev,
			 "%s: memdev disabled, abort error handling\n",
			 dev_name(dev));
		return;
	}

	if (cxlds->rcd)
		cxl_handle_rdport_errors(cxlds);

	cxl_handle_cor_ras(&cxlmd->dev, cxlds->serial,
			   cxlmd->endpoint->regs.ras);
}
EXPORT_SYMBOL_NS_GPL(cxl_cor_error_detected, "CXL");

pci_ers_result_t cxl_pci_error_detected(struct pci_dev *pdev,
					pci_channel_state_t error)
{
	struct cxl_port *port __free(put_cxl_port) = get_cxl_port(pdev);
	pci_ers_result_t rc;

	guard(device)(&port->dev);

	rc = cxl_port_error_detected(&pdev->dev);
	if (rc == PCI_ERS_RESULT_PANIC)
		panic("CXL cachemem error.");

	return rc;
}
EXPORT_SYMBOL_NS_GPL(cxl_pci_error_detected, "CXL");

static void cxl_handle_proto_error(struct cxl_proto_err_work_data *err_info)
{
	struct pci_dev *pdev = err_info->pdev;

	if (err_info->severity == AER_CORRECTABLE) {

		if (!pcie_aer_is_native(pdev))
			return;

		if (pdev->aer_cap)
			pci_clear_and_set_config_dword(pdev,
						       pdev->aer_cap + PCI_ERR_COR_STATUS,
						       0, PCI_ERR_COR_INTERNAL);

		cxl_port_cor_error_detected(&pdev->dev);

		pcie_clear_device_status(pdev);
	} else {
		cxl_do_recovery(pdev);
	}
}

static void cxl_proto_err_work_fn(struct work_struct *work)
{
	struct cxl_proto_err_work_data wd;

	while (cxl_proto_err_kfifo_get(&wd)) {
		struct pci_dev *pdev __free(pci_dev_put) = wd.pdev;

		if (!pdev) {
			pr_err_ratelimited("NULL PCI device passed in AER-CXL KFIFO\n");
			continue;
		}

		struct cxl_port *port __free(put_cxl_port) = get_cxl_port(pdev);
		if (!port) {
			pr_err_ratelimited("Failed to find parent Port device in CXL topology.\n");
			continue;
		}
		guard(device)(&port->dev);

		cxl_handle_proto_error(&wd);
	}
}

static struct work_struct cxl_proto_err_work;
static DECLARE_WORK(cxl_proto_err_work, cxl_proto_err_work_fn);

int cxl_ras_init(void)
{
	if (cxl_cper_register_prot_err_work(&cxl_cper_prot_err_work))
		pr_err("Failed to initialize CXL RAS CPER\n");

	cxl_register_proto_err_work(&cxl_proto_err_work);

	return 0;
}

void cxl_ras_exit(void)
{
	cxl_cper_unregister_prot_err_work(&cxl_cper_prot_err_work);
	cancel_work_sync(&cxl_cper_prot_err_work);

	cxl_unregister_proto_err_work();
	cancel_work_sync(&cxl_proto_err_work);
}
