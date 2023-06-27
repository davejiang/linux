// SPDX-License-Identifier: GPL-2.0-only
/*
 * KEYP ACPI table parsing
 *
 * Copyright (C) 2023 Intel Corporation
 */

#include <linux/pci.h>
#include <linux/acpi.h>
#include <linux/bitfield.h>
#include <linux/fw_table.h>
#include <linux/pci-ide.h>

#define KCU_STR_CAP_NUM_STREAMS		GENMASK(8, 0)
#define KCU_STR_CAP_TX_KEY_SLOTS	GENMASK(19, 10)
#define KCU_STR_CAP_RX_KEY_SLOTS	GENMASK(29, 20)

struct keyp_config_unit;

#define KEY_SLOT_INVALID	-1

struct stream {
	struct keyp_config_unit *kcu;
	int pos_id;
	int key_slots[KEY_SET_MAX][KEY_SLOT_MAX];
	struct pci_dev *dsd;
	struct mutex lock;
};

struct keyp_config_unit {
	u64 reg_base;
	void __iomem *addr;
	int map_size;
	enum acpi_keyp_protocol_type type;
	int version;
	struct list_head list;
	struct kref kref;
	struct mutex lock;
	int rp_count;
	int stream_id_claimed;
	int max_streams;
	int tx_key_slots;
	int rx_key_slots;
	struct ida key_slot_ida;
	struct stream *streams;
};

static DEFINE_XARRAY(keyp_xa);
static LIST_HEAD(keyp_cu_list);

static inline u32 construct_xa_key(u16 segment, u8 bus, u8 devfn)
{
	return (u32)segment << 16 | (u32)bus << 8 | devfn;
}

void keyp_setup_pcie_ide_stream(struct pci_dev *pdev)
{
	u16 segment = pci_domain_nr(pdev->bus);
	u32 index = construct_xa_key(segment, pdev->bus->number, pdev->devfn);
	struct keyp_config_unit *kcu;
	int max_rp_streams;

	kcu = xa_load(&keyp_xa, index);
	if (!kcu)
		return;

	/*
	 * PCIe base spec r6.0.1, 7.9.26.4 and 7.9.26.5
	 * Stream ID is an 8bit field so only 256 IDs are available per root port.
	 * However, for the KEYP config unit the stream IDs must be unique. A single
	 * KEYP config unit may have multiple root ports
	 */
	max_rp_streams = 256 / kcu->rp_count;
	pdev->ide.stream_min = kcu->stream_id_claimed;
	pdev->ide.stream_max = kcu->stream_id_claimed + max_rp_streams - 1;
	kcu->stream_id_claimed += max_rp_streams;
}
EXPORT_SYMBOL_GPL(keyp_setup_pcie_ide_stream);

void keyp_inc_ref(struct pci_dev *pdev)
{
	u16 segment = pci_domain_nr(pdev->bus);
	u32 index = construct_xa_key(segment, pdev->bus->number, pdev->devfn);
	struct keyp_config_unit *kcu;

	kcu = xa_load(&keyp_xa, index);
	if (!kcu)
		return;

	guard(mutex)(&kcu->lock);
	kref_get(&kcu->kref);
}
EXPORT_SYMBOL_GPL(keyp_inc_ref);

static void keyp_unit_release(struct kref *kref)
{
	struct keyp_config_unit *kcu =
		container_of(kref, struct keyp_config_unit, kref);
	struct keyp_config_unit *iter;
	unsigned long index;

	xa_for_each(&keyp_xa, index, iter) {
		if (iter == kcu)
			xa_erase(&keyp_xa, index);
	}
	list_del(&kcu->list);
	iounmap(kcu->addr);
	release_mem_region(kcu->reg_base, kcu->map_size);
	ida_destroy(&kcu->key_slot_ida);
	kfree(kcu->streams);
	kfree(kcu);
}

void keyp_dec_ref(struct pci_dev *pdev)
{
	u16 segment = pci_domain_nr(pdev->bus);
	u32 index = construct_xa_key(segment, pdev->bus->number, pdev->devfn);
	struct keyp_config_unit *kcu;

	kcu = xa_load(&keyp_xa, index);
	if (!kcu)
		return;

	guard(mutex)(&kcu->lock);
	kref_put(&kcu->kref, keyp_unit_release);
	/*
	 * The kref really is a way to release the resources once all the RPs
	 * holding a reference are gone. So once refcount == 1, no more RPs are
	 * using this data and it can be released.
	 */
	if (kref_read(&kcu->kref) == 1)
		kref_put(&kcu->kref, keyp_unit_release);
}
EXPORT_SYMBOL_GPL(keyp_dec_ref);

static void set_key_slots(int keyslots[KEY_SET_MAX][KEY_SLOT_MAX], int val)
{
	int i, j;

	for (i = 0; i < KEY_SET_MAX; i++) {
		for (j = 0; j < KEY_SLOT_MAX; j++)
			keyslots[i][j] = val;
	}
}

static int keyp_config_unit_handler(union acpi_subtable_headers *header,
				    void *arg, const unsigned long end)
{
	struct acpi_keyp_config_unit *acpi_cu =
		(struct acpi_keyp_config_unit *)&header->keyp;
	int rc = 0, i, j, size, rp_size, rp_count;
	struct keyp_config_unit *kcu __free(kfree) =
		kzalloc(sizeof(*kcu), GFP_KERNEL);
	void __iomem *addr;
	u32 xa_key;
	u32 cap;

	rp_size = acpi_cu->header.length - sizeof(*acpi_cu);

	if (rp_size % sizeof(struct acpi_keyp_rp_info))
		return -EINVAL;

	rp_count = rp_size / sizeof(struct acpi_keyp_rp_info);
	if (rp_count != acpi_cu->root_port_count)
		return -EINVAL;

	kcu = kzalloc(sizeof(*kcu), GFP_KERNEL);
	if (!kcu)
		return -ENOMEM;
	kref_init(&kcu->kref);
	mutex_init(&kcu->lock);
	kcu->reg_base = acpi_cu->register_base_address;
	kcu->type = acpi_cu->protocol_type;
	list_add(&kcu->list, &keyp_cu_list);
	ida_init(&kcu->key_slot_ida);
	kcu->rp_count = acpi_cu->root_port_count;

	addr = ioremap(kcu->reg_base, sizeof(cap));
	if (!addr) {
		rc = -ENOMEM;
		goto map_err;
	}
	cap = ioread32(addr);
	iounmap(addr);

	kcu->max_streams = FIELD_GET(KCU_STR_CAP_NUM_STREAMS, cap) + 1;
	kcu->tx_key_slots = FIELD_GET(KCU_STR_CAP_TX_KEY_SLOTS, cap) + 1;
	kcu->rx_key_slots = FIELD_GET(KCU_STR_CAP_RX_KEY_SLOTS, cap) + 1;

	/*
	 * Total key configuration unit block size is size of cap +
	 * total TX key slots + total TX IV value slots +
	 * total RX key slots + total RX IV value slots.
	 */
	size = sizeof(cap) + kcu->max_streams * 0x24 +
	       kcu->tx_key_slots * 0x20 + kcu->tx_key_slots * 0x8 +
	       kcu->rx_key_slots * 0x20 + kcu->rx_key_slots * 0x8;
	kcu->map_size = size;

	if (!request_mem_region(kcu->reg_base, size, "KEYP Config Unit")) {
		rc = -ENOMEM;
		goto request_err;
	}

	kcu->addr = ioremap(kcu->reg_base, size);
	if (!kcu->addr) {
		rc = -ENOMEM;
		goto map_err;
	}

	struct stream *streams __free(kfree) =
		kcalloc(kcu->max_streams, sizeof(struct stream), GFP_KERNEL);
	if (!streams) {
		rc = -ENOMEM;
		goto streams_err;
	}

	for (i = 0; i < kcu->max_streams; i++) {
		struct stream *stm = &streams[i];

		stm->pos_id = i;
		stm->kcu = kcu;
		set_key_slots(stm->key_slots, KEY_SLOT_INVALID);
		mutex_init(&stm->lock);
	}

	for (i = 0; i < rp_count; i++) {
		struct acpi_keyp_rp_info *keyp_ri = &acpi_cu->rp_info[i];

		xa_key = construct_xa_key(keyp_ri->segment, keyp_ri->bus,
					  keyp_ri->devfn);

		rc = xa_insert(&keyp_xa, xa_key, kcu, GFP_KERNEL);
		if (rc)
			goto xa_err;
	}

	kcu->streams = streams;
	no_free_ptr(streams);
	no_free_ptr(kcu);
	return 0;

xa_err:
	for (j = 0; j < i; j++) {
		struct acpi_keyp_rp_info *keyp_ri = &acpi_cu->rp_info[j];

		xa_key = construct_xa_key(keyp_ri->segment, keyp_ri->bus,
					  keyp_ri->devfn);
		xa_erase(&keyp_xa, xa_key);
	}

streams_err:
request_err:
map_err:
	list_del(&kcu->list);
	return rc;
}

int keyp_init(void)
{
	struct acpi_table_header *tbl;
	acpi_status status;
	int rc;

	status = acpi_get_table(ACPI_SIG_KEYP, 0, &tbl);
	if (ACPI_FAILURE(status))
		return -ENXIO;

	rc = acpi_table_parse_keyp(ACPI_KEYP_TYPE_CONFIG_UNIT,
				   keyp_config_unit_handler, NULL);
	if (rc < 0)
		return rc;

	acpi_put_table(tbl);

	return 0;
}
EXPORT_SYMBOL_GPL(keyp_init);
