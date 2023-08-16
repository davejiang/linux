// SPDX-License-Identifier: GPL-2.0-only
/*
 * KEYP ACPI table parsing
 *
 * Copyright (C) 2023 Intel Corporation
 */

#include <linux/pci.h>
#include <linux/acpi.h>
#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/fw_table.h>
#include <linux/pci-ide.h>
#include <linux/cleanup.h>

static struct workqueue_struct *keyp_wq;

#define KEYP_STM_KEY_REFRESH_TIME	30
#define KEYP_STM_CAP_SIZE		4
#define KEYP_STM_CONFIG_SIZE		36

#define KCU_STR_CAP_NUM_STREAMS		GENMASK(8, 0)
#define KCU_STR_CAP_TX_KEY_SLOTS	GENMASK(19, 10)
#define KCU_STR_CAP_RX_KEY_SLOTS	GENMASK(29, 20)

struct keyp_config_unit;

#define KEY_SLOT_INVALID	-1

enum key_slot_state {
	KEY_SLOT_STATE_CLEAR,
	KEY_SLOT_STATE_ALLOCATED,
	KEY_SLOT_STATE_RELEASING
};

struct stream {
	struct keyp_config_unit *kcu;
	int pos_id;
	int stream_id;					/* stream ID unique for KCU */
	int key_slots[KEY_SET_MAX][KEY_SLOT_MAX];
	struct pci_dev *dsd;
	struct mutex lock;
	enum key_set_index keyset;			/* current key set */
	enum key_slot_state key_slot_state;
	struct delayed_work dwork;
	struct delayed_work key_refresh_dwork;
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
	struct ida stream_pos_ida;
	struct ida key_slot_ida;
	struct stream *streams;
};

#define KEYP_STM_CAP_NUM_STREAMS	GENMASK(8, 0)
#define KEYP_STM_NUM_TX_KEY_SLOTS	GENMASK(19, 10)
#define KEYP_STM_NUM_RX_KEY_SLOTS	GENMASK(29, 20)

/* Per-Stream Configuration Register Block */
#define KEYP_STM_CTRL_OFS		0
#define KEYP_STM_TX_CTRL_OFS		0x4
#define KEYP_STM_TX_STS_OFS		0x8
#define KEYP_STM_RX_CTRL_OFS		0xc
#define KEYP_STM_RX_STS_OFS		0x10
#define KEYP_STM_TX_KEY0_IDX_OFS	0x14
#define KEYP_STM_TX_KEY1_IDX_OFS	0x18
#define KEYP_STM_RX_KEY0_IDX_OFS	0x1c
#define KEYP_STM_RX_KEY1_IDX_OFS	0x20

#define KEYP_STM_CTRL_EN		BIT(0)
#define KEYP_STM_CTRL_ID		GENMASK(31, 24)

#define KEYP_STM_TX_CTRL_SEL		GENMASK(1, 0)
#define KEYP_STM_TX_CTRL_PKEY_SET_0	BIT(8)
#define KEYP_STM_TX_CTRL_PKEY_SET_1	BIT(16)

#define KEYP_STM_TX_KEY_SEL_NONE	0
#define KEYP_STM_TX_KEY_SEL_0		0x1
#define KEYP_STM_TX_KEY_SEL_1		0x10

#define KEYP_STM_TX_STS_SET		GENMASK(1, 0)
#define KEYP_STM_TX_STS_KEY_NONE	0
#define KEYP_STM_TX_STS_KEY_SET_0	0x1
#define KEYP_STM_TX_STS_KEY_SET_1	0x10
#define KEYP_STM_TX_STS_KEY_TRANSITION	0x11
#define KEYP_STM_TX_STS_RDY_KEY_SET_0	BIT(8)
#define KEYP_STM_TX_STS_RDY_KEY_SET_1	BIT(9)

#define KEYP_STM_RX_CTRL_PKEY_SET_0	BIT(8)
#define KEYP_STM_RX_CTRL_PKEY_SET_1	BIT(16)

#define KEYP_STM_RX_STS_LAST_RCVD_SET_PR	GENMASK(1, 0)
#define KEYP_STM_RX_STS_LAST_RCVD_SET_NPR	GENMASK(3, 2)
#define KEYP_STM_RX_STS_LAST_RCVD_SET_CPL	GENMASK(5, 4)
#define KEYP_STM_RX_STS_LAST_RCVD_NONE		0
#define KEYP_STM_RX_STS_LAST_RCVD_SET_0		0x1
#define KEYP_STM_RX_STS_LAST_RCVD_SET_1		0x10
#define KEYP_STM_RX_STS_RDY_KEY_SET_0		BIT(8)
#define KEYP_STM_RX_STS_RDY_KEY_SET_1		BIT(9)

#define KEYP_STM_KEY_PR_IDX		GENMASK(9, 0)
#define KEYP_STM_KEY_NPR_IDX		GENMASK(19, 10)
#define KEYP_STM_KEY_CPL_IDX		GENMASK(29, 20)

static DEFINE_XARRAY(keyp_xa);
static LIST_HEAD(keyp_cu_list);

static inline int stream_pos_id_get(struct keyp_config_unit *kcu)
{
	return ida_alloc_max(&kcu->stream_pos_ida, kcu->max_streams, GFP_KERNEL);
}

static inline void stream_pos_id_put(struct keyp_config_unit *kcu, int pos_id)
{
	ida_free(&kcu->stream_pos_ida, pos_id);
}

static inline int key_slot_get(struct keyp_config_unit *kcu)
{
	return ida_alloc_max(&kcu->key_slot_ida,
			     min(kcu->tx_key_slots, kcu->rx_key_slots),
			     GFP_KERNEL);
}

static inline void key_slot_put(struct keyp_config_unit *kcu, int id)
{
	ida_free(&kcu->key_slot_ida, id);
}

static inline u32 construct_xa_key(u16 segment, u8 bus, u8 devfn)
{
	return (u32)segment << 16 | (u32)bus << 8 | devfn;
}

static void key_slot_ids_cleanup(struct stream *stm)
{
	struct keyp_config_unit *kcu = stm->kcu;
	int i, j;

	for (i = 0; i < KEY_SET_MAX; i++) {
		for (j = 0; i < KEY_SLOT_MAX; j++) {
			if (stm->key_slots[i][j] == KEY_SLOT_INVALID)
				continue;
			key_slot_put(kcu, stm->key_slots[i][j]);
			stm->key_slots[i][j] = KEY_SLOT_INVALID;
		}
	}
}

static int keyp_write_keys(struct stream *stm, struct key_package *pkg,
			   enum key_set_index key_set)
{
	struct keyp_config_unit *kcu = stm->kcu;
	int key_base, iv_base, ofs, i;

	if (key_set > KEY_SET_MAX)
		return -EINVAL;

	/*
	 * PCIe Base Spec 6.0.1 6.33.5 IDE TLP Sub-Streams
	 * Each sub-stream must support the use of its own unique key value and
	 * invocation field initial counter value. Allocate a key slot id for
	 * each substream.
	 */
	for (i = 0; i < KEY_SLOT_MAX; i++) {
		int key_slot = key_slot_get(kcu);

		if (key_slot < 0) {
			key_slot_ids_cleanup(stm);
			return key_slot;
		}
		stm->key_slots[key_set][i] = key_slot;
	}
	stm->key_slot_state = KEY_SLOT_STATE_ALLOCATED;

	/* TX key base */
	key_base = KEYP_STM_CAP_SIZE +
		   KEYP_STM_CONFIG_SIZE * kcu->max_streams;
	/* TX IV base */
	iv_base = key_base + kcu->tx_key_slots * IDE_KEY_SIZE;

	for (i = KEY_SLOT_TX_PR; i < 3; i++) {
		ofs = key_base + stm->key_slots[key_set][i] * IDE_KEY_SIZE;
		memcpy_toio(kcu->addr + ofs, pkg->key[i],
			    IDE_KEY_SIZE);

		ofs = iv_base + stm->key_slots[key_set][i] * IDE_IV_SIZE;
		memcpy_toio(kcu->addr + ofs, pkg->iv[i], IDE_IV_SIZE);
	}

	/* RX key base */
	key_base = KEYP_STM_CAP_SIZE +
		   KEYP_STM_CONFIG_SIZE * kcu->max_streams +
		   IDE_KEY_SIZE * kcu->tx_key_slots +
		   IDE_IV_SIZE * kcu->tx_key_slots;
	/* RX IV base */
	iv_base = key_base + kcu->rx_key_slots * IDE_KEY_SIZE;

	for (i = KEY_SLOT_RX_PR; i < KEY_SLOT_MAX; i++) {
		ofs = key_base + stm->key_slots[key_set][i] * IDE_KEY_SIZE;
		memcpy_toio(kcu->addr + ofs, pkg->key[i], IDE_KEY_SIZE);

		ofs = iv_base + stm->key_slots[key_set][i] * IDE_IV_SIZE;
		memcpy_toio(kcu->addr + ofs, pkg->iv[i], IDE_IV_SIZE);
	}

	return 0;
}

static int keyp_prime_key(struct stream *stm, struct key_package *pkg,
			  enum key_set_index key_set,
			  enum stream_direction dir)
{
	struct keyp_config_unit *kcu = stm->kcu;
	u32 tx_key_set, rx_key_set, tx_key_ready, rx_key_ready;
	u32 val, key_select;
	int stm_base;

	stm_base = KEYP_STM_CAP_SIZE + KEYP_STM_CONFIG_SIZE * stm->pos_id;

	/* Program TX key indicies */
	if (dir == IDE_STREAM_TX) {
		val = FIELD_PREP(KEYP_STM_KEY_PR_IDX,
				 stm->key_slots[key_set][KEY_SLOT_TX_PR]);
		val |= FIELD_PREP(KEYP_STM_KEY_NPR_IDX,
				  stm->key_slots[key_set][KEY_SLOT_TX_NPR]);
		val |= FIELD_PREP(KEYP_STM_KEY_CPL_IDX,
				  stm->key_slots[key_set][KEY_SLOT_TX_CPL]);
		writel(val, kcu->addr + stm_base + KEYP_STM_TX_KEY0_IDX_OFS +
		       key_set * sizeof(u32));

		if (key_set == KEY_SET_0) {
			tx_key_set = KEYP_STM_TX_CTRL_PKEY_SET_0;
			tx_key_ready = KEYP_STM_TX_STS_RDY_KEY_SET_0;
		} else {
			tx_key_set = KEYP_STM_TX_CTRL_PKEY_SET_1;
			tx_key_ready = KEYP_STM_TX_STS_RDY_KEY_SET_1;
		}

		/* Prime TX key */
		key_select = readl(kcu->addr + stm_base + KEYP_STM_TX_CTRL_OFS);
		key_select |= tx_key_set;
		writel(key_select, kcu->addr + stm_base + KEYP_STM_TX_CTRL_OFS);

		/* Check if TX keys are ready */
		val = readl(kcu->addr + stm_base + KEYP_STM_TX_STS_OFS);
		if (!(val & tx_key_ready))
			return -ENXIO;

		return 0;
	}

	/* Program RX key indicies */
	val = FIELD_PREP(KEYP_STM_KEY_PR_IDX,
			 stm->key_slots[key_set][KEY_SLOT_RX_PR]);
	val |= FIELD_PREP(KEYP_STM_KEY_NPR_IDX,
			  stm->key_slots[key_set][KEY_SLOT_RX_NPR]);
	val |= FIELD_PREP(KEYP_STM_KEY_CPL_IDX,
			  stm->key_slots[key_set][KEY_SLOT_RX_CPL]);
	writel(val, kcu->addr + stm_base + KEYP_STM_RX_KEY0_IDX_OFS +
	       key_set * sizeof(u32));

	if (key_set == KEY_SET_0) {
		rx_key_set = KEYP_STM_RX_CTRL_PKEY_SET_0;
		rx_key_ready = KEYP_STM_RX_STS_RDY_KEY_SET_0;
	} else {
		rx_key_set = KEYP_STM_RX_CTRL_PKEY_SET_1;
		rx_key_ready = KEYP_STM_RX_STS_RDY_KEY_SET_1;
	}

	/* Prime RX key */
	writel(rx_key_set, kcu->addr + stm_base + KEYP_STM_RX_CTRL_OFS);

	/* Check if the RX keys are ready */
	val = readl(kcu->addr + stm_base + KEYP_STM_RX_STS_OFS);
	if (!(val & rx_key_ready))
		return -ENXIO;

	return 0;
}

static void keyp_select_key(struct stream *stm, enum key_set_index key_set)
{
	struct keyp_config_unit *kcu = stm->kcu;
	int stm_base;
	u32 select;

	select = key_set ? KEYP_STM_TX_KEY_SEL_1 : KEYP_STM_TX_KEY_SEL_0;
	stm_base = KEYP_STM_CAP_SIZE + KEYP_STM_CONFIG_SIZE * stm->pos_id;
	writel(select, kcu->addr + stm_base + KEYP_STM_RX_CTRL_OFS);
	stm->keyset = key_set;
}

static void keyp_clear_keys(struct stream *stm)
{
	struct keyp_config_unit *kcu = stm->kcu;
	int key_base, ofs, i, keyset;
	u8 key[IDE_KEY_SIZE];

	keyset = stm->keyset;
	/* Get random bytes to be written to all key slots */
	while (get_random_bytes_wait(key, IDE_KEY_SIZE));

	/* TX key base */
	key_base = KEYP_STM_CAP_SIZE +
		   KEYP_STM_CONFIG_SIZE * kcu->max_streams;
	for (i = KEY_SLOT_TX_PR; i < 3; i++) {
		ofs = key_base + stm->key_slots[keyset][i] * IDE_KEY_SIZE;
		memcpy_toio(kcu->addr + ofs, key, IDE_KEY_SIZE);
	}

	/* RX key base */
	key_base = KEYP_STM_CAP_SIZE +
		   KEYP_STM_CONFIG_SIZE * kcu->max_streams +
		   IDE_KEY_SIZE * kcu->tx_key_slots +
		   IDE_IV_SIZE * kcu->tx_key_slots;
	for (i = KEY_SLOT_RX_PR; i < KEY_SLOT_MAX; i++) {
		ofs = key_base + stm->key_slots[keyset][i] * IDE_KEY_SIZE;
		memcpy_toio(kcu->addr + ofs, key, IDE_KEY_SIZE);
	}
}

static void keyp_keys_free(struct stream *stm)
{
	struct keyp_config_unit *kcu = stm->kcu;

	for (int i = 0; i < 3; i++) {
		if (stm->key_slots[stm->keyset][i] == KEY_SLOT_INVALID)
			continue;
		key_slot_put(kcu, stm->key_slots[stm->keyset][i]);
		stm->key_slots[stm->keyset][i] = KEY_SLOT_INVALID;
	}

	for (int i = KEY_SLOT_RX_PR; i < KEY_SLOT_MAX; i++) {
		if (stm->key_slots[stm->keyset][i] == KEY_SLOT_INVALID)
			continue;
		key_slot_put(kcu, stm->key_slots[stm->keyset][i]);
		stm->key_slots[stm->keyset][i] = KEY_SLOT_INVALID;
	}
}

static int keyp_tx_keys_validate(struct stream *stm)
{
	struct keyp_config_unit *kcu = stm->kcu;
	int stm_base;
	u32 val, sts;

	stm_base = KEYP_STM_CAP_SIZE + KEYP_STM_CONFIG_SIZE * stm->pos_id;
	val = readl(kcu->addr + stm_base + KEYP_STM_TX_STS_OFS);
	sts = FIELD_GET(KEYP_STM_TX_STS_SET, val);

	if (sts == KEYP_STM_TX_STS_KEY_NONE ||
	    sts == KEYP_STM_TX_STS_KEY_TRANSITION)
		return -EAGAIN;

	if (stm->keyset == KEY_SET_0 &&
	    sts != KEYP_STM_TX_STS_KEY_SET_0)
		return -EINVAL;

	if (stm->keyset == KEY_SET_1 &&
	    sts != KEYP_STM_TX_STS_KEY_SET_1)
		return -EINVAL;

	return 0;
}

static int keyp_rx_keys_validate(struct stream *stm)
{
	struct keyp_config_unit *kcu = stm->kcu;
	u32 val, pr_sts, npr_sts, cpl_sts;
	int stm_base;

	stm_base = KEYP_STM_CAP_SIZE + KEYP_STM_CONFIG_SIZE * stm->pos_id;
	val = readl(kcu->addr + stm_base + KEYP_STM_TX_STS_OFS);
	pr_sts = FIELD_GET(KEYP_STM_RX_STS_LAST_RCVD_SET_PR, val);
	npr_sts = FIELD_GET(KEYP_STM_RX_STS_LAST_RCVD_SET_NPR, val);
	cpl_sts = FIELD_GET(KEYP_STM_RX_STS_LAST_RCVD_SET_CPL, val);
	if (pr_sts == KEYP_STM_RX_STS_LAST_RCVD_NONE ||
	    npr_sts == KEYP_STM_RX_STS_LAST_RCVD_NONE ||
	    cpl_sts == KEYP_STM_RX_STS_LAST_RCVD_NONE)
		return -EAGAIN;

	if (stm->keyset == KEY_SET_0 &&
	    pr_sts == KEYP_STM_RX_STS_LAST_RCVD_SET_0 &&
	    npr_sts == KEYP_STM_RX_STS_LAST_RCVD_SET_0 &&
	    cpl_sts == KEYP_STM_RX_STS_LAST_RCVD_SET_0)
		return 0;

	if (stm->keyset == KEY_SET_1 &&
	    pr_sts == KEYP_STM_RX_STS_LAST_RCVD_SET_1 &&
	    npr_sts == KEYP_STM_RX_STS_LAST_RCVD_SET_1 &&
	    cpl_sts == KEYP_STM_RX_STS_LAST_RCVD_SET_1)
		return 0;

	return -EINVAL;
}

static void keyp_keys_validate_and_free(struct work_struct *work)
{
	struct stream *stm = container_of(work, struct stream, dwork.work);
	int rc;

	guard(mutex)(&stm->lock);
	if (stm->key_slot_state == KEY_SLOT_STATE_CLEAR)
		return;

	stm->key_slot_state = KEY_SLOT_STATE_RELEASING;
	rc = keyp_tx_keys_validate(stm);
	if (rc) {
		queue_delayed_work(keyp_wq, &stm->dwork, msecs_to_jiffies(100));
		return;
	}

	rc = keyp_rx_keys_validate(stm);
	if (rc) {
		queue_delayed_work(keyp_wq, &stm->dwork, msecs_to_jiffies(100));
		return;
	}

	keyp_clear_keys(stm);
	keyp_keys_free(stm);
	stm->key_slot_state = KEY_SLOT_STATE_CLEAR;
}


static void keyp_stream_control(struct stream *stm, bool enable)
{
	struct keyp_config_unit *kcu = stm->kcu;
	int stm_base;
	u32 val;

	stm_base = KEYP_STM_CAP_SIZE + KEYP_STM_CONFIG_SIZE * stm->pos_id;
	val = readl(kcu->addr + stm_base + KEYP_STM_CTRL_OFS);
	if (enable)
		val |= FIELD_PREP(KEYP_STM_CTRL_EN, 1);
	else
		val &= ~FIELD_PREP(KEYP_STM_CTRL_EN, 1);
	writel(val, kcu->addr + stm_base + KEYP_STM_CTRL_OFS);
}

static void keyp_stream_id_write(struct stream *stm)
{
	struct keyp_config_unit *kcu = stm->kcu;
	int stm_base;
	u32 val;

	stm_base = KEYP_STM_CAP_SIZE + KEYP_STM_CONFIG_SIZE * stm->pos_id;
	val = FIELD_PREP(KEYP_STM_CTRL_ID, stm->stream_id);
	writel(val, kcu->addr + stm_base + KEYP_STM_CTRL_OFS);
}

/* Use PCIe base spec 6.0.1 Figure 6-59 IDE_KM Example as reference */
DEFINE_FREE(keyset_free, struct key_package *, if (_T) ide_km_keyset_free(_T))
static int keyp_stream_setup(struct keyp_config_unit *kcu,
			     struct pci_dev *pdev1, struct pci_dev *pdev2,
			     enum pci_ide_stream_type type)
{
	struct stream *stm;
	struct key_package *pkg __free(keyset_free) =
		ide_km_keyset_alloc();
	int stream_id = pdev2->ide.stream_id;
	int stm_pos_id, stm_base, keyset;
	int rc = 0;
	u32 val;

	if (!pkg)
		return -ENOMEM;

	guard(mutex)(&pdev1->ide.lock);
	guard(mutex)(&pdev2->ide.lock);

	/* Config IDE Extended Cap registers on RP and EP */
	rc = pci_ide_stream_setup(pdev1, pdev2, type);
	if (rc)
		return rc;

	keyset = pdev2->ide.keyset;

	stm_pos_id = stream_pos_id_get(kcu);
	if (stm_pos_id < 0)
		return stm_pos_id;

	stm = &kcu->streams[stm_pos_id];
	guard(mutex)(&stm->lock);
	stm->stream_id = stream_id;

	/* Make sure the stream isn't enabled already */
	stm_base = KEYP_STM_CAP_SIZE + KEYP_STM_CONFIG_SIZE * stm_pos_id;
	val = readl(kcu->addr + stm_base + KEYP_STM_CTRL_OFS);
	if (FIELD_GET(KEYP_STM_CTRL_EN, val)) {
		rc = -EBUSY;
		goto ctrl_err;
	}

	keyp_stream_id_write(stm);

	/* Program keyset to RP */
	rc = keyp_write_keys(stm, pkg, keyset);
	if (rc < 0)
		goto key_write_err;

	rc = ide_km_send_query(pdev2);
	if (rc)
		goto key_write_err;

	/* Distribute keyset and IVs to EP via DOE */
	rc = ide_km_set_keyset(pdev2, stream_id, keyset,
			       pkg, IDE_DEV_DOWNSTREAM);
	if (rc)
		goto key_write_err;

	/* Prime RP Rx */
	rc = keyp_prime_key(stm, pkg, keyset, IDE_STREAM_RX);
	if (rc < 0)
		goto key_write_err;

	/* Trigger IDE at EP Rx, IDE_KM K_SET_GO(Rx) */
	rc = ide_km_enable_keyset(pdev2, stream_id, keyset, IDE_STREAM_RX);
	if (rc)
		goto key_write_err;

	/* Prime RP Tx */
	rc = keyp_prime_key(stm, pkg, keyset, IDE_STREAM_TX);
	if (rc < 0)
		goto key_write_err;

	keyp_select_key(stm, keyset);

	/* Trigger IDE at EP Tx */
	rc = ide_km_enable_keyset(pdev2, stream_id, keyset, IDE_STREAM_TX);
	if (rc)
		goto key_write_err;

	/* Enable IDE by setting stream enable in IDE config */
	rc = pci_ide_stream_enable(pdev1, pdev2, type);
	if (rc)
		goto stream_en_err;

	/* Enable the stream in KEYP */
	keyp_stream_control(stm, true);
	stm->dsd = pdev2;

	if (!ide_stream_is_secure(pdev2, true))
		return -ENXIO;

	pdev2->ide.stream_type = type;
	pdev2->ide.secure = true;

	/*
	 * Root Complex IDE Programming Guide (Intel) section 3.3.2
	 * Wait at least 100ms after selecting a new key before freeing
	 * the key slots.
	 */
	queue_delayed_work(keyp_wq, &stm->dwork, msecs_to_jiffies(100));
	queue_delayed_work(keyp_wq, &stm->key_refresh_dwork,
			   msecs_to_jiffies(KEYP_STM_KEY_REFRESH_TIME) * 1000);

	return 0;

stream_en_err:
	ide_km_disable_keyset(pdev2, stream_id, keyset, IDE_STREAM_TX);
	ide_km_disable_keyset(pdev2, stream_id, keyset, IDE_STREAM_RX);
key_write_err:
	key_slot_ids_cleanup(stm);
ctrl_err:
	stream_pos_id_put(kcu, stm->pos_id);
	return rc;
}

static int keyp_stream_create(struct pci_dev *pdev1, struct pci_dev *pdev2,
			      struct pci_dev *ep, enum pci_ide_stream_type type)
{
	u16 segment = pci_domain_nr(ep->bus);
	u32 index = construct_xa_key(segment, ep->bus->number, ep->devfn);
	struct keyp_config_unit *kcu;

	if (pci_pcie_type(pdev1) != PCI_EXP_TYPE_ROOT_PORT)
		return -EINVAL;

	if (pci_pcie_type(ep) != PCI_EXP_TYPE_ENDPOINT &&
	    pci_pcie_type(ep) != PCI_EXP_TYPE_RC_END)
		return -EINVAL;

	kcu = xa_load(&keyp_xa, index);
	if (!kcu)
		return -ENODEV;

	if (type == PCI_IDE_STREAM_TYPE_SELECTIVE)
		return keyp_stream_setup(kcu, pdev1, ep, type);

	return keyp_stream_setup(kcu, pdev1, pdev2, type);
}

static void keyp_stream_shutdown(struct pci_dev *pdev1, struct pci_dev *pdev2,
				 struct pci_dev *ep, enum pci_ide_stream_type type)
{
	u16 segment = pci_domain_nr(ep->bus);
	u32 index = construct_xa_key(segment, ep->bus->number, ep->devfn);
	struct keyp_config_unit *kcu;
	struct stream *stm;
	bool found = false;
	int i;

	/* Stream traffic is expected to be quiesced */
	/* PCIe stream termination */
	kcu = xa_load(&keyp_xa, index);
	if (!kcu)
		return;

	for (i = 0; i < kcu->stream_id_claimed; i++) {
		stm = &kcu->streams[i];
		mutex_lock(&stm->lock);
		if (stm->dsd == ep) {
			found = true;
			break;
		}
		mutex_unlock(&stm->lock);
	}

	if (!found) {
		dev_dbg(&pdev1->dev, "Active stream not found!\n");
		return;
	}

	guard(mutex)(&pdev1->ide.lock);
	guard(mutex)(&pdev2->ide.lock);
	ide_km_disable_keyset(pdev2, pdev2->ide.stream_id, stm->keyset,
			      IDE_STREAM_TX);
	ide_km_disable_keyset(pdev2, pdev2->ide.stream_id, stm->keyset,
			      IDE_STREAM_RX);

	cancel_delayed_work_sync(&stm->key_refresh_dwork);
	cancel_delayed_work_sync(&stm->dwork);

	if (stm->key_slot_state != KEY_SLOT_STATE_CLEAR) {
		keyp_clear_keys(stm);
		keyp_keys_free(stm);
		stm->key_slot_state = KEY_SLOT_STATE_CLEAR;
	}

	pci_ide_stream_disable(pdev1, ep, PCI_IDE_STREAM_TYPE_SELECTIVE);
	keyp_stream_control(stm, false);

	/*
	 * No need to write random values to key slots. This is done by the delayed
	 * workqueue.
	 */

	stream_pos_id_put(kcu, stm->pos_id);
	stm->dsd = NULL;
	mutex_unlock(&stm->lock);
	pci_ide_stream_release(pdev1, ep);
	pdev2->ide.stream_type = PCI_IDE_STREAM_TYPE_NONE;
	pdev2->ide.secure = false;
}

static const struct pci_ide_ops keyp_ide_ops = {
	.stream_create = keyp_stream_create,
	.stream_shutdown = keyp_stream_shutdown,
};

static void keyp_stream_key_refresh(struct work_struct *work)
{
	struct stream *stm = container_of(work, struct stream, dwork.work);
	struct key_package *pkg __free(keyset_free) = ide_km_keyset_alloc();
	int keyset = next_keyset(stm->keyset);
	struct pci_dev *pdev;
	int stream_id, rc;

	if (!pkg)
		return;

	guard(mutex)(&stm->lock);
	stream_id = stm->dsd->ide.stream_id;
	pdev = stm->dsd;
	guard(mutex)(&pdev->ide.lock);

	rc = keyp_write_keys(stm, pkg, keyset);
	if (rc)
		return;

	rc = keyp_prime_key(stm, pkg, keyset, IDE_STREAM_RX);
	if (rc)
		return;

	rc = keyp_prime_key(stm, pkg, keyset, IDE_STREAM_TX);
	if (rc)
		return;

	/* Distribute keys to EP as next set */
	rc = ide_km_set_keyset(pdev, stream_id, keyset, pkg,
			       IDE_DEV_DOWNSTREAM);
	if (rc)
		return;

	/* Inform the EP Rx to switch to next keyset */
	rc = ide_km_enable_keyset(pdev, stream_id, keyset, IDE_STREAM_RX);
	if (rc) {
		dev_dbg(&pdev->dev, "Refresh keyset failed to activate.\n");
		return;
	}

	/* Trigger RP Tx to use new key */
	keyp_select_key(stm, keyset);

	/* Inform the EP Tx to switch to next keyset */
	rc = ide_km_enable_keyset(pdev, stream_id, keyset, IDE_STREAM_TX);
	if (rc) {
		dev_dbg(&pdev->dev, "Refresh keyset failed to activate.\n");
		return;
	}

	stm->keyset = keyset;
	pdev->ide.keyset = keyset;

	queue_delayed_work(keyp_wq, &stm->key_refresh_dwork,
			   msecs_to_jiffies(KEYP_STM_KEY_REFRESH_TIME) * 1000);
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
	pdev->ide.ops = &keyp_ide_ops;
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
	ida_destroy(&kcu->stream_pos_ida);
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
	ida_init(&kcu->stream_pos_ida);
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
		INIT_DELAYED_WORK(&stm->dwork, keyp_keys_validate_and_free);
		INIT_DELAYED_WORK(&stm->key_refresh_dwork, keyp_stream_key_refresh);
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

	keyp_wq = create_singlethread_workqueue("keyp");

	return 0;
}
EXPORT_SYMBOL_GPL(keyp_init);
