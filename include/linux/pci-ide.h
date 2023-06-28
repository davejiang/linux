/* SPDX-License-Identifier: GPL-2.0 */
/*
 *	pci-ide.h
 *
 *	Copyright 2023 Intel Corporation
 *
 *	Common definitions for PCI IDE
 */
#ifndef _LINUX_PCI_IDE_H_
#define _LINUX_PCI_IDE_H_

enum key_set_index {
	KEY_SET_0 = 0,
	KEY_SET_1,
	KEY_SET_MAX
};

#define next_keyset(x) ((x) == KEY_SET_0 ? KEY_SET_1 : KEY_SET_0)

enum key_slot_index {
	KEY_SLOT_RX_PR,
	KEY_SLOT_RX_NPR,
	KEY_SLOT_RX_CPL,
	KEY_SLOT_TX_PR,
	KEY_SLOT_TX_NPR,
	KEY_SLOT_TX_CPL,
	KEY_SLOT_MAX
};

enum stream_direction {
	IDE_STREAM_RX = 0,
	IDE_STREAM_TX,
	IDE_STREAM_DIRECTION_MAX
};

#define flip_direction(x) ((x) == IDE_STREAM_RX ? IDE_STREAM_TX : IDE_STREAM_RX)

#define IDE_KEY_SIZE		32
#define IDE_IV_SIZE		8
#define IDE_NUM_SUBSTREAMS	3
#define IDE_STREAM_STATUS_DELAY	10	/* 10ms */

struct key_package {
	u8 key[KEY_SLOT_MAX][IDE_KEY_SIZE];
	u8 iv[KEY_SLOT_MAX][IDE_IV_SIZE];
};

enum ide_dev_type {
	IDE_DEV_UPSTREAM,
	IDE_DEV_DOWNSTREAM
};

int ide_km_send_query(struct pci_dev *pdev);
int ide_km_set_keyset(struct pci_dev *pdev, int stream_id, int keyset,
		      struct key_package *key_package, enum ide_dev_type dtype);
int ide_km_enable_keyset(struct pci_dev *pdev, int stream_id, int keyset,
			 enum stream_direction dir);
void ide_km_disable_keyset(struct pci_dev *pdev, int stream_id, int keyset,
			   enum stream_direction dir);

struct key_package *ide_km_keyset_alloc(void);
void ide_km_keyset_free(struct key_package *pkg);

#endif
