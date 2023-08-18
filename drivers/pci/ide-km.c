// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/pci.h>
#include <linux/pci-ide.h>
#include "pci.h"

#define PCI_DOE_PROTOCOL_IDE	0

enum km_object_id {
	KM_OBJ_ID_QUERY = 0,
	KM_OBJ_ID_QUERY_RESP,
	KM_OBJ_ID_KEY_PROG,
	KM_OBJ_ID_KP_ACK,
	KM_OBJ_ID_K_SET_GO,
	KM_OBJ_ID_K_SET_STOP,
	KM_OBJ_ID_K_GOSTOP_ACK
};

struct ide_km_header {
	u8 protocol_id;
	u8 object_id;
	union {
		struct {
			u8 reserved;
			u8 port_index;
		};
		__le16 reserved1;
	};
};

struct km_query {
	struct ide_km_header hdr;
};

struct km_link_reg_block {
	__le32 stream_ctrl;
	__le32 stream_status;
};

struct km_sel_addr_assoc_block {
	__le32 addr_assoc_1;
	__le32 addr_assoc_2;
	__le32 addr_assoc_3;
};

struct km_sel_reg_block {
	__le32 cap;
	__le32 ctrl;
	__le32 status;
	__le32 rid_assoc_1;
	__le32 rid_assoc_2;
	struct km_sel_addr_assoc_block addr_assoc[];
};

struct km_query_response_hdr {
	struct ide_km_header hdr;
	u8 dev_fn;
	u8 bus;
	u8 segment;
	u8 max_port_index;
	__le32 ide_cap_reg;
	__le32 ide_ctrl_reg;
};

enum KM_KEY_DIRECTION {
	KM_KEY_RX = 0,
	KM_KEY_TX
};

enum KM_KEY_SUBSTREAM_ID {
	KM_KEY_SUBSTREAM_PR = 0,
	KM_KEY_SUBSTREAM_NPR = 1,
	KM_KEY_SUBSTREAM_CPL = 2,
};

struct km_key_context {
	u8 stream_id;
	u8 reserved;
	u8 key_set:1;
	u8 rx_tx:1;
	u8 reserved1:1;
	u8 sub_stream:5;
	u8 port_index;
};

struct km_key_prog {
	struct ide_km_header hdr;
	struct km_key_context k;
	u8 key[32];
	u8 iv[8];
};

struct km_kp_ack {
	struct ide_km_header hdr;
	struct km_key_context k;
};

struct km_k_set_go {
	struct ide_km_header hdr;
	struct km_key_context k;
};

struct km_k_set_stop {
	struct ide_km_header hdr;
	struct km_key_context k;
};

struct km_k_gostop_ack {
	struct ide_km_header hdr;
	struct km_key_context k;
};


int ide_km_send_query(struct pci_dev *pdev)
{
	struct km_query query = {0};
	struct km_query_response_hdr *resp;

	/* May need to change PortIndex for switch downstream port */

	/* Send query command via SPDM */

	/* Wait for response */

	/* Do we need to do anything about response? */

	return 0;
}
EXPORT_SYMBOL_GPL(ide_km_send_query);

int ide_km_set_keyset(struct pci_dev *pdev, int stream_id, int keyset,
		      struct key_package *key_package, enum ide_dev_type dtype)
{
	struct km_key_prog key_prog;
	int port_idx = 0;	/* change for sw dsp */
	int i, j;

	for (i = 0; i < IDE_STREAM_DIRECTION_MAX; i++) { /* direction */
		for (j = 0; j < IDE_NUM_SUBSTREAMS; j++) { /* sub-streams */
			int dir;

			/*
			 * Downstream device (dsd) rx/tx is the opposite of upstream
			 * device (usd). So the direction needs to be flipped so the
			 * keys can be mirrored. usd tx keys == dsd rx keys and usd
			 * rx keys = dsd tx keys.
			 */
			if (dtype == IDE_DEV_UPSTREAM)
				dir = i;
			else
				dir = flip_direction(i);


			memset(&key_prog, 0, sizeof(key_prog));
			key_prog.hdr.object_id = KM_OBJ_ID_KEY_PROG;

			key_prog.k.stream_id = stream_id;
			key_prog.k.key_set = keyset;
			key_prog.k.rx_tx = dir;
			key_prog.k.sub_stream = j;
			key_prog.k.port_index = port_idx;
			memcpy(key_prog.key, key_package->key[dir + j], IDE_KEY_SIZE);
			memcpy(key_prog.iv, key_package->iv[dir + j], IDE_IV_SIZE);

			/* Send KEY_PROG via SPDM */

			/* Wait for KP_ACK */
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ide_km_set_keyset);

static int ide_km_toggle_keyset(struct pci_dev *pdev, int stream_id, int keyset,
				int cmd, enum stream_direction dir)
{
	struct km_k_set_go key_go = {0};
	int port_idx = 0;	/* change for sw dsp */
	int i;

	for (i = 0; i < IDE_NUM_SUBSTREAMS; i++) { /* sub-streams */
		memset(&key_go, 0, sizeof(key_go));
		key_go.hdr.object_id = cmd;

		key_go.k.stream_id = stream_id;
		key_go.k.key_set = keyset;
		key_go.k.rx_tx = dir;
		key_go.k.sub_stream = i;
		key_go.k.port_index = port_idx;

		/* Send cmd via SPDM */

		/* Wait for K_GOSTOP_ACK */
	}

	return 0;
}

int ide_km_enable_keyset(struct pci_dev *pdev, int stream_id, int keyset,
			 enum stream_direction dir)
{
	return ide_km_toggle_keyset(pdev, stream_id, keyset,
				    KM_OBJ_ID_K_SET_GO, dir);
}
EXPORT_SYMBOL_GPL(ide_km_enable_keyset);

void ide_km_disable_keyset(struct pci_dev *pdev, int stream_id, int keyset,
			   enum stream_direction dir)
{
	ide_km_toggle_keyset(pdev, stream_id, keyset,
			     KM_OBJ_ID_K_SET_STOP, dir);
}
EXPORT_SYMBOL_GPL(ide_km_disable_keyset);

