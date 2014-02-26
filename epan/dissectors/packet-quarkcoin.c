/* packet-quarkcoin.c
 * Routines for litcoin dissection
 * Copyright 2014, arowser <arowser@gmail.com>
 * bitcoin address: 1JesArEyh7JCw7ZYeYf1JNZkVogBcWkj3w
 *
 * See https://en.quarkcoin.it/wiki/Protocol_specification
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-tcp.h"

#define QUARKCOIN_MAIN_MAGIC_NUMBER       0xDD03A5FE
#define QUARKCOIN_TESTNET_MAGIC_NUMBER    0xF7391A01

static const value_string inv_types[] =
{
  { 0, "ERROR" },
  { 1, "MSG_TX" },
  { 2, "MSG_BLOCK" },
  { 0, NULL }
};

/*
 * Minimum quarkcoin identification header.
 * - Magic - 4 bytes
 * - Command - 12 bytes
 * - Payload length - 4 bytes
 * - Checksum - 4 bytes
 */
#define QUARKCOIN_HEADER_LENGTH 4+12+4+4

void proto_register_quarkcoin(void);
void proto_reg_handoff_quarkcoin(void);

static dissector_handle_t quarkcoin_handle;

static header_field_info *hfi_quarkcoin = NULL;

#define QUARKCOIN_HFI_INIT HFI_INIT(proto_quarkcoin)

static header_field_info hfi_quarkcoin_magic QUARKCOIN_HFI_INIT =
  { "Packet magic", "quarkcoin.magic", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_quarkcoin_command QUARKCOIN_HFI_INIT =
  { "Command name", "quarkcoin.command", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_quarkcoin_length QUARKCOIN_HFI_INIT =
  { "Payload Length", "quarkcoin.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_quarkcoin_checksum QUARKCOIN_HFI_INIT =
  { "Payload checksum", "quarkcoin.checksum", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

/* version message */
static header_field_info hfi_quarkcoin_msg_version QUARKCOIN_HFI_INIT =
  { "Version message", "quarkcoin.version", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_version QUARKCOIN_HFI_INIT =
  { "Protocol version", "quarkcoin.version.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_services QUARKCOIN_HFI_INIT =
  { "Node services", "quarkcoin.version.services", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_timestamp QUARKCOIN_HFI_INIT =
  { "Node timestamp", "quarkcoin.version.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_addr_me QUARKCOIN_HFI_INIT =
  { "Address of emmitting node", "quarkcoin.version.addr_me", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_addr_you QUARKCOIN_HFI_INIT =
  { "Address as receiving node", "quarkcoin.version.addr_you", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_nonce QUARKCOIN_HFI_INIT =
  { "Random nonce", "quarkcoin.version.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_user_agent QUARKCOIN_HFI_INIT =
  { "User agent", "quarkcoin.version.user_agent", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_start_height QUARKCOIN_HFI_INIT =
  { "Block start height", "quarkcoin.version.start_height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* addr message */
static header_field_info hfi_msg_addr_count8 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.addr.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_count16 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.addr.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_count32 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.addr.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_count64 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.addr.count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_quarkcoin_msg_addr QUARKCOIN_HFI_INIT =
  { "Address message", "quarkcoin.addr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_address QUARKCOIN_HFI_INIT =
  { "Address", "quarkcoin.addr.address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_timestamp QUARKCOIN_HFI_INIT =
  { "Address timestamp", "quarkcoin.addr.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

/* inv message */
static header_field_info hfi_msg_inv_count8 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.inv.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_count16 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.inv.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_count32 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.inv.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_count64 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.inv.count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_quarkcoin_msg_inv QUARKCOIN_HFI_INIT =
  { "Inventory message", "quarkcoin.inv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_type QUARKCOIN_HFI_INIT =
  { "Type", "quarkcoin.inv.type", FT_UINT32, BASE_DEC, VALS(inv_types), 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_hash QUARKCOIN_HFI_INIT =
  { "Data hash", "quarkcoin.inv.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* getdata message */
static header_field_info hfi_msg_getdata_count8 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getdata.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count16 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getdata.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count32 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getdata.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count64 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getdata.count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_quarkcoin_msg_getdata QUARKCOIN_HFI_INIT =
  { "Getdata message", "quarkcoin.getdata", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_type QUARKCOIN_HFI_INIT =
  { "Type", "quarkcoin.getdata.type", FT_UINT32, BASE_DEC, VALS(inv_types), 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_hash QUARKCOIN_HFI_INIT =
  { "Data hash", "quarkcoin.getdata.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* getblocks message */
static header_field_info hfi_msg_getblocks_count8 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getblocks.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_count16 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getblocks.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_count32 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getblocks.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_count64 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getblocks.count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_quarkcoin_msg_getblocks QUARKCOIN_HFI_INIT =
  { "Getdata message", "quarkcoin.getblocks", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_start QUARKCOIN_HFI_INIT =
  { "Starting hash", "quarkcoin.getblocks.hash_start", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_stop QUARKCOIN_HFI_INIT =
  { "Stopping hash", "quarkcoin.getblocks.hash_stop", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* getheaders message */
static header_field_info hfi_msg_getheaders_count8 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getheaders.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_count16 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getheaders.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_count32 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getheaders.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_count64 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.getheaders.count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_quarkcoin_msg_getheaders QUARKCOIN_HFI_INIT =
  { "Getheaders message", "quarkcoin.getheaders", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_start QUARKCOIN_HFI_INIT =
  { "Starting hash", "quarkcoin.getheaders.hash_start", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_stop QUARKCOIN_HFI_INIT =
  { "Stopping hash", "quarkcoin.getheaders.hash_stop", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* tx message */
static header_field_info hfi_msg_tx_in_count8 QUARKCOIN_HFI_INIT =
  { "Input Count", "quarkcoin.tx.input_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_count16 QUARKCOIN_HFI_INIT =
  { "Input Count", "quarkcoin.tx.input_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_count32 QUARKCOIN_HFI_INIT =
  { "Input Count", "quarkcoin.tx.input_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_count64 QUARKCOIN_HFI_INIT =
  { "Input Count", "quarkcoin.tx.input_count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_quarkcoin_msg_tx QUARKCOIN_HFI_INIT =
  { "Tx message", "quarkcoin.tx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_version QUARKCOIN_HFI_INIT =
  { "Transaction version", "quarkcoin.tx.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script8 QUARKCOIN_HFI_INIT =
  { "Script Length", "quarkcoin.tx.in.script_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script16 QUARKCOIN_HFI_INIT =
  { "Script Length", "quarkcoin.tx.in.script_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script32 QUARKCOIN_HFI_INIT =
  { "Script Length", "quarkcoin.tx.in.script_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script64 QUARKCOIN_HFI_INIT =
  { "Script Length", "quarkcoin.tx.in.script_length", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in QUARKCOIN_HFI_INIT =
  { "Transaction input", "quarkcoin.tx.in", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_prev_output QUARKCOIN_HFI_INIT =
  { "Previous output", "quarkcoin.tx.in.prev_output", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_prev_outp_hash QUARKCOIN_HFI_INIT =
  { "Hash", "quarkcoin.tx.in.prev_output.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_prev_outp_index QUARKCOIN_HFI_INIT =
  { "Index", "quarkcoin.tx.in.prev_output.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_sig_script QUARKCOIN_HFI_INIT =
  { "Signature script", "quarkcoin.tx.in.sig_script", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_seq QUARKCOIN_HFI_INIT =
  { "Sequence", "quarkcoin.tx.in.seq", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count8 QUARKCOIN_HFI_INIT =
  { "Output Count", "quarkcoin.tx.output_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count16 QUARKCOIN_HFI_INIT =
  { "Output Count", "quarkcoin.tx.output_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count32 QUARKCOIN_HFI_INIT =
  { "Output Count", "quarkcoin.tx.output_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count64 QUARKCOIN_HFI_INIT =
  { "Output Count", "quarkcoin.tx.output_count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out QUARKCOIN_HFI_INIT =
  { "Transaction output", "quarkcoin.tx.out", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_value QUARKCOIN_HFI_INIT =
  { "Value", "quarkcoin.tx.out.value", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script8 QUARKCOIN_HFI_INIT =
  { "Script Length", "quarkcoin.tx.out.script_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script16 QUARKCOIN_HFI_INIT =
  { "Script Length", "quarkcoin.tx.out.script_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script32 QUARKCOIN_HFI_INIT =
  { "Script Length", "quarkcoin.tx.out.script_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script64 QUARKCOIN_HFI_INIT =
  { "Script Length", "quarkcoin.tx.out.script_length", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script QUARKCOIN_HFI_INIT =
  { "Script", "quarkcoin.tx.out.script", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_lock_time QUARKCOIN_HFI_INIT =
  { "Block lock time or block ID", "quarkcoin.tx.lock_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* block message */
static header_field_info hfi_msg_block_transactions8 QUARKCOIN_HFI_INIT =
  { "Number of transactions", "quarkcoin.block.num_transactions", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_transactions16 QUARKCOIN_HFI_INIT =
  { "Number of transactions", "quarkcoin.tx.num_transactions", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_transactions32 QUARKCOIN_HFI_INIT =
  { "Number of transactions", "quarkcoin.tx.num_transactions", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_transactions64 QUARKCOIN_HFI_INIT =
  { "Number of transactions", "quarkcoin.tx.num_transactions", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_quarkcoin_msg_block QUARKCOIN_HFI_INIT =
  { "Block message", "quarkcoin.block", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_version QUARKCOIN_HFI_INIT =
  { "Block version", "quarkcoin.block.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_prev_block QUARKCOIN_HFI_INIT =
  { "Previous block", "quarkcoin.block.prev_block", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_merkle_root QUARKCOIN_HFI_INIT =
  { "Merkle root", "quarkcoin.block.merkle_root", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_time QUARKCOIN_HFI_INIT =
  { "Block timestamp", "quarkcoin.block.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_bits QUARKCOIN_HFI_INIT =
  { "Bits", "quarkcoin.block.merkle_root", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_nonce QUARKCOIN_HFI_INIT =
  { "Nonce", "quarkcoin.block.nonce", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

/* services */
static header_field_info hfi_services_network QUARKCOIN_HFI_INIT =
  { "Network node", "quarkcoin.services.network", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x1, NULL, HFILL };

/* address */
static header_field_info hfi_address_services QUARKCOIN_HFI_INIT =
  { "Node services", "quarkcoin.address.services", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_address_address QUARKCOIN_HFI_INIT =
  { "Node address", "quarkcoin.address.address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_address_port QUARKCOIN_HFI_INIT =
  { "Node port", "quarkcoin.address.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* variable string */
static header_field_info hfi_string_value QUARKCOIN_HFI_INIT =
  { "String value", "quarkcoin.string.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count8 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.string.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count16 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.string.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count32 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.string.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count64 QUARKCOIN_HFI_INIT =
  { "Count", "quarkcoin.string.count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };


static gint ett_quarkcoin = -1;
static gint ett_quarkcoin_msg = -1;
static gint ett_services = -1;
static gint ett_address = -1;
static gint ett_string = -1;
static gint ett_addr_list = -1;
static gint ett_inv_list = -1;
static gint ett_getdata_list = -1;
static gint ett_getblocks_list = -1;
static gint ett_getheaders_list = -1;
static gint ett_tx_in_list = -1;
static gint ett_tx_in_outp = -1;
static gint ett_tx_out_list = -1;

static expert_field ei_quarkcoin_command_unknown = EI_INIT;


static gboolean quarkcoin_desegment  = TRUE;

static guint
get_quarkcoin_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 length;
  length = QUARKCOIN_HEADER_LENGTH;

  /* add payload length */
  length += tvb_get_letohl(tvb, offset+16);

  return length;
}

/**
 * Create a services sub-tree for bit-by-bit display
 */
static proto_tree *
create_services_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;
  guint64 services;

  tree = proto_item_add_subtree(ti, ett_services);

  /* start of services */
  /* NOTE:
   *  - 2011-06-05
   *    Currently the boolean tree only supports a maximum of
   *    32 bits - so we split services in two
   */
  services = tvb_get_letoh64(tvb, offset);

  /* service = NODE_NETWORK */
  proto_tree_add_boolean(tree, &hfi_services_network, tvb, offset, 4, (guint32)services);

  /* end of services */

  return tree;
}

/**
 * Create a sub-tree and fill it with a net_addr structure
 */
static proto_tree *
create_address_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;

  tree = proto_item_add_subtree(ti, ett_address);

  /* services */
  ti = proto_tree_add_item(tree, &hfi_address_services, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  create_services_tree(tvb, ti, offset);
  offset += 8;

  /* IPv6 address */
  proto_tree_add_item(tree, &hfi_address_address, tvb, offset, 16, ENC_NA);
  offset += 16;

  /* port */
  proto_tree_add_item(tree, &hfi_address_port, tvb, offset, 2, ENC_BIG_ENDIAN);

  return tree;
}

/**
 * Extract a variable length integer from a tvbuff
 */
static void
get_varint(tvbuff_t *tvb, const gint offset, gint *length, guint64 *ret)
{
  guint value;

  /* Note: just throw an exception if not enough  bytes are available in the tvbuff */

  /* calculate variable length */
  value = tvb_get_guint8(tvb, offset);
  if (value < 0xfd)
  {
    *length = 1;
    *ret = value;
    return;
  }

  if (value == 0xfd)
  {
    *length = 3;
    *ret = tvb_get_letohs(tvb, offset+1);
    return;
  }
  if (value == 0xfe)
  {
    *length = 5;
    *ret = tvb_get_letohl(tvb, offset+1);
    return;
  }

  *length = 9;
  *ret = tvb_get_letoh64(tvb, offset+1);
  return;

}

static void add_varint_item(proto_tree *tree, tvbuff_t *tvb, const gint offset, gint length,
                            header_field_info *hfi8, header_field_info *hfi16, header_field_info *hfi32, header_field_info *hfi64)
{
  switch (length)
  {
  case 1:
    proto_tree_add_item(tree, hfi8,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
    break;
  case 3:
    proto_tree_add_item(tree, hfi16, tvb, offset+1, 2, ENC_LITTLE_ENDIAN);
    break;
  case 5:
    proto_tree_add_item(tree, hfi32, tvb, offset+1, 4, ENC_LITTLE_ENDIAN);
    break;
  case 9:
    proto_tree_add_item(tree, hfi64, tvb, offset+1, 8, ENC_LITTLE_ENDIAN);
    break;
  }
}

static proto_tree *
create_string_tree(proto_tree *tree, header_field_info* hfi, tvbuff_t *tvb, guint32* offset)
{
  proto_tree *subtree;
  proto_item *ti;
  gint        varint_length;
  guint64     varint;
  gint        string_length;

  /* First is the length of the following string as a varint  */
  get_varint(tvb, *offset, &varint_length, &varint);
  string_length = (gint) varint;

  ti = proto_tree_add_item(tree, hfi, tvb, *offset, varint_length + string_length, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_string);

  /* length */
  add_varint_item(subtree, tvb, *offset, varint_length, &hfi_string_varint_count8,
                  &hfi_string_varint_count16, &hfi_string_varint_count32,
                  &hfi_string_varint_count64);
  *offset += varint_length;

  /* string */
  proto_tree_add_item(subtree, &hfi_string_value, tvb, *offset, string_length,
                      ENC_ASCII|ENC_NA);
  *offset += string_length;

  return subtree;
}

/* Note: A number of the following message handlers include code of the form:
 *          ...
 *          guint64     count;
 *          ...
 *          for (; count > 0; count--)
 *          {
 *            proto_tree_add_item9...);
 *            offset += ...;
 *            proto_tree_add_item9...);
 *            offset += ...;
 *            ...
 *          }
 *          ...
 *
 * Issue if 'count' is a very large number:
 *    If 'tree' is NULL, then the result will be effectively (but not really)
 *    an infinite loop. This is true because if 'tree' is NULL then
 *    proto_tree_add_item(tree, ...) is effectively a no-op and will not throw
 *    an exception.
 *    So: the loop should be executed only when 'tree' is defined so that the
 *        proto_ calls will throw an exception when the tvb is used up;
 *        This should only take a few-hundred loops at most.
 *           https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8312
 */

/**
 * Handler for version messages
 */
static void
dissect_quarkcoin_msg_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *ti;
  guint32     version;
  guint32     offset = 0;

  if (!tree)
    return;

  ti   = proto_tree_add_item(tree, &hfi_quarkcoin_msg_version, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_quarkcoin_msg);

  version = tvb_get_letohl(tvb, offset);

  proto_tree_add_item(tree, &hfi_msg_version_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  ti = proto_tree_add_item(tree, &hfi_msg_version_services, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  create_services_tree(tvb, ti, offset);
  offset += 8;

  proto_tree_add_item(tree, &hfi_msg_version_timestamp, tvb, offset, 8, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
  offset += 8;

  ti = proto_tree_add_item(tree, &hfi_msg_version_addr_you, tvb, offset, 26, ENC_NA);
  create_address_tree(tvb, ti, offset);
  offset += 26;

  if (version >= 106)
  {
    ti = proto_tree_add_item(tree, &hfi_msg_version_addr_me, tvb, offset, 26, ENC_NA);
    create_address_tree(tvb, ti, offset);
    offset += 26;

    proto_tree_add_item(tree, &hfi_msg_version_nonce, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    create_string_tree(tree, &hfi_msg_version_user_agent, tvb, &offset);

    if (version >= 209)
    {
      proto_tree_add_item(tree, &hfi_msg_version_start_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      /* offset += 4; */
    }
  }
}

/**
 * Handler for address messages
 */
static void
dissect_quarkcoin_msg_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  if (!tree)
    return;

  ti   = proto_tree_add_item(tree, &hfi_quarkcoin_msg_addr, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_quarkcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_addr_count8, &hfi_msg_addr_count16,
                  &hfi_msg_addr_count32, &hfi_msg_addr_count64);
  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    ti = proto_tree_add_item(tree, &hfi_msg_addr_address, tvb, offset, 30, ENC_NA);
    subtree = create_address_tree(tvb, ti, offset+4);

    proto_tree_add_item(subtree, &hfi_msg_addr_timestamp, tvb, offset, 4, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
    offset += 26;
    offset += 4;
  }
}

/**
 * Handler for inventory messages
 */
static void
dissect_quarkcoin_msg_inv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  if (!tree)
    return;

  ti   = proto_tree_add_item(tree, &hfi_quarkcoin_msg_inv, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_quarkcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_inv_count8, &hfi_msg_inv_count16,
                  &hfi_msg_inv_count32, &hfi_msg_inv_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    ti = proto_tree_add_text(tree, tvb, offset, 36, "Inventory vector");
    subtree = proto_item_add_subtree(ti, ett_inv_list);

    proto_tree_add_item(subtree, &hfi_msg_inv_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, &hfi_msg_inv_hash, tvb, offset, 32, ENC_NA);
    offset += 32;
  }
}

/**
 * Handler for getdata messages
 */
static void
dissect_quarkcoin_msg_getdata(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  if (!tree)
    return;

  ti   = proto_tree_add_item(tree, &hfi_quarkcoin_msg_getdata, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_quarkcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_getdata_count8, &hfi_msg_getdata_count16,
                  &hfi_msg_getdata_count32, &hfi_msg_getdata_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    ti = proto_tree_add_text(tree, tvb, offset, 36, "Inventory vector");
    subtree = proto_item_add_subtree(ti, ett_getdata_list);

    proto_tree_add_item(subtree, &hfi_msg_getdata_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, &hfi_msg_getdata_hash, tvb, offset, 32, ENC_NA);
    offset += 32;
  }
}

/**
 * Handler for getblocks messages
 */
static void
dissect_quarkcoin_msg_getblocks(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  if (!tree)
    return;

  ti   = proto_tree_add_item(tree, &hfi_quarkcoin_msg_getblocks, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_quarkcoin_msg);

  /* why the protcol version is sent here nobody knows */
  proto_tree_add_item(tree, &hfi_msg_version_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_getblocks_count8, &hfi_msg_getblocks_count16,
                  &hfi_msg_getblocks_count32, &hfi_msg_getblocks_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree_add_item(tree, &hfi_msg_getblocks_start, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  proto_tree_add_item(tree, &hfi_msg_getblocks_stop, tvb, offset, 32, ENC_NA);
}

/**
 * Handler for getheaders messages
 * UNTESTED
 */
static void
dissect_quarkcoin_msg_getheaders(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  if (!tree)
    return;

  ti   = proto_tree_add_item(tree, &hfi_quarkcoin_msg_getheaders, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_quarkcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_getheaders_count8, &hfi_msg_getheaders_count16,
                  &hfi_msg_getheaders_count32, &hfi_msg_getheaders_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree_add_item(tree, &hfi_msg_getheaders_start, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  proto_tree_add_item(tree, &hfi_msg_getheaders_stop, tvb, offset, 32, ENC_NA);
  return;
}

/**
 * Handler for tx message body
 */
static guint32
dissect_quarkcoin_msg_tx_common(tvbuff_t *tvb, guint32 offset, packet_info *pinfo _U_, proto_tree *tree, guint msgnum)
{
  proto_item *rti;
  gint        count_length;
  guint64     in_count;
  guint64     out_count;

  DISSECTOR_ASSERT(tree != NULL);

  if (msgnum == 0) {
    rti  = proto_tree_add_item(tree, &hfi_quarkcoin_msg_tx, tvb, offset, -1, ENC_NA);
  } else {
    rti  = proto_tree_add_none_format(tree, hfi_quarkcoin_msg_tx.id, tvb, offset, -1, "Tx message [ %4d ]", msgnum);
  }
  tree = proto_item_add_subtree(rti, ett_quarkcoin_msg);

  proto_tree_add_item(tree, &hfi_msg_tx_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* TxIn[] */
  get_varint(tvb, offset, &count_length, &in_count);
  add_varint_item(tree, tvb, offset, count_length, &hfi_msg_tx_in_count8, &hfi_msg_tx_in_count16,
                  &hfi_msg_tx_in_count32, &hfi_msg_tx_in_count64);

  offset += count_length;

  /* TxIn
   *   [36]  previous_output    outpoint
   *   [1+]  script length      var_int
   *   [ ?]  signature script   uchar[]
   *   [ 4]  sequence           uint32_t
   *
   * outpoint (aka previous output)
   *   [32]  hash               char[32
   *   [ 4]  index              uint32_t
   *
   */
  for (; in_count > 0; in_count--)
  {
    proto_tree *subtree;
    proto_tree *prevtree;
    proto_item *ti;
    proto_item *pti;
    guint64     script_length;

    get_varint(tvb, offset+36, &count_length, &script_length);

    /* A funny script_length won't cause an exception since the field type is FT_NONE */
    ti = proto_tree_add_item(tree, &hfi_msg_tx_in, tvb, offset,
        36 + count_length + (guint)script_length + 4, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_tx_in_list);

    /* previous output */
    pti = proto_tree_add_item(subtree, &hfi_msg_tx_in_prev_output, tvb, offset, 36, ENC_NA);
    prevtree = proto_item_add_subtree(pti, ett_tx_in_outp);

    proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_hash, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* end previous output */

    add_varint_item(subtree, tvb, offset, count_length, &hfi_msg_tx_in_script8, &hfi_msg_tx_in_script16,
                    &hfi_msg_tx_in_script32, &hfi_msg_tx_in_script64);

    offset += count_length;

    if ((offset + script_length) > G_MAXINT)
      THROW(ReportedBoundsError);  /* special check since script_length is guint64 */

    proto_tree_add_item(subtree, &hfi_msg_tx_in_sig_script, tvb, offset, (guint)script_length, ENC_NA);
    offset += (guint)script_length;

    proto_tree_add_item(subtree, &hfi_msg_tx_in_seq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
  }

  /* TxOut[] */
  get_varint(tvb, offset, &count_length, &out_count);
  add_varint_item(tree, tvb, offset, count_length, &hfi_msg_tx_out_count8, &hfi_msg_tx_out_count16,
                  &hfi_msg_tx_out_count32, &hfi_msg_tx_out_count64);

  offset += count_length;

  /*  TxOut
   *    [ 8] value
   *    [1+] script length [var_int]
   *    [ ?] script
   */
  for (; out_count > 0; out_count--)
  {
    proto_item *ti;
    proto_tree *subtree;
    guint64     script_length;

    get_varint(tvb, offset+8, &count_length, &script_length);

    /* A funny script_length won't cause an exception since the field type is FT_NONE */
    ti = proto_tree_add_item(tree, &hfi_msg_tx_out, tvb, offset,
                             8 + count_length + (guint)script_length , ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_tx_out_list);

    proto_tree_add_item(subtree, &hfi_msg_tx_out_value, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    add_varint_item(subtree, tvb, offset, count_length, &hfi_msg_tx_out_script8, &hfi_msg_tx_out_script16,
                    &hfi_msg_tx_out_script32, &hfi_msg_tx_out_script64);

    offset += count_length;

    if ((offset + script_length) > G_MAXINT)
      THROW(ReportedBoundsError);  /* special check since script_length is guint64 */

    proto_tree_add_item(subtree, &hfi_msg_tx_out_script, tvb, offset, (guint)script_length, ENC_NA);
    offset += (guint)script_length;
  }

  proto_tree_add_item(tree, &hfi_msg_tx_lock_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* needed for block nesting */
  proto_item_set_len(rti, offset);

  return offset;
}

/**
 * Handler for tx message
 */
static void
dissect_quarkcoin_msg_tx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!tree)
    return;

  dissect_quarkcoin_msg_tx_common(tvb, 0, pinfo, tree, 0);
}


/**
 * Handler for block messages
 */

static void
dissect_quarkcoin_msg_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint       msgnum;
  guint32     offset = 0;

  if (!tree)
    return;

  /*  Block
   *    [ 4] version         uint32_t
   *    [32] prev_block      char[32]
   *    [32] merkle_root     char[32]
   *    [ 4] timestamp       uint32_t  A unix timestamp ... (Currently limited to dates before the year 2106!)
   *    [ 4] bits            uint32_t
   *    [ 4] nonce           uint32_t
   *    [ ?] txn_count       var_int
   *    [ ?] txns            tx[]      Block transactions, in format of "tx" command
   */

  ti   = proto_tree_add_item(tree, &hfi_quarkcoin_msg_block, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_quarkcoin_msg);

  proto_tree_add_item(tree, &hfi_msg_block_version,     tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_block_prev_block,  tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, &hfi_msg_block_merkle_root, tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, &hfi_msg_block_time,        tvb, offset,  4, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_block_bits,        tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_block_nonce,       tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_block_transactions8, &hfi_msg_block_transactions16,
                  &hfi_msg_block_transactions32, &hfi_msg_block_transactions64);

  offset += length;

  msgnum = 0;
  for (; count > 0; count--)
  {
    msgnum += 1;
    offset = dissect_quarkcoin_msg_tx_common(tvb, offset, pinfo, tree, msgnum);
  }
}

/**
 * Handler for unimplemented or payload-less messages
 */
static void
dissect_quarkcoin_msg_empty(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_)
{
  return;
}

typedef void (*msg_dissector_func_t)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

typedef struct msg_dissector
{
  const gchar *command;
  msg_dissector_func_t function;
} msg_dissector_t;

static msg_dissector_t msg_dissectors[] =
{
  {"version",     dissect_quarkcoin_msg_version},
  {"addr",        dissect_quarkcoin_msg_addr},
  {"inv",         dissect_quarkcoin_msg_inv},
  {"getdata",     dissect_quarkcoin_msg_getdata},
  {"getblocks",   dissect_quarkcoin_msg_getblocks},
  {"getheaders",  dissect_quarkcoin_msg_getheaders},
  {"tx",          dissect_quarkcoin_msg_tx},
  {"block",       dissect_quarkcoin_msg_block},

  /* messages with no payload */
  {"verack",      dissect_quarkcoin_msg_empty},
  {"getaddr",     dissect_quarkcoin_msg_empty},
  {"ping",        dissect_quarkcoin_msg_empty},

  /* messages not implemented */
  {"notfound",    dissect_quarkcoin_msg_empty},
  {"headers",     dissect_quarkcoin_msg_empty},
  {"mempool",     dissect_quarkcoin_msg_empty},
  {"checkorder",  dissect_quarkcoin_msg_empty},
  {"submitorder", dissect_quarkcoin_msg_empty},
  {"reply",       dissect_quarkcoin_msg_empty},
  {"pong",        dissect_quarkcoin_msg_empty},
  {"filterload",  dissect_quarkcoin_msg_empty},
  {"filteradd",   dissect_quarkcoin_msg_empty},
  {"filterclear", dissect_quarkcoin_msg_empty},
  {"merkleblock", dissect_quarkcoin_msg_empty},
  {"reject",      dissect_quarkcoin_msg_empty},
  {"alert",       dissect_quarkcoin_msg_empty}
};

static int dissect_quarkcoin_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     i;
  guint32     offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Quarkcoin");

  ti   = proto_tree_add_item(tree, hfi_quarkcoin, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_quarkcoin);

  /* add basic protocol data */
  proto_tree_add_item(tree, &hfi_quarkcoin_magic,   tvb,  0,  4, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, &hfi_quarkcoin_command, tvb,  4, 12, ENC_ASCII|ENC_NA);
  proto_tree_add_item(tree, &hfi_quarkcoin_length,  tvb, 16,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, &hfi_quarkcoin_checksum, tvb, 20,  4, ENC_BIG_ENDIAN);

  offset = 24;

  /* handle command specific message part */
  for (i = 0; i < array_length(msg_dissectors); i++)
  {
    if (tvb_memeql(tvb, 4, msg_dissectors[i].command,
          strlen(msg_dissectors[i].command)) == 0)
    {
      tvbuff_t *tvb_sub;

      col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", msg_dissectors[i].command);

      tvb_sub = tvb_new_subset_remaining(tvb, offset);
      msg_dissectors[i].function(tvb_sub, pinfo, tree);
      return tvb_length(tvb);
    }
  }

  /* no handler found */
  col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "[unknown command]");

  expert_add_info(pinfo, ti, &ei_quarkcoin_command_unknown);
  return tvb_length(tvb);
}

static int
dissect_quarkcoin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  col_clear(pinfo->cinfo, COL_INFO);
  tcp_dissect_pdus(tvb, pinfo, tree, quarkcoin_desegment, QUARKCOIN_HEADER_LENGTH,
      get_quarkcoin_pdu_length, dissect_quarkcoin_tcp_pdu, data);

  return tvb_reported_length(tvb);
}

static gboolean
dissect_quarkcoin_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  guint32 magic_number;
  conversation_t *conversation;

  if (tvb_length(tvb) < 4)
      return FALSE;

  magic_number = tvb_get_letohl(tvb, 0);
  if ((magic_number != QUARKCOIN_MAIN_MAGIC_NUMBER) &&
      (magic_number != QUARKCOIN_TESTNET_MAGIC_NUMBER))
     return FALSE;

  /* Ok: This connection should always use the quarkcoin dissector */
  conversation = find_or_create_conversation(pinfo);
  conversation_set_dissector(conversation, quarkcoin_handle);

  dissect_quarkcoin(tvb, pinfo, tree, data);
  return TRUE;
}

void
proto_register_quarkcoin(void)
{
#ifndef HAVE_HFI_SECTION_INIT
  static header_field_info *hfi[] = {
    &hfi_quarkcoin_magic,
    &hfi_quarkcoin_command,
    &hfi_quarkcoin_length,
    &hfi_quarkcoin_checksum,

    /* version message */
    &hfi_quarkcoin_msg_version,
    &hfi_msg_version_version,
    &hfi_msg_version_services,
    &hfi_msg_version_addr_me,
    &hfi_msg_version_addr_you,
    &hfi_msg_version_timestamp,
    &hfi_msg_version_nonce,
    &hfi_msg_version_user_agent,
    &hfi_msg_version_start_height,

    /* addr message */
    &hfi_msg_addr_count8,
    &hfi_msg_addr_count16,
    &hfi_msg_addr_count32,
    &hfi_msg_addr_count64,
    &hfi_quarkcoin_msg_addr,
    &hfi_msg_addr_address,
    &hfi_msg_addr_timestamp,

    /* inv message */
    &hfi_msg_inv_count8,
    &hfi_msg_inv_count16,
    &hfi_msg_inv_count32,
    &hfi_msg_inv_count64,
    &hfi_quarkcoin_msg_inv,
    &hfi_msg_inv_type,
    &hfi_msg_inv_hash,

    /* getdata message */
    &hfi_msg_getdata_count8,
    &hfi_msg_getdata_count16,
    &hfi_msg_getdata_count32,
    &hfi_msg_getdata_count64,
    &hfi_quarkcoin_msg_getdata,
    &hfi_msg_getdata_type,
    &hfi_msg_getdata_hash,

    /* getblocks message */
    &hfi_msg_getblocks_count8,
    &hfi_msg_getblocks_count16,
    &hfi_msg_getblocks_count32,
    &hfi_msg_getblocks_count64,
    &hfi_quarkcoin_msg_getblocks,
    &hfi_msg_getblocks_start,
    &hfi_msg_getblocks_stop,

    /* getheaders message */
    &hfi_msg_getheaders_count8,
    &hfi_msg_getheaders_count16,
    &hfi_msg_getheaders_count32,
    &hfi_msg_getheaders_count64,
    &hfi_quarkcoin_msg_getheaders,
    &hfi_msg_getheaders_start,
    &hfi_msg_getheaders_stop,

    /* tx message */
    &hfi_quarkcoin_msg_tx,
    &hfi_msg_tx_version,

    /* tx message - input */
    &hfi_msg_tx_in_count8,
    &hfi_msg_tx_in_count16,
    &hfi_msg_tx_in_count32,
    &hfi_msg_tx_in_count64,

    &hfi_msg_tx_in,
    &hfi_msg_tx_in_prev_output,

    &hfi_msg_tx_in_prev_outp_hash,
    &hfi_msg_tx_in_prev_outp_index,

    &hfi_msg_tx_in_script8,
    &hfi_msg_tx_in_script16,
    &hfi_msg_tx_in_script32,
    &hfi_msg_tx_in_script64,
    &hfi_msg_tx_in_sig_script,
    &hfi_msg_tx_in_seq,

    /* tx message - output */
    &hfi_msg_tx_out_count8,
    &hfi_msg_tx_out_count16,
    &hfi_msg_tx_out_count32,
    &hfi_msg_tx_out_count64,
    &hfi_msg_tx_out,
    &hfi_msg_tx_out_value,
    &hfi_msg_tx_out_script8,
    &hfi_msg_tx_out_script16,
    &hfi_msg_tx_out_script32,
    &hfi_msg_tx_out_script64,
    &hfi_msg_tx_out_script,

    &hfi_msg_tx_lock_time,

    /* block message */
    &hfi_msg_block_transactions8,
    &hfi_msg_block_transactions16,
    &hfi_msg_block_transactions32,
    &hfi_msg_block_transactions64,
    &hfi_quarkcoin_msg_block,
    &hfi_msg_block_version,
    &hfi_msg_block_prev_block,
    &hfi_msg_block_merkle_root,
    &hfi_msg_block_time,
    &hfi_msg_block_bits,
    &hfi_msg_block_nonce,

    /* services */
    &hfi_services_network,

    /* address */
    &hfi_address_services,
    &hfi_address_address,
    &hfi_address_port,

    /* variable string */
    &hfi_string_value,
    &hfi_string_varint_count8,
    &hfi_string_varint_count16,
    &hfi_string_varint_count32,
    &hfi_string_varint_count64,
  };
#endif

  static gint *ett[] = {
    &ett_quarkcoin,
    &ett_quarkcoin_msg,
    &ett_services,
    &ett_address,
    &ett_string,
    &ett_addr_list,
    &ett_inv_list,
    &ett_getdata_list,
    &ett_getblocks_list,
    &ett_getheaders_list,
    &ett_tx_in_list,
    &ett_tx_in_outp,
    &ett_tx_out_list,
  };

  static ei_register_info ei[] = {
     { &ei_quarkcoin_command_unknown, { "quarkcoin.command.unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
  };

  module_t *quarkcoin_module;
  expert_module_t* expert_quarkcoin;

  int proto_quarkcoin;


  proto_quarkcoin = proto_register_protocol("Quarkcoin protocol", "Quarkcoin", "quarkcoin");
  hfi_quarkcoin = proto_registrar_get_nth(proto_quarkcoin);

  proto_register_subtree_array(ett, array_length(ett));
  proto_register_fields(proto_quarkcoin, hfi, array_length(hfi));

  expert_quarkcoin = expert_register_protocol(proto_quarkcoin);
  expert_register_field_array(expert_quarkcoin, ei, array_length(ei));

  quarkcoin_handle = new_register_dissector("quarkcoin", dissect_quarkcoin, proto_quarkcoin);

  quarkcoin_module = prefs_register_protocol(proto_quarkcoin, NULL);
  prefs_register_bool_preference(quarkcoin_module, "desegment",
                                 "Desegment all Quarkcoin messages spanning multiple TCP segments",
                                 "Whether the Quarkcoin dissector should desegment all messages"
                                 " spanning multiple TCP segments",
                                 &quarkcoin_desegment);

}

void
proto_reg_handoff_quarkcoin(void)
{
  dissector_add_handle("tcp.port", quarkcoin_handle);  /* for 'decode-as' */

  heur_dissector_add( "tcp", dissect_quarkcoin_heur, hfi_quarkcoin->id);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
