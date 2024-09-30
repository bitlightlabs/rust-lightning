use crate::chain::transaction::OutPoint;
use crate::ln::chan_utils::{
	get_counterparty_payment_script, BuiltCommitmentTransaction, ClosingTransaction,
	CommitmentTransaction, HTLCOutputInCommitment,
};
use crate::ln::channel::{ChannelContext, ChannelError};
use crate::ln::channelmanager::{ChannelDetails, MsgHandleErrInternal};
use crate::ln::features::ChannelTypeFeatures;
use crate::ln::{ChannelId, PaymentHash};
use crate::sign::SignerProvider;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::PublicKey;
use bitcoin::TxOut;
use hex::DisplayHex;
use rgb_lib::{
	bitcoin::psbt::Psbt as RgbLibPsbt,
	wallet::{
		rust_only::{AssetColoringInfo, ColoringInfo},
		AssetIface, DatabaseType, Outpoint, WalletData,
	},
	BitcoinNetwork, ConsignmentExt, ContractId, Error as RgbLibError, FileContent, RgbTransfer,
	RgbTransport, RgbTxid, Wallet,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use core::ops::Deref;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::rgb_utils::{RgbInfo, RgbPaymentInfo, TransferInfo};

/// Static blinding costant (will be removed in the future)
pub const STATIC_BLINDING: u64 = 777;
/// Name of the file containing the bitcoin network
pub const BITCOIN_NETWORK_FNAME: &str = "bitcoin_network";
/// Name of the file containing the electrum URL
pub const INDEXER_URL_FNAME: &str = "indexer_url";
/// Name of the file containing the wallet fingerprint
pub const WALLET_FINGERPRINT_FNAME: &str = "wallet_fingerprint";
/// Name of the file containing the wallet account xPub
pub const WALLET_ACCOUNT_XPUB_FNAME: &str = "wallet_account_xpub";
const INBOUND_EXT: &str = "inbound";
const OUTBOUND_EXT: &str = "outbound";

/// RGB Lightning Node color extension trait
pub trait ColorSource {
	/// just for migration from legacy code
	fn get_ldk_data_dir(&self) -> PathBuf;
}

/// RGB Lightning Node color extension implementation
pub struct ColorSourceImpl {
	ldk_data_dir: PathBuf,
}

impl ColorSource for ColorSourceImpl {
	fn get_ldk_data_dir(&self) -> PathBuf {
		self.ldk_data_dir.clone()
	}
}

impl From<PathBuf> for ColorSourceImpl {
	fn from(dir: PathBuf) -> Self {
		Self { ldk_data_dir: dir }
	}
}

impl ColorSourceImpl {
	fn _get_file_in_parent(&self, fname: &str) -> PathBuf {
		self.ldk_data_dir.parent().unwrap().join(fname)
	}

	fn _read_file_in_parent(&self, fname: &str) -> String {
		fs::read_to_string(self._get_file_in_parent(fname)).unwrap()
	}

	fn _get_rgb_wallet_dir(&self) -> PathBuf {
		let fingerprint = self._read_file_in_parent(WALLET_FINGERPRINT_FNAME);
		self._get_file_in_parent(&fingerprint)
	}

	fn _get_bitcoin_network(&self) -> BitcoinNetwork {
		let bitcoin_network = self._read_file_in_parent(BITCOIN_NETWORK_FNAME);
		BitcoinNetwork::from_str(&bitcoin_network).unwrap()
	}

	fn _get_account_xpub(&self) -> String {
		self._read_file_in_parent(WALLET_ACCOUNT_XPUB_FNAME)
	}

	fn _get_indexer_url(&self) -> String {
		self._read_file_in_parent(INDEXER_URL_FNAME)
	}

	fn _new_rgb_wallet(
		data_dir: String, bitcoin_network: BitcoinNetwork, pubkey: String,
	) -> Wallet {
		Wallet::new(WalletData {
			data_dir,
			bitcoin_network,
			database_type: DatabaseType::Sqlite,
			max_allocations_per_utxo: 1,
			pubkey,
			mnemonic: None,
			vanilla_keychain: None,
		})
		.expect("valid rgb-lib wallet")
	}

	fn _get_wallet_data(&self) -> (String, BitcoinNetwork, String) {
		let data_dir = self.ldk_data_dir.parent().unwrap().to_string_lossy().to_string();
		let bitcoin_network = self._get_bitcoin_network();
		let pubkey = self._get_account_xpub();
		(data_dir, bitcoin_network, pubkey)
	}

	async fn _get_rgb_wallet(&self) -> Wallet {
		let (data_dir, bitcoin_network, pubkey) = self._get_wallet_data();
		tokio::task::spawn_blocking(move || {
			Self::_new_rgb_wallet(data_dir, bitcoin_network, pubkey)
		})
		.await
		.unwrap()
	}

	async fn _accept_transfer(
		&self, funding_txid: String, consignment_endpoint: RgbTransport,
	) -> Result<(RgbTransfer, u64), RgbLibError> {
		let (data_dir, bitcoin_network, pubkey) = self._get_wallet_data();
		let indexer_url = self._get_indexer_url();
		tokio::task::spawn_blocking(move || {
			let mut wallet = Self::_new_rgb_wallet(data_dir, bitcoin_network, pubkey);
			wallet.go_online(true, indexer_url).unwrap();
			wallet.accept_transfer(funding_txid.clone(), 0, consignment_endpoint, STATIC_BLINDING)
		})
		.await
		.unwrap()
	}

	/// Read TransferInfo file
	pub fn read_rgb_transfer_info(&self, path: &Path) -> TransferInfo {
		let serialized_info = fs::read_to_string(path).expect("able to read transfer info file");
		serde_json::from_str(&serialized_info).expect("valid transfer info")
	}

	/// Write TransferInfo file
	pub fn write_rgb_transfer_info(&self, path: &PathBuf, info: &TransferInfo) {
		let serialized_info = serde_json::to_string(&info).expect("valid transfer info");
		fs::write(path, serialized_info).expect("able to write transfer info file")
	}

	fn _counterparty_output_index(
		&self, outputs: &[TxOut], channel_type_features: &ChannelTypeFeatures,
		payment_key: &PublicKey,
	) -> Option<usize> {
		let counterparty_payment_script =
			get_counterparty_payment_script(channel_type_features, payment_key);
		outputs
			.iter()
			.enumerate()
			.find(|(_, out)| out.script_pubkey == counterparty_payment_script)
			.map(|(idx, _)| idx)
	}

	/// Return the position of the OP_RETURN output, if present
	pub fn op_return_position(&self, tx: &Transaction) -> Option<usize> {
		tx.output.iter().position(|o| o.script_pubkey.is_op_return())
	}

	/// Whether the transaction is colored (i.e. it has an OP_RETURN output)
	pub fn is_tx_colored(&self, tx: &Transaction) -> bool {
		self.op_return_position(tx).is_some()
	}

	/// Color commitment transaction
	pub(crate) fn color_commitment<SP: Deref>(
		&self, channel_context: &ChannelContext<SP>,
		commitment_transaction: &mut CommitmentTransaction, counterparty: bool,
	) -> Result<(), ChannelError>
	where
		<SP as std::ops::Deref>::Target: SignerProvider,
	{
		let channel_id = &channel_context.channel_id;
		let funding_outpoint =
			channel_context.channel_transaction_parameters.funding_outpoint.unwrap();

		let commitment_tx = commitment_transaction.clone().built.transaction;

		let (rgb_info, _) = self.get_rgb_channel_info_pending(channel_id);
		let contract_id = rgb_info.contract_id;

		let chan_id = channel_id.0.as_hex();
		let mut rgb_offered_htlc = 0;
		let mut rgb_received_htlc = 0;
		let mut last_rgb_payment_info = None;
		let mut output_map = HashMap::new();

		for htlc in commitment_transaction.htlcs() {
			if htlc.amount_rgb.unwrap_or(0) == 0 {
				continue;
			}
			let htlc_amount_rgb = htlc.amount_rgb.expect("this HTLC has RGB assets");

			let htlc_vout = htlc.transaction_output_index.unwrap();

			let inbound = htlc.offered == counterparty;

			let htlc_payment_hash = htlc.payment_hash.0.as_hex().to_string();
			let htlc_proxy_id = format!("{chan_id}{htlc_payment_hash}");
			let mut rgb_payment_info_proxy_id_path = self.ldk_data_dir.join(htlc_proxy_id);
			let rgb_payment_info_path = self.ldk_data_dir.join(htlc_payment_hash);
			let mut rgb_payment_info_path = rgb_payment_info_path.clone();
			if inbound {
				rgb_payment_info_proxy_id_path.set_extension(INBOUND_EXT);
				rgb_payment_info_path.set_extension(INBOUND_EXT);
			} else {
				rgb_payment_info_proxy_id_path.set_extension(OUTBOUND_EXT);
				rgb_payment_info_path.set_extension(OUTBOUND_EXT);
			}
			let rgb_payment_info_tmp_path = self._append_pending_extension(&rgb_payment_info_path);

			if rgb_payment_info_tmp_path.exists() {
				let mut rgb_payment_info = self.parse_rgb_payment_info(&rgb_payment_info_tmp_path);
				rgb_payment_info.local_rgb_amount = rgb_info.local_rgb_amount;
				rgb_payment_info.remote_rgb_amount = rgb_info.remote_rgb_amount;
				let serialized_info =
					serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
				fs::write(&rgb_payment_info_proxy_id_path, serialized_info)
					.expect("able to write rgb payment info file");
				fs::remove_file(rgb_payment_info_tmp_path).expect("able to remove file");
			}

			let rgb_payment_info = if rgb_payment_info_proxy_id_path.exists() {
				self.parse_rgb_payment_info(&rgb_payment_info_proxy_id_path)
			} else {
				let rgb_payment_info = RgbPaymentInfo {
					contract_id,
					amount: htlc_amount_rgb,
					local_rgb_amount: rgb_info.local_rgb_amount,
					remote_rgb_amount: rgb_info.remote_rgb_amount,
					swap_payment: true,
					inbound,
				};
				let serialized_info =
					serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
				fs::write(rgb_payment_info_proxy_id_path, serialized_info.clone())
					.expect("able to write rgb payment info file");
				fs::write(rgb_payment_info_path, serialized_info)
					.expect("able to write rgb payment info file");
				rgb_payment_info
			};

			if inbound {
				rgb_received_htlc += rgb_payment_info.amount
			} else {
				rgb_offered_htlc += rgb_payment_info.amount
			};

			output_map.insert(htlc_vout, rgb_payment_info.amount);

			last_rgb_payment_info = Some(rgb_payment_info);
		}

		let (local_amt, remote_amt) = if let Some(last_rgb_payment_info) = last_rgb_payment_info {
			(
				last_rgb_payment_info.local_rgb_amount - rgb_offered_htlc,
				last_rgb_payment_info.remote_rgb_amount - rgb_received_htlc,
			)
		} else {
			(rgb_info.local_rgb_amount, rgb_info.remote_rgb_amount)
		};
		let (vout_p2wpkh_amt, vout_p2wsh_amt) =
			if counterparty { (local_amt, remote_amt) } else { (remote_amt, local_amt) };

		let payment_point = if counterparty {
			channel_context.get_holder_pubkeys().payment_point
		} else {
			channel_context.get_counterparty_pubkeys().payment_point
		};

		if let Some(vout_p2wpkh) = self._counterparty_output_index(
			&commitment_tx.output,
			&channel_context.channel_type,
			&payment_point,
		) {
			output_map.insert(vout_p2wpkh as u32, vout_p2wpkh_amt);
		}

		if let Some(vout_p2wsh) = commitment_transaction.trust().revokeable_output_index() {
			output_map.insert(vout_p2wsh as u32, vout_p2wsh_amt);
		}

		let asset_coloring_info = AssetColoringInfo {
			iface: AssetIface::RGB20,
			input_outpoints: vec![Outpoint {
				txid: funding_outpoint.txid.to_string(),
				vout: funding_outpoint.index as u32,
			}],
			output_map,
			static_blinding: Some(STATIC_BLINDING),
		};
		let coloring_info = ColoringInfo {
			asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
			static_blinding: Some(STATIC_BLINDING),
			nonce: None,
		};
		let psbt = Psbt::from_unsigned_tx(commitment_tx.clone()).unwrap();
		let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
		let handle = Handle::current();
		let _ = handle.enter();
		let wallet = futures::executor::block_on(self._get_rgb_wallet());
		let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
		let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
		let modified_tx = psbt.extract_tx();

		let txid = modified_tx.txid();
		commitment_transaction.built =
			BuiltCommitmentTransaction { transaction: modified_tx, txid };

		wallet
			.consume_fascia(fascia.clone(), RgbTxid::from_str(&txid.to_string()).unwrap())
			.unwrap();

		// save RGB transfer data to disk
		let rgb_amount = if counterparty {
			vout_p2wpkh_amt + rgb_offered_htlc
		} else {
			vout_p2wsh_amt + rgb_received_htlc
		};
		let transfer_info = TransferInfo { contract_id, rgb_amount };
		let transfer_info_path = self.ldk_data_dir.join(format!("{txid}_transfer_info"));
		self.write_rgb_transfer_info(&transfer_info_path, &transfer_info);

		Ok(())
	}

	/// Color HTLC transaction
	pub(crate) fn color_htlc(
		&self, htlc_tx: &mut Transaction, htlc: &HTLCOutputInCommitment,
	) -> Result<(), ChannelError> {
		if htlc.amount_rgb.unwrap_or(0) == 0 {
			return Ok(());
		}
		let htlc_amount_rgb = htlc.amount_rgb.expect("this HTLC has RGB assets");

		let consignment_htlc_outpoint = htlc_tx.input.first().unwrap().previous_output;
		let commitment_txid = consignment_htlc_outpoint.txid.to_string();

		let transfer_info_path = self.ldk_data_dir.join(format!("{commitment_txid}_transfer_info"));
		let transfer_info = self.read_rgb_transfer_info(&transfer_info_path);
		let contract_id = transfer_info.contract_id;

		let asset_coloring_info = AssetColoringInfo {
			iface: AssetIface::RGB20,
			input_outpoints: vec![Outpoint {
				txid: commitment_txid,
				vout: consignment_htlc_outpoint.vout,
			}],
			output_map: HashMap::from([(0, htlc_amount_rgb)]),
			static_blinding: Some(STATIC_BLINDING),
		};
		let coloring_info = ColoringInfo {
			asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
			static_blinding: Some(STATIC_BLINDING),
			nonce: Some(1),
		};
		let psbt = Psbt::from_unsigned_tx(htlc_tx.clone()).unwrap();
		let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
		let handle = Handle::current();
		let _ = handle.enter();
		let wallet = futures::executor::block_on(self._get_rgb_wallet());
		let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
		let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
		let modified_tx = psbt.extract_tx();
		let txid = &modified_tx.txid();

		wallet
			.consume_fascia(fascia.clone(), RgbTxid::from_str(&txid.to_string()).unwrap())
			.unwrap();

		// save RGB transfer data to disk
		let transfer_info = TransferInfo { contract_id, rgb_amount: htlc_amount_rgb };
		let transfer_info_path = self.ldk_data_dir.join(format!("{txid}_transfer_info"));
		self.write_rgb_transfer_info(&transfer_info_path, &transfer_info);

		Ok(())
	}

	/// Color closing transaction
	pub(crate) fn color_closing(
		&self, channel_id: &ChannelId, funding_outpoint: &OutPoint,
		closing_transaction: &mut ClosingTransaction,
	) -> Result<(), ChannelError> {
		let closing_tx = closing_transaction.clone().built;

		let (rgb_info, _) = self.get_rgb_channel_info_pending(channel_id);
		let contract_id = rgb_info.contract_id;

		let holder_vout_amount = rgb_info.local_rgb_amount;
		let counterparty_vout_amount = rgb_info.remote_rgb_amount;

		let mut output_map = HashMap::new();

		if closing_transaction.to_holder_value_sat() > 0 {
			let holder_vout = closing_tx
				.output
				.iter()
				.position(|o| &o.script_pubkey == closing_transaction.to_holder_script())
				.unwrap();
			output_map.insert(holder_vout as u32, holder_vout_amount);
		}

		if closing_transaction.to_counterparty_value_sat() > 0 {
			let counterparty_vout = closing_tx
				.output
				.iter()
				.position(|o| &o.script_pubkey == closing_transaction.to_counterparty_script())
				.unwrap();
			output_map.insert(counterparty_vout as u32, counterparty_vout_amount);
		}

		let asset_coloring_info = AssetColoringInfo {
			iface: AssetIface::RGB20,
			input_outpoints: vec![Outpoint {
				txid: funding_outpoint.txid.to_string(),
				vout: funding_outpoint.index as u32,
			}],
			output_map,
			static_blinding: Some(STATIC_BLINDING),
		};
		let coloring_info = ColoringInfo {
			asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
			static_blinding: Some(STATIC_BLINDING),
			nonce: None,
		};
		let psbt = Psbt::from_unsigned_tx(closing_tx.clone()).unwrap();
		let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
		let handle = Handle::current();
		let _ = handle.enter();
		let wallet = futures::executor::block_on(self._get_rgb_wallet());
		let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
		let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
		let modified_tx = psbt.extract_tx();

		let txid = &modified_tx.txid();
		closing_transaction.built = modified_tx;

		wallet
			.consume_fascia(fascia.clone(), RgbTxid::from_str(&txid.to_string()).unwrap())
			.unwrap();

		// save RGB transfer data to disk
		let transfer_info = TransferInfo { contract_id, rgb_amount: holder_vout_amount };
		let transfer_info_path = self.ldk_data_dir.join(format!("{txid}_transfer_info"));
		self.write_rgb_transfer_info(&transfer_info_path, &transfer_info);

		Ok(())
	}

	/// Get RgbPaymentInfo file path
	pub fn get_rgb_payment_info_path(&self, payment_hash: &PaymentHash, inbound: bool) -> PathBuf {
		let mut path = self.ldk_data_dir.join(payment_hash.0.as_hex().to_string());
		path.set_extension(if inbound { INBOUND_EXT } else { OUTBOUND_EXT });
		path
	}

	/// Parse RgbPaymentInfo
	pub fn parse_rgb_payment_info(&self, rgb_payment_info_path: &PathBuf) -> RgbPaymentInfo {
		let serialized_info =
			fs::read_to_string(rgb_payment_info_path).expect("valid rgb payment info");
		serde_json::from_str(&serialized_info).expect("valid rgb info file")
	}

	/// Get RgbInfo file path
	pub fn get_rgb_channel_info_path(&self, channel_id: &str, pending: bool) -> PathBuf {
		let mut info_file_path = self.ldk_data_dir.join(channel_id);
		if pending {
			info_file_path.set_extension("pending");
		}
		info_file_path
	}

	/// Get RgbInfo file
	pub(crate) fn get_rgb_channel_info(
		&self, channel_id: &str, pending: bool,
	) -> (RgbInfo, PathBuf) {
		let info_file_path = self.get_rgb_channel_info_path(channel_id, pending);
		let info = self.parse_rgb_channel_info(&info_file_path);
		(info, info_file_path)
	}

	/// Get pending RgbInfo file
	pub fn get_rgb_channel_info_pending(&self, channel_id: &ChannelId) -> (RgbInfo, PathBuf) {
		self.get_rgb_channel_info(&channel_id.0.as_hex().to_string(), true)
	}

	/// Parse RgbInfo
	pub fn parse_rgb_channel_info(&self, rgb_channel_info_path: &PathBuf) -> RgbInfo {
		let serialized_info =
			fs::read_to_string(rgb_channel_info_path).expect("valid rgb info file");
		serde_json::from_str(&serialized_info).expect("valid rgb info file")
	}

	/// Whether the channel data for a channel exist
	pub fn is_channel_rgb(&self, channel_id: &ChannelId) -> bool {
		self.get_rgb_channel_info_path(&channel_id.0.as_hex().to_string(), false).exists()
	}

	/// Write RgbInfo file
	pub fn write_rgb_channel_info(&self, path: &PathBuf, rgb_info: &RgbInfo) {
		let serialized_info = serde_json::to_string(&rgb_info).expect("valid rgb info");
		fs::write(path, serialized_info).expect("able to write")
	}

	fn _append_pending_extension(&self, path: &Path) -> PathBuf {
		let mut new_path = path.to_path_buf();
		new_path
			.set_extension(format!("{}_pending", new_path.extension().unwrap().to_string_lossy()));
		new_path
	}

	/// Write RGB payment info to file
	pub fn write_rgb_payment_info_file(
		&self, payment_hash: &PaymentHash, contract_id: ContractId, amount_rgb: u64,
		swap_payment: bool, inbound: bool,
	) {
		let rgb_payment_info_path = self.get_rgb_payment_info_path(payment_hash, inbound);
		let rgb_payment_info_tmp_path = self._append_pending_extension(&rgb_payment_info_path);
		let rgb_payment_info = RgbPaymentInfo {
			contract_id,
			amount: amount_rgb,
			local_rgb_amount: 0,
			remote_rgb_amount: 0,
			swap_payment,
			inbound,
		};
		let serialized_info =
			serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
		std::fs::write(rgb_payment_info_path, serialized_info.clone())
			.expect("able to write rgb payment info file");
		std::fs::write(rgb_payment_info_tmp_path, serialized_info)
			.expect("able to write rgb payment info tmp file");
	}

	/// Rename RGB files from temporary to final channel ID
	pub(crate) fn rename_rgb_files(
		&self, channel_id: &ChannelId, temporary_channel_id: &ChannelId,
	) {
		let temp_chan_id = temporary_channel_id.0.as_hex().to_string();
		let chan_id = channel_id.0.as_hex().to_string();

		fs::rename(
			self.get_rgb_channel_info_path(&temp_chan_id, false),
			self.get_rgb_channel_info_path(&chan_id, false),
		)
		.expect("rename ok");
		fs::rename(
			self.get_rgb_channel_info_path(&temp_chan_id, true),
			self.get_rgb_channel_info_path(&chan_id, true),
		)
		.expect("rename ok");

		let funding_consignment_tmp =
			self.ldk_data_dir.join(format!("consignment_{}", temp_chan_id));
		if funding_consignment_tmp.exists() {
			let funding_consignment = self.ldk_data_dir.join(format!("consignment_{}", chan_id));
			fs::rename(funding_consignment_tmp, funding_consignment).expect("rename ok");
		}
	}

	/// Handle funding on the receiver side
	pub(crate) fn handle_funding(
		&self, temporary_channel_id: &ChannelId, funding_txid: String,
		consignment_endpoint: RgbTransport,
	) -> Result<(), MsgHandleErrInternal> {
		let handle = Handle::current();
		let _ = handle.enter();
		let accept_res = futures::executor::block_on(
			self._accept_transfer(funding_txid.clone(), consignment_endpoint),
		);
		let (consignment, remote_rgb_amount) = match accept_res {
			Ok(res) => res,
			Err(RgbLibError::InvalidConsignment) => {
				return Err(MsgHandleErrInternal::send_err_msg_no_close(
					"Invalid RGB consignment for funding".to_owned(),
					*temporary_channel_id,
				))
			},
			Err(RgbLibError::NoConsignment) => {
				return Err(MsgHandleErrInternal::send_err_msg_no_close(
					"Failed to find RGB consignment".to_owned(),
					*temporary_channel_id,
				))
			},
			Err(RgbLibError::UnknownRgbSchema { schema_id }) => {
				return Err(MsgHandleErrInternal::send_err_msg_no_close(
					format!("Unsupported RGB schema: {schema_id}"),
					*temporary_channel_id,
				))
			},
			Err(e) => {
				return Err(MsgHandleErrInternal::send_err_msg_no_close(
					format!("Unexpected error: {e}"),
					*temporary_channel_id,
				))
			},
		};

		let consignment_path = self.ldk_data_dir.join(format!("consignment_{}", funding_txid));
		consignment.save_file(consignment_path).expect("unable to write file");
		let consignment_path =
			self.ldk_data_dir.join(format!("consignment_{}", temporary_channel_id.0.as_hex()));
		consignment.save_file(consignment_path).expect("unable to write file");

		let rgb_info = RgbInfo {
			contract_id: consignment.contract_id(),
			local_rgb_amount: 0,
			remote_rgb_amount,
		};
		let temporary_channel_id_str = temporary_channel_id.0.as_hex().to_string();
		self.write_rgb_channel_info(
			&self.get_rgb_channel_info_path(&temporary_channel_id_str, true),
			&rgb_info,
		);
		self.write_rgb_channel_info(
			&self.get_rgb_channel_info_path(&temporary_channel_id_str, false),
			&rgb_info,
		);

		Ok(())
	}

	/// Update RGB channel amount
	pub fn update_rgb_channel_amount(
		&self, channel_id: &str, rgb_offered_htlc: u64, rgb_received_htlc: u64, pending: bool,
	) {
		let (mut rgb_info, info_file_path) = self.get_rgb_channel_info(channel_id, pending);

		if rgb_offered_htlc > rgb_received_htlc {
			let spent = rgb_offered_htlc - rgb_received_htlc;
			rgb_info.local_rgb_amount -= spent;
			rgb_info.remote_rgb_amount += spent;
		} else {
			let received = rgb_received_htlc - rgb_offered_htlc;
			rgb_info.local_rgb_amount += received;
			rgb_info.remote_rgb_amount -= received;
		}

		self.write_rgb_channel_info(&info_file_path, &rgb_info)
	}

	/// Update pending RGB channel amount
	pub(crate) fn update_rgb_channel_amount_pending(
		&self, channel_id: &ChannelId, rgb_offered_htlc: u64, rgb_received_htlc: u64,
	) {
		self.update_rgb_channel_amount(
			&channel_id.0.as_hex().to_string(),
			rgb_offered_htlc,
			rgb_received_htlc,
			true,
		)
	}

	/// Whether the payment is colored
	pub(crate) fn is_payment_rgb(&self, payment_hash: &PaymentHash) -> bool {
		self.get_rgb_payment_info_path(payment_hash, false).exists()
			|| self.get_rgb_payment_info_path(payment_hash, true).exists()
	}

	/// Detect the contract ID of the payment and then filter hops based on contract ID and amount
	pub(crate) fn filter_first_hops(
		&self, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>,
	) -> (ContractId, u64) {
		let rgb_payment_info_path = self.get_rgb_payment_info_path(payment_hash, false);
		let rgb_payment_info = self.parse_rgb_payment_info(&rgb_payment_info_path);
		let contract_id = rgb_payment_info.contract_id;
		let rgb_amount = rgb_payment_info.amount;
		first_hops.retain(|h| {
			let info_file_path = self.ldk_data_dir.join(h.channel_id.0.as_hex().to_string());
			if !info_file_path.exists() {
				return false;
			}
			let serialized_info = fs::read_to_string(info_file_path).expect("valid rgb info file");
			let rgb_info: RgbInfo =
				serde_json::from_str(&serialized_info).expect("valid rgb info file");
			rgb_info.contract_id == contract_id && rgb_info.local_rgb_amount >= rgb_amount
		});
		(contract_id, rgb_amount)
	}
}
