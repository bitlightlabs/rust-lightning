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

use bitcoin::bip32::ExtendedPrivKey;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::psbt::{PartiallySignedTransaction, Psbt};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{TxOut, Txid};
use database::{
	ColorDatabaseImpl, ConsignmentBinaryData, PaymentDirection, PaymentHashKey, ProxyIdKey,
	RgbInfoKey,
};
use hex::DisplayHex;
use rgb_lib::wallet::rust_only::AssetBeneficiariesMap;
use rgb_lib::Fascia;
use rgb_lib::{
	bitcoin::psbt::Psbt as RgbLibPsbt,
	wallet::{
		rust_only::{AssetColoringInfo, ColoringInfo},
		AssetIface, DatabaseType, Outpoint, WalletData,
	},
	BitcoinNetwork, ConsignmentExt, ContractId, Error as RgbLibError, FileContent, RgbTransfer,
	RgbTransport, RgbTxid, Wallet,
};
use tokio::runtime::Handle;

use core::net;
use core::ops::Deref;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::rgb_utils::{RgbInfo, RgbPaymentInfo, TransferInfo};

#[allow(missing_docs)]
pub mod database;

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
	fn ldk_data_dir(&self) -> PathBuf;
	fn network(&self) -> BitcoinNetwork;
}

pub type ColorSourceWrapper = Arc<Mutex<ColorSourceImpl>>;

pub trait WalletProxy {
	fn consume_fascia(&self, fascia: Fascia, witness_txid: RgbTxid) -> Result<(), String>;
}

pub struct WalletProxyImpl {
	network: BitcoinNetwork,
	xprv: ExtendedPrivKey,
	ldk_data_dir: PathBuf,
}
impl fmt::Debug for WalletProxyImpl {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("WalletProxyImpl").field("xpub_getter", &"Function").finish()
	}
}
impl WalletProxy for WalletProxyImpl {
	fn consume_fascia(&self, fascia: Fascia, witness_txid: RgbTxid) -> Result<(), String> {
		println!("block_on consume_fascia");
		let wallet = futures::executor::block_on(self._get_rgb_wallet(&self.ldk_data_dir.clone()));
		wallet.consume_fascia(fascia, witness_txid).map_err(|e| e.to_string())
	}
}

impl WalletProxyImpl {
	fn new(network: BitcoinNetwork, xprv: ExtendedPrivKey, ldk_data_dir: PathBuf) -> Self {
		Self { network, xprv, ldk_data_dir }
	}

	pub fn color_psbt(
		&self, psbt_to_color: &mut PartiallySignedTransaction, coloring_info: ColoringInfo,
	) -> Result<(Fascia, AssetBeneficiariesMap), String> {
		println!("block_on color_psbt");
		let wallet = futures::executor::block_on(self._get_rgb_wallet(&self.ldk_data_dir.clone()));
		let (fascia, asset_beneficiaries_map) =
			wallet.color_psbt(psbt_to_color, coloring_info).map_err(|e| e.to_string())?;
		Ok((fascia, asset_beneficiaries_map))
	}

	// pub fn is_online(&self) -> bool {
	// 	let wallet = futures::executor::block_on(self._get_rgb_wallet(&self.ldk_data_dir.clone()));
	// 	// wallet.go_online(true, indexer_url).unwrap();
	// }

	pub fn xpub(&self) -> String {
		bitcoin::bip32::ExtendedPubKey::from_priv(&bitcoin::key::Secp256k1::new(), &self.xprv)
			.to_string()
	}

	async fn _get_rgb_wallet(&self, ldk_data_dir: &Path) -> Wallet {
		let data_dir = ldk_data_dir.parent().unwrap().to_string_lossy().to_string();
		let bitcoin_network = self.network.clone();
		let xpub = self.xpub().clone();
		tokio::task::spawn_blocking(move || {
			Wallet::new(WalletData {
				data_dir,
				bitcoin_network,
				database_type: DatabaseType::Sqlite,
				max_allocations_per_utxo: 1,
				pubkey: xpub,
				mnemonic: None,
				vanilla_keychain: None,
			})
			.expect("valid rgb-lib wallet")
		})
		.await
		.unwrap()
	}
}

/// RGB Lightning Node color extension implementation
#[derive(Debug)]
pub struct ColorSourceImpl {
	ldk_data_dir: PathBuf,
	network: BitcoinNetwork,
	wallet_proxy: WalletProxyImpl,
	database: ColorDatabaseImpl,
}

impl ColorSource for ColorSourceImpl {
	fn ldk_data_dir(&self) -> PathBuf {
		self.ldk_data_dir.clone()
	}

	fn network(&self) -> BitcoinNetwork {
		self.network
	}
}

impl ColorSourceImpl {
	pub fn new(ldk_data_dir: PathBuf, network: BitcoinNetwork, xprv: ExtendedPrivKey) -> Self {
		let ldk_data_dir = Arc::new(ldk_data_dir);

		let instance = Self {
			ldk_data_dir: Arc::clone(&ldk_data_dir).to_path_buf(),
			network,
			wallet_proxy: WalletProxyImpl::new(
				network,
				xprv,
				Arc::clone(&ldk_data_dir).to_path_buf(),
			),
			database: ColorDatabaseImpl::new(),
		};

		instance
	}

	fn xpub(&self) -> String {
		self.wallet_proxy.xpub()
	}

	fn _xpub(ldk_data_dir: PathBuf) -> String {
		let parent_dir = ldk_data_dir.parent().expect("Failed to get parent directory");
		let file_path = parent_dir.join("wallet_account_xpub");
		std::fs::read_to_string(file_path).expect("Failed to read the file")
	}

	fn wallet_proxy(&self) -> &WalletProxyImpl {
		&self.wallet_proxy
	}
	//--------------//--------------//--------------//--------------//--------------

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
		let bitcoin_network = self.network();
		let pubkey = self.xpub();
		(data_dir, bitcoin_network, pubkey)
	}

	async fn _accept_transfer(
		&self, funding_txid: String, consignment_endpoint: RgbTransport,
	) -> Result<(RgbTransfer, u64), RgbLibError> {
		let (data_dir, bitcoin_network, pubkey) = self._get_wallet_data();
		// if !self.wallet_proxy().is_online() {
		// 	return Err(RgbLibError::Internal { details: "Wallet is offline".to_string() });
		// }

		tokio::task::spawn_blocking(move || {
			let mut wallet = Self::_new_rgb_wallet(data_dir, bitcoin_network, pubkey);
			wallet.go_online(true, "127.0.0.1:50001".to_string()).expect("valid indexer url"); // local demo only
			wallet.accept_transfer(funding_txid.clone(), 0, consignment_endpoint, STATIC_BLINDING)
		})
		.await
		.unwrap()
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
	pub fn op_return_position(tx: &Transaction) -> Option<usize> {
		tx.output.iter().position(|o| o.script_pubkey.is_op_return())
	}

	/// Whether the transaction is colored (i.e. it has an OP_RETURN output)
	pub fn is_tx_colored(tx: &Transaction) -> bool {
		ColorSourceImpl::op_return_position(tx).is_some()
	}

	/// Color commitment transaction
	pub(crate) fn color_commitment<SP: Deref>(
		&self, channel_context: &ChannelContext<SP>,
		commitment_transaction: &mut CommitmentTransaction, counterparty: bool,
	) -> Result<(), ChannelError>
	where
		<SP as std::ops::Deref>::Target: SignerProvider,
	{
		println!("debug: color_source -> color_commitment");
		let channel_id = &channel_context.channel_id;
		let funding_outpoint =
			channel_context.channel_transaction_parameters.funding_outpoint.unwrap();

		let commitment_tx = commitment_transaction.clone().built.transaction;

		let (rgb_info, _) = self.get_rgb_channel_info_pending(channel_id);
		if rgb_info.is_none() {
			return Err(ChannelError::Close("RgbInfo lost".to_string()));
		}

		let rgb_info = rgb_info.unwrap();
		let contract_id = rgb_info.contract_id;

		let chan_id = channel_id.0.as_hex();
		let mut rgb_offered_htlc = 0;
		let mut rgb_received_htlc = 0;
		let mut last_rgb_payment_info = None;
		let mut output_map = HashMap::new();
		println!("debug: color_source -> color_commitment handle htlc");
		for htlc in commitment_transaction.htlcs() {
			if htlc.amount_rgb.unwrap_or(0) == 0 {
				continue;
			}
			let htlc_amount_rgb = htlc.amount_rgb.expect("this HTLC has RGB assets");
			let htlc_vout = htlc.transaction_output_index.unwrap();
			let inbound = htlc.offered == counterparty;
			let htlc_payment_hash = htlc.payment_hash;
			let htlc_proxy_id = format!("{}{}", chan_id, htlc_payment_hash);

			let proxy_id_key = ProxyIdKey::new(channel_id, &htlc.payment_hash, inbound.into());
			let payment_hash_key = PaymentHashKey::from(&proxy_id_key);

			let info = self
				.database
				.rgb_payment()
				.lock()
				.unwrap()
				.get_pending_payment(&htlc.payment_hash)
				.cloned();

			if let Some(mut rgb_payment_info) = info {
				rgb_payment_info.local_rgb_amount = rgb_info.local_rgb_amount;
				rgb_payment_info.remote_rgb_amount = rgb_info.remote_rgb_amount;
				self.database.rgb_payment().lock().unwrap().insert(
					&proxy_id_key,
					rgb_payment_info.clone(),
					false,
				);
			}

			let info = self
				.database
				.rgb_payment()
				.lock()
				.unwrap()
				.get_by_proxy_id_key(&proxy_id_key)
				.cloned();

			let rgb_payment_info = info.unwrap_or_else(|| {
				let info = RgbPaymentInfo {
					contract_id,
					amount: htlc_amount_rgb,
					local_rgb_amount: rgb_info.local_rgb_amount,
					remote_rgb_amount: rgb_info.remote_rgb_amount,
					swap_payment: true,
					inbound,
				};
				self.database.rgb_payment().lock().unwrap().insert(
					&proxy_id_key,
					info.clone(),
					false,
				);
				info
			});

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
		// let wallet = futures::executor::block_on(self._get_rgb_wallet());
		let wallet = self.wallet_proxy();
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
		// let transfer_info_path = self.ldk_data_dir.join(format!("{txid}_transfer_info"));
		// self.write_rgb_transfer_info(&transfer_info_path, &transfer_info);
		self.database.transfer_info().lock().unwrap().insert(txid, transfer_info);
		println!("debug: color_source -> color_commitment done");

		Ok(())
	}

	/// Color HTLC transaction
	pub(crate) fn color_htlc(
		&self, htlc_tx: &mut Transaction, htlc: &HTLCOutputInCommitment,
	) -> Result<(), ChannelError> {
		println!("debug: color_source -> color_htlc");
		if htlc.amount_rgb.unwrap_or(0) == 0 {
			return Ok(());
		}
		let htlc_amount_rgb = htlc.amount_rgb.expect("this HTLC has RGB assets");

		let consignment_htlc_outpoint = htlc_tx.input.first().unwrap().previous_output;
		let commitment_txid = consignment_htlc_outpoint.txid;

		// let transfer_info_path = self.ldk_data_dir.join(format!("{commitment_txid}_transfer_info"));
		// let transfer_info = self.read_rgb_transfer_info(&transfer_info_path);
		let transfer_info = self
			.database
			.transfer_info()
			.lock()
			.unwrap()
			.get_by_txid(&commitment_txid)
			.unwrap()
			.to_owned();
		let contract_id = transfer_info.contract_id;

		let asset_coloring_info = AssetColoringInfo {
			iface: AssetIface::RGB20,
			input_outpoints: vec![Outpoint {
				txid: commitment_txid.to_string(),
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
		let wallet = self.wallet_proxy();
		let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
		let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
		let modified_tx = psbt.extract_tx();
		let txid = &modified_tx.txid();

		wallet
			.consume_fascia(fascia.clone(), RgbTxid::from_str(&txid.to_string()).unwrap())
			.unwrap();

		// save RGB transfer data to disk
		let transfer_info = TransferInfo { contract_id, rgb_amount: htlc_amount_rgb };
		// let transfer_info_path = self.ldk_data_dir.join(format!("{txid}_transfer_info"));
		// self.write_rgb_transfer_info(&transfer_info_path, &transfer_info);
		self.database.transfer_info().lock().unwrap().insert(*txid, transfer_info);

		Ok(())
	}

	/// Color closing transaction
	pub(crate) fn color_closing(
		&self, channel_id: &ChannelId, funding_outpoint: &OutPoint,
		closing_transaction: &mut ClosingTransaction,
	) -> Result<(), ChannelError> {
		println!("debug: color_source -> color_closing");
		let closing_tx = closing_transaction.clone().built;

		let (rgb_info, _) = self.get_rgb_channel_info_pending(channel_id);
		if rgb_info.is_none() {
			return Err(ChannelError::Close("RgbInfo lost".to_string()));
		}

		let rgb_info = rgb_info.unwrap();
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
		let wallet = self.wallet_proxy();
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
		// let transfer_info_path = self.ldk_data_dir.join(format!("{txid}_transfer_info"));
		// self.write_rgb_transfer_info(&transfer_info_path, &transfer_info);
		self.database.transfer_info().lock().unwrap().insert(*txid, transfer_info);

		Ok(())
	}

	/// Get RgbInfo file
	pub fn get_rgb_channel_info(
		&self, channel_id: &ChannelId, pending: bool,
	) -> (Option<RgbInfo>, RgbInfoKey) {
		let key = RgbInfoKey::new(channel_id, pending);
		let info =
			self.database.rgb_info().lock().unwrap().get_by_rgb_info_key(&key).map(|i| i.clone());
		(info, key)
	}

	/// Get pending RgbInfo file
	pub fn get_rgb_channel_info_pending(
		&self, channel_id: &ChannelId,
	) -> (Option<RgbInfo>, RgbInfoKey) {
		self.get_rgb_channel_info(&channel_id, true)
	}

	/// Whether the channel data for a channel exist
	pub fn is_channel_rgb(&self, channel_id: &ChannelId) -> bool {
		let cache_key = RgbInfoKey::new(&channel_id, false);
		self.database.rgb_info().lock().unwrap().get_by_rgb_info_key(&cache_key).is_some()
	}

	/// Write RgbInfo file
	pub fn save_rgb_channel_info(&self, key: &RgbInfoKey, rgb_info: &RgbInfo) {
		self.database.rgb_info().lock().unwrap().insert(*key, rgb_info.clone());
	}

	pub fn save_rgb_payment_info(
		&self, channel_id: Option<&ChannelId>, payment_hash: &PaymentHash, is_pending: bool,
		rgb_payment_info: &RgbPaymentInfo,
	) {
		if channel_id.is_none() && is_pending {
			// 推测当 is_pending 为 true 时，因为时 keysend 所以暂时还没有 channel_id
			self.database.rgb_payment().lock().unwrap().insert_without_proxy_id(
				&PaymentHashKey::new(payment_hash.clone(), rgb_payment_info.inbound.into()),
				rgb_payment_info.clone(),
			);
		} else {
			self.database.rgb_payment().lock().unwrap().insert(
				&ProxyIdKey::new(channel_id.unwrap(), payment_hash, is_pending.into()),
				rgb_payment_info.clone(),
				is_pending,
			);
		}
	}
	/// Rename RGB files from temporary to final channel ID
	pub(crate) fn rename_rgb_files(
		&self, channel_id: &ChannelId, temporary_channel_id: &ChannelId,
	) {
		let temp_chan_id = temporary_channel_id;
		let chan_id = channel_id;

		println!("rename_channel_id");
		self.database.rename_channel_id(temp_chan_id, chan_id);
	}

	/// Handle funding on the receiver side
	pub(crate) fn handle_funding(
		&self, temporary_channel_id: &ChannelId, funding_txid: String,
		consignment_endpoint: RgbTransport,
	) -> Result<(), MsgHandleErrInternal> {
		let handle = Handle::current();
		let _ = handle.enter();
		println!("block_on handle_funding");
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

		let funding_txid = Txid::from_str(&funding_txid).unwrap();
		let mut consignment_data = ConsignmentBinaryData::default();
		let ret = consignment.save(&mut consignment_data);
		assert!(ret.is_ok());
		self.database.consignment().lock().unwrap().insert(
			temporary_channel_id,
			funding_txid,
			consignment_data,
		);

		let rgb_info = RgbInfo {
			contract_id: consignment.contract_id(),
			local_rgb_amount: 0,
			remote_rgb_amount,
		};
		self.save_rgb_channel_info(&RgbInfoKey::new(&temporary_channel_id, true), &rgb_info);
		self.save_rgb_channel_info(&RgbInfoKey::new(&temporary_channel_id, false), &rgb_info);

		Ok(())
	}

	/// Update RGB channel amount
	pub fn update_rgb_channel_amount_impl(
		&self, channel_id: &ChannelId, rgb_offered_htlc: u64, rgb_received_htlc: u64, pending: bool,
	) {
		let (rgb_info, key) = self.get_rgb_channel_info(channel_id, pending);
		if rgb_info.is_none() {
			return;
		}
		let mut rgb_info = rgb_info.unwrap();

		if rgb_offered_htlc > rgb_received_htlc {
			let spent = rgb_offered_htlc - rgb_received_htlc;
			rgb_info.local_rgb_amount -= spent;
			rgb_info.remote_rgb_amount += spent;
		} else {
			let received = rgb_received_htlc - rgb_offered_htlc;
			rgb_info.local_rgb_amount += received;
			rgb_info.remote_rgb_amount -= received;
		}

		self.save_rgb_channel_info(&key, &rgb_info)
	}

	/// Update pending RGB channel amount
	pub fn update_rgb_channel_amount_pending(
		&self, channel_id: &ChannelId, rgb_offered_htlc: u64, rgb_received_htlc: u64,
	) {
		println!("debug: color_source -> update_rgb_channel_amount_pending");
		self.update_rgb_channel_amount_impl(&channel_id, rgb_offered_htlc, rgb_received_htlc, true)
	}

	/// Whether the payment is colored
	pub(crate) fn is_payment_rgb(&self, payment_hash: &PaymentHash) -> bool {
		self.database.rgb_payment().lock().unwrap().get_by_payment_hash(payment_hash).is_some()
	}

	pub fn get_rgb_payment_info(
		&self, payment_hash: &PaymentHash, inbound: bool,
	) -> Option<RgbPaymentInfo> {
		self.database
			.rgb_payment()
			.lock()
			.unwrap()
			.get_by_payment_hash_key(&PaymentHashKey::new(
				payment_hash.clone(),
				if inbound {
					database::PaymentDirection::Inbound
				} else {
					database::PaymentDirection::Outbound
				},
			))
			.map(|i| i.clone())
	}

	/// Detect the contract ID of the payment and then filter hops based on contract ID and amount
	pub(crate) fn filter_first_hops(
		&self, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>,
	) -> (ContractId, u64) {
		let htlc_payment_hash = payment_hash;
		let payment_hash_key =
			PaymentHashKey::new(payment_hash.clone(), database::PaymentDirection::Outbound);
		let rgb_payment_info = self
			.database
			.rgb_payment()
			.lock()
			.unwrap()
			.get_by_payment_hash_key(&payment_hash_key)
			.unwrap()
			.to_owned();
		let contract_id = rgb_payment_info.contract_id;
		let rgb_amount = rgb_payment_info.amount;
		first_hops.retain(|h| {
			let rgb_info_key = RgbInfoKey::new(&h.channel_id, false);
			let (rgb_info, _) = self.get_rgb_channel_info_pending(&h.channel_id);
			if rgb_info.is_none() {
				unreachable!("Channel should have RGB info")
			}

			let rgb_info = rgb_info.unwrap();
			rgb_info.contract_id == contract_id && rgb_info.local_rgb_amount >= rgb_amount
		});
		(contract_id, rgb_amount)
	}

	pub fn update_rgb_channel_amount(&self, payment_hash: &PaymentHash, receiver: bool) {
		let payment = self
			.database
			.rgb_payment()
			.lock()
			.unwrap()
			.get_by_payment_hash_key(&PaymentHashKey::new(
				payment_hash.clone(),
				PaymentDirection::from(receiver),
			))
			.cloned();
		if payment.is_none() {
			return;
		}
		let rgb_payment_info = payment.unwrap();

		let channel_id =
			self.database.rgb_payment().lock().unwrap().resolve_channel_id(payment_hash);

		if channel_id.is_none() {
			panic!("failed to resolve channel id, which is a bug or of broken data.");
		}

		let channel_id = channel_id.unwrap();

		let (offered, received) =
			if receiver { (0, rgb_payment_info.amount) } else { (rgb_payment_info.amount, 0) };
		self.update_rgb_channel_amount_impl(&channel_id, offered, received, false);
	}

	pub fn get_transfer_info(&self, txid: &Txid) -> Option<TransferInfo> {
		self.database.transfer_info().lock().unwrap().get_by_txid(txid).cloned()
	}
}
