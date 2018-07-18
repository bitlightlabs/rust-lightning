use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::{TxIn,TxOut,SigHashType,Transaction};
use bitcoin::blockdata::script::Script;
use bitcoin::network::serialize;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util::bip143;

use crypto::digest::Digest;

use secp256k1::{Secp256k1,Message,Signature};
use secp256k1::key::{SecretKey,PublicKey};

use ln::msgs::HandleError;
use ln::chan_utils;
use ln::chan_utils::HTLCOutputInCommitment;
use chain::chaininterface::{ChainListener, ChainWatchInterface, BroadcasterInterface};
use chain::transaction::OutPoint;
use util::sha2::Sha256;
use util::byte_utils;

use std::collections::HashMap;
use std::sync::{Arc,Mutex};
use std::{hash,cmp};

pub enum ChannelMonitorUpdateErr {
	/// Used to indicate a temporary failure (eg connection to a watchtower failed, but is expected
	/// to succeed at some point in the future).
	/// Such a failure will "freeze" a channel, preventing us from revoking old states or
	/// submitting new commitment transactions to the remote party.
	/// ChannelManager::test_restore_channel_monitor can be used to retry the update(s) and restore
	/// the channel to an operational state.
	TemporaryFailure,
	/// Used to indicate no further channel monitor updates will be allowed (eg we've moved on to a
	/// different watchtower and cannot update with all watchtowers that were previously informed
	/// of this channel). This will force-close the channel in question.
	PermanentFailure,
}

/// Simple trait indicating ability to track a set of ChannelMonitors and multiplex events between
/// them. Generally should be implemented by keeping a local SimpleManyChannelMonitor and passing
/// events to it, while also taking any add_update_monitor events and passing them to some remote
/// server(s).
/// Note that any updates to a channel's monitor *must* be applied to each instance of the
/// channel's monitor everywhere (including remote watchtowers) *before* this function returns. If
/// an update occurs and a remote watchtower is left with old state, it may broadcast transactions
/// which we have revoked, allowing our counterparty to claim all funds in the channel!
pub trait ManyChannelMonitor: Send + Sync {
	/// Adds or updates a monitor for the given `funding_txo`.
	fn add_update_monitor(&self, funding_txo: OutPoint, monitor: ChannelMonitor) -> Result<(), ChannelMonitorUpdateErr>;
}

/// A simple implementation of a ManyChannelMonitor and ChainListener. Can be used to create a
/// watchtower or watch our own channels.
/// Note that you must provide your own key by which to refer to channels.
/// If you're accepting remote monitors (ie are implementing a watchtower), you must verify that
/// users cannot overwrite a given channel by providing a duplicate key. ie you should probably
/// index by a PublicKey which is required to sign any updates.
/// If you're using this for local monitoring of your own channels, you probably want to use
/// `OutPoint` as the key, which will give you a ManyChannelMonitor implementation.
pub struct SimpleManyChannelMonitor<Key> {
	monitors: Mutex<HashMap<Key, ChannelMonitor>>,
	chain_monitor: Arc<ChainWatchInterface>,
	broadcaster: Arc<BroadcasterInterface>
}

impl<Key : Send + cmp::Eq + hash::Hash> ChainListener for SimpleManyChannelMonitor<Key> {
	fn block_connected(&self, _header: &BlockHeader, height: u32, txn_matched: &[&Transaction], _indexes_of_txn_matched: &[u32]) {
		let monitors = self.monitors.lock().unwrap();
		for monitor in monitors.values() {
			monitor.block_connected(txn_matched, height, &*self.broadcaster);
		}
	}

	fn block_disconnected(&self, _: &BlockHeader) { }
}

impl<Key : Send + cmp::Eq + hash::Hash + 'static> SimpleManyChannelMonitor<Key> {
	pub fn new(chain_monitor: Arc<ChainWatchInterface>, broadcaster: Arc<BroadcasterInterface>) -> Arc<SimpleManyChannelMonitor<Key>> {
		let res = Arc::new(SimpleManyChannelMonitor {
			monitors: Mutex::new(HashMap::new()),
			chain_monitor,
			broadcaster
		});
		let weak_res = Arc::downgrade(&res);
		res.chain_monitor.register_listener(weak_res);
		res
	}

	pub fn add_update_monitor_by_key(&self, key: Key, monitor: ChannelMonitor) -> Result<(), HandleError> {
		let mut monitors = self.monitors.lock().unwrap();
		match monitors.get_mut(&key) {
			Some(orig_monitor) => return orig_monitor.insert_combine(monitor),
			None => {}
		};
		match monitor.funding_txo {
			None => self.chain_monitor.watch_all_txn(),
			Some(outpoint) => self.chain_monitor.install_watch_outpoint((outpoint.txid, outpoint.index as u32)),
		}
		monitors.insert(key, monitor);
		Ok(())
	}
}

impl ManyChannelMonitor for SimpleManyChannelMonitor<OutPoint> {
	fn add_update_monitor(&self, funding_txo: OutPoint, monitor: ChannelMonitor) -> Result<(), ChannelMonitorUpdateErr> {
		match self.add_update_monitor_by_key(funding_txo, monitor) {
			Ok(_) => Ok(()),
			Err(_) => Err(ChannelMonitorUpdateErr::PermanentFailure),
		}
	}
}

/// If an HTLC expires within this many blocks, don't try to claim it in a shared transaction,
/// instead claiming it in its own individual transaction.
const CLTV_SHARED_CLAIM_BUFFER: u32 = 12;
/// If an HTLC expires within this many blocks, force-close the channel to broadcast the
/// HTLC-Success transaction.
const CLTV_CLAIM_BUFFER: u32 = 6;

#[derive(Clone, PartialEq)]
enum KeyStorage {
	PrivMode {
		revocation_base_key: SecretKey,
		htlc_base_key: SecretKey,
	},
	SigsMode {
		revocation_base_key: PublicKey,
		htlc_base_key: PublicKey,
		sigs: HashMap<Sha256dHash, Signature>,
	}
}

#[derive(Clone, PartialEq)]
struct LocalSignedTx {
	/// txid of the transaction in tx, just used to make comparison faster
	txid: Sha256dHash,
	tx: Transaction,
	revocation_key: PublicKey,
	a_htlc_key: PublicKey,
	b_htlc_key: PublicKey,
	delayed_payment_key: PublicKey,
	feerate_per_kw: u64,
	htlc_outputs: Vec<(HTLCOutputInCommitment, Signature, Signature)>,
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

pub struct ChannelMonitor {
	funding_txo: Option<OutPoint>,
	commitment_transaction_number_obscure_factor: u64,

	key_storage: KeyStorage,
	delayed_payment_base_key: PublicKey,
	their_htlc_base_key: Option<PublicKey>,
	// first is the idx of the first of the two revocation points
	their_cur_revocation_points: Option<(u64, PublicKey, Option<PublicKey>)>,

	our_to_self_delay: u16,
	their_to_self_delay: Option<u16>,

	old_secrets: [([u8; 32], u64); 49],
	remote_claimable_outpoints: HashMap<Sha256dHash, Vec<HTLCOutputInCommitment>>,
	/// We cannot identify HTLC-Success or HTLC-Timeout transactions by themselves on the chain.
	/// Nor can we figure out their commitment numbers without the commitment transaction they are
	/// spending. Thus, in order to claim them via revocation key, we track all the remote
	/// commitment transactions which we find on-chain, mapping them to the commitment number which
	/// can be used to derive the revocation key and claim the transactions.
	remote_commitment_txn_on_chain: Mutex<HashMap<Sha256dHash, u64>>,
	/// Cache used to make pruning of payment_preimages faster.
	/// Maps payment_hash values to commitment numbers for remote transactions for non-revoked
	/// remote transactions (ie should remain pretty small).
	/// Serialized to disk but should generally not be sent to Watchtowers.
	remote_hash_commitment_number: HashMap<[u8; 32], u64>,

	// We store two local commitment transactions to avoid any race conditions where we may update
	// some monitors (potentially on watchtowers) but then fail to update others, resulting in the
	// various monitors for one channel being out of sync, and us broadcasting a local
	// transaction for which we have deleted claim information on some watchtowers.
	prev_local_signed_commitment_tx: Option<LocalSignedTx>,
	current_local_signed_commitment_tx: Option<LocalSignedTx>,

	payment_preimages: HashMap<[u8; 32], [u8; 32]>,

	destination_script: Script,
	secp_ctx: Secp256k1, //TODO: dedup this a bit...
}
impl Clone for ChannelMonitor {
	fn clone(&self) -> Self {
		ChannelMonitor {
			funding_txo: self.funding_txo.clone(),
			commitment_transaction_number_obscure_factor: self.commitment_transaction_number_obscure_factor.clone(),

			key_storage: self.key_storage.clone(),
			delayed_payment_base_key: self.delayed_payment_base_key.clone(),
			their_htlc_base_key: self.their_htlc_base_key.clone(),
			their_cur_revocation_points: self.their_cur_revocation_points.clone(),

			our_to_self_delay: self.our_to_self_delay,
			their_to_self_delay: self.their_to_self_delay,

			old_secrets: self.old_secrets.clone(),
			remote_claimable_outpoints: self.remote_claimable_outpoints.clone(),
			remote_commitment_txn_on_chain: Mutex::new((*self.remote_commitment_txn_on_chain.lock().unwrap()).clone()),
			remote_hash_commitment_number: self.remote_hash_commitment_number.clone(),

			prev_local_signed_commitment_tx: self.prev_local_signed_commitment_tx.clone(),
			current_local_signed_commitment_tx: self.current_local_signed_commitment_tx.clone(),

			payment_preimages: self.payment_preimages.clone(),

			destination_script: self.destination_script.clone(),
			secp_ctx: self.secp_ctx.clone(),
		}
	}
}

#[cfg(any(test, feature = "fuzztarget"))]
/// Used only in testing and fuzztarget to check serialization roundtrips don't change the
/// underlying object
impl PartialEq for ChannelMonitor {
	fn eq(&self, other: &Self) -> bool {
		if self.funding_txo != other.funding_txo ||
			self.commitment_transaction_number_obscure_factor != other.commitment_transaction_number_obscure_factor ||
			self.key_storage != other.key_storage ||
			self.delayed_payment_base_key != other.delayed_payment_base_key ||
			self.their_htlc_base_key != other.their_htlc_base_key ||
			self.their_cur_revocation_points != other.their_cur_revocation_points ||
			self.our_to_self_delay != other.our_to_self_delay ||
			self.their_to_self_delay != other.their_to_self_delay ||
			self.remote_claimable_outpoints != other.remote_claimable_outpoints ||
			self.remote_hash_commitment_number != other.remote_hash_commitment_number ||
			self.prev_local_signed_commitment_tx != other.prev_local_signed_commitment_tx ||
			self.current_local_signed_commitment_tx != other.current_local_signed_commitment_tx ||
			self.payment_preimages != other.payment_preimages ||
			self.destination_script != other.destination_script
		{
			false
		} else {
			for (&(ref secret, ref idx), &(ref o_secret, ref o_idx)) in self.old_secrets.iter().zip(other.old_secrets.iter()) {
				if secret != o_secret || idx != o_idx {
					return false
				}
			}
			let us = self.remote_commitment_txn_on_chain.lock().unwrap();
			let them = other.remote_commitment_txn_on_chain.lock().unwrap();
			*us == *them
		}
	}
}

impl ChannelMonitor {
	pub fn new(revocation_base_key: &SecretKey, delayed_payment_base_key: &PublicKey, htlc_base_key: &SecretKey, our_to_self_delay: u16, destination_script: Script) -> ChannelMonitor {
		ChannelMonitor {
			funding_txo: None,
			commitment_transaction_number_obscure_factor: 0,

			key_storage: KeyStorage::PrivMode {
				revocation_base_key: revocation_base_key.clone(),
				htlc_base_key: htlc_base_key.clone(),
			},
			delayed_payment_base_key: delayed_payment_base_key.clone(),
			their_htlc_base_key: None,
			their_cur_revocation_points: None,

			our_to_self_delay: our_to_self_delay,
			their_to_self_delay: None,

			old_secrets: [([0; 32], 1 << 48); 49],
			remote_claimable_outpoints: HashMap::new(),
			remote_commitment_txn_on_chain: Mutex::new(HashMap::new()),
			remote_hash_commitment_number: HashMap::new(),

			prev_local_signed_commitment_tx: None,
			current_local_signed_commitment_tx: None,

			payment_preimages: HashMap::new(),

			destination_script: destination_script,
			secp_ctx: Secp256k1::new(),
		}
	}

	#[inline]
	fn place_secret(idx: u64) -> u8 {
		for i in 0..48 {
			if idx & (1 << i) == (1 << i) {
				return i
			}
		}
		48
	}

	#[inline]
	fn derive_secret(secret: [u8; 32], bits: u8, idx: u64) -> [u8; 32] {
		let mut res: [u8; 32] = secret;
		for i in 0..bits {
			let bitpos = bits - 1 - i;
			if idx & (1 << bitpos) == (1 << bitpos) {
				res[(bitpos / 8) as usize] ^= 1 << (bitpos & 7);
				let mut sha = Sha256::new();
				sha.input(&res);
				sha.result(&mut res);
			}
		}
		res
	}

	/// Inserts a revocation secret into this channel monitor. Also optionally tracks the next
	/// revocation point which may be required to claim HTLC outputs which we know the preimage of
	/// in case the remote end force-closes using their latest state. Prunes old preimages if neither
	/// needed by local commitment transactions HTCLs nor by remote ones. Unless we haven't already seen remote
	/// commitment transaction's secret, they are de facto pruned (we can use revocation key).
	pub(super) fn provide_secret(&mut self, idx: u64, secret: [u8; 32], their_next_revocation_point: Option<(u64, PublicKey)>) -> Result<(), HandleError> {
		let pos = ChannelMonitor::place_secret(idx);
		for i in 0..pos {
			let (old_secret, old_idx) = self.old_secrets[i as usize];
			if ChannelMonitor::derive_secret(secret, pos, old_idx) != old_secret {
				return Err(HandleError{err: "Previous secret did not match new one", msg: None})
			}
		}
		self.old_secrets[pos as usize] = (secret, idx);

		if let Some(new_revocation_point) = their_next_revocation_point {
			match self.their_cur_revocation_points {
				Some(old_points) => {
					if old_points.0 == new_revocation_point.0 + 1 {
						self.their_cur_revocation_points = Some((old_points.0, old_points.1, Some(new_revocation_point.1)));
					} else if old_points.0 == new_revocation_point.0 + 2 {
						if let Some(old_second_point) = old_points.2 {
							self.their_cur_revocation_points = Some((old_points.0 - 1, old_second_point, Some(new_revocation_point.1)));
						} else {
							self.their_cur_revocation_points = Some((new_revocation_point.0, new_revocation_point.1, None));
						}
					} else {
						self.their_cur_revocation_points = Some((new_revocation_point.0, new_revocation_point.1, None));
					}
				},
				None => {
					self.their_cur_revocation_points = Some((new_revocation_point.0, new_revocation_point.1, None));
				}
			}
		}

		if !self.payment_preimages.is_empty() {
			let local_signed_commitment_tx = self.current_local_signed_commitment_tx.as_ref().expect("Channel needs at least an initial commitment tx !");
			let prev_local_signed_commitment_tx = self.prev_local_signed_commitment_tx.as_ref();
			let min_idx = self.get_min_seen_secret();
			let remote_hash_commitment_number = &mut self.remote_hash_commitment_number;

			self.payment_preimages.retain(|&k, _| {
				for &(ref htlc, _, _) in &local_signed_commitment_tx.htlc_outputs {
					if k == htlc.payment_hash {
						return true
					}
				}
				if let Some(prev_local_commitment_tx) = prev_local_signed_commitment_tx {
					for &(ref htlc, _, _) in prev_local_commitment_tx.htlc_outputs.iter() {
						if k == htlc.payment_hash {
							return true
						}
					}
				}
				let contains = if let Some(cn) = remote_hash_commitment_number.get(&k) {
					if *cn < min_idx {
						return true
					}
					true
				} else { false };
				if contains {
					remote_hash_commitment_number.remove(&k);
				}
				false
			});
		}

		Ok(())
	}

	/// Informs this monitor of the latest remote (ie non-broadcastable) commitment transaction.
	/// The monitor watches for it to be broadcasted and then uses the HTLC information (and
	/// possibly future revocation/preimage information) to claim outputs where possible.
	/// We cache also the mapping hash:commitment number to lighten pruning of old preimages by watchtowers.
	pub(super) fn provide_latest_remote_commitment_tx_info(&mut self, unsigned_commitment_tx: &Transaction, htlc_outputs: Vec<HTLCOutputInCommitment>, commitment_number: u64) {
		// TODO: Encrypt the htlc_outputs data with the single-hash of the commitment transaction
		// so that a remote monitor doesn't learn anything unless there is a malicious close.
		// (only maybe, sadly we cant do the same for local info, as we need to be aware of
		// timeouts)
		for htlc in &htlc_outputs {
			self.remote_hash_commitment_number.insert(htlc.payment_hash, commitment_number);
		}
		self.remote_claimable_outpoints.insert(unsigned_commitment_tx.txid(), htlc_outputs);
	}

	/// Informs this monitor of the latest local (ie broadcastable) commitment transaction. The
	/// monitor watches for timeouts and may broadcast it if we approach such a timeout. Thus, it
	/// is important that any clones of this channel monitor (including remote clones) by kept
	/// up-to-date as our local commitment transaction is updated.
	/// Panics if set_their_to_self_delay has never been called.
	pub(super) fn provide_latest_local_commitment_tx_info(&mut self, signed_commitment_tx: Transaction, local_keys: chan_utils::TxCreationKeys, feerate_per_kw: u64, htlc_outputs: Vec<(HTLCOutputInCommitment, Signature, Signature)>) {
		assert!(self.their_to_self_delay.is_some());
		self.prev_local_signed_commitment_tx = self.current_local_signed_commitment_tx.take();
		self.current_local_signed_commitment_tx = Some(LocalSignedTx {
			txid: signed_commitment_tx.txid(),
			tx: signed_commitment_tx,
			revocation_key: local_keys.revocation_key,
			a_htlc_key: local_keys.a_htlc_key,
			b_htlc_key: local_keys.b_htlc_key,
			delayed_payment_key: local_keys.a_delayed_payment_key,
			feerate_per_kw,
			htlc_outputs,
		});
	}

	/// Provides a payment_hash->payment_preimage mapping. Will be automatically pruned when all
	/// commitment_tx_infos which contain the payment hash have been revoked.
	pub(super) fn provide_payment_preimage(&mut self, payment_hash: &[u8; 32], payment_preimage: &[u8; 32]) {
		self.payment_preimages.insert(payment_hash.clone(), payment_preimage.clone());
	}

	pub fn insert_combine(&mut self, mut other: ChannelMonitor) -> Result<(), HandleError> {
		match self.funding_txo {
			Some(txo) => if other.funding_txo.is_some() && other.funding_txo.unwrap() != txo {
				return Err(HandleError{err: "Funding transaction outputs are not identical!", msg: None});
			},
			None => if other.funding_txo.is_some() {
				self.funding_txo = other.funding_txo;
			}
		}
		let other_min_secret = other.get_min_seen_secret();
		let our_min_secret = self.get_min_seen_secret();
		if our_min_secret > other_min_secret {
			self.provide_secret(other_min_secret, other.get_secret(other_min_secret).unwrap(), None)?;
		}
		if our_min_secret >= other_min_secret {
			self.their_cur_revocation_points = other.their_cur_revocation_points;
			for (txid, htlcs) in other.remote_claimable_outpoints.drain() {
				self.remote_claimable_outpoints.insert(txid, htlcs);
			}
			if let Some(local_tx) = other.prev_local_signed_commitment_tx {
				self.prev_local_signed_commitment_tx = Some(local_tx);
			}
			if let Some(local_tx) = other.current_local_signed_commitment_tx {
				self.current_local_signed_commitment_tx = Some(local_tx);
			}
			self.payment_preimages = other.payment_preimages;
		}
		Ok(())
	}

	/// Panics if commitment_transaction_number_obscure_factor doesn't fit in 48 bits
	pub(super) fn set_commitment_obscure_factor(&mut self, commitment_transaction_number_obscure_factor: u64) {
		assert!(commitment_transaction_number_obscure_factor < (1 << 48));
		self.commitment_transaction_number_obscure_factor = commitment_transaction_number_obscure_factor;
	}

	/// Allows this monitor to scan only for transactions which are applicable. Note that this is
	/// optional, without it this monitor cannot be used in an SPV client, but you may wish to
	/// avoid this (or call unset_funding_info) on a monitor you wish to send to a watchtower as it
	/// provides slightly better privacy.
	pub(super) fn set_funding_info(&mut self, funding_info: OutPoint) {
		self.funding_txo = Some(funding_info);
	}

	pub(super) fn set_their_htlc_base_key(&mut self, their_htlc_base_key: &PublicKey) {
		self.their_htlc_base_key = Some(their_htlc_base_key.clone());
	}

	pub(super) fn set_their_to_self_delay(&mut self, their_to_self_delay: u16) {
		self.their_to_self_delay = Some(their_to_self_delay);
	}

	pub(super) fn unset_funding_info(&mut self) {
		self.funding_txo = None;
	}

	pub fn get_funding_txo(&self) -> Option<OutPoint> {
		self.funding_txo
	}

	/// Serializes into a vec, with various modes for the exposed pub fns
	fn serialize(&self, for_local_storage: bool) -> Vec<u8> {
		let mut res = Vec::new();
		res.push(SERIALIZATION_VERSION);
		res.push(MIN_SERIALIZATION_VERSION);

		match self.funding_txo {
			Some(outpoint) => {
				res.extend_from_slice(&outpoint.txid[..]);
				res.extend_from_slice(&byte_utils::be16_to_array(outpoint.index));
			},
			None => {
				// We haven't even been initialized...not sure why anyone is serializing us, but
				// not much to give them.
				return res;
			},
		}

		// Set in initial Channel-object creation, so should always be set by now:
		res.extend_from_slice(&byte_utils::be48_to_array(self.commitment_transaction_number_obscure_factor));

		match self.key_storage {
			KeyStorage::PrivMode { ref revocation_base_key, ref htlc_base_key } => {
				res.push(0);
				res.extend_from_slice(&revocation_base_key[..]);
				res.extend_from_slice(&htlc_base_key[..]);
			},
			KeyStorage::SigsMode { .. } => unimplemented!(),
		}

		res.extend_from_slice(&self.delayed_payment_base_key.serialize());
		res.extend_from_slice(&self.their_htlc_base_key.as_ref().unwrap().serialize());

		match self.their_cur_revocation_points {
			Some((idx, pubkey, second_option)) => {
				res.extend_from_slice(&byte_utils::be48_to_array(idx));
				res.extend_from_slice(&pubkey.serialize());
				match second_option {
					Some(second_pubkey) => {
						res.extend_from_slice(&second_pubkey.serialize());
					},
					None => {
						res.extend_from_slice(&[0; 33]);
					},
				}
			},
			None => {
				res.extend_from_slice(&byte_utils::be48_to_array(0));
			},
		}

		res.extend_from_slice(&byte_utils::be16_to_array(self.our_to_self_delay));
		res.extend_from_slice(&byte_utils::be16_to_array(self.their_to_self_delay.unwrap()));

		for &(ref secret, ref idx) in self.old_secrets.iter() {
			res.extend_from_slice(secret);
			res.extend_from_slice(&byte_utils::be64_to_array(*idx));
		}

		macro_rules! serialize_htlc_in_commitment {
			($htlc_output: expr) => {
				res.push($htlc_output.offered as u8);
				res.extend_from_slice(&byte_utils::be64_to_array($htlc_output.amount_msat));
				res.extend_from_slice(&byte_utils::be32_to_array($htlc_output.cltv_expiry));
				res.extend_from_slice(&$htlc_output.payment_hash);
				res.extend_from_slice(&byte_utils::be32_to_array($htlc_output.transaction_output_index));
			}
		}

		res.extend_from_slice(&byte_utils::be64_to_array(self.remote_claimable_outpoints.len() as u64));
		for (txid, htlc_outputs) in self.remote_claimable_outpoints.iter() {
			res.extend_from_slice(&txid[..]);
			res.extend_from_slice(&byte_utils::be64_to_array(htlc_outputs.len() as u64));
			for htlc_output in htlc_outputs.iter() {
				serialize_htlc_in_commitment!(htlc_output);
			}
		}

		{
			let remote_commitment_txn_on_chain = self.remote_commitment_txn_on_chain.lock().unwrap();
			res.extend_from_slice(&byte_utils::be64_to_array(remote_commitment_txn_on_chain.len() as u64));
			for (txid, commitment_number) in remote_commitment_txn_on_chain.iter() {
				res.extend_from_slice(&txid[..]);
				res.extend_from_slice(&byte_utils::be48_to_array(*commitment_number));
			}
		}

		if for_local_storage {
			res.extend_from_slice(&byte_utils::be64_to_array(self.remote_hash_commitment_number.len() as u64));
			for (payment_hash, commitment_number) in self.remote_hash_commitment_number.iter() {
				res.extend_from_slice(payment_hash);
				res.extend_from_slice(&byte_utils::be48_to_array(*commitment_number));
			}
		} else {
			res.extend_from_slice(&byte_utils::be64_to_array(0));
		}

		macro_rules! serialize_local_tx {
			($local_tx: expr) => {
				let tx_ser = serialize::serialize(&$local_tx.tx).unwrap();
				res.extend_from_slice(&byte_utils::be64_to_array(tx_ser.len() as u64));
				res.extend_from_slice(&tx_ser);

				res.extend_from_slice(&$local_tx.revocation_key.serialize());
				res.extend_from_slice(&$local_tx.a_htlc_key.serialize());
				res.extend_from_slice(&$local_tx.b_htlc_key.serialize());
				res.extend_from_slice(&$local_tx.delayed_payment_key.serialize());

				res.extend_from_slice(&byte_utils::be64_to_array($local_tx.feerate_per_kw));
				res.extend_from_slice(&byte_utils::be64_to_array($local_tx.htlc_outputs.len() as u64));
				for &(ref htlc_output, ref their_sig, ref our_sig) in $local_tx.htlc_outputs.iter() {
					serialize_htlc_in_commitment!(htlc_output);
					res.extend_from_slice(&their_sig.serialize_compact(&self.secp_ctx));
					res.extend_from_slice(&our_sig.serialize_compact(&self.secp_ctx));
				}
			}
		}

		if let Some(ref prev_local_tx) = self.prev_local_signed_commitment_tx {
			res.push(1);
			serialize_local_tx!(prev_local_tx);
		} else {
			res.push(0);
		}

		if let Some(ref cur_local_tx) = self.current_local_signed_commitment_tx {
			res.push(1);
			serialize_local_tx!(cur_local_tx);
		} else {
			res.push(0);
		}

		res.extend_from_slice(&byte_utils::be64_to_array(self.payment_preimages.len() as u64));
		for payment_preimage in self.payment_preimages.values() {
			res.extend_from_slice(payment_preimage);
		}

		res.extend_from_slice(&byte_utils::be64_to_array(self.destination_script.len() as u64));
		res.extend_from_slice(&self.destination_script[..]);

		res
	}

	/// Encodes this monitor into a byte array, suitable for writing to disk.
	pub fn serialize_for_disk(&self) -> Vec<u8> {
		self.serialize(true)
	}

	/// Encodes this monitor into a byte array, suitable for sending to a remote watchtower
	pub fn serialize_for_watchtower(&self) -> Vec<u8> {
		self.serialize(false)
	}

	/// Attempts to decode a serialized monitor
	pub fn deserialize(data: &[u8]) -> Option<Self> {
		let mut read_pos = 0;
		macro_rules! read_bytes {
			($byte_count: expr) => {
				{
					if ($byte_count as usize) > data.len() - read_pos {
						return None;
					}
					read_pos += $byte_count as usize;
					&data[read_pos - $byte_count as usize..read_pos]
				}
			}
		}

		let secp_ctx = Secp256k1::new();
		macro_rules! unwrap_obj {
			($key: expr) => {
				match $key {
					Ok(res) => res,
					Err(_) => return None,
				}
			}
		}

		let _ver = read_bytes!(1)[0];
		let min_ver = read_bytes!(1)[0];
		if min_ver > SERIALIZATION_VERSION {
			return None;
		}

		// Technically this can fail and serialize fail a round-trip, but only for serialization of
		// barely-init'd ChannelMonitors that we can't do anything with.
		let funding_txo = Some(OutPoint {
			txid: Sha256dHash::from(read_bytes!(32)),
			index: byte_utils::slice_to_be16(read_bytes!(2)),
		});
		let commitment_transaction_number_obscure_factor = byte_utils::slice_to_be48(read_bytes!(6));

		let key_storage = match read_bytes!(1)[0] {
			0 => {
				KeyStorage::PrivMode {
					revocation_base_key: unwrap_obj!(SecretKey::from_slice(&secp_ctx, read_bytes!(32))),
					htlc_base_key: unwrap_obj!(SecretKey::from_slice(&secp_ctx, read_bytes!(32))),
				}
			},
			_ => return None,
		};

		let delayed_payment_base_key = unwrap_obj!(PublicKey::from_slice(&secp_ctx, read_bytes!(33)));
		let their_htlc_base_key = Some(unwrap_obj!(PublicKey::from_slice(&secp_ctx, read_bytes!(33))));

		let their_cur_revocation_points = {
			let first_idx = byte_utils::slice_to_be48(read_bytes!(6));
			if first_idx == 0 {
				None
			} else {
				let first_point = unwrap_obj!(PublicKey::from_slice(&secp_ctx, read_bytes!(33)));
				let second_point_slice = read_bytes!(33);
				if second_point_slice[0..32] == [0; 32] && second_point_slice[32] == 0 {
					Some((first_idx, first_point, None))
				} else {
					Some((first_idx, first_point, Some(unwrap_obj!(PublicKey::from_slice(&secp_ctx, second_point_slice)))))
				}
			}
		};

		let our_to_self_delay = byte_utils::slice_to_be16(read_bytes!(2));
		let their_to_self_delay = Some(byte_utils::slice_to_be16(read_bytes!(2)));

		let mut old_secrets = [([0; 32], 1 << 48); 49];
		for &mut (ref mut secret, ref mut idx) in old_secrets.iter_mut() {
			secret.copy_from_slice(read_bytes!(32));
			*idx = byte_utils::slice_to_be64(read_bytes!(8));
		}

		macro_rules! read_htlc_in_commitment {
			() => {
				{
					let offered = match read_bytes!(1)[0] {
						0 => false, 1 => true,
						_ => return None,
					};
					let amount_msat = byte_utils::slice_to_be64(read_bytes!(8));
					let cltv_expiry = byte_utils::slice_to_be32(read_bytes!(4));
					let mut payment_hash = [0; 32];
					payment_hash[..].copy_from_slice(read_bytes!(32));
					let transaction_output_index = byte_utils::slice_to_be32(read_bytes!(4));

					HTLCOutputInCommitment {
						offered, amount_msat, cltv_expiry, payment_hash, transaction_output_index
					}
				}
			}
		}

		let remote_claimable_outpoints_len = byte_utils::slice_to_be64(read_bytes!(8));
		if remote_claimable_outpoints_len > data.len() as u64 / 64 { return None; }
		let mut remote_claimable_outpoints = HashMap::with_capacity(remote_claimable_outpoints_len as usize);
		for _ in 0..remote_claimable_outpoints_len {
			let txid = Sha256dHash::from(read_bytes!(32));
			let outputs_count = byte_utils::slice_to_be64(read_bytes!(8));
			if outputs_count > data.len() as u64 * 32 { return None; }
			let mut outputs = Vec::with_capacity(outputs_count as usize);
			for _ in 0..outputs_count {
				outputs.push(read_htlc_in_commitment!());
			}
			if let Some(_) = remote_claimable_outpoints.insert(txid, outputs) {
				return None;
			}
		}

		let remote_commitment_txn_on_chain_len = byte_utils::slice_to_be64(read_bytes!(8));
		if remote_commitment_txn_on_chain_len > data.len() as u64 / 32 { return None; }
		let mut remote_commitment_txn_on_chain = HashMap::with_capacity(remote_commitment_txn_on_chain_len as usize);
		for _ in 0..remote_commitment_txn_on_chain_len {
			let txid = Sha256dHash::from(read_bytes!(32));
			let commitment_number = byte_utils::slice_to_be48(read_bytes!(6));
			if let Some(_) = remote_commitment_txn_on_chain.insert(txid, commitment_number) {
				return None;
			}
		}

		let remote_hash_commitment_number_len = byte_utils::slice_to_be64(read_bytes!(8));
		if remote_hash_commitment_number_len > data.len() as u64 / 32 { return None; }
		let mut remote_hash_commitment_number = HashMap::with_capacity(remote_hash_commitment_number_len as usize);
		for _ in 0..remote_hash_commitment_number_len {
			let mut txid = [0; 32];
			txid[..].copy_from_slice(read_bytes!(32));
			let commitment_number = byte_utils::slice_to_be48(read_bytes!(6));
			if let Some(_) = remote_hash_commitment_number.insert(txid, commitment_number) {
				return None;
			}
		}

		macro_rules! read_local_tx {
			() => {
				{
					let tx_len = byte_utils::slice_to_be64(read_bytes!(8));
					let tx_ser = read_bytes!(tx_len);
					let tx: Transaction = unwrap_obj!(serialize::deserialize(tx_ser));
					if serialize::serialize(&tx).unwrap() != tx_ser {
						// We check that the tx re-serializes to the same form to ensure there is
						// no extra data, and as rust-bitcoin doesn't handle the 0-input ambiguity
						// all that well.
						return None;
					}

					let revocation_key = unwrap_obj!(PublicKey::from_slice(&secp_ctx, read_bytes!(33)));
					let a_htlc_key = unwrap_obj!(PublicKey::from_slice(&secp_ctx, read_bytes!(33)));
					let b_htlc_key = unwrap_obj!(PublicKey::from_slice(&secp_ctx, read_bytes!(33)));
					let delayed_payment_key = unwrap_obj!(PublicKey::from_slice(&secp_ctx, read_bytes!(33)));
					let feerate_per_kw = byte_utils::slice_to_be64(read_bytes!(8));

					let htlc_outputs_len = byte_utils::slice_to_be64(read_bytes!(8));
					if htlc_outputs_len > data.len() as u64 / 128 { return None; }
					let mut htlc_outputs = Vec::with_capacity(htlc_outputs_len as usize);
					for _ in 0..htlc_outputs_len {
						htlc_outputs.push((read_htlc_in_commitment!(),
								unwrap_obj!(Signature::from_compact(&secp_ctx, read_bytes!(64))),
								unwrap_obj!(Signature::from_compact(&secp_ctx, read_bytes!(64)))));
					}

					LocalSignedTx {
						txid: tx.txid(),
						tx, revocation_key, a_htlc_key, b_htlc_key, delayed_payment_key, feerate_per_kw, htlc_outputs
					}
				}
			}
		}

		let prev_local_signed_commitment_tx = match read_bytes!(1)[0] {
			0 => None,
			1 => {
				Some(read_local_tx!())
			},
			_ => return None,
		};

		let current_local_signed_commitment_tx = match read_bytes!(1)[0] {
			0 => None,
			1 => {
				Some(read_local_tx!())
			},
			_ => return None,
		};

		let payment_preimages_len = byte_utils::slice_to_be64(read_bytes!(8));
		if payment_preimages_len > data.len() as u64 / 32 { return None; }
		let mut payment_preimages = HashMap::with_capacity(payment_preimages_len as usize);
		let mut sha = Sha256::new();
		for _ in 0..payment_preimages_len {
			let mut preimage = [0; 32];
			preimage[..].copy_from_slice(read_bytes!(32));
			sha.reset();
			sha.input(&preimage);
			let mut hash = [0; 32];
			sha.result(&mut hash);
			if let Some(_) = payment_preimages.insert(hash, preimage) {
				return None;
			}
		}

		let destination_script_len = byte_utils::slice_to_be64(read_bytes!(8));
		let destination_script = Script::from(read_bytes!(destination_script_len).to_vec());

		Some(ChannelMonitor {
			funding_txo,
			commitment_transaction_number_obscure_factor,

			key_storage,
			delayed_payment_base_key,
			their_htlc_base_key,
			their_cur_revocation_points,

			our_to_self_delay,
			their_to_self_delay,

			old_secrets,
			remote_claimable_outpoints,
			remote_commitment_txn_on_chain: Mutex::new(remote_commitment_txn_on_chain),
			remote_hash_commitment_number,

			prev_local_signed_commitment_tx,
			current_local_signed_commitment_tx,

			payment_preimages,

			destination_script,
			secp_ctx,
		})
	}

	//TODO: Functions to serialize/deserialize (with different forms depending on which information
	//we want to leave out (eg funding_txo, etc).

	/// Can only fail if idx is < get_min_seen_secret
	pub fn get_secret(&self, idx: u64) -> Result<[u8; 32], HandleError> {
		for i in 0..self.old_secrets.len() {
			if (idx & (!((1 << i) - 1))) == self.old_secrets[i].1 {
				return Ok(ChannelMonitor::derive_secret(self.old_secrets[i].0, i as u8, idx))
			}
		}
		assert!(idx < self.get_min_seen_secret());
		Err(HandleError{err: "idx too low", msg: None})
	}

	pub fn get_min_seen_secret(&self) -> u64 {
		//TODO This can be optimized?
		let mut min = 1 << 48;
		for &(_, idx) in self.old_secrets.iter() {
			if idx < min {
				min = idx;
			}
		}
		min
	}

	/// Attempts to claim a remote commitment transaction's outputs using the revocation key and
	/// data in remote_claimable_outpoints. Will directly claim any HTLC outputs which expire at a
	/// height > height + CLTV_SHARED_CLAIM_BUFFER. In any case, will install monitoring for
	/// HTLC-Success/HTLC-Timeout transactions, and claim them using the revocation key (if
	/// applicable) as well.
	fn check_spend_remote_transaction(&self, tx: &Transaction, height: u32) -> Vec<Transaction> {
		// Most secp and related errors trying to create keys means we have no hope of constructing
		// a spend transaction...so we return no transactions to broadcast
		let mut txn_to_broadcast = Vec::new();
		macro_rules! ignore_error {
			( $thing : expr ) => {
				match $thing {
					Ok(a) => a,
					Err(_) => return txn_to_broadcast
				}
			};
		}

		let commitment_txid = tx.txid(); //TODO: This is gonna be a performance bottleneck for watchtowers!
		let per_commitment_option = self.remote_claimable_outpoints.get(&commitment_txid);

		let commitment_number = (((tx.input[0].sequence as u64 & 0xffffff) << 3*8) | (tx.lock_time as u64 & 0xffffff)) ^ self.commitment_transaction_number_obscure_factor;
		if commitment_number >= self.get_min_seen_secret() {
			let secret = self.get_secret(commitment_number).unwrap();
			let per_commitment_key = ignore_error!(SecretKey::from_slice(&self.secp_ctx, &secret));
			let (revocation_pubkey, b_htlc_key) = match self.key_storage {
				KeyStorage::PrivMode { ref revocation_base_key, ref htlc_base_key } => {
					let per_commitment_point = ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &per_commitment_key));
					(ignore_error!(chan_utils::derive_public_revocation_key(&self.secp_ctx, &per_commitment_point, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &revocation_base_key)))),
					ignore_error!(chan_utils::derive_public_key(&self.secp_ctx, &per_commitment_point, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &htlc_base_key)))))
				},
				KeyStorage::SigsMode { ref revocation_base_key, ref htlc_base_key, .. } => {
					let per_commitment_point = ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &per_commitment_key));
					(ignore_error!(chan_utils::derive_public_revocation_key(&self.secp_ctx, &per_commitment_point, &revocation_base_key)),
					ignore_error!(chan_utils::derive_public_key(&self.secp_ctx, &per_commitment_point, &htlc_base_key)))
				},
			};
			let delayed_key = ignore_error!(chan_utils::derive_public_key(&self.secp_ctx, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &per_commitment_key)), &self.delayed_payment_base_key));
			let a_htlc_key = match self.their_htlc_base_key {
				None => return txn_to_broadcast,
				Some(their_htlc_base_key) => ignore_error!(chan_utils::derive_public_key(&self.secp_ctx, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &per_commitment_key)), &their_htlc_base_key)),
			};

			let revokeable_redeemscript = chan_utils::get_revokeable_redeemscript(&revocation_pubkey, self.our_to_self_delay, &delayed_key);
			let revokeable_p2wsh = revokeable_redeemscript.to_v0_p2wsh();

			let mut total_value = 0;
			let mut values = Vec::new();
			let mut inputs = Vec::new();
			let mut htlc_idxs = Vec::new();

			for (idx, outp) in tx.output.iter().enumerate() {
				if outp.script_pubkey == revokeable_p2wsh {
					inputs.push(TxIn {
						prev_hash: commitment_txid,
						prev_index: idx as u32,
						script_sig: Script::new(),
						sequence: 0xfffffffd,
						witness: Vec::new(),
					});
					htlc_idxs.push(None);
					values.push(outp.value);
					total_value += outp.value;
					break; // There can only be one of these
				}
			}

			macro_rules! sign_input {
				($sighash_parts: expr, $input: expr, $htlc_idx: expr, $amount: expr) => {
					{
						let (sig, redeemscript) = match self.key_storage {
							KeyStorage::PrivMode { ref revocation_base_key, .. } => {
								let redeemscript = if $htlc_idx.is_none() { revokeable_redeemscript.clone() } else {
									let htlc = &per_commitment_option.unwrap()[$htlc_idx.unwrap()];
									chan_utils::get_htlc_redeemscript_with_explicit_keys(htlc, &a_htlc_key, &b_htlc_key, &revocation_pubkey)
								};
								let sighash = ignore_error!(Message::from_slice(&$sighash_parts.sighash_all(&$input, &redeemscript, $amount)[..]));
								let revocation_key = ignore_error!(chan_utils::derive_private_revocation_key(&self.secp_ctx, &per_commitment_key, &revocation_base_key));
								(ignore_error!(self.secp_ctx.sign(&sighash, &revocation_key)), redeemscript)
							},
							KeyStorage::SigsMode { .. } => {
								unimplemented!();
							}
						};
						$input.witness.push(sig.serialize_der(&self.secp_ctx).to_vec());
						$input.witness[0].push(SigHashType::All as u8);
						if $htlc_idx.is_none() {
							$input.witness.push(vec!(1));
						} else {
							$input.witness.push(revocation_pubkey.serialize().to_vec());
						}
						$input.witness.push(redeemscript.into_vec());
					}
				}
			}

			if let Some(per_commitment_data) = per_commitment_option {
				inputs.reserve_exact(per_commitment_data.len());

				for (idx, htlc) in per_commitment_data.iter().enumerate() {
					let expected_script = chan_utils::get_htlc_redeemscript_with_explicit_keys(&htlc, &a_htlc_key, &b_htlc_key, &revocation_pubkey);
					if htlc.transaction_output_index as usize >= tx.output.len() ||
							tx.output[htlc.transaction_output_index as usize].value != htlc.amount_msat / 1000 ||
							tx.output[htlc.transaction_output_index as usize].script_pubkey != expected_script.to_v0_p2wsh() {
						return txn_to_broadcast; // Corrupted per_commitment_data, fuck this user
					}
					let input = TxIn {
						prev_hash: commitment_txid,
						prev_index: htlc.transaction_output_index,
						script_sig: Script::new(),
						sequence: 0xfffffffd,
						witness: Vec::new(),
					};
					if htlc.cltv_expiry > height + CLTV_SHARED_CLAIM_BUFFER {
						inputs.push(input);
						htlc_idxs.push(Some(idx));
						values.push(tx.output[htlc.transaction_output_index as usize].value);
						total_value += htlc.amount_msat / 1000;
					} else {
						let mut single_htlc_tx = Transaction {
							version: 2,
							lock_time: 0,
							input: vec![input],
							output: vec!(TxOut {
								script_pubkey: self.destination_script.clone(),
								value: htlc.amount_msat / 1000, //TODO: - fee
							}),
						};
						let sighash_parts = bip143::SighashComponents::new(&single_htlc_tx);
						sign_input!(sighash_parts, single_htlc_tx.input[0], Some(idx), htlc.amount_msat / 1000);
						txn_to_broadcast.push(single_htlc_tx); // TODO: This is not yet tested in ChannelManager!
					}
				}
			}

			if !inputs.is_empty() || !txn_to_broadcast.is_empty() { // ie we're confident this is actually ours
				// We're definitely a remote commitment transaction!
				// TODO: Register commitment_txid with the ChainWatchInterface!
				self.remote_commitment_txn_on_chain.lock().unwrap().insert(commitment_txid, commitment_number);
			}
			if inputs.is_empty() { return txn_to_broadcast; } // Nothing to be done...probably a false positive/local tx

			let outputs = vec!(TxOut {
				script_pubkey: self.destination_script.clone(),
				value: total_value, //TODO: - fee
			});
			let mut spend_tx = Transaction {
				version: 2,
				lock_time: 0,
				input: inputs,
				output: outputs,
			};

			let mut values_drain = values.drain(..);
			let sighash_parts = bip143::SighashComponents::new(&spend_tx);

			for (input, htlc_idx) in spend_tx.input.iter_mut().zip(htlc_idxs.iter()) {
				let value = values_drain.next().unwrap();
				sign_input!(sighash_parts, input, htlc_idx, value);
			}

			txn_to_broadcast.push(spend_tx);
		} else if let Some(per_commitment_data) = per_commitment_option {
			// While this isn't useful yet, there is a potential race where if a counterparty
			// revokes a state at the same time as the commitment transaction for that state is
			// confirmed, and the watchtower receives the block before the user, the user could
			// upload a new ChannelMonitor with the revocation secret but the watchtower has
			// already processed the block, resulting in the remote_commitment_txn_on_chain entry
			// not being generated by the above conditional. Thus, to be safe, we go ahead and
			// insert it here.
			self.remote_commitment_txn_on_chain.lock().unwrap().insert(commitment_txid, commitment_number);

			if let Some(revocation_points) = self.their_cur_revocation_points {
				let revocation_point_option =
					if revocation_points.0 == commitment_number { Some(&revocation_points.1) }
					else if let Some(point) = revocation_points.2.as_ref() {
						if revocation_points.0 == commitment_number + 1 { Some(point) } else { None }
					} else { None };
				if let Some(revocation_point) = revocation_point_option {
					let (revocation_pubkey, b_htlc_key) = match self.key_storage {
						KeyStorage::PrivMode { ref revocation_base_key, ref htlc_base_key } => {
							(ignore_error!(chan_utils::derive_public_revocation_key(&self.secp_ctx, revocation_point, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &revocation_base_key)))),
							ignore_error!(chan_utils::derive_public_key(&self.secp_ctx, revocation_point, &ignore_error!(PublicKey::from_secret_key(&self.secp_ctx, &htlc_base_key)))))
						},
						KeyStorage::SigsMode { ref revocation_base_key, ref htlc_base_key, .. } => {
							(ignore_error!(chan_utils::derive_public_revocation_key(&self.secp_ctx, revocation_point, &revocation_base_key)),
							ignore_error!(chan_utils::derive_public_key(&self.secp_ctx, revocation_point, &htlc_base_key)))
						},
					};
					let a_htlc_key = match self.their_htlc_base_key {
						None => return txn_to_broadcast,
						Some(their_htlc_base_key) => ignore_error!(chan_utils::derive_public_key(&self.secp_ctx, revocation_point, &their_htlc_base_key)),
					};

					let mut total_value = 0;
					let mut values = Vec::new();
					let mut inputs = Vec::new();

					macro_rules! sign_input {
						($sighash_parts: expr, $input: expr, $amount: expr, $preimage: expr) => {
							{
								let (sig, redeemscript) = match self.key_storage {
									KeyStorage::PrivMode { ref htlc_base_key, .. } => {
										let htlc = &per_commitment_option.unwrap()[$input.sequence as usize];
										let redeemscript = chan_utils::get_htlc_redeemscript_with_explicit_keys(htlc, &a_htlc_key, &b_htlc_key, &revocation_pubkey);
										let sighash = ignore_error!(Message::from_slice(&$sighash_parts.sighash_all(&$input, &redeemscript, $amount)[..]));
										let htlc_key = ignore_error!(chan_utils::derive_private_key(&self.secp_ctx, revocation_point, &htlc_base_key));
										(ignore_error!(self.secp_ctx.sign(&sighash, &htlc_key)), redeemscript)
									},
									KeyStorage::SigsMode { .. } => {
										unimplemented!();
									}
								};
								$input.witness.push(sig.serialize_der(&self.secp_ctx).to_vec());
								$input.witness[0].push(SigHashType::All as u8);
								$input.witness.push($preimage);
								$input.witness.push(redeemscript.into_vec());
							}
						}
					}

					for (idx, htlc) in per_commitment_data.iter().enumerate() {
						if let Some(payment_preimage) = self.payment_preimages.get(&htlc.payment_hash) {
							let input = TxIn {
								prev_hash: commitment_txid,
								prev_index: htlc.transaction_output_index,
								script_sig: Script::new(),
								sequence: idx as u32, // reset to 0xfffffffd in sign_input
								witness: Vec::new(),
							};
							if htlc.cltv_expiry > height + CLTV_SHARED_CLAIM_BUFFER {
								inputs.push(input);
								values.push((tx.output[htlc.transaction_output_index as usize].value, payment_preimage));
								total_value += htlc.amount_msat / 1000;
							} else {
								let mut single_htlc_tx = Transaction {
									version: 2,
									lock_time: 0,
									input: vec![input],
									output: vec!(TxOut {
										script_pubkey: self.destination_script.clone(),
										value: htlc.amount_msat / 1000, //TODO: - fee
									}),
								};
								let sighash_parts = bip143::SighashComponents::new(&single_htlc_tx);
								sign_input!(sighash_parts, single_htlc_tx.input[0], htlc.amount_msat / 1000, payment_preimage.to_vec());
								txn_to_broadcast.push(single_htlc_tx);
							}
						}
					}

					if inputs.is_empty() { return txn_to_broadcast; } // Nothing to be done...probably a false positive/local tx

					let outputs = vec!(TxOut {
						script_pubkey: self.destination_script.clone(),
						value: total_value, //TODO: - fee
					});
					let mut spend_tx = Transaction {
						version: 2,
						lock_time: 0,
						input: inputs,
						output: outputs,
					};

					let mut values_drain = values.drain(..);
					let sighash_parts = bip143::SighashComponents::new(&spend_tx);

					for input in spend_tx.input.iter_mut() {
						let value = values_drain.next().unwrap();
						sign_input!(sighash_parts, input, value.0, value.1.to_vec());
					}

					txn_to_broadcast.push(spend_tx);
				}
			}
		} else {
			//TODO: For each input check if its in our remote_commitment_txn_on_chain map!
		}

		txn_to_broadcast
	}

	fn broadcast_by_local_state(&self, local_tx: &LocalSignedTx) -> Vec<Transaction> {
		let mut res = Vec::with_capacity(local_tx.htlc_outputs.len());

		for &(ref htlc, ref their_sig, ref our_sig) in local_tx.htlc_outputs.iter() {
			if htlc.offered {
				let mut htlc_timeout_tx = chan_utils::build_htlc_transaction(&local_tx.txid, local_tx.feerate_per_kw, self.their_to_self_delay.unwrap(), htlc, &local_tx.delayed_payment_key, &local_tx.revocation_key);

				htlc_timeout_tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

				htlc_timeout_tx.input[0].witness.push(their_sig.serialize_der(&self.secp_ctx).to_vec());
				htlc_timeout_tx.input[0].witness[1].push(SigHashType::All as u8);
				htlc_timeout_tx.input[0].witness.push(our_sig.serialize_der(&self.secp_ctx).to_vec());
				htlc_timeout_tx.input[0].witness[2].push(SigHashType::All as u8);

				htlc_timeout_tx.input[0].witness.push(Vec::new());
				htlc_timeout_tx.input[0].witness.push(chan_utils::get_htlc_redeemscript_with_explicit_keys(htlc, &local_tx.a_htlc_key, &local_tx.b_htlc_key, &local_tx.revocation_key).into_vec());

				res.push(htlc_timeout_tx);
			} else {
				if let Some(payment_preimage) = self.payment_preimages.get(&htlc.payment_hash) {
					let mut htlc_success_tx = chan_utils::build_htlc_transaction(&local_tx.txid, local_tx.feerate_per_kw, self.their_to_self_delay.unwrap(), htlc, &local_tx.delayed_payment_key, &local_tx.revocation_key);

					htlc_success_tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

					htlc_success_tx.input[0].witness.push(their_sig.serialize_der(&self.secp_ctx).to_vec());
					htlc_success_tx.input[0].witness[1].push(SigHashType::All as u8);
					htlc_success_tx.input[0].witness.push(our_sig.serialize_der(&self.secp_ctx).to_vec());
					htlc_success_tx.input[0].witness[2].push(SigHashType::All as u8);

					htlc_success_tx.input[0].witness.push(payment_preimage.to_vec());
					htlc_success_tx.input[0].witness.push(chan_utils::get_htlc_redeemscript_with_explicit_keys(htlc, &local_tx.a_htlc_key, &local_tx.b_htlc_key, &local_tx.revocation_key).into_vec());

					res.push(htlc_success_tx);
				}
			}
		}

		res
	}

	/// Attempts to claim any claimable HTLCs in a commitment transaction which was not (yet)
	/// revoked using data in local_claimable_outpoints.
	/// Should not be used if check_spend_revoked_transaction succeeds.
	fn check_spend_local_transaction(&self, tx: &Transaction, _height: u32) -> Vec<Transaction> {
		let commitment_txid = tx.txid();
		if let &Some(ref local_tx) = &self.current_local_signed_commitment_tx {
			if local_tx.txid == commitment_txid {
				return self.broadcast_by_local_state(local_tx);
			}
		}
		if let &Some(ref local_tx) = &self.prev_local_signed_commitment_tx {
			if local_tx.txid == commitment_txid {
				return self.broadcast_by_local_state(local_tx);
			}
		}
		Vec::new()
	}

	fn block_connected(&self, txn_matched: &[&Transaction], height: u32, broadcaster: &BroadcasterInterface) {
		for tx in txn_matched {
			for txin in tx.input.iter() {
				if self.funding_txo.is_none() || (txin.prev_hash == self.funding_txo.unwrap().txid && txin.prev_index == self.funding_txo.unwrap().index as u32) {
					let mut txn = self.check_spend_remote_transaction(tx, height);
					if txn.is_empty() {
						txn = self.check_spend_local_transaction(tx, height);
					}
					for tx in txn.iter() {
						broadcaster.broadcast_transaction(tx);
					}
				}
			}
		}
		if let Some(ref cur_local_tx) = self.current_local_signed_commitment_tx {
			let mut needs_broadcast = false;
			for &(ref htlc, _, _) in cur_local_tx.htlc_outputs.iter() {
				if htlc.cltv_expiry <= height + CLTV_CLAIM_BUFFER {
					if htlc.offered || self.payment_preimages.contains_key(&htlc.payment_hash) {
						needs_broadcast = true;
					}
				}
			}

			if needs_broadcast {
				broadcaster.broadcast_transaction(&cur_local_tx.tx);
				for tx in self.broadcast_by_local_state(&cur_local_tx) {
					broadcaster.broadcast_transaction(&tx);
				}
			}
		}
	}

	pub fn would_broadcast_at_height(&self, height: u32) -> bool {
		if let Some(ref cur_local_tx) = self.current_local_signed_commitment_tx {
			for &(ref htlc, _, _) in cur_local_tx.htlc_outputs.iter() {
				if htlc.cltv_expiry <= height + CLTV_CLAIM_BUFFER {
					if htlc.offered || self.payment_preimages.contains_key(&htlc.payment_hash) {
						return true;
					}
				}
			}
		}
		false
	}
}

#[cfg(test)]
mod tests {
	use bitcoin::util::misc::hex_bytes;
	use bitcoin::blockdata::script::Script;
	use bitcoin::blockdata::transaction::Transaction;
	use crypto::digest::Digest;
	use ln::channelmonitor::ChannelMonitor;
	use ln::chan_utils::{HTLCOutputInCommitment, TxCreationKeys};
	use util::sha2::Sha256;
	use secp256k1::key::{SecretKey,PublicKey};
	use secp256k1::{Secp256k1, Signature};
	use rand::{thread_rng,Rng};

	#[test]
	fn test_per_commitment_storage() {
		// Test vectors from BOLT 3:
		let mut secrets: Vec<[u8; 32]> = Vec::new();
		let mut monitor: ChannelMonitor;
		let secp_ctx = Secp256k1::new();

		macro_rules! test_secrets {
			() => {
				let mut idx = 281474976710655;
				for secret in secrets.iter() {
					assert_eq!(monitor.get_secret(idx).unwrap(), *secret);
					idx -= 1;
				}
				assert_eq!(monitor.get_min_seen_secret(), idx + 1);
				assert!(monitor.get_secret(idx).is_err());
			};
		}

		{
			// insert_secret correct sequence
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &SecretKey::from_slice(&secp_ctx, &[43; 32]).unwrap(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			monitor.provide_secret(281474976710648, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();
		}

		{
			// insert_secret #1 incorrect
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &SecretKey::from_slice(&secp_ctx, &[43; 32]).unwrap(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			assert_eq!(monitor.provide_secret(281474976710654, secrets.last().unwrap().clone(), None).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #2 incorrect (#1 derived from incorrect)
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &SecretKey::from_slice(&secp_ctx, &[43; 32]).unwrap(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			assert_eq!(monitor.provide_secret(281474976710652, secrets.last().unwrap().clone(), None).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #3 incorrect
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &SecretKey::from_slice(&secp_ctx, &[43; 32]).unwrap(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			assert_eq!(monitor.provide_secret(281474976710652, secrets.last().unwrap().clone(), None).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #4 incorrect (1,2,3 derived from incorrect)
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &SecretKey::from_slice(&secp_ctx, &[43; 32]).unwrap(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("ba65d7b0ef55a3ba300d4e87af29868f394f8f138d78a7011669c79b37b936f4").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			assert_eq!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone(), None).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #5 incorrect
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &SecretKey::from_slice(&secp_ctx, &[43; 32]).unwrap(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			assert_eq!(monitor.provide_secret(281474976710650, secrets.last().unwrap().clone(), None).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #6 incorrect (5 derived from incorrect)
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &SecretKey::from_slice(&secp_ctx, &[43; 32]).unwrap(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("b7e76a83668bde38b373970155c868a653304308f9896692f904a23731224bb1").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			assert_eq!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone(), None).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #7 incorrect
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &SecretKey::from_slice(&secp_ctx, &[43; 32]).unwrap(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("e7971de736e01da8ed58b94c2fc216cb1dca9e326f3a96e7194fe8ea8af6c0a3").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17").unwrap());
			assert_eq!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone(), None).unwrap_err().err,
					"Previous secret did not match new one");
		}

		{
			// insert_secret #8 incorrect
			monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &SecretKey::from_slice(&secp_ctx, &[43; 32]).unwrap(), 0, Script::new());
			secrets.clear();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
			monitor.provide_secret(281474976710655, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
			monitor.provide_secret(281474976710654, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
			monitor.provide_secret(281474976710653, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
			monitor.provide_secret(281474976710652, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd").unwrap());
			monitor.provide_secret(281474976710651, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2").unwrap());
			monitor.provide_secret(281474976710650, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32").unwrap());
			monitor.provide_secret(281474976710649, secrets.last().unwrap().clone(), None).unwrap();
			test_secrets!();

			secrets.push([0; 32]);
			secrets.last_mut().unwrap()[0..32].clone_from_slice(&hex_bytes("a7efbc61aac46d34f77778bac22c8a20c6a46ca460addc49009bda875ec88fa4").unwrap());
			assert_eq!(monitor.provide_secret(281474976710648, secrets.last().unwrap().clone(), None).unwrap_err().err,
					"Previous secret did not match new one");
		}
	}

	#[test]
	fn test_prune_preimages() {
		let secp_ctx = Secp256k1::new();
		let dummy_sig = Signature::from_der(&secp_ctx, &hex_bytes("3045022100fa86fa9a36a8cd6a7bb8f06a541787d51371d067951a9461d5404de6b928782e02201c8b7c334c10aed8976a3a465be9a28abff4cb23acbf00022295b378ce1fa3cd").unwrap()[..]).unwrap();

		macro_rules! dummy_keys {
			() => {
				TxCreationKeys {
					per_commitment_point: PublicKey::new(),
					revocation_key: PublicKey::new(),
					a_htlc_key: PublicKey::new(),
					b_htlc_key: PublicKey::new(),
					a_delayed_payment_key: PublicKey::new(),
					b_payment_key: PublicKey::new(),
				}
			}
		}
		let dummy_tx = Transaction { version: 0, lock_time: 0, input: Vec::new(), output: Vec::new() };

		let mut preimages = Vec::new();
		{
			let mut rng  = thread_rng();
			for _ in 0..20 {
				let mut preimage = [0; 32];
				rng.fill_bytes(&mut preimage);
				let mut sha = Sha256::new();
				sha.input(&preimage);
				let mut hash = [0; 32];
				sha.result(&mut hash);
				preimages.push((preimage, hash));
			}
		}

		macro_rules! preimages_slice_to_htlc_outputs {
			($preimages_slice: expr) => {
				{
					let mut res = Vec::new();
					for (idx, preimage) in $preimages_slice.iter().enumerate() {
						res.push(HTLCOutputInCommitment {
							offered: true,
							amount_msat: 0,
							cltv_expiry: 0,
							payment_hash: preimage.1.clone(),
							transaction_output_index: idx as u32,
						});
					}
					res
				}
			}
		}
		macro_rules! preimages_to_local_htlcs {
			($preimages_slice: expr) => {
				{
					let mut inp = preimages_slice_to_htlc_outputs!($preimages_slice);
					let res: Vec<_> = inp.drain(..).map(|e| { (e, dummy_sig.clone(), dummy_sig.clone()) }).collect();
					res
				}
			}
		}

		macro_rules! test_preimages_exist {
			($preimages_slice: expr, $monitor: expr) => {
				for preimage in $preimages_slice {
					assert!($monitor.payment_preimages.contains_key(&preimage.1));
				}
			}
		}

		// Prune with one old state and a local commitment tx holding a few overlaps with the
		// old state.
		let mut monitor = ChannelMonitor::new(&SecretKey::from_slice(&secp_ctx, &[42; 32]).unwrap(), &PublicKey::new(), &SecretKey::from_slice(&secp_ctx, &[43; 32]).unwrap(), 0, Script::new());
		monitor.set_their_to_self_delay(10);

		monitor.provide_latest_local_commitment_tx_info(dummy_tx.clone(), dummy_keys!(), 0, preimages_to_local_htlcs!(preimages[0..10]));
		monitor.provide_latest_remote_commitment_tx_info(&dummy_tx, preimages_slice_to_htlc_outputs!(preimages[5..15]), 281474976710655);
		monitor.provide_latest_remote_commitment_tx_info(&dummy_tx, preimages_slice_to_htlc_outputs!(preimages[15..20]), 281474976710654);
		monitor.provide_latest_remote_commitment_tx_info(&dummy_tx, preimages_slice_to_htlc_outputs!(preimages[17..20]), 281474976710653);
		monitor.provide_latest_remote_commitment_tx_info(&dummy_tx, preimages_slice_to_htlc_outputs!(preimages[18..20]), 281474976710652);
		for &(ref preimage, ref hash) in preimages.iter() {
			monitor.provide_payment_preimage(hash, preimage);
		}

		// Now provide a secret, pruning preimages 10-15
		let mut secret = [0; 32];
		secret[0..32].clone_from_slice(&hex_bytes("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc").unwrap());
		monitor.provide_secret(281474976710655, secret.clone(), None).unwrap();
		assert_eq!(monitor.payment_preimages.len(), 15);
		test_preimages_exist!(&preimages[0..10], monitor);
		test_preimages_exist!(&preimages[15..20], monitor);

		// Now provide a further secret, pruning preimages 15-17
		secret[0..32].clone_from_slice(&hex_bytes("c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964").unwrap());
		monitor.provide_secret(281474976710654, secret.clone(), None).unwrap();
		assert_eq!(monitor.payment_preimages.len(), 13);
		test_preimages_exist!(&preimages[0..10], monitor);
		test_preimages_exist!(&preimages[17..20], monitor);

		// Now update local commitment tx info, pruning only element 18 as we still care about the
		// previous commitment tx's preimages too
		monitor.provide_latest_local_commitment_tx_info(dummy_tx.clone(), dummy_keys!(), 0, preimages_to_local_htlcs!(preimages[0..5]));
		secret[0..32].clone_from_slice(&hex_bytes("2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8").unwrap());
		monitor.provide_secret(281474976710653, secret.clone(), None).unwrap();
		assert_eq!(monitor.payment_preimages.len(), 12);
		test_preimages_exist!(&preimages[0..10], monitor);
		test_preimages_exist!(&preimages[18..20], monitor);

		// But if we do it again, we'll prune 5-10
		monitor.provide_latest_local_commitment_tx_info(dummy_tx.clone(), dummy_keys!(), 0, preimages_to_local_htlcs!(preimages[0..3]));
		secret[0..32].clone_from_slice(&hex_bytes("27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116").unwrap());
		monitor.provide_secret(281474976710652, secret.clone(), None).unwrap();
		assert_eq!(monitor.payment_preimages.len(), 5);
		test_preimages_exist!(&preimages[0..5], monitor);
	}

	// Further testing is done in the ChannelManager integration tests.
}
