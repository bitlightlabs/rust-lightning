use core::fmt::{Display, Formatter};
use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
};

use bitcoin::Txid;

use crate::{ln::{ChannelId, PaymentHash}, rgb_utils::{RgbPaymentInfo, TransferInfo}};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PaymentDirection {
	Inbound,
	Outbound,
}

impl From<bool> for PaymentDirection {
	fn from(inbound: bool) -> Self {
		if inbound {
			PaymentDirection::Inbound
		} else {
			PaymentDirection::Outbound
		}
	}
}

impl Display for PaymentDirection {
	fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
		match self {
			PaymentDirection::Inbound => write!(f, "Inbound"),
			PaymentDirection::Outbound => write!(f, "Outbound"),
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProxyIdKey {
	channel_id: ChannelId,
	payment_hash: PaymentHash,
	direction: PaymentDirection,
}

impl Display for ProxyIdKey {
	fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
		write!(
			f,
			"{}.{}.{}",
			self.channel_id,
			self.payment_hash,
			self.direction
		)
	}
}

impl ProxyIdKey {
	pub fn new(channel_id: &ChannelId, payment_hash: &PaymentHash, direction: PaymentDirection) -> Self {
		Self {
			channel_id: channel_id.clone(),
			payment_hash: payment_hash.clone(),
			direction,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PaymentHashKey {
	payment_hash: PaymentHash,
	direction: PaymentDirection,
}

impl From<&ProxyIdKey> for PaymentHashKey {
	fn from(proxy_id_key:& ProxyIdKey) -> Self {
		Self {
			payment_hash: proxy_id_key.payment_hash,
			direction: proxy_id_key.direction,
		}
	}
}

impl Display for PaymentHashKey {
	fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
		write!(
			f,
			"{}.{}",
			self.payment_hash,
			self.direction
		)
	}
}

impl PaymentHashKey {
	pub fn new(payment_hash: PaymentHash, direction: PaymentDirection) -> Self {
		Self {
			payment_hash,
			direction,
		}
	}
}

#[derive(Clone, Debug, Default)]
struct RgbPaymentCache {
	by_proxy_id: HashMap<ProxyIdKey, RgbPaymentInfo>,
	by_payment_hash_key: HashMap<PaymentHashKey, RgbPaymentInfo>,
	by_payment_hash: HashMap<PaymentHash, RgbPaymentInfo>,
	pending_payments: HashMap<PaymentHash, RgbPaymentInfo>,
}

impl RgbPaymentCache {
	fn new() -> Self {
		Self::default()
	}

	pub fn get_by_proxy_id_key(&self, proxy_id: &ProxyIdKey) -> Option<&RgbPaymentInfo> {
		self.by_proxy_id.get(proxy_id)
	}

	pub fn get_by_payment_hash(&self, payment_hash: &PaymentHash) -> Option<&RgbPaymentInfo> {
		self.by_payment_hash.get(payment_hash)
	}

	pub fn get_by_payment_hash_key(&self, payment_hash_key: &PaymentHashKey) -> Option<&RgbPaymentInfo> {
		self.by_payment_hash_key.get(payment_hash_key)
	}

	pub fn is_pending(&self, payment_hash: &PaymentHash) -> bool {
		self.pending_payments.contains_key(payment_hash)
	}

	pub fn get_pending_payment(&self, payment_hash: &PaymentHash) -> Option<&RgbPaymentInfo> {
		self.pending_payments.get(payment_hash)
	}

	pub fn insert(&mut self, proxy_id_key: &ProxyIdKey, info: RgbPaymentInfo, is_pending: bool) {
		self.by_proxy_id.insert(proxy_id_key.clone(), info.clone());
		self.by_payment_hash_key.insert(proxy_id_key.into(), info.clone());
		self.by_payment_hash.insert(proxy_id_key.payment_hash, info.clone());
		if is_pending {
			self.pending_payments.insert(proxy_id_key.payment_hash, info.clone());
		} else {
			self.pending_payments.remove(&proxy_id_key.payment_hash);
		}
	}

	pub fn remove(&mut self, proxy_id: &ProxyIdKey) {
		self.by_proxy_id.remove(proxy_id);
		self.by_payment_hash_key.remove(&proxy_id.into());
		self.by_payment_hash.remove(&proxy_id.payment_hash);
	}
}

#[derive(Clone, Debug, Default)]
struct TransferInfoCache {
	by_txid: HashMap<Txid, TransferInfo>,
}

impl TransferInfoCache {
	fn new() -> Self {
		Self::default()
	}

	pub fn get_by_txid(&self, txid: &Txid) -> Option<&TransferInfo> {
		self.by_txid.get(txid)
	}

	pub fn insert(&mut self, txid: Txid, info: TransferInfo) {
		self.by_txid.insert(txid, info);
	}

	pub fn remove(&mut self, txid: &Txid) {
		self.by_txid.remove(txid);
	}
}

#[derive(Default)]
pub struct ColorDatabaseImpl {
	rgb_payment_cache: Arc<Mutex<RgbPaymentCache>>,
	transfer_info: Arc<Mutex<TransferInfoCache>>,
}

impl ColorDatabaseImpl {
	pub fn new() -> Self {
		Self::default()
	}
	pub fn rgb_payment(&self) -> Arc<Mutex<RgbPaymentCache>> {
		self.rgb_payment_cache.clone()
	}
	pub fn transfer_info(&self) -> Arc<Mutex<TransferInfoCache>> {
		self.transfer_info.clone()
	}
}
