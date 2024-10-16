use core::fmt::{Display, Formatter};
use std::{
	collections::HashMap,
	io::{self, Write},
	sync::{Arc, Mutex},
};

use bitcoin::Txid;

use crate::{
	ln::{ChannelId, PaymentHash},
	rgb_utils::{RgbInfo, RgbPaymentInfo, TransferInfo},
};

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
		write!(f, "{}.{}.{}", self.channel_id, self.payment_hash, self.direction)
	}
}

impl ProxyIdKey {
	pub fn new(
		channel_id: &ChannelId, payment_hash: &PaymentHash, direction: PaymentDirection,
	) -> Self {
		Self { channel_id: channel_id.clone(), payment_hash: payment_hash.clone(), direction }
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PaymentHashKey {
	payment_hash: PaymentHash,
	direction: PaymentDirection,
}

impl From<&ProxyIdKey> for PaymentHashKey {
	fn from(proxy_id_key: &ProxyIdKey) -> Self {
		Self { payment_hash: proxy_id_key.payment_hash, direction: proxy_id_key.direction }
	}
}

impl Display for PaymentHashKey {
	fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "{}.{}", self.payment_hash, self.direction)
	}
}

impl PaymentHashKey {
	pub fn new(payment_hash: PaymentHash, direction: PaymentDirection) -> Self {
		Self { payment_hash, direction }
	}
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RgbPaymentCache {
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

	pub fn resolve_channel_id(&self, payment_hash: &PaymentHash) -> Option<ChannelId> {
		for key in self.by_proxy_id.keys() {
			if key.payment_hash == *payment_hash {
				return Some(key.channel_id.clone());
			}
		}
		None
	}

	pub fn get_by_payment_hash(&self, payment_hash: &PaymentHash) -> Option<&RgbPaymentInfo> {
		self.by_payment_hash.get(payment_hash)
	}

	pub fn get_by_payment_hash_key(
		&self, payment_hash_key: &PaymentHashKey,
	) -> Option<&RgbPaymentInfo> {
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

	pub fn insert_without_proxy_id(
		&mut self, payment_hash_key: &PaymentHashKey, info: RgbPaymentInfo,
	) {
		self.by_payment_hash_key.insert(payment_hash_key.clone(), info.clone());
		self.by_payment_hash.insert(payment_hash_key.payment_hash, info.clone());
		self.pending_payments.insert(payment_hash_key.payment_hash, info.clone());
	}

	pub fn remove(&mut self, proxy_id: &ProxyIdKey) {
		self.by_proxy_id.remove(proxy_id);
		self.by_payment_hash_key.remove(&proxy_id.into());
		self.by_payment_hash.remove(&proxy_id.payment_hash);
	}
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TransferInfoCache {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RgbInfoKey {
	channel_id: ChannelId,
	is_pending: bool,
}

impl Display for RgbInfoKey {
	fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "{}.{}", self.channel_id, if self.is_pending { "pending" } else { "" })
	}
}

impl RgbInfoKey {
	pub fn new(channel_id: &ChannelId, is_pending: bool) -> Self {
		Self { channel_id: channel_id.clone(), is_pending }
	}
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RgbInfoCache {
	by_rgb_info_key: HashMap<RgbInfoKey, RgbInfo>,
}

impl RgbInfoCache {
	fn new() -> Self {
		Self::default()
	}

	pub fn get_by_rgb_info_key(&self, rgb_info_key: &RgbInfoKey) -> Option<&RgbInfo> {
		self.by_rgb_info_key.get(rgb_info_key)
	}

	pub fn insert(&mut self, rgb_info_key: RgbInfoKey, info: RgbInfo) {
		self.by_rgb_info_key.insert(rgb_info_key, info);
	}

	pub fn remove(&mut self, rgb_info_key: &RgbInfoKey) {
		self.by_rgb_info_key.remove(rgb_info_key);
	}
}

#[derive(Clone, Debug, Default)]
pub struct ConsignmentBinaryData(Vec<u8>);

impl Write for ConsignmentBinaryData {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.0.extend_from_slice(buf);
		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConsignmentHandle(usize);

#[derive(Clone, Debug, Default)]
pub(crate) struct ConsignmentCache {
	by_channel_id: HashMap<ChannelId, ConsignmentHandle>,
	by_funding_txid: HashMap<Txid, ConsignmentHandle>,
	data_store: HashMap<ConsignmentHandle, ConsignmentBinaryData>,
	next_handle: usize,
}

impl ConsignmentCache {
	fn new() -> Self {
		Self::default()
	}

	pub fn get_by_channel_id(&self, channel_id: &ChannelId) -> Option<ConsignmentHandle> {
		self.by_channel_id.get(channel_id).copied()
	}

	pub fn get_by_funding_txid(&self, funding_txid: &Txid) -> Option<ConsignmentHandle> {
		self.by_funding_txid.get(funding_txid).copied()
	}

	pub fn insert(
		&mut self, channel_id: &ChannelId, funding_txid: Txid, info: ConsignmentBinaryData,
	) -> ConsignmentHandle {
		let handle = ConsignmentHandle(self.next_handle);
		self.next_handle += 1;
		self.data_store.insert(handle, info);
		self.by_channel_id.insert(channel_id.clone(), handle);
		self.by_funding_txid.insert(funding_txid, handle);

		handle
	}

	pub fn remove(&mut self, channel_id: &ChannelId, funding_txid: Txid) {
		if let Some(handle) = self.by_channel_id.remove(channel_id) {
			self.by_funding_txid.retain(|_, &mut v| v != handle);
			self.data_store.remove(&handle);
		}
		self.by_funding_txid.remove(&funding_txid);
	}

	pub fn resolve(&self, handle: ConsignmentHandle) -> Option<&ConsignmentBinaryData> {
		self.data_store.get(&handle)
	}

	pub fn rename_channel_id(
		&mut self, handle: ConsignmentHandle, old_channel_id: &ChannelId,
		new_channel_id: &ChannelId,
	) {
		if let Some(old_handle) = self.by_channel_id.remove(old_channel_id) {
			if old_handle == handle {
				self.by_channel_id.insert(new_channel_id.clone(), handle);
			}
		}
	}
}

#[derive(Default, Debug)]
pub struct ColorDatabaseImpl {
	rgb_payment_cache: Arc<Mutex<RgbPaymentCache>>,
	transfer_info: Arc<Mutex<TransferInfoCache>>,
	rgb_info: Arc<Mutex<RgbInfoCache>>,
	consignment_cache: Arc<Mutex<ConsignmentCache>>,
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

	pub fn rgb_info(&self) -> Arc<Mutex<RgbInfoCache>> {
		self.rgb_info.clone()
	}

	pub fn consignment(&self) -> Arc<Mutex<ConsignmentCache>> {
		self.consignment_cache.clone()
	}

	pub fn rename_channel_id(&self, old_channel_id: &ChannelId, new_channel_id: &ChannelId) {
		let rgb_info_key = RgbInfoKey::new(old_channel_id, false);
		let info = self.rgb_info().lock().unwrap().get_by_rgb_info_key(&rgb_info_key).cloned();
		if let Some(info) = info {
			let new_info = info.clone();
			self.rgb_info()
				.lock()
				.unwrap()
				.insert(RgbInfoKey::new(new_channel_id, false), new_info);
			self.rgb_info().lock().unwrap().remove(&rgb_info_key);
		}
		println!("rename_channel_id before rgb_info_key_pending");

		let rgb_info_key_pending = RgbInfoKey::new(old_channel_id, true);
		let info =
			self.rgb_info().lock().unwrap().get_by_rgb_info_key(&rgb_info_key_pending).cloned();
		if let Some(info) = info {
			let new_info = info.clone();
			self.rgb_info().lock().unwrap().insert(RgbInfoKey::new(new_channel_id, true), new_info);
			self.rgb_info().lock().unwrap().remove(&rgb_info_key_pending);
		}
		println!("rename_channel_id before consignment");

		let consignment_handle = self.consignment().lock().unwrap().get_by_channel_id(old_channel_id);
		if let Some(consignment_handle) = consignment_handle {
			println!("rename_channel_id consignment");
			self.consignment().lock().unwrap().rename_channel_id(
				consignment_handle,
				old_channel_id,
				new_channel_id,
			);
		}
	}
}
