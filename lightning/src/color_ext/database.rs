use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
};

use bitcoin::Txid;

use crate::rgb_utils::{RgbPaymentInfo, TransferInfo};

#[derive(Clone, Debug, Default)]
struct RgbPaymentCache {
	by_proxy_id: HashMap<String, RgbPaymentInfo>,
	by_payment_hash: HashMap<String, RgbPaymentInfo>,
}

impl RgbPaymentCache {
	fn new() -> Self {
		Self::default()
	}

	fn get_by_proxy_id(&self, proxy_id: &str) -> Option<&RgbPaymentInfo> {
		self.by_proxy_id.get(proxy_id)
	}

	fn get_by_payment_hash(&self, payment_hash: &str) -> Option<&RgbPaymentInfo> {
		self.by_payment_hash.get(payment_hash)
	}

	fn insert(&mut self, proxy_id: String, payment_hash: String, info: RgbPaymentInfo) {
		self.by_proxy_id.insert(proxy_id, info.clone());
		self.by_payment_hash.insert(payment_hash, info);
	}

	fn remove(&mut self, proxy_id: &str, payment_hash: &str) {
		self.by_proxy_id.remove(proxy_id);
		self.by_payment_hash.remove(payment_hash);
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

	fn get_by_txid(&self, txid: &Txid) -> Option<&TransferInfo> {
		self.by_txid.get(txid)
	}

	fn insert(&mut self, txid: Txid, info: TransferInfo) {
		self.by_txid.insert(txid, info);
	}

	fn remove(&mut self, txid: &Txid) {
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
