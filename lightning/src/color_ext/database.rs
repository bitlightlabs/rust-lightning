use core::fmt::{Display, Formatter};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use bitcoin::Txid;
use rusqlite::{Connection, params};
use serde_json;

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
fn hex_str_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    if s.len() % 2 != 0 {
        return Err("Hex string has an odd length");
    }

    let mut bytes = Vec::with_capacity(s.len() / 2);

    for i in (0..s.len()).step_by(2) {
        let hex_pair = &s[i..i + 2];
        
        match u8::from_str_radix(hex_pair, 16) {
            Ok(byte) => bytes.push(byte),
            Err(_) => return Err("Invalid hex string"),
        }
    }

    Ok(bytes)
}

fn channel_from_str(s: &str) -> ChannelId {
	let array: [u8; 32] = hex_str_decode(s).expect("Invalid hex string").try_into().expect("Invalid length");
    ChannelId::from_bytes(array)
}

#[derive(Clone, Debug)]
pub(crate) struct RgbPaymentCache {
    conn: Arc<Mutex<Connection>>,
}

impl RgbPaymentCache {
    fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    pub fn get_by_proxy_id_key(&self, proxy_id: &ProxyIdKey) -> Option<RgbPaymentInfo> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT info FROM rgb_payments WHERE channel_id = ? AND payment_hash = ? AND direction = ?").unwrap();
        let result = stmt.query_row(params![proxy_id.channel_id.to_string(), proxy_id.payment_hash.to_string(), proxy_id.direction.to_string()],
            |row| {
                let info_str: String = row.get(0)?;
                Ok(serde_json::from_str(&info_str).unwrap())
            });
        result.ok()
    }

    pub fn resolve_channel_id(&self, payment_hash: &PaymentHash) -> Option<ChannelId> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT channel_id FROM rgb_payments WHERE payment_hash = ? LIMIT 1").unwrap();
        let result = stmt.query_row(params![payment_hash.to_string()],
            |row| {
                let channel_id_str: String = row.get(0)?;
                Ok(channel_from_str(&channel_id_str))
            });
        result.ok()
    }

    pub fn get_by_payment_hash(&self, payment_hash: &PaymentHash) -> Option<RgbPaymentInfo> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT info FROM rgb_payments WHERE payment_hash = ? LIMIT 1").unwrap();
        let result = stmt.query_row(params![payment_hash.to_string()],
            |row| {
                let info_str: String = row.get(0)?;
                Ok(serde_json::from_str(&info_str).unwrap())
            });
        result.ok()
    }

    pub fn get_by_payment_hash_key(&self, payment_hash_key: &PaymentHashKey) -> Option<RgbPaymentInfo> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT info FROM rgb_payments WHERE payment_hash = ? AND direction = ?").unwrap();
        let result = stmt.query_row(params![payment_hash_key.payment_hash.to_string(), payment_hash_key.direction.to_string()],
            |row| {
                let info_str: String = row.get(0)?;
                Ok(serde_json::from_str(&info_str).unwrap())
            });
        result.ok()
    }

    pub fn is_pending(&self, payment_hash: &PaymentHash) -> bool {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT 1 FROM pending_payments WHERE payment_hash = ?").unwrap();
        stmt.exists(params![payment_hash.to_string()]).unwrap()
    }

    pub fn get_pending_payment(&self, payment_hash: &PaymentHash) -> Option<RgbPaymentInfo> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT info FROM pending_payments WHERE payment_hash = ?").unwrap();
        let result = stmt.query_row(params![payment_hash.to_string()],
            |row| {
                let info_str: String = row.get(0)?;
                Ok(serde_json::from_str(&info_str).unwrap())
            });
        result.ok()
    }

	pub fn insert(&mut self, proxy_id_key: &ProxyIdKey, info: RgbPaymentInfo, is_pending: bool) {
		let conn = self.conn.lock().unwrap();
		let info_str = serde_json::to_string(&info).unwrap();
	
		// Check if the payment_hash already exists in the rgb_payments table
		let mut stmt = conn.prepare("SELECT COUNT(*) FROM rgb_payments WHERE payment_hash = ?").unwrap();
		let mut rows = stmt.query(params![proxy_id_key.payment_hash.to_string()]).unwrap();
		let exists = rows.next().unwrap().unwrap().get::<_, i64>(0).unwrap() > 0;
	
		if exists {
			// Update the existing entry
			conn.execute(
				"UPDATE rgb_payments SET channel_id = ?, direction = ?, info = ? WHERE payment_hash = ?",
				params![proxy_id_key.channel_id.to_string(), proxy_id_key.direction.to_string(), info_str, proxy_id_key.payment_hash.to_string()],
			).unwrap();
		} else {
			// Insert a new entry
			conn.execute(
				"INSERT INTO rgb_payments (channel_id, payment_hash, direction, info) VALUES (?, ?, ?, ?)",
				params![proxy_id_key.channel_id.to_string(), proxy_id_key.payment_hash.to_string(), proxy_id_key.direction.to_string(), info_str],
			).unwrap();
		}
	
		if is_pending {
			// Check if the payment_hash already exists in the pending_payments table
			let mut stmt = conn.prepare("SELECT COUNT(*) FROM pending_payments WHERE payment_hash = ?").unwrap();
			let mut rows = stmt.query(params![proxy_id_key.payment_hash.to_string()]).unwrap();
			let pending_exists = rows.next().unwrap().unwrap().get::<_, i64>(0).unwrap() > 0;
	
			if pending_exists {
				// Update the existing pending entry
				conn.execute(
					"UPDATE pending_payments SET info = ? WHERE payment_hash = ?",
					params![info_str, proxy_id_key.payment_hash.to_string()],
				).unwrap();
			} else {
				// Insert a new pending entry
				conn.execute(
					"INSERT INTO pending_payments (payment_hash, info) VALUES (?, ?)",
					params![proxy_id_key.payment_hash.to_string(), info_str],
				).unwrap();
			}
		} else {
			// Delete the entry from pending_payments if it exists
			conn.execute(
				"DELETE FROM pending_payments WHERE payment_hash = ?",
				params![proxy_id_key.payment_hash.to_string()],
			).unwrap();
		}
	}
	
    pub fn insert_without_proxy_id(&mut self, payment_hash_key: &PaymentHashKey, info: RgbPaymentInfo) {
        let conn = self.conn.lock().unwrap();
        let info_str = serde_json::to_string(&info).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO rgb_payments (payment_hash, direction, info) VALUES (?, ?, ?)",
            params![payment_hash_key.payment_hash.to_string(), payment_hash_key.direction.to_string(), info_str],
        ).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO pending_payments (payment_hash, info) VALUES (?, ?)",
            params![payment_hash_key.payment_hash.to_string(), info_str],
        ).unwrap();
    }

    pub fn remove(&mut self, proxy_id: &ProxyIdKey) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM rgb_payments WHERE channel_id = ? AND payment_hash = ? AND direction = ?",
            params![proxy_id.channel_id.to_string(), proxy_id.payment_hash.to_string(), proxy_id.direction.to_string()],
        ).unwrap();
        conn.execute(
            "DELETE FROM pending_payments WHERE payment_hash = ?",
            params![proxy_id.payment_hash.to_string()],
        ).unwrap();
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TransferInfoCache {
    conn: Arc<Mutex<Connection>>,
}

impl TransferInfoCache {
    fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    pub fn get_by_txid(&self, txid: &Txid) -> Option<TransferInfo> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT info FROM transfer_info WHERE txid = ?").unwrap();
        let result = stmt.query_row(params![txid.to_string()],
            |row| {
                let info_str: String = row.get(0)?;
                Ok(serde_json::from_str(&info_str).unwrap())
            });
        result.ok()
    }

    pub fn insert(&mut self, txid: Txid, info: TransferInfo) {
        let conn = self.conn.lock().unwrap();
        let info_str = serde_json::to_string(&info).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO transfer_info (txid, info) VALUES (?, ?)",
            params![txid.to_string(), info_str],
        ).unwrap();
    }

    pub fn remove(&mut self, txid: &Txid) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM transfer_info WHERE txid = ?",
            params![txid.to_string()],
        ).unwrap();
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

#[derive(Clone, Debug)]
pub(crate) struct RgbInfoCache {
    conn: Arc<Mutex<Connection>>,
}

impl RgbInfoCache {
    fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    pub fn get_by_rgb_info_key(&self, rgb_info_key: &RgbInfoKey) -> Option<RgbInfo> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT info FROM rgb_info WHERE channel_id = ? AND is_pending = ?").unwrap();
        let result = stmt.query_row(params![rgb_info_key.channel_id.to_string(), rgb_info_key.is_pending],
            |row| {
                let info_str: String = row.get(0)?;
                Ok(serde_json::from_str(&info_str).unwrap())
            });
        result.ok()
    }

    pub fn insert(&mut self, rgb_info_key: RgbInfoKey, info: RgbInfo) {
        let conn = self.conn.lock().unwrap();
        let info_str = serde_json::to_string(&info).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO rgb_info (channel_id, is_pending, info) VALUES (?, ?, ?)",
            params![rgb_info_key.channel_id.to_string(), rgb_info_key.is_pending, info_str],
        ).unwrap();
    }

    pub fn remove(&mut self, rgb_info_key: &RgbInfoKey) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM rgb_info WHERE channel_id = ? AND is_pending = ?",
            params![rgb_info_key.channel_id.to_string(), rgb_info_key.is_pending],
        ).unwrap();
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

impl Read for ConsignmentBinaryData {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = std::cmp::min(buf.len(), self.0.len());
        if len == 0 {
            return Ok(0);
        }
        buf[..len].copy_from_slice(&self.0[..len]);
        self.0.drain(..len);
        Ok(len)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConsignmentHandle(usize);

#[derive(Clone, Debug)]
pub(crate) struct ConsignmentCache {
    conn: Arc<Mutex<Connection>>,
    data_root: PathBuf,
}

impl ConsignmentCache {
    fn new(conn: Arc<Mutex<Connection>>, data_root: PathBuf) -> Self {
        Self { conn, data_root }
    }

    pub fn get_by_channel_id(&self, channel_id: &ChannelId) -> Option<ConsignmentHandle> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT handle FROM consignments WHERE channel_id = ?").unwrap();
        let result = stmt.query_row(params![channel_id.to_string()],
            |row| {
                let handle: usize = row.get(0)?;
                Ok(ConsignmentHandle(handle))
            });
        result.ok()
    }

    pub fn get_by_funding_txid(&self, funding_txid: &Txid) -> Option<ConsignmentHandle> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT handle FROM consignments WHERE funding_txid = ?").unwrap();
        let result = stmt.query_row(params![funding_txid.to_string()],
            |row| {
                let handle: usize = row.get(0)?;
                Ok(ConsignmentHandle(handle))
            });
        result.ok()
    }

    pub fn insert(
        &mut self, channel_id: &ChannelId, funding_txid: Txid, info: ConsignmentBinaryData,
    ) -> ConsignmentHandle {
        let conn = self.conn.lock().unwrap();
        let handle = conn.query_row(
            "SELECT COALESCE(MAX(handle), 0) + 1 FROM consignments",
            [],
            |row| row.get::<_, usize>(0),
        ).unwrap();

        let file_path = self.data_root.join(format!("consignment_{}.bin", handle));
        std::fs::write(&file_path, &info.0).unwrap();

        conn.execute(
            "INSERT INTO consignments (handle, channel_id, funding_txid, file_path) VALUES (?, ?, ?, ?)",
            params![handle, channel_id.to_string(), funding_txid.to_string(), file_path.to_str().unwrap()],
        ).unwrap();

        ConsignmentHandle(handle)
    }

    pub fn remove(&mut self, channel_id: &ChannelId, funding_txid: Txid) {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT file_path FROM consignments WHERE channel_id = ? OR funding_txid = ?").unwrap();
        let file_paths: Vec<String> = stmt.query_map(
            params![channel_id.to_string(), funding_txid.to_string()],
            |row| row.get(0)
        ).unwrap().filter_map(Result::ok).collect();

        for file_path in file_paths {
            std::fs::remove_file(file_path).unwrap_or_else(|e| eprintln!("Failed to remove file: {}", e));
        }

        conn.execute(
            "DELETE FROM consignments WHERE channel_id = ? OR funding_txid = ?",
            params![channel_id.to_string(), funding_txid.to_string()],
        ).unwrap();
    }

    pub fn resolve(&self, handle: ConsignmentHandle) -> Option<ConsignmentBinaryData> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT file_path FROM consignments WHERE handle = ?").unwrap();
        let result = stmt.query_row(params![handle.0],
            |row| {
                let file_path: String = row.get(0)?;
                Ok(file_path)
            });
        
        if let Ok(file_path) = result {
            std::fs::read(file_path).ok().map(ConsignmentBinaryData)
        } else {
            None
        }
    }

    pub fn rename_channel_id(
        &mut self, handle: ConsignmentHandle, old_channel_id: &ChannelId,
        new_channel_id: &ChannelId,
    ) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE consignments SET channel_id = ? WHERE handle = ? AND channel_id = ?",
            params![new_channel_id.to_string(), handle.0, old_channel_id.to_string()],
        ).unwrap();
    }
}

pub struct SqliteConnection {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteConnection {
    pub fn new(path: &PathBuf) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        
        // Create tables if they don't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS rgb_payments (
                channel_id TEXT,
                payment_hash TEXT,
                direction TEXT,
                info TEXT,
                PRIMARY KEY (channel_id, payment_hash, direction)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS pending_payments (
                payment_hash TEXT PRIMARY KEY,
                info TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS transfer_info (
                txid TEXT PRIMARY KEY,
                info TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS rgb_info (
                channel_id TEXT,
                is_pending BOOLEAN,
                info TEXT,
                PRIMARY KEY (channel_id, is_pending)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS consignments (
                handle INTEGER PRIMARY KEY,
                channel_id TEXT,
                funding_txid TEXT,
                file_path TEXT
            )",
            [],
        )?;

        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }
}

#[derive(Clone, Debug)]
pub struct ColorDatabaseImpl {
    rgb_payment_cache: Arc<Mutex<RgbPaymentCache>>,
    transfer_info: Arc<Mutex<TransferInfoCache>>,
    rgb_info: Arc<Mutex<RgbInfoCache>>,
    consignment_cache: Arc<Mutex<ConsignmentCache>>,
}

impl ColorDatabaseImpl {
    pub fn new(sqlite_conn: SqliteConnection, data_root: PathBuf) -> Self {
        Self {
            rgb_payment_cache: Arc::new(Mutex::new(RgbPaymentCache::new(sqlite_conn.conn.clone()))),
            transfer_info: Arc::new(Mutex::new(TransferInfoCache::new(sqlite_conn.conn.clone()))),
            rgb_info: Arc::new(Mutex::new(RgbInfoCache::new(sqlite_conn.conn.clone()))),
            consignment_cache: Arc::new(Mutex::new(ConsignmentCache::new(sqlite_conn.conn.clone(), data_root))),
        }
    }

    pub fn rgb_payment(&self) -> Arc<Mutex<RgbPaymentCache>> {
        Arc::clone(&self.rgb_payment_cache)
    }

    pub fn transfer_info(&self) -> Arc<Mutex<TransferInfoCache>> {
        Arc::clone(&self.transfer_info)
    }

    pub fn rgb_info(&self) -> Arc<Mutex<RgbInfoCache>> {
        Arc::clone(&self.rgb_info)
    }

    pub fn consignment(&self) -> Arc<Mutex<ConsignmentCache>> {
        Arc::clone(&self.consignment_cache)
    }

    pub fn rename_channel_id(&self, old_channel_id: &ChannelId, new_channel_id: &ChannelId) {
        let rgb_info_key = RgbInfoKey::new(old_channel_id, false);
        let info = self.rgb_info().lock().unwrap().get_by_rgb_info_key(&rgb_info_key);
        if let Some(info) = info {
            let new_info = info.clone();
            self.rgb_info().lock().unwrap().insert(RgbInfoKey::new(new_channel_id, false), new_info);
            self.rgb_info().lock().unwrap().remove(&rgb_info_key);
        }

        let rgb_info_key_pending = RgbInfoKey::new(old_channel_id, true);
        let info = self.rgb_info().lock().unwrap().get_by_rgb_info_key(&rgb_info_key_pending);
        if let Some(info) = info {
            let new_info = info.clone();
            self.rgb_info().lock().unwrap().insert(RgbInfoKey::new(new_channel_id, true), new_info);
            self.rgb_info().lock().unwrap().remove(&rgb_info_key_pending);
        }

        let consignment_handle = self.consignment().lock().unwrap().get_by_channel_id(old_channel_id);
        if let Some(consignment_handle) = consignment_handle {
            self.consignment().lock().unwrap().rename_channel_id(
                consignment_handle,
                old_channel_id,
                new_channel_id,
            );
        }
    }
}
