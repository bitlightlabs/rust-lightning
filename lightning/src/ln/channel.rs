// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use bitcoin::amount::Amount;
use bitcoin::consensus::encode;
use bitcoin::constants::ChainHash;
use bitcoin::script::{Builder, Script, ScriptBuf};
use bitcoin::sighash;
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::transaction::Transaction;

use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::sha256d::Hash as Sha256d;
use bitcoin::hashes::Hash;

use bitcoin::secp256k1;
use bitcoin::secp256k1::constants::PUBLIC_KEY_SIZE;
use bitcoin::secp256k1::{ecdsa::Signature, Secp256k1};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::hex::DisplayHex;

use rgb_lib::RgbTransport;

use crate::chain::chaininterface::{ConfirmationTarget, FeeEstimator, LowerBoundedFeeEstimator};
use crate::chain::channelmonitor::{
	ChannelMonitor, ChannelMonitorUpdate, ChannelMonitorUpdateStep, CLOSED_CHANNEL_UPDATE_ID,
	LATENCY_GRACE_PERIOD_BLOCKS,
};
use crate::chain::transaction::{OutPoint, TransactionData};
use crate::chain::BestBlock;
use crate::events::ClosureReason;
use crate::ln::chan_utils;
use crate::ln::chan_utils::{
	commit_tx_fee_sat, get_commitment_transaction_number_obscure_factor, htlc_success_tx_weight,
	htlc_timeout_tx_weight, make_funding_redeemscript,
	per_outbound_htlc_counterparty_commit_tx_fee_msat, ChannelPublicKeys,
	ChannelTransactionParameters, ClosingTransaction, CommitmentTransaction,
	CounterpartyChannelTransactionParameters, CounterpartyCommitmentSecrets,
	HTLCOutputInCommitment, HolderCommitmentTransaction, TxCreationKeys, MAX_HTLCS,
};
use crate::ln::channel_state::{
	ChannelShutdownState, CounterpartyForwardingInfo, InboundHTLCDetails, InboundHTLCStateDetails,
	OutboundHTLCDetails, OutboundHTLCStateDetails,
};
use crate::ln::channelmanager::{
	self, HTLCFailureMsg, HTLCSource, PendingHTLCInfo, PendingHTLCStatus, RAACommitmentOrder,
	SentHTLCId, BREAKDOWN_TIMEOUT, MAX_LOCAL_BREAKDOWN_TIMEOUT, MIN_CLTV_EXPIRY_DELTA,
};
use crate::ln::features::{ChannelTypeFeatures, InitFeatures};
use crate::ln::msgs;
use crate::ln::msgs::{ClosingSigned, ClosingSignedFeeRange, DecodeError};
use crate::ln::onion_utils::HTLCFailReason;
use crate::ln::script::{self, ShutdownScript};
use crate::ln::types::{ChannelId, PaymentHash, PaymentPreimage};
use crate::routing::gossip::NodeId;
use crate::sign::ecdsa::EcdsaChannelSigner;
use crate::sign::{ChannelSigner, EntropySource, NodeSigner, Recipient, SignerProvider};
use crate::util::config::{
	ChannelConfig, ChannelHandshakeConfig, ChannelHandshakeLimits, LegacyChannelConfig,
	MaxDustHTLCExposure, UserConfig,
};
use crate::util::errors::APIError;
use crate::util::logger::{Logger, Record, WithContext};
use crate::util::scid_utils::scid_from_parts;
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

use crate::io;
use crate::prelude::*;
use crate::rgb_utils::{
	color_closing, color_commitment, color_htlc, get_rgb_channel_info_path,
	get_rgb_channel_info_pending, parse_rgb_channel_info, rename_rgb_files,
	update_rgb_channel_amount_pending,
};
use core::ops::Deref;
use core::{cmp, fmt, mem};
use std::path::PathBuf;

use crate::sign::type_resolver::ChannelSignerType;
#[cfg(any(test, fuzzing, debug_assertions))]
use crate::sync::Mutex;

use super::channel_keys::{DelayedPaymentBasepoint, HtlcBasepoint, RevocationBasepoint};

#[cfg(test)]
pub struct ChannelValueStat {
	pub value_to_self_msat: u64,
	pub channel_value_msat: u64,
	pub channel_reserve_msat: u64,
	pub pending_outbound_htlcs_amount_msat: u64,
	pub pending_inbound_htlcs_amount_msat: u64,
	pub holding_cell_outbound_amount_msat: u64,
	pub counterparty_max_htlc_value_in_flight_msat: u64, // outgoing
	pub counterparty_dust_limit_msat: u64,
}

pub struct AvailableBalances {
	/// The amount that would go to us if we close the channel, ignoring any on-chain fees.
	#[deprecated(since = "0.0.124", note = "use [`ChainMonitor::get_claimable_balances`] instead")]
	pub balance_msat: u64,
	/// Total amount available for our counterparty to send to us.
	pub inbound_capacity_msat: u64,
	/// Total amount available for us to send to our counterparty.
	pub outbound_capacity_msat: u64,
	/// The maximum value we can assign to the next outbound HTLC
	pub next_outbound_htlc_limit_msat: u64,
	/// The minimum value we can assign to the next outbound HTLC
	pub next_outbound_htlc_minimum_msat: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FeeUpdateState {
	// Inbound states mirroring InboundHTLCState
	RemoteAnnounced,
	AwaitingRemoteRevokeToAnnounce,
	// Note that we do not have a AwaitingAnnouncedRemoteRevoke variant here as it is universally
	// handled the same as `Committed`, with the only exception in `InboundHTLCState` being the
	// distinction of when we allow ourselves to forward the HTLC. Because we aren't "forwarding"
	// the fee update anywhere, we can simply consider the fee update `Committed` immediately
	// instead of setting it to AwaitingAnnouncedRemoteRevoke.

	// Outbound state can only be `LocalAnnounced` or `Committed`
	Outbound,
}

enum InboundHTLCRemovalReason {
	FailRelay(msgs::OnionErrorPacket),
	FailMalformed(([u8; 32], u16)),
	Fulfill(PaymentPreimage),
}

/// Represents the resolution status of an inbound HTLC.
#[derive(Clone)]
enum InboundHTLCResolution {
	/// Resolved implies the action we must take with the inbound HTLC has already been determined,
	/// i.e., we already know whether it must be failed back or forwarded.
	//
	// TODO: Once this variant is removed, we should also clean up
	// [`MonitorRestoreUpdates::accepted_htlcs`] as the path will be unreachable.
	Resolved { pending_htlc_status: PendingHTLCStatus },
	/// Pending implies we will attempt to resolve the inbound HTLC once it has been fully committed
	/// to by both sides of the channel, i.e., once a `revoke_and_ack` has been processed by both
	/// nodes for the state update in which it was proposed.
	Pending { update_add_htlc: msgs::UpdateAddHTLC },
}

impl_writeable_tlv_based_enum!(InboundHTLCResolution,
	(0, Resolved) => {
		(0, pending_htlc_status, required),
	},
	(2, Pending) => {
		(0, update_add_htlc, required),
	},
);

enum InboundHTLCState {
	/// Offered by remote, to be included in next local commitment tx. I.e., the remote sent an
	/// update_add_htlc message for this HTLC.
	RemoteAnnounced(InboundHTLCResolution),
	/// Included in a received commitment_signed message (implying we've
	/// revoke_and_ack'd it), but the remote hasn't yet revoked their previous
	/// state (see the example below). We have not yet included this HTLC in a
	/// commitment_signed message because we are waiting on the remote's
	/// aforementioned state revocation. One reason this missing remote RAA
	/// (revoke_and_ack) blocks us from constructing a commitment_signed message
	/// is because every time we create a new "state", i.e. every time we sign a
	/// new commitment tx (see [BOLT #2]), we need a new per_commitment_point,
	/// which are provided one-at-a-time in each RAA. E.g., the last RAA they
	/// sent provided the per_commitment_point for our current commitment tx.
	/// The other reason we should not send a commitment_signed without their RAA
	/// is because their RAA serves to ACK our previous commitment_signed.
	///
	/// Here's an example of how an HTLC could come to be in this state:
	/// remote --> update_add_htlc(prev_htlc)   --> local
	/// remote --> commitment_signed(prev_htlc) --> local
	/// remote <-- revoke_and_ack               <-- local
	/// remote <-- commitment_signed(prev_htlc) <-- local
	/// [note that here, the remote does not respond with a RAA]
	/// remote --> update_add_htlc(this_htlc)   --> local
	/// remote --> commitment_signed(prev_htlc, this_htlc) --> local
	/// Now `this_htlc` will be assigned this state. It's unable to be officially
	/// accepted, i.e. included in a commitment_signed, because we're missing the
	/// RAA that provides our next per_commitment_point. The per_commitment_point
	/// is used to derive commitment keys, which are used to construct the
	/// signatures in a commitment_signed message.
	/// Implies AwaitingRemoteRevoke.
	///
	/// [BOLT #2]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md
	AwaitingRemoteRevokeToAnnounce(InboundHTLCResolution),
	/// Included in a received commitment_signed message (implying we've revoke_and_ack'd it).
	/// We have also included this HTLC in our latest commitment_signed and are now just waiting
	/// on the remote's revoke_and_ack to make this HTLC an irrevocable part of the state of the
	/// channel (before it can then get forwarded and/or removed).
	/// Implies AwaitingRemoteRevoke.
	AwaitingAnnouncedRemoteRevoke(InboundHTLCResolution),
	Committed,
	/// Removed by us and a new commitment_signed was sent (if we were AwaitingRemoteRevoke when we
	/// created it we would have put it in the holding cell instead). When they next revoke_and_ack
	/// we'll drop it.
	/// Note that we have to keep an eye on the HTLC until we've received a broadcastable
	/// commitment transaction without it as otherwise we'll have to force-close the channel to
	/// claim it before the timeout (obviously doesn't apply to revoked HTLCs that we can't claim
	/// anyway). That said, ChannelMonitor does this for us (see
	/// ChannelMonitor::should_broadcast_holder_commitment_txn) so we actually remove the HTLC from
	/// our own local state before then, once we're sure that the next commitment_signed and
	/// ChannelMonitor::provide_latest_local_commitment_tx will not include this HTLC.
	LocalRemoved(InboundHTLCRemovalReason),
}

impl From<&InboundHTLCState> for Option<InboundHTLCStateDetails> {
	fn from(state: &InboundHTLCState) -> Option<InboundHTLCStateDetails> {
		match state {
			InboundHTLCState::RemoteAnnounced(_) => None,
			InboundHTLCState::AwaitingRemoteRevokeToAnnounce(_) => {
				Some(InboundHTLCStateDetails::AwaitingRemoteRevokeToAdd)
			},
			InboundHTLCState::AwaitingAnnouncedRemoteRevoke(_) => {
				Some(InboundHTLCStateDetails::AwaitingRemoteRevokeToAdd)
			},
			InboundHTLCState::Committed => Some(InboundHTLCStateDetails::Committed),
			InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::FailRelay(_)) => {
				Some(InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail)
			},
			InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::FailMalformed(_)) => {
				Some(InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail)
			},
			InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::Fulfill(_)) => {
				Some(InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill)
			},
		}
	}
}

struct InboundHTLCOutput {
	htlc_id: u64,
	amount_msat: u64,
	cltv_expiry: u32,
	payment_hash: PaymentHash,
	state: InboundHTLCState,
	amount_rgb: Option<u64>,
}

#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
enum OutboundHTLCState {
	/// Added by us and included in a commitment_signed (if we were AwaitingRemoteRevoke when we
	/// created it we would have put it in the holding cell instead). When they next revoke_and_ack
	/// we will promote to Committed (note that they may not accept it until the next time we
	/// revoke, but we don't really care about that:
	///  * they've revoked, so worst case we can announce an old state and get our (option on)
	///    money back (though we won't), and,
	///  * we'll send them a revoke when they send a commitment_signed, and since only they're
	///    allowed to remove it, the "can only be removed once committed on both sides" requirement
	///    doesn't matter to us and it's up to them to enforce it, worst-case they jump ahead but
	///    we'll never get out of sync).
	/// Note that we Box the OnionPacket as it's rather large and we don't want to blow up
	/// OutboundHTLCOutput's size just for a temporary bit
	LocalAnnounced(Box<msgs::OnionPacket>),
	Committed,
	/// Remote removed this (outbound) HTLC. We're waiting on their commitment_signed to finalize
	/// the change (though they'll need to revoke before we fail the payment).
	RemoteRemoved(OutboundHTLCOutcome),
	/// Remote removed this and sent a commitment_signed (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// can do any backwards failing. Implies AwaitingRemoteRevoke.
	/// We also have not yet removed this HTLC in a commitment_signed message, and are waiting on a
	/// remote revoke_and_ack on a previous state before we can do so.
	AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome),
	/// Remote removed this and sent a commitment_signed (implying we've revoke_and_ack'ed it), but
	/// the remote side hasn't yet revoked their previous state, which we need them to do before we
	/// can do any backwards failing. Implies AwaitingRemoteRevoke.
	/// We have removed this HTLC in our latest commitment_signed and are now just waiting on a
	/// revoke_and_ack to drop completely.
	AwaitingRemovedRemoteRevoke(OutboundHTLCOutcome),
}

impl From<&OutboundHTLCState> for OutboundHTLCStateDetails {
	fn from(state: &OutboundHTLCState) -> OutboundHTLCStateDetails {
		match state {
			OutboundHTLCState::LocalAnnounced(_) => {
				OutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd
			},
			OutboundHTLCState::Committed => OutboundHTLCStateDetails::Committed,
			// RemoteRemoved states are ignored as the state is transient and the remote has not committed to
			// the state yet.
			OutboundHTLCState::RemoteRemoved(_) => OutboundHTLCStateDetails::Committed,
			OutboundHTLCState::AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome::Success(_)) => {
				OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess
			},
			OutboundHTLCState::AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome::Failure(_)) => {
				OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure
			},
			OutboundHTLCState::AwaitingRemovedRemoteRevoke(OutboundHTLCOutcome::Success(_)) => {
				OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveSuccess
			},
			OutboundHTLCState::AwaitingRemovedRemoteRevoke(OutboundHTLCOutcome::Failure(_)) => {
				OutboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFailure
			},
		}
	}
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
enum OutboundHTLCOutcome {
	/// LDK version 0.0.105+ will always fill in the preimage here.
	Success(Option<PaymentPreimage>),
	Failure(HTLCFailReason),
}

impl From<Option<HTLCFailReason>> for OutboundHTLCOutcome {
	fn from(o: Option<HTLCFailReason>) -> Self {
		match o {
			None => OutboundHTLCOutcome::Success(None),
			Some(r) => OutboundHTLCOutcome::Failure(r),
		}
	}
}

impl<'a> Into<Option<&'a HTLCFailReason>> for &'a OutboundHTLCOutcome {
	fn into(self) -> Option<&'a HTLCFailReason> {
		match self {
			OutboundHTLCOutcome::Success(_) => None,
			OutboundHTLCOutcome::Failure(ref r) => Some(r),
		}
	}
}

#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
struct OutboundHTLCOutput {
	htlc_id: u64,
	amount_msat: u64,
	cltv_expiry: u32,
	payment_hash: PaymentHash,
	state: OutboundHTLCState,
	source: HTLCSource,
	blinding_point: Option<PublicKey>,
	skimmed_fee_msat: Option<u64>,
	amount_rgb: Option<u64>,
}

/// See AwaitingRemoteRevoke ChannelState for more info
#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
enum HTLCUpdateAwaitingACK {
	AddHTLC {
		// TODO: Time out if we're getting close to cltv_expiry
		// always outbound
		amount_msat: u64,
		cltv_expiry: u32,
		payment_hash: PaymentHash,
		source: HTLCSource,
		onion_routing_packet: msgs::OnionPacket,
		// The extra fee we're skimming off the top of this HTLC.
		skimmed_fee_msat: Option<u64>,
		blinding_point: Option<PublicKey>,
		amount_rgb: Option<u64>,
	},
	ClaimHTLC {
		payment_preimage: PaymentPreimage,
		htlc_id: u64,
	},
	FailHTLC {
		htlc_id: u64,
		err_packet: msgs::OnionErrorPacket,
	},
	FailMalformedHTLC {
		htlc_id: u64,
		failure_code: u16,
		sha256_of_onion: [u8; 32],
	},
}

macro_rules! define_state_flags {
	($flag_type_doc: expr, $flag_type: ident, [$(($flag_doc: expr, $flag: ident, $value: expr, $get: ident, $set: ident, $clear: ident)),+], $extra_flags: expr) => {
		#[doc = $flag_type_doc]
		#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq)]
		struct $flag_type(u32);

		impl $flag_type {
			$(
				#[doc = $flag_doc]
				const $flag: $flag_type = $flag_type($value);
			)*

			/// All flags that apply to the specified [`ChannelState`] variant.
			#[allow(unused)]
			const ALL: $flag_type = Self($(Self::$flag.0 | )* $extra_flags);

			#[allow(unused)]
			fn new() -> Self { Self(0) }

			#[allow(unused)]
			fn from_u32(flags: u32) -> Result<Self, ()> {
				if flags & !Self::ALL.0 != 0 {
					Err(())
				} else {
					Ok($flag_type(flags))
				}
			}

			#[allow(unused)]
			fn is_empty(&self) -> bool { self.0 == 0 }
			#[allow(unused)]
			fn is_set(&self, flag: Self) -> bool { *self & flag == flag }
			#[allow(unused)]
			fn set(&mut self, flag: Self) { *self |= flag }
			#[allow(unused)]
			fn clear(&mut self, flag: Self) -> Self { self.0 &= !flag.0; *self }
		}

		$(
			define_state_flags!($flag_type, Self::$flag, $get, $set, $clear);
		)*

		impl core::ops::BitOr for $flag_type {
			type Output = Self;
			fn bitor(self, rhs: Self) -> Self::Output { Self(self.0 | rhs.0) }
		}
		impl core::ops::BitOrAssign for $flag_type {
			fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
		}
		impl core::ops::BitAnd for $flag_type {
			type Output = Self;
			fn bitand(self, rhs: Self) -> Self::Output { Self(self.0 & rhs.0) }
		}
		impl core::ops::BitAndAssign for $flag_type {
			fn bitand_assign(&mut self, rhs: Self) { self.0 &= rhs.0; }
		}
	};
	($flag_type_doc: expr, $flag_type: ident, $flags: tt) => {
		define_state_flags!($flag_type_doc, $flag_type, $flags, 0);
	};
	($flag_type: ident, $flag: expr, $get: ident, $set: ident, $clear: ident) => {
		impl $flag_type {
			#[allow(unused)]
			fn $get(&self) -> bool { self.is_set($flag_type::new() | $flag) }
			#[allow(unused)]
			fn $set(&mut self) { self.set($flag_type::new() | $flag) }
			#[allow(unused)]
			fn $clear(&mut self) -> Self { self.clear($flag_type::new() | $flag) }
		}
	};
	($flag_type_doc: expr, FUNDED_STATE, $flag_type: ident, $flags: tt) => {
		define_state_flags!($flag_type_doc, $flag_type, $flags, FundedStateFlags::ALL.0);

		define_state_flags!($flag_type, FundedStateFlags::PEER_DISCONNECTED,
			is_peer_disconnected, set_peer_disconnected, clear_peer_disconnected);
		define_state_flags!($flag_type, FundedStateFlags::MONITOR_UPDATE_IN_PROGRESS,
			is_monitor_update_in_progress, set_monitor_update_in_progress, clear_monitor_update_in_progress);
		define_state_flags!($flag_type, FundedStateFlags::REMOTE_SHUTDOWN_SENT,
			is_remote_shutdown_sent, set_remote_shutdown_sent, clear_remote_shutdown_sent);
		define_state_flags!($flag_type, FundedStateFlags::LOCAL_SHUTDOWN_SENT,
			is_local_shutdown_sent, set_local_shutdown_sent, clear_local_shutdown_sent);

		impl core::ops::BitOr<FundedStateFlags> for $flag_type {
			type Output = Self;
			fn bitor(self, rhs: FundedStateFlags) -> Self::Output { Self(self.0 | rhs.0) }
		}
		impl core::ops::BitOrAssign<FundedStateFlags> for $flag_type {
			fn bitor_assign(&mut self, rhs: FundedStateFlags) { self.0 |= rhs.0; }
		}
		impl core::ops::BitAnd<FundedStateFlags> for $flag_type {
			type Output = Self;
			fn bitand(self, rhs: FundedStateFlags) -> Self::Output { Self(self.0 & rhs.0) }
		}
		impl core::ops::BitAndAssign<FundedStateFlags> for $flag_type {
			fn bitand_assign(&mut self, rhs: FundedStateFlags) { self.0 &= rhs.0; }
		}
		impl PartialEq<FundedStateFlags> for $flag_type {
			fn eq(&self, other: &FundedStateFlags) -> bool { self.0 == other.0 }
		}
		impl From<FundedStateFlags> for $flag_type {
			fn from(flags: FundedStateFlags) -> Self { Self(flags.0) }
		}
	};
}

/// We declare all the states/flags here together to help determine which bits are still available
/// to choose.
mod state_flags {
	pub const OUR_INIT_SENT: u32 = 1 << 0;
	pub const THEIR_INIT_SENT: u32 = 1 << 1;
	pub const FUNDING_NEGOTIATED: u32 = 1 << 2;
	pub const AWAITING_CHANNEL_READY: u32 = 1 << 3;
	pub const THEIR_CHANNEL_READY: u32 = 1 << 4;
	pub const OUR_CHANNEL_READY: u32 = 1 << 5;
	pub const CHANNEL_READY: u32 = 1 << 6;
	pub const PEER_DISCONNECTED: u32 = 1 << 7;
	pub const MONITOR_UPDATE_IN_PROGRESS: u32 = 1 << 8;
	pub const AWAITING_REMOTE_REVOKE: u32 = 1 << 9;
	pub const REMOTE_SHUTDOWN_SENT: u32 = 1 << 10;
	pub const LOCAL_SHUTDOWN_SENT: u32 = 1 << 11;
	pub const SHUTDOWN_COMPLETE: u32 = 1 << 12;
	pub const WAITING_FOR_BATCH: u32 = 1 << 13;
}

define_state_flags!(
	"Flags that apply to all [`ChannelState`] variants in which the channel is funded.",
	FundedStateFlags, [
		("Indicates the remote side is considered \"disconnected\" and no updates are allowed \
			until after we've done a `channel_reestablish` dance.", PEER_DISCONNECTED, state_flags::PEER_DISCONNECTED,
			is_peer_disconnected, set_peer_disconnected, clear_peer_disconnected),
		("Indicates the user has told us a `ChannelMonitor` update is pending async persistence \
			somewhere and we should pause sending any outbound messages until they've managed to \
			complete it.", MONITOR_UPDATE_IN_PROGRESS, state_flags::MONITOR_UPDATE_IN_PROGRESS,
			is_monitor_update_in_progress, set_monitor_update_in_progress, clear_monitor_update_in_progress),
		("Indicates we received a `shutdown` message from the remote end. If set, they may not add \
			any new HTLCs to the channel, and we are expected to respond with our own `shutdown` \
			message when possible.", REMOTE_SHUTDOWN_SENT, state_flags::REMOTE_SHUTDOWN_SENT,
			is_remote_shutdown_sent, set_remote_shutdown_sent, clear_remote_shutdown_sent),
		("Indicates we sent a `shutdown` message. At this point, we may not add any new HTLCs to \
			the channel.", LOCAL_SHUTDOWN_SENT, state_flags::LOCAL_SHUTDOWN_SENT,
			is_local_shutdown_sent, set_local_shutdown_sent, clear_local_shutdown_sent)
	]
);

define_state_flags!(
	"Flags that only apply to [`ChannelState::NegotiatingFunding`].",
	NegotiatingFundingFlags, [
		("Indicates we have (or are prepared to) send our `open_channel`/`accept_channel` message.",
			OUR_INIT_SENT, state_flags::OUR_INIT_SENT, is_our_init_sent, set_our_init_sent, clear_our_init_sent),
		("Indicates we have received their `open_channel`/`accept_channel` message.",
			THEIR_INIT_SENT, state_flags::THEIR_INIT_SENT, is_their_init_sent, set_their_init_sent, clear_their_init_sent)
	]
);

define_state_flags!(
	"Flags that only apply to [`ChannelState::AwaitingChannelReady`].",
	FUNDED_STATE, AwaitingChannelReadyFlags, [
		("Indicates they sent us a `channel_ready` message. Once both `THEIR_CHANNEL_READY` and \
			`OUR_CHANNEL_READY` are set, our state moves on to `ChannelReady`.",
			THEIR_CHANNEL_READY, state_flags::THEIR_CHANNEL_READY,
			is_their_channel_ready, set_their_channel_ready, clear_their_channel_ready),
		("Indicates we sent them a `channel_ready` message. Once both `THEIR_CHANNEL_READY` and \
			`OUR_CHANNEL_READY` are set, our state moves on to `ChannelReady`.",
			OUR_CHANNEL_READY, state_flags::OUR_CHANNEL_READY,
			is_our_channel_ready, set_our_channel_ready, clear_our_channel_ready),
		("Indicates the channel was funded in a batch and the broadcast of the funding transaction \
			is being held until all channels in the batch have received `funding_signed` and have \
			their monitors persisted.", WAITING_FOR_BATCH, state_flags::WAITING_FOR_BATCH,
			is_waiting_for_batch, set_waiting_for_batch, clear_waiting_for_batch)
	]
);

define_state_flags!(
	"Flags that only apply to [`ChannelState::ChannelReady`].",
	FUNDED_STATE,
	ChannelReadyFlags,
	[(
		"Indicates that we have sent a `commitment_signed` but are awaiting the responding \
			`revoke_and_ack` message. During this period, we can't generate new `commitment_signed` \
			messages as we'd be unable to determine which HTLCs they included in their `revoke_and_ack` \
			implicit ACK, so instead we have to hold them away temporarily to be sent later.",
		AWAITING_REMOTE_REVOKE,
		state_flags::AWAITING_REMOTE_REVOKE,
		is_awaiting_remote_revoke,
		set_awaiting_remote_revoke,
		clear_awaiting_remote_revoke
	)]
);

// Note that the order of this enum is implicitly defined by where each variant is placed. Take this
// into account when introducing new states and update `test_channel_state_order` accordingly.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq)]
enum ChannelState {
	/// We are negotiating the parameters required for the channel prior to funding it.
	NegotiatingFunding(NegotiatingFundingFlags),
	/// We have sent `funding_created` and are awaiting a `funding_signed` to advance to
	/// `AwaitingChannelReady`. Note that this is nonsense for an inbound channel as we immediately generate
	/// `funding_signed` upon receipt of `funding_created`, so simply skip this state.
	FundingNegotiated,
	/// We've received/sent `funding_created` and `funding_signed` and are thus now waiting on the
	/// funding transaction to confirm.
	AwaitingChannelReady(AwaitingChannelReadyFlags),
	/// Both we and our counterparty consider the funding transaction confirmed and the channel is
	/// now operational.
	ChannelReady(ChannelReadyFlags),
	/// We've successfully negotiated a `closing_signed` dance. At this point, the `ChannelManager`
	/// is about to drop us, but we store this anyway.
	ShutdownComplete,
}

macro_rules! impl_state_flag {
	($get: ident, $set: ident, $clear: ident, [$($state: ident),+]) => {
		#[allow(unused)]
		fn $get(&self) -> bool {
			match self {
				$(
					ChannelState::$state(flags) => flags.$get(),
				)*
				_ => false,
			}
		}
		#[allow(unused)]
		fn $set(&mut self) {
			match self {
				$(
					ChannelState::$state(flags) => flags.$set(),
				)*
				_ => debug_assert!(false, "Attempted to set flag on unexpected ChannelState"),
			}
		}
		#[allow(unused)]
		fn $clear(&mut self) {
			match self {
				$(
					ChannelState::$state(flags) => { let _ = flags.$clear(); },
				)*
				_ => debug_assert!(false, "Attempted to clear flag on unexpected ChannelState"),
			}
		}
	};
	($get: ident, $set: ident, $clear: ident, FUNDED_STATES) => {
		impl_state_flag!($get, $set, $clear, [AwaitingChannelReady, ChannelReady]);
	};
	($get: ident, $set: ident, $clear: ident, $state: ident) => {
		impl_state_flag!($get, $set, $clear, [$state]);
	};
}

impl ChannelState {
	fn from_u32(state: u32) -> Result<Self, ()> {
		match state {
			state_flags::FUNDING_NEGOTIATED => Ok(ChannelState::FundingNegotiated),
			state_flags::SHUTDOWN_COMPLETE => Ok(ChannelState::ShutdownComplete),
			val => {
				if val & state_flags::AWAITING_CHANNEL_READY == state_flags::AWAITING_CHANNEL_READY
				{
					AwaitingChannelReadyFlags::from_u32(val & !state_flags::AWAITING_CHANNEL_READY)
						.map(|flags| ChannelState::AwaitingChannelReady(flags))
				} else if val & state_flags::CHANNEL_READY == state_flags::CHANNEL_READY {
					ChannelReadyFlags::from_u32(val & !state_flags::CHANNEL_READY)
						.map(|flags| ChannelState::ChannelReady(flags))
				} else if let Ok(flags) = NegotiatingFundingFlags::from_u32(val) {
					Ok(ChannelState::NegotiatingFunding(flags))
				} else {
					Err(())
				}
			},
		}
	}

	fn to_u32(self) -> u32 {
		match self {
			ChannelState::NegotiatingFunding(flags) => flags.0,
			ChannelState::FundingNegotiated => state_flags::FUNDING_NEGOTIATED,
			ChannelState::AwaitingChannelReady(flags) => {
				state_flags::AWAITING_CHANNEL_READY | flags.0
			},
			ChannelState::ChannelReady(flags) => state_flags::CHANNEL_READY | flags.0,
			ChannelState::ShutdownComplete => state_flags::SHUTDOWN_COMPLETE,
		}
	}

	fn is_pre_funded_state(&self) -> bool {
		matches!(self, ChannelState::NegotiatingFunding(_) | ChannelState::FundingNegotiated)
	}

	fn is_both_sides_shutdown(&self) -> bool {
		self.is_local_shutdown_sent() && self.is_remote_shutdown_sent()
	}

	fn with_funded_state_flags_mask(&self) -> FundedStateFlags {
		match self {
			ChannelState::AwaitingChannelReady(flags) => {
				FundedStateFlags((*flags & FundedStateFlags::ALL).0)
			},
			ChannelState::ChannelReady(flags) => {
				FundedStateFlags((*flags & FundedStateFlags::ALL).0)
			},
			_ => FundedStateFlags::new(),
		}
	}

	fn can_generate_new_commitment(&self) -> bool {
		match self {
			ChannelState::ChannelReady(flags) => {
				!flags.is_set(ChannelReadyFlags::AWAITING_REMOTE_REVOKE)
					&& !flags.is_set(FundedStateFlags::MONITOR_UPDATE_IN_PROGRESS.into())
					&& !flags.is_set(FundedStateFlags::PEER_DISCONNECTED.into())
			},
			_ => {
				debug_assert!(false, "Can only generate new commitment within ChannelReady");
				false
			},
		}
	}

	impl_state_flag!(
		is_peer_disconnected,
		set_peer_disconnected,
		clear_peer_disconnected,
		FUNDED_STATES
	);
	impl_state_flag!(
		is_monitor_update_in_progress,
		set_monitor_update_in_progress,
		clear_monitor_update_in_progress,
		FUNDED_STATES
	);
	impl_state_flag!(
		is_local_shutdown_sent,
		set_local_shutdown_sent,
		clear_local_shutdown_sent,
		FUNDED_STATES
	);
	impl_state_flag!(
		is_remote_shutdown_sent,
		set_remote_shutdown_sent,
		clear_remote_shutdown_sent,
		FUNDED_STATES
	);
	impl_state_flag!(
		is_our_channel_ready,
		set_our_channel_ready,
		clear_our_channel_ready,
		AwaitingChannelReady
	);
	impl_state_flag!(
		is_their_channel_ready,
		set_their_channel_ready,
		clear_their_channel_ready,
		AwaitingChannelReady
	);
	impl_state_flag!(
		is_waiting_for_batch,
		set_waiting_for_batch,
		clear_waiting_for_batch,
		AwaitingChannelReady
	);
	impl_state_flag!(
		is_awaiting_remote_revoke,
		set_awaiting_remote_revoke,
		clear_awaiting_remote_revoke,
		ChannelReady
	);
}

pub const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

pub const DEFAULT_MAX_HTLCS: u16 = 5;

pub const ANCHOR_OUTPUT_VALUE_SATOSHI: u64 = 330;

/// The percentage of the channel value `holder_max_htlc_value_in_flight_msat` used to be set to,
/// before this was made configurable. The percentage was made configurable in LDK 0.0.107,
/// although LDK 0.0.104+ enabled serialization of channels with a different value set for
/// `holder_max_htlc_value_in_flight_msat`.
pub const MAX_IN_FLIGHT_PERCENT_LEGACY: u8 = 10;

/// Maximum `funding_satoshis` value according to the BOLT #2 specification, if
/// `option_support_large_channel` (aka wumbo channels) is not supported.
/// It's 2^24 - 1.
pub const MAX_FUNDING_SATOSHIS_NO_WUMBO: u64 = (1 << 24) - 1;

/// Total bitcoin supply in satoshis.
pub const TOTAL_BITCOIN_SUPPLY_SATOSHIS: u64 = 21_000_000 * 1_0000_0000;

/// The maximum network dust limit for standard script formats. This currently represents the
/// minimum output value for a P2SH output before Bitcoin Core 22 considers the entire
/// transaction non-standard and thus refuses to relay it.
/// We also use this as the maximum counterparty `dust_limit_satoshis` allowed, given many
/// implementations use this value for their dust limit today.
pub const MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS: u64 = 546;

/// The maximum channel dust limit we will accept from our counterparty.
pub const MAX_CHAN_DUST_LIMIT_SATOSHIS: u64 = MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS;

/// The dust limit is used for both the commitment transaction outputs as well as the closing
/// transactions. For cooperative closing transactions, we require segwit outputs, though accept
/// *any* segwit scripts, which are allowed to be up to 42 bytes in length.
/// In order to avoid having to concern ourselves with standardness during the closing process, we
/// simply require our counterparty to use a dust limit which will leave any segwit output
/// standard.
/// See <https://github.com/lightning/bolts/issues/905> for more details.
pub const MIN_CHAN_DUST_LIMIT_SATOSHIS: u64 = 354;

// Just a reasonable implementation-specific safe lower bound, higher than the dust limit.
pub const MIN_THEIR_CHAN_RESERVE_SATOSHIS: u64 = 1000;

/// Used to return a simple Error back to ChannelManager. Will get converted to a
/// msgs::ErrorAction::SendErrorMessage or msgs::ErrorAction::IgnoreError as appropriate with our
/// channel_id in ChannelManager.
pub enum ChannelError {
	Ignore(String),
	Warn(String),
	Close((String, ClosureReason)),
}

impl fmt::Debug for ChannelError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			&ChannelError::Ignore(ref e) => write!(f, "Ignore : {}", e),
			&ChannelError::Warn(ref e) => write!(f, "Warn : {}", e),
			&ChannelError::Close((ref e, _)) => write!(f, "Close : {}", e),
		}
	}
}

impl fmt::Display for ChannelError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			&ChannelError::Ignore(ref e) => write!(f, "{}", e),
			&ChannelError::Warn(ref e) => write!(f, "{}", e),
			&ChannelError::Close((ref e, _)) => write!(f, "{}", e),
		}
	}
}

impl ChannelError {
	pub(super) fn close(err: String) -> Self {
		ChannelError::Close((err.clone(), ClosureReason::ProcessingError { err }))
	}
}

pub(super) struct WithChannelContext<'a, L: Deref>
where
	L::Target: Logger,
{
	pub logger: &'a L,
	pub peer_id: Option<PublicKey>,
	pub channel_id: Option<ChannelId>,
	pub payment_hash: Option<PaymentHash>,
}

impl<'a, L: Deref> Logger for WithChannelContext<'a, L>
where
	L::Target: Logger,
{
	fn log(&self, mut record: Record) {
		record.peer_id = self.peer_id;
		record.channel_id = self.channel_id;
		record.payment_hash = self.payment_hash;
		self.logger.log(record)
	}
}

impl<'a, 'b, L: Deref> WithChannelContext<'a, L>
where
	L::Target: Logger,
{
	pub(super) fn from<S: Deref>(
		logger: &'a L, context: &'b ChannelContext<S>, payment_hash: Option<PaymentHash>,
	) -> Self
	where
		S::Target: SignerProvider,
	{
		WithChannelContext {
			logger,
			peer_id: Some(context.counterparty_node_id),
			channel_id: Some(context.channel_id),
			payment_hash,
		}
	}
}

macro_rules! secp_check {
	($res: expr, $err: expr) => {
		match $res {
			Ok(thing) => thing,
			Err(_) => return Err(ChannelError::close($err)),
		}
	};
}

/// The "channel disabled" bit in channel_update must be set based on whether we are connected to
/// our counterparty or not. However, we don't want to announce updates right away to avoid
/// spamming the network with updates if the connection is flapping. Instead, we "stage" updates to
/// our channel_update message and track the current state here.
/// See implementation at [`super::channelmanager::ChannelManager::timer_tick_occurred`].
#[derive(Clone, Copy, PartialEq)]
pub(super) enum ChannelUpdateStatus {
	/// We've announced the channel as enabled and are connected to our peer.
	Enabled,
	/// Our channel is no longer live, but we haven't announced the channel as disabled yet.
	DisabledStaged(u8),
	/// Our channel is live again, but we haven't announced the channel as enabled yet.
	EnabledStaged(u8),
	/// We've announced the channel as disabled.
	Disabled,
}

/// We track when we sent an `AnnouncementSignatures` to our peer in a few states, described here.
#[derive(PartialEq)]
pub enum AnnouncementSigsState {
	/// We have not sent our peer an `AnnouncementSignatures` yet, or our peer disconnected since
	/// we sent the last `AnnouncementSignatures`.
	NotSent,
	/// We sent an `AnnouncementSignatures` to our peer since the last time our peer disconnected.
	/// This state never appears on disk - instead we write `NotSent`.
	MessageSent,
	/// We sent a `CommitmentSigned` after the last `AnnouncementSignatures` we sent. Because we
	/// only ever have a single `CommitmentSigned` pending at once, if we sent one after sending
	/// `AnnouncementSignatures` then we know the peer received our `AnnouncementSignatures` if
	/// they send back a `RevokeAndACK`.
	/// This state never appears on disk - instead we write `NotSent`.
	Committed,
	/// We received a `RevokeAndACK`, effectively ack-ing our `AnnouncementSignatures`, at this
	/// point we no longer need to re-send our `AnnouncementSignatures` again on reconnect.
	PeerReceived,
}

/// An enum indicating whether the local or remote side offered a given HTLC.
enum HTLCInitiator {
	LocalOffered,
	RemoteOffered,
}

/// Current counts of various HTLCs, useful for calculating current balances available exactly.
struct HTLCStats {
	pending_inbound_htlcs: usize,
	pending_outbound_htlcs: usize,
	pending_inbound_htlcs_value_msat: u64,
	pending_outbound_htlcs_value_msat: u64,
	on_counterparty_tx_dust_exposure_msat: u64,
	on_holder_tx_dust_exposure_msat: u64,
	outbound_holding_cell_msat: u64,
	on_holder_tx_outbound_holding_cell_htlcs_count: u32, // dust HTLCs *non*-included
}

/// An enum gathering stats on commitment transaction, either local or remote.
#[derive(Debug)]
struct CommitmentStats<'a> {
	tx: CommitmentTransaction, // the transaction info
	feerate_per_kw: u32,       // the feerate included to build the transaction
	total_fee_sat: u64,        // the total fee included in the transaction
	num_nondust_htlcs: usize,  // the number of HTLC outputs (dust HTLCs *non*-included)
	htlcs_included: Vec<(HTLCOutputInCommitment, Option<&'a HTLCSource>)>, // the list of HTLCs (dust HTLCs *included*) which were not ignored when building the transaction
	local_balance_msat: u64, // local balance before fees *not* considering dust limits
	remote_balance_msat: u64, // remote balance before fees *not* considering dust limits
	outbound_htlc_preimages: Vec<PaymentPreimage>, // preimages for successful offered HTLCs since last commitment
	inbound_htlc_preimages: Vec<PaymentPreimage>, // preimages for successful received HTLCs since last commitment
}

/// Used when calculating whether we or the remote can afford an additional HTLC.
struct HTLCCandidate {
	amount_msat: u64,
	origin: HTLCInitiator,
}

impl HTLCCandidate {
	fn new(amount_msat: u64, origin: HTLCInitiator) -> Self {
		Self { amount_msat, origin }
	}
}

/// A return value enum for get_update_fulfill_htlc. See UpdateFulfillCommitFetch variants for
/// description
enum UpdateFulfillFetch {
	NewClaim {
		monitor_update: ChannelMonitorUpdate,
		htlc_value_msat: u64,
		msg: Option<msgs::UpdateFulfillHTLC>,
	},
	DuplicateClaim {},
}

/// The return type of get_update_fulfill_htlc_and_commit.
pub enum UpdateFulfillCommitFetch {
	/// Indicates the HTLC fulfill is new, and either generated an update_fulfill message, placed
	/// it in the holding cell, or re-generated the update_fulfill message after the same claim was
	/// previously placed in the holding cell (and has since been removed).
	NewClaim {
		/// The ChannelMonitorUpdate which places the new payment preimage in the channel monitor
		monitor_update: ChannelMonitorUpdate,
		/// The value of the HTLC which was claimed, in msat.
		htlc_value_msat: u64,
	},
	/// Indicates the HTLC fulfill is duplicative and already existed either in the holding cell
	/// or has been forgotten (presumably previously claimed).
	DuplicateClaim {},
}

/// The return value of `monitor_updating_restored`
pub(super) struct MonitorRestoreUpdates {
	pub raa: Option<msgs::RevokeAndACK>,
	pub commitment_update: Option<msgs::CommitmentUpdate>,
	pub order: RAACommitmentOrder,
	pub accepted_htlcs: Vec<(PendingHTLCInfo, u64)>,
	pub failed_htlcs: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>,
	pub finalized_claimed_htlcs: Vec<HTLCSource>,
	pub pending_update_adds: Vec<msgs::UpdateAddHTLC>,
	pub funding_broadcastable: Option<Transaction>,
	pub channel_ready: Option<msgs::ChannelReady>,
	pub announcement_sigs: Option<msgs::AnnouncementSignatures>,
}

/// The return value of `signer_maybe_unblocked`
#[allow(unused)]
pub(super) struct SignerResumeUpdates {
	pub commitment_update: Option<msgs::CommitmentUpdate>,
	pub revoke_and_ack: Option<msgs::RevokeAndACK>,
	pub funding_signed: Option<msgs::FundingSigned>,
	pub channel_ready: Option<msgs::ChannelReady>,
	pub order: RAACommitmentOrder,
	pub closing_signed: Option<msgs::ClosingSigned>,
	pub signed_closing_tx: Option<Transaction>,
}

/// The return value of `channel_reestablish`
pub(super) struct ReestablishResponses {
	pub channel_ready: Option<msgs::ChannelReady>,
	pub raa: Option<msgs::RevokeAndACK>,
	pub commitment_update: Option<msgs::CommitmentUpdate>,
	pub order: RAACommitmentOrder,
	pub announcement_sigs: Option<msgs::AnnouncementSignatures>,
	pub shutdown_msg: Option<msgs::Shutdown>,
}

/// The result of a shutdown that should be handled.
#[must_use]
pub(crate) struct ShutdownResult {
	pub(crate) closure_reason: ClosureReason,
	/// A channel monitor update to apply.
	pub(crate) monitor_update: Option<(PublicKey, OutPoint, ChannelId, ChannelMonitorUpdate)>,
	/// A list of dropped outbound HTLCs that can safely be failed backwards immediately.
	pub(crate) dropped_outbound_htlcs: Vec<(HTLCSource, PaymentHash, PublicKey, ChannelId)>,
	/// An unbroadcasted batch funding transaction id. The closure of this channel should be
	/// propagated to the remainder of the batch.
	pub(crate) unbroadcasted_batch_funding_txid: Option<Txid>,
	pub(crate) channel_id: ChannelId,
	pub(crate) user_channel_id: u128,
	pub(crate) channel_capacity_satoshis: u64,
	pub(crate) counterparty_node_id: PublicKey,
	pub(crate) is_manual_broadcast: bool,
	pub(crate) unbroadcasted_funding_tx: Option<Transaction>,
	pub(crate) channel_funding_txo: Option<OutPoint>,
}

/// Tracks the transaction number, along with current and next commitment points.
/// This consolidates the logic to advance our commitment number and request new
/// commitment points from our signer.
#[derive(Debug, Copy, Clone)]
enum HolderCommitmentPoint {
	// TODO: add a variant for before our first commitment point is retrieved
	/// We've advanced our commitment number and are waiting on the next commitment point.
	/// Until the `get_per_commitment_point` signer method becomes async, this variant
	/// will not be used.
	PendingNext { transaction_number: u64, current: PublicKey },
	/// Our current commitment point is ready, we've cached our next point,
	/// and we are not pending a new one.
	Available { transaction_number: u64, current: PublicKey, next: PublicKey },
}

impl HolderCommitmentPoint {
	pub fn new<SP: Deref>(
		signer: &ChannelSignerType<SP>, secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Self
	where
		SP::Target: SignerProvider,
	{
		HolderCommitmentPoint::Available {
			transaction_number: INITIAL_COMMITMENT_NUMBER,
			// TODO(async_signing): remove this expect with the Uninitialized variant
			current: signer
				.as_ref()
				.get_per_commitment_point(INITIAL_COMMITMENT_NUMBER, secp_ctx)
				.expect("Signer must be able to provide initial commitment point"),
			// TODO(async_signing): remove this expect with the Uninitialized variant
			next: signer
				.as_ref()
				.get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - 1, secp_ctx)
				.expect("Signer must be able to provide second commitment point"),
		}
	}

	pub fn is_available(&self) -> bool {
		if let HolderCommitmentPoint::Available { .. } = self {
			true
		} else {
			false
		}
	}

	pub fn transaction_number(&self) -> u64 {
		match self {
			HolderCommitmentPoint::PendingNext { transaction_number, .. } => *transaction_number,
			HolderCommitmentPoint::Available { transaction_number, .. } => *transaction_number,
		}
	}

	pub fn current_point(&self) -> PublicKey {
		match self {
			HolderCommitmentPoint::PendingNext { current, .. } => *current,
			HolderCommitmentPoint::Available { current, .. } => *current,
		}
	}

	pub fn next_point(&self) -> Option<PublicKey> {
		match self {
			HolderCommitmentPoint::PendingNext { .. } => None,
			HolderCommitmentPoint::Available { next, .. } => Some(*next),
		}
	}

	/// If we are pending the next commitment point, this method tries asking the signer again,
	/// and transitions to the next state if successful.
	///
	/// This method is used for the following transitions:
	/// - `PendingNext` -> `Available`
	pub fn try_resolve_pending<SP: Deref, L: Deref>(
		&mut self, signer: &ChannelSignerType<SP>, secp_ctx: &Secp256k1<secp256k1::All>, logger: &L,
	) where
		SP::Target: SignerProvider,
		L::Target: Logger,
	{
		if let HolderCommitmentPoint::PendingNext { transaction_number, current } = self {
			if let Ok(next) =
				signer.as_ref().get_per_commitment_point(*transaction_number - 1, secp_ctx)
			{
				log_trace!(
					logger,
					"Retrieved next per-commitment point {}",
					*transaction_number - 1
				);
				*self = HolderCommitmentPoint::Available {
					transaction_number: *transaction_number,
					current: *current,
					next,
				};
			} else {
				log_trace!(logger, "Next per-commitment point {} is pending", transaction_number);
			}
		}
	}

	/// If we are not pending the next commitment point, this method advances the commitment number
	/// and requests the next commitment point from the signer. Returns `Ok` if we were at
	/// `Available` and were able to advance our commitment number (even if we are still pending
	/// the next commitment point).
	///
	/// If our signer is not ready to provide the next commitment point, we will
	/// only advance to `PendingNext`, and should be tried again later in `signer_unblocked`
	/// via `try_resolve_pending`.
	///
	/// If our signer is ready to provide the next commitment point, we will advance all the
	/// way to `Available`.
	///
	/// This method is used for the following transitions:
	/// - `Available` -> `PendingNext`
	/// - `Available` -> `PendingNext` -> `Available` (in one fell swoop)
	pub fn advance<SP: Deref, L: Deref>(
		&mut self, signer: &ChannelSignerType<SP>, secp_ctx: &Secp256k1<secp256k1::All>, logger: &L,
	) -> Result<(), ()>
	where
		SP::Target: SignerProvider,
		L::Target: Logger,
	{
		if let HolderCommitmentPoint::Available { transaction_number, next, .. } = self {
			*self = HolderCommitmentPoint::PendingNext {
				transaction_number: *transaction_number - 1,
				current: *next,
			};
			self.try_resolve_pending(signer, secp_ctx, logger);
			return Ok(());
		}
		Err(())
	}
}

/// If the majority of the channels funds are to the fundee and the initiator holds only just
/// enough funds to cover their reserve value, channels are at risk of getting "stuck". Because the
/// initiator controls the feerate, if they then go to increase the channel fee, they may have no
/// balance but the fundee is unable to send a payment as the increase in fee more than drains
/// their reserve value. Thus, neither side can send a new HTLC and the channel becomes useless.
/// Thus, before sending an HTLC when we are the initiator, we check that the feerate can increase
/// by this multiple without hitting this case, before sending.
/// This multiple is effectively the maximum feerate "jump" we expect until more HTLCs flow over
/// the channel. Sadly, there isn't really a good number for this - if we expect to have no new
/// HTLCs for days we may need this to suffice for feerate increases across days, but that may
/// leave the channel less usable as we hold a bigger reserve.
#[cfg(any(fuzzing, test))]
pub const FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE: u64 = 2;
#[cfg(not(any(fuzzing, test)))]
const FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE: u64 = 2;

/// If we fail to see a funding transaction confirmed on-chain within this many blocks after the
/// channel creation on an inbound channel, we simply force-close and move on.
/// This constant is the one suggested in BOLT 2.
pub(crate) const FUNDING_CONF_DEADLINE_BLOCKS: u32 = 2016;

/// In case of a concurrent update_add_htlc proposed by our counterparty, we might
/// not have enough balance value remaining to cover the onchain cost of this new
/// HTLC weight. If this happens, our counterparty fails the reception of our
/// commitment_signed including this new HTLC due to infringement on the channel
/// reserve.
/// To prevent this case, we compute our outbound update_fee with an HTLC buffer of
/// size 2. However, if the number of concurrent update_add_htlc is higher, this still
/// leads to a channel force-close. Ultimately, this is an issue coming from the
/// design of LN state machines, allowing asynchronous updates.
pub(crate) const CONCURRENT_INBOUND_HTLC_FEE_BUFFER: u32 = 2;

/// When a channel is opened, we check that the funding amount is enough to pay for relevant
/// commitment transaction fees, with at least this many HTLCs present on the commitment
/// transaction (not counting the value of the HTLCs themselves).
pub(crate) const MIN_AFFORDABLE_HTLC_COUNT: usize = 4;

/// When a [`Channel`] has its [`ChannelConfig`] updated, its existing one is stashed for up to this
/// number of ticks to allow forwarding HTLCs by nodes that have yet to receive the new
/// ChannelUpdate prompted by the config update. This value was determined as follows:
///
///   * The expected interval between ticks (1 minute).
///   * The average convergence delay of updates across the network, i.e., ~300 seconds on average
///      for a node to see an update as seen on `<https://arxiv.org/pdf/2205.12737.pdf>`.
///   * `EXPIRE_PREV_CONFIG_TICKS` = convergence_delay / tick_interval
pub(crate) const EXPIRE_PREV_CONFIG_TICKS: usize = 5;

/// The number of ticks that may elapse while we're waiting for a response to a
/// [`msgs::RevokeAndACK`] or [`msgs::ChannelReestablish`] message before we attempt to disconnect
/// them.
///
/// See [`ChannelContext::sent_message_awaiting_response`] for more information.
pub(crate) const DISCONNECT_PEER_AWAITING_RESPONSE_TICKS: usize = 2;

/// The number of ticks that may elapse while we're waiting for an unfunded outbound/inbound channel
/// to be promoted to a [`Channel`] since the unfunded channel was created. An unfunded channel
/// exceeding this age limit will be force-closed and purged from memory.
pub(crate) const UNFUNDED_CHANNEL_AGE_LIMIT_TICKS: usize = 60;

/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub(crate) const COINBASE_MATURITY: u32 = 100;

struct PendingChannelMonitorUpdate {
	update: ChannelMonitorUpdate,
}

impl_writeable_tlv_based!(PendingChannelMonitorUpdate, {
	(0, update, required),
});

/// The `ChannelPhase` enum describes the current phase in life of a lightning channel with each of
/// its variants containing an appropriate channel struct.
pub(super) enum ChannelPhase<SP: Deref>
where
	SP::Target: SignerProvider,
{
	UnfundedOutboundV1(OutboundV1Channel<SP>),
	UnfundedInboundV1(InboundV1Channel<SP>),
	#[cfg(any(dual_funding, splicing))]
	UnfundedOutboundV2(OutboundV2Channel<SP>),
	#[cfg(any(dual_funding, splicing))]
	UnfundedInboundV2(InboundV2Channel<SP>),
	Funded(Channel<SP>),
}

impl<'a, SP: Deref> ChannelPhase<SP>
where
	SP::Target: SignerProvider,
	<SP::Target as SignerProvider>::EcdsaSigner: ChannelSigner,
{
	pub fn context(&'a self) -> &'a ChannelContext<SP> {
		match self {
			ChannelPhase::Funded(chan) => &chan.context,
			ChannelPhase::UnfundedOutboundV1(chan) => &chan.context,
			ChannelPhase::UnfundedInboundV1(chan) => &chan.context,
			#[cfg(any(dual_funding, splicing))]
			ChannelPhase::UnfundedOutboundV2(chan) => &chan.context,
			#[cfg(any(dual_funding, splicing))]
			ChannelPhase::UnfundedInboundV2(chan) => &chan.context,
		}
	}

	pub fn context_mut(&'a mut self) -> &'a mut ChannelContext<SP> {
		match self {
			ChannelPhase::Funded(ref mut chan) => &mut chan.context,
			ChannelPhase::UnfundedOutboundV1(ref mut chan) => &mut chan.context,
			ChannelPhase::UnfundedInboundV1(ref mut chan) => &mut chan.context,
			#[cfg(any(dual_funding, splicing))]
			ChannelPhase::UnfundedOutboundV2(ref mut chan) => &mut chan.context,
			#[cfg(any(dual_funding, splicing))]
			ChannelPhase::UnfundedInboundV2(ref mut chan) => &mut chan.context,
		}
	}
}

/// Contains all state common to unfunded inbound/outbound channels.
pub(super) struct UnfundedChannelContext {
	/// A counter tracking how many ticks have elapsed since this unfunded channel was
	/// created. If this unfunded channel reaches peer has yet to respond after reaching
	/// `UNFUNDED_CHANNEL_AGE_LIMIT_TICKS`, it will be force-closed and purged from memory.
	///
	/// This is so that we don't keep channels around that haven't progressed to a funded state
	/// in a timely manner.
	unfunded_channel_age_ticks: usize,
}

impl UnfundedChannelContext {
	/// Determines whether we should force-close and purge this unfunded channel from memory due to it
	/// having reached the unfunded channel age limit.
	///
	/// This should be called on every [`super::channelmanager::ChannelManager::timer_tick_occurred`].
	pub fn should_expire_unfunded_channel(&mut self) -> bool {
		self.unfunded_channel_age_ticks += 1;
		self.unfunded_channel_age_ticks >= UNFUNDED_CHANNEL_AGE_LIMIT_TICKS
	}
}

/// Contains everything about the channel including state, and various flags.
pub(crate) struct ChannelContext<SP: Deref>
where
	SP::Target: SignerProvider,
{
	config: LegacyChannelConfig,

	// Track the previous `ChannelConfig` so that we can continue forwarding HTLCs that were
	// constructed using it. The second element in the tuple corresponds to the number of ticks that
	// have elapsed since the update occurred.
	prev_config: Option<(ChannelConfig, usize)>,

	inbound_handshake_limits_override: Option<ChannelHandshakeLimits>,

	user_id: u128,

	/// The current channel ID.
	pub(crate) channel_id: ChannelId,
	/// The temporary channel ID used during channel setup. Value kept even after transitioning to a final channel ID.
	/// Will be `None` for channels created prior to 0.0.115.
	temporary_channel_id: Option<ChannelId>,
	channel_state: ChannelState,

	// When we reach max(6 blocks, minimum_depth), we need to send an AnnouncementSigs message to
	// our peer. However, we want to make sure they received it, or else rebroadcast it when we
	// next connect.
	// We do so here, see `AnnouncementSigsSent` for more details on the state(s).
	// Note that a number of our tests were written prior to the behavior here which retransmits
	// AnnouncementSignatures until after an RAA completes, so the behavior is short-circuited in
	// many tests.
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) announcement_sigs_state: AnnouncementSigsState,
	#[cfg(not(any(test, feature = "_test_utils")))]
	announcement_sigs_state: AnnouncementSigsState,

	secp_ctx: Secp256k1<secp256k1::All>,
	channel_value_satoshis: u64,

	latest_monitor_update_id: u64,

	holder_signer: ChannelSignerType<SP>,
	shutdown_scriptpubkey: Option<ShutdownScript>,
	destination_script: ScriptBuf,

	// Our commitment numbers start at 2^48-1 and count down, whereas the ones used in transaction
	// generation start at 0 and count up...this simplifies some parts of implementation at the
	// cost of others, but should really just be changed.
	holder_commitment_point: HolderCommitmentPoint,
	cur_counterparty_commitment_transaction_number: u64,
	value_to_self_msat: u64, // Excluding all pending_htlcs, fees, and anchor outputs
	pending_inbound_htlcs: Vec<InboundHTLCOutput>,
	pending_outbound_htlcs: Vec<OutboundHTLCOutput>,
	holding_cell_htlc_updates: Vec<HTLCUpdateAwaitingACK>,

	/// When resending CS/RAA messages on channel monitor restoration or on reconnect, we always
	/// need to ensure we resend them in the order we originally generated them. Note that because
	/// there can only ever be one in-flight CS and/or one in-flight RAA at any time, it is
	/// sufficient to simply set this to the opposite of any message we are generating as we
	/// generate it. ie when we generate a CS, we set this to RAAFirst as, if there is a pending
	/// in-flight RAA to resend, it will have been the first thing we generated, and thus we should
	/// send it first.
	resend_order: RAACommitmentOrder,

	monitor_pending_channel_ready: bool,
	monitor_pending_revoke_and_ack: bool,
	monitor_pending_commitment_signed: bool,

	// TODO: If a channel is drop'd, we don't know whether the `ChannelMonitor` is ultimately
	// responsible for some of the HTLCs here or not - we don't know whether the update in question
	// completed or not. We currently ignore these fields entirely when force-closing a channel,
	// but need to handle this somehow or we run the risk of losing HTLCs!
	monitor_pending_forwards: Vec<(PendingHTLCInfo, u64)>,
	monitor_pending_failures: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>,
	monitor_pending_finalized_fulfills: Vec<HTLCSource>,
	monitor_pending_update_adds: Vec<msgs::UpdateAddHTLC>,

	/// If we went to send a revoke_and_ack but our signer was unable to give us a signature,
	/// we should retry at some point in the future when the signer indicates it may have a
	/// signature for us.
	///
	/// This may also be used to make sure we send a `revoke_and_ack` after a `commitment_signed`
	/// if we need to maintain ordering of messages, but are pending the signer on a previous
	/// message.
	signer_pending_revoke_and_ack: bool,
	/// If we went to send a commitment update (ie some messages then [`msgs::CommitmentSigned`])
	/// but our signer (initially) refused to give us a signature, we should retry at some point in
	/// the future when the signer indicates it may have a signature for us.
	///
	/// This flag is set in such a case. Note that we don't need to persist this as we'll end up
	/// setting it again as a side-effect of [`Channel::channel_reestablish`].
	signer_pending_commitment_update: bool,
	/// Similar to [`Self::signer_pending_commitment_update`] but we're waiting to send either a
	/// [`msgs::FundingCreated`] or [`msgs::FundingSigned`] depending on if this channel is
	/// outbound or inbound.
	signer_pending_funding: bool,
	/// If we attempted to sign a cooperative close transaction but the signer wasn't ready, then this
	/// will be set to `true`.
	signer_pending_closing: bool,

	// pending_update_fee is filled when sending and receiving update_fee.
	//
	// Because it follows the same commitment flow as HTLCs, `FeeUpdateState` is either `Outbound`
	// or matches a subset of the `InboundHTLCOutput` variants. It is then updated/used when
	// generating new commitment transactions with exactly the same criteria as inbound/outbound
	// HTLCs with similar state.
	pending_update_fee: Option<(u32, FeeUpdateState)>,
	// If a `send_update_fee()` call is made with ChannelState::AwaitingRemoteRevoke set, we place
	// it here instead of `pending_update_fee` in the same way as we place outbound HTLC updates in
	// `holding_cell_htlc_updates` instead of `pending_outbound_htlcs`. It is released into
	// `pending_update_fee` with the same criteria as outbound HTLC updates but can be updated by
	// further `send_update_fee` calls, dropping the previous holding cell update entirely.
	holding_cell_update_fee: Option<u32>,
	next_holder_htlc_id: u64,
	next_counterparty_htlc_id: u64,
	feerate_per_kw: u32,

	/// The timestamp set on our latest `channel_update` message for this channel. It is updated
	/// when the channel is updated in ways which may impact the `channel_update` message or when a
	/// new block is received, ensuring it's always at least moderately close to the current real
	/// time.
	update_time_counter: u32,

	#[cfg(debug_assertions)]
	/// Max to_local and to_remote outputs in a locally-generated commitment transaction
	holder_max_commitment_tx_output: Mutex<(u64, u64)>,
	#[cfg(debug_assertions)]
	/// Max to_local and to_remote outputs in a remote-generated commitment transaction
	counterparty_max_commitment_tx_output: Mutex<(u64, u64)>,

	// (fee_sats, skip_remote_output, fee_range, holder_sig)
	last_sent_closing_fee: Option<(u64, bool, ClosingSignedFeeRange, Option<Signature>)>,
	last_received_closing_sig: Option<Signature>,
	target_closing_feerate_sats_per_kw: Option<u32>,

	/// If our counterparty sent us a closing_signed while we were waiting for a `ChannelMonitor`
	/// update, we need to delay processing it until later. We do that here by simply storing the
	/// closing_signed message and handling it in `maybe_propose_closing_signed`.
	pending_counterparty_closing_signed: Option<msgs::ClosingSigned>,

	/// The minimum and maximum absolute fee, in satoshis, we are willing to place on the closing
	/// transaction. These are set once we reach `closing_negotiation_ready`.
	#[cfg(test)]
	pub(crate) closing_fee_limits: Option<(u64, u64)>,
	#[cfg(not(test))]
	closing_fee_limits: Option<(u64, u64)>,

	/// If we remove an HTLC (or fee update), commit, and receive our counterparty's
	/// `revoke_and_ack`, we remove all knowledge of said HTLC (or fee update). However, the latest
	/// local commitment transaction that we can broadcast still contains the HTLC (or old fee)
	/// until we receive a further `commitment_signed`. Thus we are not eligible for initiating the
	/// `closing_signed` negotiation if we're expecting a counterparty `commitment_signed`.
	///
	/// To ensure we don't send a `closing_signed` too early, we track this state here, waiting
	/// until we see a `commitment_signed` before doing so.
	///
	/// We don't bother to persist this - we anticipate this state won't last longer than a few
	/// milliseconds, so any accidental force-closes here should be exceedingly rare.
	expecting_peer_commitment_signed: bool,

	/// The hash of the block in which the funding transaction was included.
	funding_tx_confirmed_in: Option<BlockHash>,
	funding_tx_confirmation_height: u32,
	short_channel_id: Option<u64>,
	/// Either the height at which this channel was created or the height at which it was last
	/// serialized if it was serialized by versions prior to 0.0.103.
	/// We use this to close if funding is never broadcasted.
	pub(super) channel_creation_height: u32,

	counterparty_dust_limit_satoshis: u64,

	#[cfg(test)]
	pub(super) holder_dust_limit_satoshis: u64,
	#[cfg(not(test))]
	holder_dust_limit_satoshis: u64,

	#[cfg(test)]
	pub(super) counterparty_max_htlc_value_in_flight_msat: u64,
	#[cfg(not(test))]
	counterparty_max_htlc_value_in_flight_msat: u64,

	#[cfg(test)]
	pub(super) holder_max_htlc_value_in_flight_msat: u64,
	#[cfg(not(test))]
	holder_max_htlc_value_in_flight_msat: u64,

	/// minimum channel reserve for self to maintain - set by them.
	counterparty_selected_channel_reserve_satoshis: Option<u64>,

	#[cfg(test)]
	pub(super) holder_selected_channel_reserve_satoshis: u64,
	#[cfg(not(test))]
	holder_selected_channel_reserve_satoshis: u64,

	counterparty_htlc_minimum_msat: u64,
	holder_htlc_minimum_msat: u64,
	#[cfg(test)]
	pub counterparty_max_accepted_htlcs: u16,
	#[cfg(not(test))]
	counterparty_max_accepted_htlcs: u16,
	holder_max_accepted_htlcs: u16,
	minimum_depth: Option<u32>,

	counterparty_forwarding_info: Option<CounterpartyForwardingInfo>,

	pub(crate) channel_transaction_parameters: ChannelTransactionParameters,
	/// The transaction which funds this channel. Note that for manually-funded channels (i.e.,
	/// is_manual_broadcast is true) this will be a dummy empty transaction.
	funding_transaction: Option<Transaction>,
	/// This flag indicates that it is the user's responsibility to validated and broadcast the
	/// funding transaction.
	is_manual_broadcast: bool,
	is_batch_funding: Option<()>,

	counterparty_cur_commitment_point: Option<PublicKey>,
	counterparty_prev_commitment_point: Option<PublicKey>,
	counterparty_node_id: PublicKey,

	counterparty_shutdown_scriptpubkey: Option<ScriptBuf>,

	commitment_secrets: CounterpartyCommitmentSecrets,

	channel_update_status: ChannelUpdateStatus,
	/// Once we reach `closing_negotiation_ready`, we set this, indicating if closing_signed does
	/// not complete within a single timer tick (one minute), we should force-close the channel.
	/// This prevents us from keeping unusable channels around forever if our counterparty wishes
	/// to DoS us.
	/// Note that this field is reset to false on deserialization to give us a chance to connect to
	/// our peer and start the closing_signed negotiation fresh.
	closing_signed_in_flight: bool,

	/// Our counterparty's channel_announcement signatures provided in announcement_signatures.
	/// This can be used to rebroadcast the channel_announcement message later.
	announcement_sigs: Option<(Signature, Signature)>,

	// We save these values so we can make sure `next_local_commit_tx_fee_msat` and
	// `next_remote_commit_tx_fee_msat` properly predict what the next commitment transaction fee will
	// be, by comparing the cached values to the fee of the tranaction generated by
	// `build_commitment_transaction`.
	#[cfg(any(test, fuzzing))]
	next_local_commitment_tx_fee_info_cached: Mutex<Option<CommitmentTxInfoCached>>,
	#[cfg(any(test, fuzzing))]
	next_remote_commitment_tx_fee_info_cached: Mutex<Option<CommitmentTxInfoCached>>,

	/// lnd has a long-standing bug where, upon reconnection, if the channel is not yet confirmed
	/// they will not send a channel_reestablish until the channel locks in. Then, they will send a
	/// channel_ready *before* sending the channel_reestablish (which is clearly a violation of
	/// the BOLT specs). We copy c-lightning's workaround here and simply store the channel_ready
	/// message until we receive a channel_reestablish.
	///
	/// See-also <https://github.com/lightningnetwork/lnd/issues/4006>
	pub workaround_lnd_bug_4006: Option<msgs::ChannelReady>,

	/// An option set when we wish to track how many ticks have elapsed while waiting for a response
	/// from our counterparty after sending a message. If the peer has yet to respond after reaching
	/// `DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`, a reconnection should be attempted to try to
	/// unblock the state machine.
	///
	/// This behavior is mostly motivated by a lnd bug in which we don't receive a message we expect
	/// to in a timely manner, which may lead to channels becoming unusable and/or force-closed. An
	/// example of such can be found at <https://github.com/lightningnetwork/lnd/issues/7682>.
	///
	/// This is currently only used when waiting for a [`msgs::ChannelReestablish`] or
	/// [`msgs::RevokeAndACK`] message from the counterparty.
	sent_message_awaiting_response: Option<usize>,

	#[cfg(any(test, fuzzing))]
	// When we receive an HTLC fulfill on an outbound path, we may immediately fulfill the
	// corresponding HTLC on the inbound path. If, then, the outbound path channel is
	// disconnected and reconnected (before we've exchange commitment_signed and revoke_and_ack
	// messages), they may re-broadcast their update_fulfill_htlc, causing a duplicate claim. This
	// is fine, but as a sanity check in our failure to generate the second claim, we check here
	// that the original was a claim, and that we aren't now trying to fulfill a failed HTLC.
	historical_inbound_htlc_fulfills: HashSet<u64>,

	/// This channel's type, as negotiated during channel open
	pub(crate) channel_type: ChannelTypeFeatures,

	// Our counterparty can offer us SCID aliases which they will map to this channel when routing
	// outbound payments. These can be used in invoice route hints to avoid explicitly revealing
	// the channel's funding UTXO.
	//
	// We also use this when sending our peer a channel_update that isn't to be broadcasted
	// publicly - allowing them to re-use their map of SCID -> channel for channel_update ->
	// associated channel mapping.
	//
	// We only bother storing the most recent SCID alias at any time, though our counterparty has
	// to store all of them.
	latest_inbound_scid_alias: Option<u64>,

	// We always offer our counterparty a static SCID alias, which we recognize as for this channel
	// if we see it in HTLC forwarding instructions. We don't bother rotating the alias given we
	// don't currently support node id aliases and eventually privacy should be provided with
	// blinded paths instead of simple scid+node_id aliases.
	outbound_scid_alias: u64,

	// We track whether we already emitted a `ChannelPending` event.
	channel_pending_event_emitted: bool,

	// We track whether we already emitted a `FundingTxBroadcastSafe` event.
	funding_tx_broadcast_safe_event_emitted: bool,

	// We track whether we already emitted a `ChannelReady` event.
	channel_ready_event_emitted: bool,

	/// Some if we initiated to shut down the channel.
	local_initiated_shutdown: Option<()>,

	/// The unique identifier used to re-derive the private key material for the channel through
	/// [`SignerProvider::derive_channel_signer`].
	#[cfg(not(test))]
	channel_keys_id: [u8; 32],
	#[cfg(test)]
	pub channel_keys_id: [u8; 32],

	/// If we can't release a [`ChannelMonitorUpdate`] until some external action completes, we
	/// store it here and only release it to the `ChannelManager` once it asks for it.
	blocked_monitor_updates: Vec<PendingChannelMonitorUpdate>,
	/// The consignment endpoint used to exchange the RGB consignment
	pub(super) consignment_endpoint: Option<RgbTransport>,

	pub(crate) ldk_data_dir: PathBuf,
}

impl<SP: Deref> ChannelContext<SP>
where
	SP::Target: SignerProvider,
{
	fn new_for_inbound_channel<'a, ES: Deref, F: Deref, L: Deref>(
		fee_estimator: &'a LowerBoundedFeeEstimator<F>, entropy_source: &'a ES,
		signer_provider: &'a SP, counterparty_node_id: PublicKey, their_features: &'a InitFeatures,
		user_id: u128, config: &'a UserConfig, current_chain_height: u32, logger: &'a L,
		is_0conf: bool, our_funding_satoshis: u64, counterparty_pubkeys: ChannelPublicKeys,
		channel_type: ChannelTypeFeatures, holder_selected_channel_reserve_satoshis: u64,
		msg_channel_reserve_satoshis: u64, msg_push_msat: u64,
		open_channel_fields: msgs::CommonOpenChannelFields,
		consignment_endpoint: Option<RgbTransport>, ldk_data_dir: PathBuf,
	) -> Result<ChannelContext<SP>, ChannelError>
	where
		ES::Target: EntropySource,
		F::Target: FeeEstimator,
		L::Target: Logger,
		SP::Target: SignerProvider,
	{
		let logger = WithContext::from(
			logger,
			Some(counterparty_node_id),
			Some(open_channel_fields.temporary_channel_id),
			None,
		);
		let announce_for_forwarding =
			if (open_channel_fields.channel_flags & 1) == 1 { true } else { false };

		let channel_value_satoshis =
			our_funding_satoshis.saturating_add(open_channel_fields.funding_satoshis);

		let channel_keys_id =
			signer_provider.generate_channel_keys_id(true, channel_value_satoshis, user_id);
		let holder_signer =
			signer_provider.derive_channel_signer(channel_value_satoshis, channel_keys_id);
		let pubkeys = holder_signer.pubkeys().clone();

		if config.channel_handshake_config.our_to_self_delay < BREAKDOWN_TIMEOUT {
			return Err(ChannelError::close(format!("Configured with an unreasonable our_to_self_delay ({}) putting user funds at risks. It must be greater than {}", config.channel_handshake_config.our_to_self_delay, BREAKDOWN_TIMEOUT)));
		}

		// Check sanity of message fields:
		if channel_value_satoshis > config.channel_handshake_limits.max_funding_satoshis {
			return Err(ChannelError::close(format!(
				"Per our config, funding must be at most {}. It was {}. Peer contribution: {}. Our contribution: {}",
				config.channel_handshake_limits.max_funding_satoshis, channel_value_satoshis,
				open_channel_fields.funding_satoshis, our_funding_satoshis)));
		}
		if channel_value_satoshis >= TOTAL_BITCOIN_SUPPLY_SATOSHIS {
			return Err(ChannelError::close(format!(
				"Funding must be smaller than the total bitcoin supply. It was {}",
				channel_value_satoshis
			)));
		}
		if msg_channel_reserve_satoshis > channel_value_satoshis {
			return Err(ChannelError::close(format!("Bogus channel_reserve_satoshis ({}). Must be no greater than channel_value_satoshis: {}", msg_channel_reserve_satoshis, channel_value_satoshis)));
		}
		let full_channel_value_msat =
			(channel_value_satoshis - msg_channel_reserve_satoshis) * 1000;
		if msg_push_msat > full_channel_value_msat {
			return Err(ChannelError::close(format!(
				"push_msat {} was larger than channel amount minus reserve ({})",
				msg_push_msat, full_channel_value_msat
			)));
		}
		if open_channel_fields.dust_limit_satoshis > channel_value_satoshis {
			return Err(ChannelError::close(format!("dust_limit_satoshis {} was larger than channel_value_satoshis {}. Peer never wants payout outputs?", open_channel_fields.dust_limit_satoshis, channel_value_satoshis)));
		}
		if open_channel_fields.htlc_minimum_msat >= full_channel_value_msat {
			return Err(ChannelError::close(format!(
				"Minimum htlc value ({}) was larger than full channel value ({})",
				open_channel_fields.htlc_minimum_msat, full_channel_value_msat
			)));
		}
		Channel::<SP>::check_remote_fee(
			&channel_type,
			fee_estimator,
			open_channel_fields.commitment_feerate_sat_per_1000_weight,
			None,
			&&logger,
		)?;

		let max_counterparty_selected_contest_delay = u16::min(
			config.channel_handshake_limits.their_to_self_delay,
			MAX_LOCAL_BREAKDOWN_TIMEOUT,
		);
		if open_channel_fields.to_self_delay > max_counterparty_selected_contest_delay {
			return Err(ChannelError::close(format!("They wanted our payments to be delayed by a needlessly long period. Upper limit: {}. Actual: {}", max_counterparty_selected_contest_delay, open_channel_fields.to_self_delay)));
		}
		if open_channel_fields.max_accepted_htlcs < 1 {
			return Err(ChannelError::close(
				"0 max_accepted_htlcs makes for a useless channel".to_owned(),
			));
		}
		if open_channel_fields.max_accepted_htlcs > MAX_HTLCS {
			return Err(ChannelError::close(format!(
				"max_accepted_htlcs was {}. It must not be larger than {}",
				open_channel_fields.max_accepted_htlcs, MAX_HTLCS
			)));
		}

		// Now check against optional parameters as set by config...
		if channel_value_satoshis < config.channel_handshake_limits.min_funding_satoshis {
			return Err(ChannelError::close(format!(
				"Funding satoshis ({}) is less than the user specified limit ({})",
				channel_value_satoshis, config.channel_handshake_limits.min_funding_satoshis
			)));
		}
		if open_channel_fields.htlc_minimum_msat
			> config.channel_handshake_limits.max_htlc_minimum_msat
		{
			return Err(ChannelError::close(format!(
				"htlc_minimum_msat ({}) is higher than the user specified limit ({})",
				open_channel_fields.htlc_minimum_msat,
				config.channel_handshake_limits.max_htlc_minimum_msat
			)));
		}
		if open_channel_fields.max_htlc_value_in_flight_msat
			< config.channel_handshake_limits.min_max_htlc_value_in_flight_msat
		{
			return Err(ChannelError::close(format!(
				"max_htlc_value_in_flight_msat ({}) is less than the user specified limit ({})",
				open_channel_fields.max_htlc_value_in_flight_msat,
				config.channel_handshake_limits.min_max_htlc_value_in_flight_msat
			)));
		}
		if msg_channel_reserve_satoshis
			> config.channel_handshake_limits.max_channel_reserve_satoshis
		{
			return Err(ChannelError::close(format!(
				"channel_reserve_satoshis ({}) is higher than the user specified limit ({})",
				msg_channel_reserve_satoshis,
				config.channel_handshake_limits.max_channel_reserve_satoshis
			)));
		}
		if open_channel_fields.max_accepted_htlcs
			< config.channel_handshake_limits.min_max_accepted_htlcs
		{
			return Err(ChannelError::close(format!(
				"max_accepted_htlcs ({}) is less than the user specified limit ({})",
				open_channel_fields.max_accepted_htlcs,
				config.channel_handshake_limits.min_max_accepted_htlcs
			)));
		}
		if open_channel_fields.dust_limit_satoshis < MIN_CHAN_DUST_LIMIT_SATOSHIS {
			return Err(ChannelError::close(format!(
				"dust_limit_satoshis ({}) is less than the implementation limit ({})",
				open_channel_fields.dust_limit_satoshis, MIN_CHAN_DUST_LIMIT_SATOSHIS
			)));
		}
		if open_channel_fields.dust_limit_satoshis > MAX_CHAN_DUST_LIMIT_SATOSHIS {
			return Err(ChannelError::close(format!(
				"dust_limit_satoshis ({}) is greater than the implementation limit ({})",
				open_channel_fields.dust_limit_satoshis, MAX_CHAN_DUST_LIMIT_SATOSHIS
			)));
		}

		// Convert things into internal flags and prep our state:

		if config.channel_handshake_limits.force_announced_channel_preference {
			if config.channel_handshake_config.announce_for_forwarding != announce_for_forwarding {
				return Err(ChannelError::close("Peer tried to open channel but their announcement preference is different from ours".to_owned()));
			}
		}

		if holder_selected_channel_reserve_satoshis < MIN_CHAN_DUST_LIMIT_SATOSHIS {
			// Protocol level safety check in place, although it should never happen because
			// of `MIN_THEIR_CHAN_RESERVE_SATOSHIS`
			return Err(ChannelError::close(format!("Suitable channel reserve not found. remote_channel_reserve was ({}). dust_limit_satoshis is ({}).", holder_selected_channel_reserve_satoshis, MIN_CHAN_DUST_LIMIT_SATOSHIS)));
		}
		if holder_selected_channel_reserve_satoshis * 1000 >= full_channel_value_msat {
			return Err(ChannelError::close(format!("Suitable channel reserve not found. remote_channel_reserve was ({})msats. Channel value is ({} - {})msats.", holder_selected_channel_reserve_satoshis * 1000, full_channel_value_msat, msg_push_msat)));
		}
		if msg_channel_reserve_satoshis < MIN_CHAN_DUST_LIMIT_SATOSHIS {
			log_debug!(logger, "channel_reserve_satoshis ({}) is smaller than our dust limit ({}). We can broadcast stale states without any risk, implying this channel is very insecure for our counterparty.",
				msg_channel_reserve_satoshis, MIN_CHAN_DUST_LIMIT_SATOSHIS);
		}
		if holder_selected_channel_reserve_satoshis < open_channel_fields.dust_limit_satoshis {
			return Err(ChannelError::close(format!("Dust limit ({}) too high for the channel reserve we require the remote to keep ({})", open_channel_fields.dust_limit_satoshis, holder_selected_channel_reserve_satoshis)));
		}

		// check if the funder's amount for the initial commitment tx is sufficient
		// for full fee payment plus a few HTLCs to ensure the channel will be useful.
		let anchor_outputs_value = if channel_type.supports_anchors_zero_fee_htlc_tx() {
			ANCHOR_OUTPUT_VALUE_SATOSHI * 2
		} else {
			0
		};
		let funders_amount_msat = open_channel_fields.funding_satoshis * 1000 - msg_push_msat;
		let commitment_tx_fee = commit_tx_fee_sat(
			open_channel_fields.commitment_feerate_sat_per_1000_weight,
			MIN_AFFORDABLE_HTLC_COUNT,
			&channel_type,
		);
		if (funders_amount_msat / 1000).saturating_sub(anchor_outputs_value) < commitment_tx_fee {
			return Err(ChannelError::close(format!("Funding amount ({} sats) can't even pay fee for initial commitment transaction fee of {} sats.", (funders_amount_msat / 1000).saturating_sub(anchor_outputs_value), commitment_tx_fee)));
		}

		let to_remote_satoshis =
			funders_amount_msat / 1000 - commitment_tx_fee - anchor_outputs_value;
		// While it's reasonable for us to not meet the channel reserve initially (if they don't
		// want to push much to us), our counterparty should always have more than our reserve.
		if to_remote_satoshis < holder_selected_channel_reserve_satoshis {
			return Err(ChannelError::close(
				"Insufficient funding amount for initial reserve".to_owned(),
			));
		}

		let counterparty_shutdown_scriptpubkey = if their_features
			.supports_upfront_shutdown_script()
		{
			match &open_channel_fields.shutdown_scriptpubkey {
				&Some(ref script) => {
					// Peer is signaling upfront_shutdown and has opt-out with a 0-length script. We don't enforce anything
					if script.len() == 0 {
						None
					} else {
						if !script::is_bolt2_compliant(&script, their_features) {
							return Err(ChannelError::close(format!("Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: {}", script)));
						}
						Some(script.clone())
					}
				},
				// Peer is signaling upfront shutdown but don't opt-out with correct mechanism (a.k.a 0-length script). Peer looks buggy, we fail the channel
				&None => {
					return Err(ChannelError::close("Peer is signaling upfront_shutdown but we don't get any script. Use 0-length script to opt-out".to_owned()));
				},
			}
		} else {
			None
		};

		let shutdown_scriptpubkey =
			if config.channel_handshake_config.commit_upfront_shutdown_pubkey {
				match signer_provider.get_shutdown_scriptpubkey() {
					Ok(scriptpubkey) => Some(scriptpubkey),
					Err(_) => {
						return Err(ChannelError::close(
							"Failed to get upfront shutdown scriptpubkey".to_owned(),
						))
					},
				}
			} else {
				None
			};

		if let Some(shutdown_scriptpubkey) = &shutdown_scriptpubkey {
			if !shutdown_scriptpubkey.is_compatible(&their_features) {
				return Err(ChannelError::close(format!(
					"Provided a scriptpubkey format not accepted by peer: {}",
					shutdown_scriptpubkey
				)));
			}
		}

		let destination_script = match signer_provider.get_destination_script(channel_keys_id) {
			Ok(script) => script,
			Err(_) => {
				return Err(ChannelError::close("Failed to get destination script".to_owned()))
			},
		};

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		let minimum_depth = if is_0conf {
			Some(0)
		} else {
			Some(cmp::max(config.channel_handshake_config.minimum_depth, 1))
		};

		let value_to_self_msat = our_funding_satoshis * 1000 + msg_push_msat;

		let holder_signer = ChannelSignerType::Ecdsa(holder_signer);
		let holder_commitment_point = HolderCommitmentPoint::new(&holder_signer, &secp_ctx);

		// TODO(dual_funding): Checks for `funding_feerate_sat_per_1000_weight`?

		let channel_context = ChannelContext {
			user_id,

			config: LegacyChannelConfig {
				options: config.channel_config.clone(),
				announce_for_forwarding,
				commit_upfront_shutdown_pubkey: config
					.channel_handshake_config
					.commit_upfront_shutdown_pubkey,
			},

			prev_config: None,

			inbound_handshake_limits_override: None,

			temporary_channel_id: Some(open_channel_fields.temporary_channel_id),
			channel_id: open_channel_fields.temporary_channel_id,
			channel_state: ChannelState::NegotiatingFunding(
				NegotiatingFundingFlags::OUR_INIT_SENT | NegotiatingFundingFlags::THEIR_INIT_SENT,
			),
			announcement_sigs_state: AnnouncementSigsState::NotSent,
			secp_ctx,

			latest_monitor_update_id: 0,

			holder_signer,
			shutdown_scriptpubkey,
			destination_script,

			holder_commitment_point,
			cur_counterparty_commitment_transaction_number: INITIAL_COMMITMENT_NUMBER,
			value_to_self_msat,

			pending_inbound_htlcs: Vec::new(),
			pending_outbound_htlcs: Vec::new(),
			holding_cell_htlc_updates: Vec::new(),
			pending_update_fee: None,
			holding_cell_update_fee: None,
			next_holder_htlc_id: 0,
			next_counterparty_htlc_id: 0,
			update_time_counter: 1,

			resend_order: RAACommitmentOrder::CommitmentFirst,

			monitor_pending_channel_ready: false,
			monitor_pending_revoke_and_ack: false,
			monitor_pending_commitment_signed: false,
			monitor_pending_forwards: Vec::new(),
			monitor_pending_failures: Vec::new(),
			monitor_pending_finalized_fulfills: Vec::new(),
			monitor_pending_update_adds: Vec::new(),

			signer_pending_revoke_and_ack: false,
			signer_pending_commitment_update: false,
			signer_pending_funding: false,
			signer_pending_closing: false,

			#[cfg(debug_assertions)]
			holder_max_commitment_tx_output: Mutex::new((
				value_to_self_msat,
				(channel_value_satoshis * 1000 - msg_push_msat).saturating_sub(value_to_self_msat),
			)),
			#[cfg(debug_assertions)]
			counterparty_max_commitment_tx_output: Mutex::new((
				value_to_self_msat,
				(channel_value_satoshis * 1000 - msg_push_msat).saturating_sub(value_to_self_msat),
			)),

			last_sent_closing_fee: None,
			last_received_closing_sig: None,
			pending_counterparty_closing_signed: None,
			expecting_peer_commitment_signed: false,
			closing_fee_limits: None,
			target_closing_feerate_sats_per_kw: None,

			funding_tx_confirmed_in: None,
			funding_tx_confirmation_height: 0,
			short_channel_id: None,
			channel_creation_height: current_chain_height,

			feerate_per_kw: open_channel_fields.commitment_feerate_sat_per_1000_weight,
			channel_value_satoshis,
			counterparty_dust_limit_satoshis: open_channel_fields.dust_limit_satoshis,
			holder_dust_limit_satoshis: MIN_CHAN_DUST_LIMIT_SATOSHIS,
			counterparty_max_htlc_value_in_flight_msat: cmp::min(
				open_channel_fields.max_htlc_value_in_flight_msat,
				channel_value_satoshis * 1000,
			),
			holder_max_htlc_value_in_flight_msat: get_holder_max_htlc_value_in_flight_msat(
				channel_value_satoshis,
				&config.channel_handshake_config,
			),
			counterparty_selected_channel_reserve_satoshis: Some(msg_channel_reserve_satoshis),
			holder_selected_channel_reserve_satoshis,
			counterparty_htlc_minimum_msat: open_channel_fields.htlc_minimum_msat,
			holder_htlc_minimum_msat: if config.channel_handshake_config.our_htlc_minimum_msat == 0
			{
				1
			} else {
				config.channel_handshake_config.our_htlc_minimum_msat
			},
			counterparty_max_accepted_htlcs: open_channel_fields.max_accepted_htlcs,
			holder_max_accepted_htlcs: cmp::min(
				config.channel_handshake_config.our_max_accepted_htlcs,
				MAX_HTLCS,
			),
			minimum_depth,

			counterparty_forwarding_info: None,

			channel_transaction_parameters: ChannelTransactionParameters {
				holder_pubkeys: pubkeys,
				holder_selected_contest_delay: config.channel_handshake_config.our_to_self_delay,
				is_outbound_from_holder: false,
				counterparty_parameters: Some(CounterpartyChannelTransactionParameters {
					selected_contest_delay: open_channel_fields.to_self_delay,
					pubkeys: counterparty_pubkeys,
				}),
				funding_outpoint: None,
				channel_type_features: channel_type.clone(),
			},
			funding_transaction: None,
			is_batch_funding: None,

			counterparty_cur_commitment_point: Some(open_channel_fields.first_per_commitment_point),
			counterparty_prev_commitment_point: None,
			counterparty_node_id,

			counterparty_shutdown_scriptpubkey,

			commitment_secrets: CounterpartyCommitmentSecrets::new(),

			channel_update_status: ChannelUpdateStatus::Enabled,
			closing_signed_in_flight: false,

			announcement_sigs: None,

			#[cfg(any(test, fuzzing))]
			next_local_commitment_tx_fee_info_cached: Mutex::new(None),
			#[cfg(any(test, fuzzing))]
			next_remote_commitment_tx_fee_info_cached: Mutex::new(None),

			workaround_lnd_bug_4006: None,
			sent_message_awaiting_response: None,

			latest_inbound_scid_alias: None,
			outbound_scid_alias: 0,

			channel_pending_event_emitted: false,
			funding_tx_broadcast_safe_event_emitted: false,
			channel_ready_event_emitted: false,

			#[cfg(any(test, fuzzing))]
			historical_inbound_htlc_fulfills: new_hash_set(),

			channel_type,
			channel_keys_id,

			local_initiated_shutdown: None,

			blocked_monitor_updates: Vec::new(),
			consignment_endpoint,
			ldk_data_dir,

			is_manual_broadcast: false,
		};

		Ok(channel_context)
	}

	fn new_for_outbound_channel<'a, ES: Deref, F: Deref, L: Deref>(
		fee_estimator: &'a LowerBoundedFeeEstimator<F>, entropy_source: &'a ES,
		signer_provider: &'a SP, counterparty_node_id: PublicKey, their_features: &'a InitFeatures,
		funding_satoshis: u64, push_msat: u64, user_id: u128, config: &'a UserConfig,
		current_chain_height: u32, outbound_scid_alias: u64,
		temporary_channel_id: Option<ChannelId>, holder_selected_channel_reserve_satoshis: u64,
		channel_keys_id: [u8; 32], holder_signer: <SP::Target as SignerProvider>::EcdsaSigner,
		pubkeys: ChannelPublicKeys, consignment_endpoint: Option<RgbTransport>,
		ldk_data_dir: PathBuf, _logger: L,
	) -> Result<ChannelContext<SP>, APIError>
	where
		ES::Target: EntropySource,
		F::Target: FeeEstimator,
		SP::Target: SignerProvider,
		L::Target: Logger,
	{
		// This will be updated with the counterparty contribution if this is a dual-funded channel
		let channel_value_satoshis = funding_satoshis;

		let holder_selected_contest_delay = config.channel_handshake_config.our_to_self_delay;

		if !their_features.supports_wumbo()
			&& channel_value_satoshis > MAX_FUNDING_SATOSHIS_NO_WUMBO
		{
			return Err(APIError::APIMisuseError {
				err: format!(
					"funding_value must not exceed {}, it was {}",
					MAX_FUNDING_SATOSHIS_NO_WUMBO, channel_value_satoshis
				),
			});
		}
		if channel_value_satoshis >= TOTAL_BITCOIN_SUPPLY_SATOSHIS {
			return Err(APIError::APIMisuseError {
				err: format!(
					"funding_value must be smaller than the total bitcoin supply, it was {}",
					channel_value_satoshis
				),
			});
		}
		let channel_value_msat = channel_value_satoshis * 1000;
		if push_msat > channel_value_msat {
			return Err(APIError::APIMisuseError {
				err: format!(
					"Push value ({}) was larger than channel_value ({})",
					push_msat, channel_value_msat
				),
			});
		}
		if holder_selected_contest_delay < BREAKDOWN_TIMEOUT {
			return Err(APIError::APIMisuseError {err: format!("Configured with an unreasonable our_to_self_delay ({}) putting user funds at risks", holder_selected_contest_delay)});
		}

		let channel_type = get_initial_channel_type(&config, their_features);
		debug_assert!(!channel_type.supports_any_optional_bits());
		debug_assert!(!channel_type
			.requires_unknown_bits_from(&channelmanager::provided_channel_type_features(&config)));

		let (commitment_conf_target, anchor_outputs_value_msat) =
			if channel_type.supports_anchors_zero_fee_htlc_tx() {
				(ConfirmationTarget::AnchorChannelFee, ANCHOR_OUTPUT_VALUE_SATOSHI * 2 * 1000)
			} else {
				(ConfirmationTarget::NonAnchorChannelFee, 0)
			};
		let commitment_feerate = fee_estimator.bounded_sat_per_1000_weight(commitment_conf_target);

		let value_to_self_msat = channel_value_satoshis * 1000 - push_msat;
		let commitment_tx_fee =
			commit_tx_fee_sat(commitment_feerate, MIN_AFFORDABLE_HTLC_COUNT, &channel_type) * 1000;
		if value_to_self_msat.saturating_sub(anchor_outputs_value_msat) < commitment_tx_fee {
			return Err(APIError::APIMisuseError{ err: format!("Funding amount ({}) can't even pay fee for initial commitment transaction fee of {}.", value_to_self_msat / 1000, commitment_tx_fee / 1000) });
		}

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		let shutdown_scriptpubkey =
			if config.channel_handshake_config.commit_upfront_shutdown_pubkey {
				match signer_provider.get_shutdown_scriptpubkey() {
					Ok(scriptpubkey) => Some(scriptpubkey),
					Err(_) => {
						return Err(APIError::ChannelUnavailable {
							err: "Failed to get shutdown scriptpubkey".to_owned(),
						})
					},
				}
			} else {
				None
			};

		if let Some(shutdown_scriptpubkey) = &shutdown_scriptpubkey {
			if !shutdown_scriptpubkey.is_compatible(&their_features) {
				return Err(APIError::IncompatibleShutdownScript {
					script: shutdown_scriptpubkey.clone(),
				});
			}
		}

		let destination_script = match signer_provider.get_destination_script(channel_keys_id) {
			Ok(script) => script,
			Err(_) => {
				return Err(APIError::ChannelUnavailable {
					err: "Failed to get destination script".to_owned(),
				})
			},
		};

		let temporary_channel_id = temporary_channel_id
			.unwrap_or_else(|| ChannelId::temporary_from_entropy_source(entropy_source));

		let holder_signer = ChannelSignerType::Ecdsa(holder_signer);
		let holder_commitment_point = HolderCommitmentPoint::new(&holder_signer, &secp_ctx);

		Ok(Self {
			user_id,

			config: LegacyChannelConfig {
				options: config.channel_config.clone(),
				announce_for_forwarding: config.channel_handshake_config.announce_for_forwarding,
				commit_upfront_shutdown_pubkey: config
					.channel_handshake_config
					.commit_upfront_shutdown_pubkey,
			},

			prev_config: None,

			inbound_handshake_limits_override: Some(config.channel_handshake_limits.clone()),

			channel_id: temporary_channel_id,
			temporary_channel_id: Some(temporary_channel_id),
			channel_state: ChannelState::NegotiatingFunding(NegotiatingFundingFlags::OUR_INIT_SENT),
			announcement_sigs_state: AnnouncementSigsState::NotSent,
			secp_ctx,
			// We'll add our counterparty's `funding_satoshis` when we receive `accept_channel2`.
			channel_value_satoshis,

			latest_monitor_update_id: 0,

			holder_signer,
			shutdown_scriptpubkey,
			destination_script,

			holder_commitment_point,
			cur_counterparty_commitment_transaction_number: INITIAL_COMMITMENT_NUMBER,
			value_to_self_msat,

			pending_inbound_htlcs: Vec::new(),
			pending_outbound_htlcs: Vec::new(),
			holding_cell_htlc_updates: Vec::new(),
			pending_update_fee: None,
			holding_cell_update_fee: None,
			next_holder_htlc_id: 0,
			next_counterparty_htlc_id: 0,
			update_time_counter: 1,

			resend_order: RAACommitmentOrder::CommitmentFirst,

			monitor_pending_channel_ready: false,
			monitor_pending_revoke_and_ack: false,
			monitor_pending_commitment_signed: false,
			monitor_pending_forwards: Vec::new(),
			monitor_pending_failures: Vec::new(),
			monitor_pending_finalized_fulfills: Vec::new(),
			monitor_pending_update_adds: Vec::new(),

			signer_pending_revoke_and_ack: false,
			signer_pending_commitment_update: false,
			signer_pending_funding: false,
			signer_pending_closing: false,

			// We'll add our counterparty's `funding_satoshis` to these max commitment output assertions
			// when we receive `accept_channel2`.
			#[cfg(debug_assertions)]
			holder_max_commitment_tx_output: Mutex::new((
				channel_value_satoshis * 1000 - push_msat,
				push_msat,
			)),
			#[cfg(debug_assertions)]
			counterparty_max_commitment_tx_output: Mutex::new((
				channel_value_satoshis * 1000 - push_msat,
				push_msat,
			)),

			last_sent_closing_fee: None,
			last_received_closing_sig: None,
			pending_counterparty_closing_signed: None,
			expecting_peer_commitment_signed: false,
			closing_fee_limits: None,
			target_closing_feerate_sats_per_kw: None,

			funding_tx_confirmed_in: None,
			funding_tx_confirmation_height: 0,
			short_channel_id: None,
			channel_creation_height: current_chain_height,

			feerate_per_kw: commitment_feerate,
			counterparty_dust_limit_satoshis: 0,
			holder_dust_limit_satoshis: MIN_CHAN_DUST_LIMIT_SATOSHIS,
			counterparty_max_htlc_value_in_flight_msat: 0,
			// We'll adjust this to include our counterparty's `funding_satoshis` when we
			// receive `accept_channel2`.
			holder_max_htlc_value_in_flight_msat: get_holder_max_htlc_value_in_flight_msat(
				channel_value_satoshis,
				&config.channel_handshake_config,
			),
			counterparty_selected_channel_reserve_satoshis: None, // Filled in in accept_channel
			holder_selected_channel_reserve_satoshis,
			counterparty_htlc_minimum_msat: 0,
			holder_htlc_minimum_msat: if config.channel_handshake_config.our_htlc_minimum_msat == 0
			{
				1
			} else {
				config.channel_handshake_config.our_htlc_minimum_msat
			},
			counterparty_max_accepted_htlcs: 0,
			holder_max_accepted_htlcs: cmp::min(
				config.channel_handshake_config.our_max_accepted_htlcs,
				MAX_HTLCS,
			),
			minimum_depth: None, // Filled in in accept_channel

			counterparty_forwarding_info: None,

			channel_transaction_parameters: ChannelTransactionParameters {
				holder_pubkeys: pubkeys,
				holder_selected_contest_delay: config.channel_handshake_config.our_to_self_delay,
				is_outbound_from_holder: true,
				counterparty_parameters: None,
				funding_outpoint: None,
				channel_type_features: channel_type.clone(),
			},
			funding_transaction: None,
			is_batch_funding: None,

			counterparty_cur_commitment_point: None,
			counterparty_prev_commitment_point: None,
			counterparty_node_id,

			counterparty_shutdown_scriptpubkey: None,

			commitment_secrets: CounterpartyCommitmentSecrets::new(),

			channel_update_status: ChannelUpdateStatus::Enabled,
			closing_signed_in_flight: false,

			announcement_sigs: None,

			#[cfg(any(test, fuzzing))]
			next_local_commitment_tx_fee_info_cached: Mutex::new(None),
			#[cfg(any(test, fuzzing))]
			next_remote_commitment_tx_fee_info_cached: Mutex::new(None),

			workaround_lnd_bug_4006: None,
			sent_message_awaiting_response: None,

			latest_inbound_scid_alias: None,
			outbound_scid_alias,

			channel_pending_event_emitted: false,
			funding_tx_broadcast_safe_event_emitted: false,
			channel_ready_event_emitted: false,

			#[cfg(any(test, fuzzing))]
			historical_inbound_htlc_fulfills: new_hash_set(),

			channel_type,
			channel_keys_id,

			blocked_monitor_updates: Vec::new(),
			local_initiated_shutdown: None,
			consignment_endpoint,
			ldk_data_dir,
			consignment_endpoint,
			ldk_data_dir,

			is_manual_broadcast: false,
		})
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_update_time_counter(&self) -> u32 {
		self.update_time_counter
	}

	pub fn get_latest_monitor_update_id(&self) -> u64 {
		self.latest_monitor_update_id
	}

	pub fn should_announce(&self) -> bool {
		self.config.announce_for_forwarding
	}

	pub fn is_colored(&self) -> bool {
		self.consignment_endpoint.is_some()
	}
	pub fn is_outbound(&self) -> bool {
		self.channel_transaction_parameters.is_outbound_from_holder
	}

	/// Gets the fee we'd want to charge for adding an HTLC output to this Channel
	/// Allowed in any state (including after shutdown)
	pub fn get_outbound_forwarding_fee_base_msat(&self) -> u32 {
		self.config.options.forwarding_fee_base_msat
	}

	/// Returns true if we've ever received a message from the remote end for this Channel
	pub fn have_received_message(&self) -> bool {
		self.channel_state
			> ChannelState::NegotiatingFunding(NegotiatingFundingFlags::OUR_INIT_SENT)
	}

	/// Returns true if this channel is fully established and not known to be closing.
	/// Allowed in any state (including after shutdown)
	pub fn is_usable(&self) -> bool {
		matches!(self.channel_state, ChannelState::ChannelReady(_))
			&& !self.channel_state.is_local_shutdown_sent()
			&& !self.channel_state.is_remote_shutdown_sent()
			&& !self.monitor_pending_channel_ready
	}

	/// shutdown state returns the state of the channel in its various stages of shutdown
	pub fn shutdown_state(&self) -> ChannelShutdownState {
		match self.channel_state {
			ChannelState::AwaitingChannelReady(_) | ChannelState::ChannelReady(_) => {
				if self.channel_state.is_local_shutdown_sent()
					&& !self.channel_state.is_remote_shutdown_sent()
				{
					ChannelShutdownState::ShutdownInitiated
				} else if (self.channel_state.is_local_shutdown_sent()
					|| self.channel_state.is_remote_shutdown_sent())
					&& !self.closing_negotiation_ready()
				{
					ChannelShutdownState::ResolvingHTLCs
				} else if (self.channel_state.is_local_shutdown_sent()
					|| self.channel_state.is_remote_shutdown_sent())
					&& self.closing_negotiation_ready()
				{
					ChannelShutdownState::NegotiatingClosingFee
				} else {
					ChannelShutdownState::NotShuttingDown
				}
			},
			ChannelState::ShutdownComplete => ChannelShutdownState::ShutdownComplete,
			_ => ChannelShutdownState::NotShuttingDown,
		}
	}

	fn closing_negotiation_ready(&self) -> bool {
		let is_ready_to_close = match self.channel_state {
			ChannelState::AwaitingChannelReady(flags) => {
				flags & FundedStateFlags::ALL
					== FundedStateFlags::LOCAL_SHUTDOWN_SENT
						| FundedStateFlags::REMOTE_SHUTDOWN_SENT
			},
			ChannelState::ChannelReady(flags) => {
				flags
					== FundedStateFlags::LOCAL_SHUTDOWN_SENT
						| FundedStateFlags::REMOTE_SHUTDOWN_SENT
			},
			_ => false,
		};
		self.pending_inbound_htlcs.is_empty()
			&& self.pending_outbound_htlcs.is_empty()
			&& self.pending_update_fee.is_none()
			&& is_ready_to_close
	}

	/// Returns true if this channel is currently available for use. This is a superset of
	/// is_usable() and considers things like the channel being temporarily disabled.
	/// Allowed in any state (including after shutdown)
	pub fn is_live(&self) -> bool {
		self.is_usable() && !self.channel_state.is_peer_disconnected()
	}

	// Public utilities:

	pub fn channel_id(&self) -> ChannelId {
		self.channel_id
	}

	// Return the `temporary_channel_id` used during channel establishment.
	//
	// Will return `None` for channels created prior to LDK version 0.0.115.
	pub fn temporary_channel_id(&self) -> Option<ChannelId> {
		self.temporary_channel_id
	}

	pub fn minimum_depth(&self) -> Option<u32> {
		self.minimum_depth
	}

	/// Gets the "user_id" value passed into the construction of this channel. It has no special
	/// meaning and exists only to allow users to have a persistent identifier of a channel.
	pub fn get_user_id(&self) -> u128 {
		self.user_id
	}

	/// Gets the channel's type
	pub fn get_channel_type(&self) -> &ChannelTypeFeatures {
		&self.channel_type
	}

	/// Gets the channel's `short_channel_id`.
	///
	/// Will return `None` if the channel hasn't been confirmed yet.
	pub fn get_short_channel_id(&self) -> Option<u64> {
		self.short_channel_id
	}

	/// Allowed in any state (including after shutdown)
	pub fn latest_inbound_scid_alias(&self) -> Option<u64> {
		self.latest_inbound_scid_alias
	}

	/// Allowed in any state (including after shutdown)
	pub fn outbound_scid_alias(&self) -> u64 {
		self.outbound_scid_alias
	}

	/// Returns the holder signer for this channel.
	#[cfg(test)]
	pub fn get_mut_signer(&mut self) -> &mut ChannelSignerType<SP> {
		return &mut self.holder_signer;
	}

	/// Only allowed immediately after deserialization if get_outbound_scid_alias returns 0,
	/// indicating we were written by LDK prior to 0.0.106 which did not set outbound SCID aliases
	/// or prior to any channel actions during `Channel` initialization.
	pub fn set_outbound_scid_alias(&mut self, outbound_scid_alias: u64) {
		debug_assert_eq!(self.outbound_scid_alias, 0);
		self.outbound_scid_alias = outbound_scid_alias;
	}

	/// Returns the funding_txo we either got from our peer, or were given by
	/// get_funding_created.
	pub fn get_funding_txo(&self) -> Option<OutPoint> {
		self.channel_transaction_parameters.funding_outpoint
	}

	/// Returns the height in which our funding transaction was confirmed.
	pub fn get_funding_tx_confirmation_height(&self) -> Option<u32> {
		let conf_height = self.funding_tx_confirmation_height;
		if conf_height > 0 {
			Some(conf_height)
		} else {
			None
		}
	}

	/// Performs checks against necessary constraints after receiving either an `accept_channel` or
	/// `accept_channel2` message.
	pub fn do_accept_channel_checks(
		&mut self, default_limits: &ChannelHandshakeLimits, their_features: &InitFeatures,
		common_fields: &msgs::CommonAcceptChannelFields, channel_reserve_satoshis: u64,
	) -> Result<(), ChannelError> {
		let peer_limits = if let Some(ref limits) = self.inbound_handshake_limits_override {
			limits
		} else {
			default_limits
		};

		// Check sanity of message fields:
		if !self.is_outbound() {
			return Err(ChannelError::close(
				"Got an accept_channel message from an inbound peer".to_owned(),
			));
		}
		if !matches!(self.channel_state, ChannelState::NegotiatingFunding(flags) if flags == NegotiatingFundingFlags::OUR_INIT_SENT)
		{
			return Err(ChannelError::close(
				"Got an accept_channel message at a strange time".to_owned(),
			));
		}
		if common_fields.dust_limit_satoshis > 21000000 * 100000000 {
			return Err(ChannelError::close(format!(
				"Peer never wants payout outputs? dust_limit_satoshis was {}",
				common_fields.dust_limit_satoshis
			)));
		}
		if channel_reserve_satoshis > self.channel_value_satoshis {
			return Err(ChannelError::close(format!(
				"Bogus channel_reserve_satoshis ({}). Must not be greater than ({})",
				channel_reserve_satoshis, self.channel_value_satoshis
			)));
		}
		if common_fields.dust_limit_satoshis > self.holder_selected_channel_reserve_satoshis {
			return Err(ChannelError::close(format!(
				"Dust limit ({}) is bigger than our channel reserve ({})",
				common_fields.dust_limit_satoshis, self.holder_selected_channel_reserve_satoshis
			)));
		}
		if channel_reserve_satoshis
			> self.channel_value_satoshis - self.holder_selected_channel_reserve_satoshis
		{
			return Err(ChannelError::close(format!("Bogus channel_reserve_satoshis ({}). Must not be greater than channel value minus our reserve ({})",
				channel_reserve_satoshis, self.channel_value_satoshis - self.holder_selected_channel_reserve_satoshis)));
		}
		let full_channel_value_msat =
			(self.channel_value_satoshis - channel_reserve_satoshis) * 1000;
		if common_fields.htlc_minimum_msat >= full_channel_value_msat {
			return Err(ChannelError::close(format!(
				"Minimum htlc value ({}) is full channel value ({})",
				common_fields.htlc_minimum_msat, full_channel_value_msat
			)));
		}
		let max_delay_acceptable =
			u16::min(peer_limits.their_to_self_delay, MAX_LOCAL_BREAKDOWN_TIMEOUT);
		if common_fields.to_self_delay > max_delay_acceptable {
			return Err(ChannelError::close(format!("They wanted our payments to be delayed by a needlessly long period. Upper limit: {}. Actual: {}", max_delay_acceptable, common_fields.to_self_delay)));
		}
		if common_fields.max_accepted_htlcs < 1 {
			return Err(ChannelError::close(
				"0 max_accepted_htlcs makes for a useless channel".to_owned(),
			));
		}
		if common_fields.max_accepted_htlcs > MAX_HTLCS {
			return Err(ChannelError::close(format!(
				"max_accepted_htlcs was {}. It must not be larger than {}",
				common_fields.max_accepted_htlcs, MAX_HTLCS
			)));
		}

		// Now check against optional parameters as set by config...
		if common_fields.htlc_minimum_msat > peer_limits.max_htlc_minimum_msat {
			return Err(ChannelError::close(format!(
				"htlc_minimum_msat ({}) is higher than the user specified limit ({})",
				common_fields.htlc_minimum_msat, peer_limits.max_htlc_minimum_msat
			)));
		}
		if common_fields.max_htlc_value_in_flight_msat
			< peer_limits.min_max_htlc_value_in_flight_msat
		{
			return Err(ChannelError::close(format!(
				"max_htlc_value_in_flight_msat ({}) is less than the user specified limit ({})",
				common_fields.max_htlc_value_in_flight_msat,
				peer_limits.min_max_htlc_value_in_flight_msat
			)));
		}
		if channel_reserve_satoshis > peer_limits.max_channel_reserve_satoshis {
			return Err(ChannelError::close(format!(
				"channel_reserve_satoshis ({}) is higher than the user specified limit ({})",
				channel_reserve_satoshis, peer_limits.max_channel_reserve_satoshis
			)));
		}
		if common_fields.max_accepted_htlcs < peer_limits.min_max_accepted_htlcs {
			return Err(ChannelError::close(format!(
				"max_accepted_htlcs ({}) is less than the user specified limit ({})",
				common_fields.max_accepted_htlcs, peer_limits.min_max_accepted_htlcs
			)));
		}
		if common_fields.dust_limit_satoshis < MIN_CHAN_DUST_LIMIT_SATOSHIS {
			return Err(ChannelError::close(format!(
				"dust_limit_satoshis ({}) is less than the implementation limit ({})",
				common_fields.dust_limit_satoshis, MIN_CHAN_DUST_LIMIT_SATOSHIS
			)));
		}
		if common_fields.dust_limit_satoshis > MAX_CHAN_DUST_LIMIT_SATOSHIS {
			return Err(ChannelError::close(format!(
				"dust_limit_satoshis ({}) is greater than the implementation limit ({})",
				common_fields.dust_limit_satoshis, MAX_CHAN_DUST_LIMIT_SATOSHIS
			)));
		}
		if common_fields.minimum_depth > peer_limits.max_minimum_depth {
			return Err(ChannelError::close(format!("We consider the minimum depth to be unreasonably large. Expected minimum: ({}). Actual: ({})", peer_limits.max_minimum_depth, common_fields.minimum_depth)));
		}

		if let Some(ty) = &common_fields.channel_type {
			if *ty != self.channel_type {
				return Err(ChannelError::close(
					"Channel Type in accept_channel didn't match the one sent in open_channel."
						.to_owned(),
				));
			}
		} else if their_features.supports_channel_type() {
			// Assume they've accepted the channel type as they said they understand it.
		} else {
			let channel_type = ChannelTypeFeatures::from_init(&their_features);
			if channel_type != ChannelTypeFeatures::only_static_remote_key() {
				return Err(ChannelError::close(
					"Only static_remote_key is supported for non-negotiated channel types"
						.to_owned(),
				));
			}
			self.channel_type = channel_type.clone();
			self.channel_transaction_parameters.channel_type_features = channel_type;
		}

		let counterparty_shutdown_scriptpubkey = if their_features
			.supports_upfront_shutdown_script()
		{
			match &common_fields.shutdown_scriptpubkey {
				&Some(ref script) => {
					// Peer is signaling upfront_shutdown and has opt-out with a 0-length script. We don't enforce anything
					if script.len() == 0 {
						None
					} else {
						if !script::is_bolt2_compliant(&script, their_features) {
							return Err(ChannelError::close(format!("Peer is signaling upfront_shutdown but has provided an unacceptable scriptpubkey format: {}", script)));
						}
						Some(script.clone())
					}
				},
				// Peer is signaling upfront shutdown but don't opt-out with correct mechanism (a.k.a 0-length script). Peer looks buggy, we fail the channel
				&None => {
					return Err(ChannelError::close("Peer is signaling upfront_shutdown but we don't get any script. Use 0-length script to opt-out".to_owned()));
				},
			}
		} else {
			None
		};

		self.counterparty_dust_limit_satoshis = common_fields.dust_limit_satoshis;
		self.counterparty_max_htlc_value_in_flight_msat = cmp::min(
			common_fields.max_htlc_value_in_flight_msat,
			self.channel_value_satoshis * 1000,
		);
		self.counterparty_selected_channel_reserve_satoshis = Some(channel_reserve_satoshis);
		self.counterparty_htlc_minimum_msat = common_fields.htlc_minimum_msat;
		self.counterparty_max_accepted_htlcs = common_fields.max_accepted_htlcs;

		if peer_limits.trust_own_funding_0conf {
			self.minimum_depth = Some(common_fields.minimum_depth);
		} else {
			self.minimum_depth = Some(cmp::max(1, common_fields.minimum_depth));
		}

		let counterparty_pubkeys = ChannelPublicKeys {
			funding_pubkey: common_fields.funding_pubkey,
			revocation_basepoint: RevocationBasepoint::from(common_fields.revocation_basepoint),
			payment_point: common_fields.payment_basepoint,
			delayed_payment_basepoint: DelayedPaymentBasepoint::from(
				common_fields.delayed_payment_basepoint,
			),
			htlc_basepoint: HtlcBasepoint::from(common_fields.htlc_basepoint),
		};

		self.channel_transaction_parameters.counterparty_parameters =
			Some(CounterpartyChannelTransactionParameters {
				selected_contest_delay: common_fields.to_self_delay,
				pubkeys: counterparty_pubkeys,
			});

		self.counterparty_cur_commitment_point = Some(common_fields.first_per_commitment_point);
		self.counterparty_shutdown_scriptpubkey = counterparty_shutdown_scriptpubkey;

		self.channel_state = ChannelState::NegotiatingFunding(
			NegotiatingFundingFlags::OUR_INIT_SENT | NegotiatingFundingFlags::THEIR_INIT_SENT,
		);
		self.inbound_handshake_limits_override = None; // We're done enforcing limits on our peer's handshake now.

		Ok(())
	}

	/// Returns the block hash in which our funding transaction was confirmed.
	pub fn get_funding_tx_confirmed_in(&self) -> Option<BlockHash> {
		self.funding_tx_confirmed_in
	}

	/// Returns the current number of confirmations on the funding transaction.
	pub fn get_funding_tx_confirmations(&self, height: u32) -> u32 {
		if self.funding_tx_confirmation_height == 0 {
			// We either haven't seen any confirmation yet, or observed a reorg.
			return 0;
		}

		height.checked_sub(self.funding_tx_confirmation_height).map_or(0, |c| c + 1)
	}

	fn get_holder_selected_contest_delay(&self) -> u16 {
		self.channel_transaction_parameters.holder_selected_contest_delay
	}

	pub(crate) fn get_holder_pubkeys(&self) -> &ChannelPublicKeys {
		&self.channel_transaction_parameters.holder_pubkeys
	}

	pub fn get_counterparty_selected_contest_delay(&self) -> Option<u16> {
		self.channel_transaction_parameters
			.counterparty_parameters
			.as_ref()
			.map(|params| params.selected_contest_delay)
	}

	pub(crate) fn get_counterparty_pubkeys(&self) -> &ChannelPublicKeys {
		&self.channel_transaction_parameters.counterparty_parameters.as_ref().unwrap().pubkeys
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_counterparty_node_id(&self) -> PublicKey {
		self.counterparty_node_id
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_holder_htlc_minimum_msat(&self) -> u64 {
		self.holder_htlc_minimum_msat
	}

	/// Allowed in any state (including after shutdown), but will return none before TheirInitSent
	pub fn get_holder_htlc_maximum_msat(&self) -> Option<u64> {
		self.get_htlc_maximum_msat(self.holder_max_htlc_value_in_flight_msat)
	}
	/// Get the channel local RGB amount
	pub fn get_local_rgb_amount(&self) -> u64 {
		let info_file_path = get_rgb_channel_info_path(
			&self.channel_id.0.as_hex().to_string(),
			&self.ldk_data_dir,
			false,
		);
		if info_file_path.exists() {
			let rgb_info = parse_rgb_channel_info(&info_file_path);
			rgb_info.local_rgb_amount
		} else {
			0
		}
	}

	/// Get the channel remote RGB amount
	pub fn get_remote_rgb_amount(&self) -> u64 {
		let info_file_path = get_rgb_channel_info_path(
			&self.channel_id.0.as_hex().to_string(),
			&self.ldk_data_dir,
			false,
		);
		if info_file_path.exists() {
			let rgb_info = parse_rgb_channel_info(&info_file_path);
			rgb_info.remote_rgb_amount
		} else {
			0
		}
	}

	/// Get the channel RGB capacity
	pub fn get_rgb_capacity(&self) -> u64 {
		self.get_local_rgb_amount() + self.get_remote_rgb_amount()
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_announced_htlc_max_msat(&self) -> u64 {
		return cmp::min(
			// Upper bound by capacity. We make it a bit less than full capacity to prevent attempts
			// to use full capacity. This is an effort to reduce routing failures, because in many cases
			// channel might have been used to route very small values (either by honest users or as DoS).
			self.channel_value_satoshis * 1000 * 9 / 10,
			self.counterparty_max_htlc_value_in_flight_msat,
		);
	}

	/// Allowed in any state (including after shutdown)
	pub fn get_counterparty_htlc_minimum_msat(&self) -> u64 {
		self.counterparty_htlc_minimum_msat
	}

	/// Allowed in any state (including after shutdown), but will return none before TheirInitSent
	pub fn get_counterparty_htlc_maximum_msat(&self) -> Option<u64> {
		self.get_htlc_maximum_msat(self.counterparty_max_htlc_value_in_flight_msat)
	}

	fn get_htlc_maximum_msat(&self, party_max_htlc_value_in_flight_msat: u64) -> Option<u64> {
		self.counterparty_selected_channel_reserve_satoshis.map(|counterparty_reserve| {
			let holder_reserve = self.holder_selected_channel_reserve_satoshis;
			cmp::min(
				(self.channel_value_satoshis - counterparty_reserve - holder_reserve) * 1000,
				party_max_htlc_value_in_flight_msat,
			)
		})
	}

	pub fn get_value_satoshis(&self) -> u64 {
		self.channel_value_satoshis
	}

	pub fn get_fee_proportional_millionths(&self) -> u32 {
		self.config.options.forwarding_fee_proportional_millionths
	}

	pub fn is_manual_broadcast(&self) -> bool {
		self.is_manual_broadcast
	}

	pub fn get_cltv_expiry_delta(&self) -> u16 {
		cmp::max(self.config.options.cltv_expiry_delta, MIN_CLTV_EXPIRY_DELTA)
	}

	fn get_dust_exposure_limiting_feerate<F: Deref>(
		&self, fee_estimator: &LowerBoundedFeeEstimator<F>,
	) -> u32
	where
		F::Target: FeeEstimator,
	{
		fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::MaximumFeeEstimate)
	}

	pub fn get_max_dust_htlc_exposure_msat(&self, limiting_feerate_sat_per_kw: u32) -> u64 {
		match self.config.options.max_dust_htlc_exposure {
			MaxDustHTLCExposure::FeeRateMultiplier(multiplier) => {
				(limiting_feerate_sat_per_kw as u64).saturating_mul(multiplier)
			},
			MaxDustHTLCExposure::FixedLimitMsat(limit) => limit,
		}
	}

	/// Returns the previous [`ChannelConfig`] applied to this channel, if any.
	pub fn prev_config(&self) -> Option<ChannelConfig> {
		self.prev_config.map(|prev_config| prev_config.0)
	}

	// Checks whether we should emit a `ChannelPending` event.
	pub(crate) fn should_emit_channel_pending_event(&mut self) -> bool {
		self.is_funding_broadcast() && !self.channel_pending_event_emitted
	}

	// Returns whether we already emitted a `ChannelPending` event.
	pub(crate) fn channel_pending_event_emitted(&self) -> bool {
		self.channel_pending_event_emitted
	}

	// Returns whether we already emitted a `FundingTxBroadcastSafe` event.
	pub(crate) fn funding_tx_broadcast_safe_event_emitted(&self) -> bool {
		self.funding_tx_broadcast_safe_event_emitted
	}

	// Remembers that we already emitted a `ChannelPending` event.
	pub(crate) fn set_channel_pending_event_emitted(&mut self) {
		self.channel_pending_event_emitted = true;
	}

	// Checks whether we should emit a `ChannelReady` event.
	pub(crate) fn should_emit_channel_ready_event(&mut self) -> bool {
		self.is_usable() && !self.channel_ready_event_emitted
	}

	// Remembers that we already emitted a `ChannelReady` event.
	pub(crate) fn set_channel_ready_event_emitted(&mut self) {
		self.channel_ready_event_emitted = true;
	}

	// Remembers that we already emitted a `FundingTxBroadcastSafe` event.
	pub(crate) fn set_funding_tx_broadcast_safe_event_emitted(&mut self) {
		self.funding_tx_broadcast_safe_event_emitted = true;
	}

	/// Tracks the number of ticks elapsed since the previous [`ChannelConfig`] was updated. Once
	/// [`EXPIRE_PREV_CONFIG_TICKS`] is reached, the previous config is considered expired and will
	/// no longer be considered when forwarding HTLCs.
	pub fn maybe_expire_prev_config(&mut self) {
		if self.prev_config.is_none() {
			return;
		}
		let prev_config = self.prev_config.as_mut().unwrap();
		prev_config.1 += 1;
		if prev_config.1 == EXPIRE_PREV_CONFIG_TICKS {
			self.prev_config = None;
		}
	}

	/// Returns the current [`ChannelConfig`] applied to the channel.
	pub fn config(&self) -> ChannelConfig {
		self.config.options
	}

	/// Updates the channel's config. A bool is returned indicating whether the config update
	/// applied resulted in a new ChannelUpdate message.
	pub fn update_config(&mut self, config: &ChannelConfig) -> bool {
		let did_channel_update = self.config.options.forwarding_fee_proportional_millionths
			!= config.forwarding_fee_proportional_millionths
			|| self.config.options.forwarding_fee_base_msat != config.forwarding_fee_base_msat
			|| self.config.options.cltv_expiry_delta != config.cltv_expiry_delta;
		if did_channel_update {
			self.prev_config = Some((self.config.options, 0));
			// Update the counter, which backs the ChannelUpdate timestamp, to allow the relay
			// policy change to propagate throughout the network.
			self.update_time_counter += 1;
		}
		self.config.options = *config;
		did_channel_update
	}

	/// Marking the channel as manual broadcast is used in order to prevent LDK from automatically
	/// broadcasting the funding transaction.
	///
	/// This is useful if you wish to get hold of the funding transaction before it is broadcasted
	/// via [`Event::FundingTxBroadcastSafe`] event.
	///
	/// [`Event::FundingTxBroadcastSafe`]: crate::events::Event::FundingTxBroadcastSafe
	pub fn set_manual_broadcast(&mut self) {
		self.is_manual_broadcast = true;
	}

	/// Returns true if funding_signed was sent/received and the
	/// funding transaction has been broadcast if necessary.
	pub fn is_funding_broadcast(&self) -> bool {
		!self.channel_state.is_pre_funded_state()
			&& !matches!(self.channel_state, ChannelState::AwaitingChannelReady(flags) if flags.is_set(AwaitingChannelReadyFlags::WAITING_FOR_BATCH))
	}

	/// Transaction nomenclature is somewhat confusing here as there are many different cases - a
	/// transaction is referred to as "a's transaction" implying that a will be able to broadcast
	/// the transaction. Thus, b will generally be sending a signature over such a transaction to
	/// a, and a can revoke the transaction by providing b the relevant per_commitment_secret. As
	/// such, a transaction is generally the result of b increasing the amount paid to a (or adding
	/// an HTLC to a).
	/// @local is used only to convert relevant internal structures which refer to remote vs local
	/// to decide value of outputs and direction of HTLCs.
	/// @generated_by_local is used to determine *which* HTLCs to include - noting that the HTLC
	/// state may indicate that one peer has informed the other that they'd like to add an HTLC but
	/// have not yet committed it. Such HTLCs will only be included in transactions which are being
	/// generated by the peer which proposed adding the HTLCs, and thus we need to understand both
	/// which peer generated this transaction and "to whom" this transaction flows.
	#[inline]
	fn build_commitment_transaction<L: Deref>(
		&self, commitment_number: u64, keys: &TxCreationKeys, local: bool,
		generated_by_local: bool, logger: &L,
	) -> CommitmentStats
	where
		L::Target: Logger,
	{
		let mut included_dust_htlcs: Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)> =
			Vec::new();
		let num_htlcs = self.pending_inbound_htlcs.len() + self.pending_outbound_htlcs.len();
		let mut included_non_dust_htlcs: Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)> =
			Vec::with_capacity(num_htlcs);

		let broadcaster_dust_limit_satoshis = if local {
			self.holder_dust_limit_satoshis
		} else {
			self.counterparty_dust_limit_satoshis
		};
		let mut remote_htlc_total_msat = 0;
		let mut local_htlc_total_msat = 0;
		let mut value_to_self_msat_offset = 0;

		let mut feerate_per_kw = self.feerate_per_kw;
		if let Some((feerate, update_state)) = self.pending_update_fee {
			if match update_state {
				// Note that these match the inclusion criteria when scanning
				// pending_inbound_htlcs below.
				FeeUpdateState::RemoteAnnounced => {
					debug_assert!(!self.is_outbound());
					!generated_by_local
				},
				FeeUpdateState::AwaitingRemoteRevokeToAnnounce => {
					debug_assert!(!self.is_outbound());
					!generated_by_local
				},
				FeeUpdateState::Outbound => {
					assert!(self.is_outbound());
					generated_by_local
				},
			} {
				feerate_per_kw = feerate;
			}
		}

		log_trace!(logger, "Building commitment transaction number {} (really {} xor {}) for channel {} for {}, generated by {} with fee {}...",
			commitment_number, (INITIAL_COMMITMENT_NUMBER - commitment_number),
			get_commitment_transaction_number_obscure_factor(&self.get_holder_pubkeys().payment_point, &self.get_counterparty_pubkeys().payment_point, self.is_outbound()),
			&self.channel_id,
			if local { "us" } else { "remote" }, if generated_by_local { "us" } else { "remote" }, feerate_per_kw);

		macro_rules! get_htlc_in_commitment {
			($htlc: expr, $offered: expr) => {
				HTLCOutputInCommitment {
					offered: $offered,
					amount_msat: $htlc.amount_msat,
					cltv_expiry: $htlc.cltv_expiry,
					payment_hash: $htlc.payment_hash,
					transaction_output_index: None,
					amount_rgb: $htlc.amount_rgb,
				}
			};
		}

		macro_rules! add_htlc_output {
			($htlc: expr, $outbound: expr, $source: expr, $state_name: expr) => {
				if $outbound == local { // "offered HTLC output"
					let htlc_in_tx = get_htlc_in_commitment!($htlc, true);
					let htlc_tx_fee = if self.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
						0
					} else {
						feerate_per_kw as u64 * htlc_timeout_tx_weight(self.get_channel_type()) / 1000
					};
					if $htlc.amount_msat / 1000 >= broadcaster_dust_limit_satoshis + htlc_tx_fee {
						log_trace!(logger, "   ...including {} {} HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, &$htlc.payment_hash, $htlc.amount_msat);
						included_non_dust_htlcs.push((htlc_in_tx, $source));
					} else {
						log_trace!(logger, "   ...including {} {} dust HTLC {} (hash {}) with value {} due to dust limit", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, &$htlc.payment_hash, $htlc.amount_msat);
						included_dust_htlcs.push((htlc_in_tx, $source));
					}
				} else {
					let htlc_in_tx = get_htlc_in_commitment!($htlc, false);
					let htlc_tx_fee = if self.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
						0
					} else {
						feerate_per_kw as u64 * htlc_success_tx_weight(self.get_channel_type()) / 1000
					};
					if $htlc.amount_msat / 1000 >= broadcaster_dust_limit_satoshis + htlc_tx_fee {
						log_trace!(logger, "   ...including {} {} HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, &$htlc.payment_hash, $htlc.amount_msat);
						included_non_dust_htlcs.push((htlc_in_tx, $source));
					} else {
						log_trace!(logger, "   ...including {} {} dust HTLC {} (hash {}) with value {}", if $outbound { "outbound" } else { "inbound" }, $state_name, $htlc.htlc_id, &$htlc.payment_hash, $htlc.amount_msat);
						included_dust_htlcs.push((htlc_in_tx, $source));
					}
				}
			}
		}

		let mut inbound_htlc_preimages: Vec<PaymentPreimage> = Vec::new();

		for ref htlc in self.pending_inbound_htlcs.iter() {
			let (include, state_name) = match htlc.state {
				InboundHTLCState::RemoteAnnounced(_) => (!generated_by_local, "RemoteAnnounced"),
				InboundHTLCState::AwaitingRemoteRevokeToAnnounce(_) => {
					(!generated_by_local, "AwaitingRemoteRevokeToAnnounce")
				},
				InboundHTLCState::AwaitingAnnouncedRemoteRevoke(_) => {
					(true, "AwaitingAnnouncedRemoteRevoke")
				},
				InboundHTLCState::Committed => (true, "Committed"),
				InboundHTLCState::LocalRemoved(_) => (!generated_by_local, "LocalRemoved"),
			};

			if include {
				add_htlc_output!(htlc, false, None, state_name);
				remote_htlc_total_msat += htlc.amount_msat;
			} else {
				log_trace!(
					logger,
					"   ...not including inbound HTLC {} (hash {}) with value {} due to state ({})",
					htlc.htlc_id,
					&htlc.payment_hash,
					htlc.amount_msat,
					state_name
				);
				match &htlc.state {
					&InboundHTLCState::LocalRemoved(ref reason) => {
						if generated_by_local {
							if let &InboundHTLCRemovalReason::Fulfill(preimage) = reason {
								inbound_htlc_preimages.push(preimage);
								value_to_self_msat_offset += htlc.amount_msat as i64;
							}
						}
					},
					_ => {},
				}
			}
		}

		let mut outbound_htlc_preimages: Vec<PaymentPreimage> = Vec::new();

		for ref htlc in self.pending_outbound_htlcs.iter() {
			let (include, state_name) = match htlc.state {
				OutboundHTLCState::LocalAnnounced(_) => (generated_by_local, "LocalAnnounced"),
				OutboundHTLCState::Committed => (true, "Committed"),
				OutboundHTLCState::RemoteRemoved(_) => (generated_by_local, "RemoteRemoved"),
				OutboundHTLCState::AwaitingRemoteRevokeToRemove(_) => {
					(generated_by_local, "AwaitingRemoteRevokeToRemove")
				},
				OutboundHTLCState::AwaitingRemovedRemoteRevoke(_) => {
					(false, "AwaitingRemovedRemoteRevoke")
				},
			};

			let preimage_opt = match htlc.state {
				OutboundHTLCState::RemoteRemoved(OutboundHTLCOutcome::Success(p)) => p,
				OutboundHTLCState::AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome::Success(
					p,
				)) => p,
				OutboundHTLCState::AwaitingRemovedRemoteRevoke(OutboundHTLCOutcome::Success(p)) => {
					p
				},
				_ => None,
			};

			if let Some(preimage) = preimage_opt {
				outbound_htlc_preimages.push(preimage);
			}

			if include {
				add_htlc_output!(htlc, true, Some(&htlc.source), state_name);
				local_htlc_total_msat += htlc.amount_msat;
			} else {
				log_trace!(logger, "   ...not including outbound HTLC {} (hash {}) with value {} due to state ({})", htlc.htlc_id, &htlc.payment_hash, htlc.amount_msat, state_name);
				match htlc.state {
					OutboundHTLCState::AwaitingRemoteRevokeToRemove(
						OutboundHTLCOutcome::Success(_),
					)
					| OutboundHTLCState::AwaitingRemovedRemoteRevoke(
						OutboundHTLCOutcome::Success(_),
					) => {
						value_to_self_msat_offset -= htlc.amount_msat as i64;
					},
					OutboundHTLCState::RemoteRemoved(OutboundHTLCOutcome::Success(_)) => {
						if !generated_by_local {
							value_to_self_msat_offset -= htlc.amount_msat as i64;
						}
					},
					_ => {},
				}
			}
		}

		let value_to_self_msat: i64 =
			(self.value_to_self_msat - local_htlc_total_msat) as i64 + value_to_self_msat_offset;
		assert!(value_to_self_msat >= 0);
		// Note that in case they have several just-awaiting-last-RAA fulfills in-progress (ie
		// AwaitingRemoteRevokeToRemove or AwaitingRemovedRemoteRevoke) we may have allowed them to
		// "violate" their reserve value by couting those against it. Thus, we have to convert
		// everything to i64 before subtracting as otherwise we can overflow.
		let value_to_remote_msat: i64 = (self.channel_value_satoshis * 1000) as i64
			- (self.value_to_self_msat as i64)
			- (remote_htlc_total_msat as i64)
			- value_to_self_msat_offset;
		assert!(value_to_remote_msat >= 0);

		#[cfg(debug_assertions)]
		{
			// Make sure that the to_self/to_remote is always either past the appropriate
			// channel_reserve *or* it is making progress towards it.
			let mut broadcaster_max_commitment_tx_output = if generated_by_local {
				self.holder_max_commitment_tx_output.lock().unwrap()
			} else {
				self.counterparty_max_commitment_tx_output.lock().unwrap()
			};
			debug_assert!(
				broadcaster_max_commitment_tx_output.0 <= value_to_self_msat as u64
					|| value_to_self_msat / 1000
						>= self.counterparty_selected_channel_reserve_satoshis.unwrap() as i64
			);
			broadcaster_max_commitment_tx_output.0 =
				cmp::max(broadcaster_max_commitment_tx_output.0, value_to_self_msat as u64);
			debug_assert!(
				broadcaster_max_commitment_tx_output.1 <= value_to_remote_msat as u64
					|| value_to_remote_msat / 1000
						>= self.holder_selected_channel_reserve_satoshis as i64
			);
			broadcaster_max_commitment_tx_output.1 =
				cmp::max(broadcaster_max_commitment_tx_output.1, value_to_remote_msat as u64);
		}

		let total_fee_sat = commit_tx_fee_sat(
			feerate_per_kw,
			included_non_dust_htlcs.len(),
			&self.channel_transaction_parameters.channel_type_features,
		);
		let anchors_val = if self
			.channel_transaction_parameters
			.channel_type_features
			.supports_anchors_zero_fee_htlc_tx()
		{
			ANCHOR_OUTPUT_VALUE_SATOSHI * 2
		} else {
			0
		} as i64;
		let (value_to_self, value_to_remote) = if self.is_outbound() {
			(
				value_to_self_msat / 1000 - anchors_val - total_fee_sat as i64,
				value_to_remote_msat / 1000,
			)
		} else {
			(
				value_to_self_msat / 1000,
				value_to_remote_msat / 1000 - anchors_val - total_fee_sat as i64,
			)
		};

		let mut value_to_a = if local { value_to_self } else { value_to_remote };
		let mut value_to_b = if local { value_to_remote } else { value_to_self };
		let (funding_pubkey_a, funding_pubkey_b) = if local {
			(
				self.get_holder_pubkeys().funding_pubkey,
				self.get_counterparty_pubkeys().funding_pubkey,
			)
		} else {
			(
				self.get_counterparty_pubkeys().funding_pubkey,
				self.get_holder_pubkeys().funding_pubkey,
			)
		};

		if value_to_a >= (broadcaster_dust_limit_satoshis as i64) {
			log_trace!(
				logger,
				"   ...including {} output with value {}",
				if local { "to_local" } else { "to_remote" },
				value_to_a
			);
		} else {
			value_to_a = 0;
		}

		if value_to_b >= (broadcaster_dust_limit_satoshis as i64) {
			log_trace!(
				logger,
				"   ...including {} output with value {}",
				if local { "to_remote" } else { "to_local" },
				value_to_b
			);
		} else {
			value_to_b = 0;
		}

		let num_nondust_htlcs = included_non_dust_htlcs.len();

		let channel_parameters = if local {
			self.channel_transaction_parameters.as_holder_broadcastable()
		} else {
			self.channel_transaction_parameters.as_counterparty_broadcastable()
		};
		let tx = CommitmentTransaction::new_with_auxiliary_htlc_data(
			commitment_number,
			value_to_a as u64,
			value_to_b as u64,
			funding_pubkey_a,
			funding_pubkey_b,
			keys.clone(),
			feerate_per_kw,
			&mut included_non_dust_htlcs,
			&channel_parameters,
		);
		let mut htlcs_included = included_non_dust_htlcs;
		// The unwrap is safe, because all non-dust HTLCs have been assigned an output index
		htlcs_included.sort_unstable_by_key(|h| h.0.transaction_output_index.unwrap());
		htlcs_included.append(&mut included_dust_htlcs);

		CommitmentStats {
			tx,
			feerate_per_kw,
			total_fee_sat,
			num_nondust_htlcs,
			htlcs_included,
			local_balance_msat: value_to_self_msat as u64,
			remote_balance_msat: value_to_remote_msat as u64,
			inbound_htlc_preimages,
			outbound_htlc_preimages,
		}
	}

	#[inline]
	/// Creates a set of keys for build_commitment_transaction to generate a transaction which our
	/// counterparty will sign (ie DO NOT send signatures over a transaction created by this to
	/// our counterparty!)
	/// The result is a transaction which we can revoke broadcastership of (ie a "local" transaction)
	/// TODO Some magic rust shit to compile-time check this?
	fn build_holder_transaction_keys(&self) -> TxCreationKeys {
		let per_commitment_point = self.holder_commitment_point.current_point();
		let delayed_payment_base = &self.get_holder_pubkeys().delayed_payment_basepoint;
		let htlc_basepoint = &self.get_holder_pubkeys().htlc_basepoint;
		let counterparty_pubkeys = self.get_counterparty_pubkeys();

		TxCreationKeys::derive_new(
			&self.secp_ctx,
			&per_commitment_point,
			delayed_payment_base,
			htlc_basepoint,
			&counterparty_pubkeys.revocation_basepoint,
			&counterparty_pubkeys.htlc_basepoint,
		)
	}

	#[inline]
	/// Creates a set of keys for build_commitment_transaction to generate a transaction which we
	/// will sign and send to our counterparty.
	/// If an Err is returned, it is a ChannelError::Close (for get_funding_created)
	fn build_remote_transaction_keys(&self) -> TxCreationKeys {
		let revocation_basepoint = &self.get_holder_pubkeys().revocation_basepoint;
		let htlc_basepoint = &self.get_holder_pubkeys().htlc_basepoint;
		let counterparty_pubkeys = self.get_counterparty_pubkeys();

		TxCreationKeys::derive_new(
			&self.secp_ctx,
			&self.counterparty_cur_commitment_point.unwrap(),
			&counterparty_pubkeys.delayed_payment_basepoint,
			&counterparty_pubkeys.htlc_basepoint,
			revocation_basepoint,
			htlc_basepoint,
		)
	}

	/// Gets the redeemscript for the funding transaction output (ie the funding transaction output
	/// pays to get_funding_redeemscript().to_v0_p2wsh()).
	/// Panics if called before accept_channel/InboundV1Channel::new
	pub fn get_funding_redeemscript(&self) -> ScriptBuf {
		make_funding_redeemscript(
			&self.get_holder_pubkeys().funding_pubkey,
			self.counterparty_funding_pubkey(),
		)
	}

	fn counterparty_funding_pubkey(&self) -> &PublicKey {
		&self.get_counterparty_pubkeys().funding_pubkey
	}

	pub fn get_feerate_sat_per_1000_weight(&self) -> u32 {
		self.feerate_per_kw
	}

	pub fn get_dust_buffer_feerate(&self, outbound_feerate_update: Option<u32>) -> u32 {
		// When calculating our exposure to dust HTLCs, we assume that the channel feerate
		// may, at any point, increase by at least 10 sat/vB (i.e 2530 sat/kWU) or 25%,
		// whichever is higher. This ensures that we aren't suddenly exposed to significantly
		// more dust balance if the feerate increases when we have several HTLCs pending
		// which are near the dust limit.
		let mut feerate_per_kw = self.feerate_per_kw;
		// If there's a pending update fee, use it to ensure we aren't under-estimating
		// potential feerate updates coming soon.
		if let Some((feerate, _)) = self.pending_update_fee {
			feerate_per_kw = cmp::max(feerate_per_kw, feerate);
		}
		if let Some(feerate) = outbound_feerate_update {
			feerate_per_kw = cmp::max(feerate_per_kw, feerate);
		}
		let feerate_plus_quarter = feerate_per_kw.checked_mul(1250).map(|v| v / 1000);
		cmp::max(feerate_per_kw.saturating_add(2530), feerate_plus_quarter.unwrap_or(u32::MAX))
	}

	/// Get forwarding information for the counterparty.
	pub fn counterparty_forwarding_info(&self) -> Option<CounterpartyForwardingInfo> {
		self.counterparty_forwarding_info.clone()
	}

	/// Returns a HTLCStats about pending htlcs
	fn get_pending_htlc_stats(
		&self, outbound_feerate_update: Option<u32>, dust_exposure_limiting_feerate: u32,
	) -> HTLCStats {
		let context = self;
		let uses_0_htlc_fee_anchors = self.get_channel_type().supports_anchors_zero_fee_htlc_tx();

		let dust_buffer_feerate = context.get_dust_buffer_feerate(outbound_feerate_update);
		let (htlc_timeout_dust_limit, htlc_success_dust_limit) = if uses_0_htlc_fee_anchors {
			(0, 0)
		} else {
			(
				dust_buffer_feerate as u64 * htlc_timeout_tx_weight(context.get_channel_type())
					/ 1000,
				dust_buffer_feerate as u64 * htlc_success_tx_weight(context.get_channel_type())
					/ 1000,
			)
		};

		let mut on_holder_tx_dust_exposure_msat = 0;
		let mut on_counterparty_tx_dust_exposure_msat = 0;

		let mut on_counterparty_tx_offered_nondust_htlcs = 0;
		let mut on_counterparty_tx_accepted_nondust_htlcs = 0;

		let mut pending_inbound_htlcs_value_msat = 0;

		{
			let counterparty_dust_limit_timeout_sat =
				htlc_timeout_dust_limit + context.counterparty_dust_limit_satoshis;
			let holder_dust_limit_success_sat =
				htlc_success_dust_limit + context.holder_dust_limit_satoshis;
			for ref htlc in context.pending_inbound_htlcs.iter() {
				pending_inbound_htlcs_value_msat += htlc.amount_msat;
				if htlc.amount_msat / 1000 < counterparty_dust_limit_timeout_sat {
					on_counterparty_tx_dust_exposure_msat += htlc.amount_msat;
				} else {
					on_counterparty_tx_offered_nondust_htlcs += 1;
				}
				if htlc.amount_msat / 1000 < holder_dust_limit_success_sat {
					on_holder_tx_dust_exposure_msat += htlc.amount_msat;
				}
			}
		}

		let mut pending_outbound_htlcs_value_msat = 0;
		let mut outbound_holding_cell_msat = 0;
		let mut on_holder_tx_outbound_holding_cell_htlcs_count = 0;
		let mut pending_outbound_htlcs = self.pending_outbound_htlcs.len();
		{
			let counterparty_dust_limit_success_sat =
				htlc_success_dust_limit + context.counterparty_dust_limit_satoshis;
			let holder_dust_limit_timeout_sat =
				htlc_timeout_dust_limit + context.holder_dust_limit_satoshis;
			for ref htlc in context.pending_outbound_htlcs.iter() {
				pending_outbound_htlcs_value_msat += htlc.amount_msat;
				if htlc.amount_msat / 1000 < counterparty_dust_limit_success_sat {
					on_counterparty_tx_dust_exposure_msat += htlc.amount_msat;
				} else {
					on_counterparty_tx_accepted_nondust_htlcs += 1;
				}
				if htlc.amount_msat / 1000 < holder_dust_limit_timeout_sat {
					on_holder_tx_dust_exposure_msat += htlc.amount_msat;
				}
			}

			for update in context.holding_cell_htlc_updates.iter() {
				if let &HTLCUpdateAwaitingACK::AddHTLC { ref amount_msat, .. } = update {
					pending_outbound_htlcs += 1;
					pending_outbound_htlcs_value_msat += amount_msat;
					outbound_holding_cell_msat += amount_msat;
					if *amount_msat / 1000 < counterparty_dust_limit_success_sat {
						on_counterparty_tx_dust_exposure_msat += amount_msat;
					} else {
						on_counterparty_tx_accepted_nondust_htlcs += 1;
					}
					if *amount_msat / 1000 < holder_dust_limit_timeout_sat {
						on_holder_tx_dust_exposure_msat += amount_msat;
					} else {
						on_holder_tx_outbound_holding_cell_htlcs_count += 1;
					}
				}
			}
		}

		// Include any mining "excess" fees in the dust calculation
		let excess_feerate_opt = outbound_feerate_update
			.or(self.pending_update_fee.map(|(fee, _)| fee))
			.unwrap_or(self.feerate_per_kw)
			.checked_sub(dust_exposure_limiting_feerate);
		if let Some(excess_feerate) = excess_feerate_opt {
			let on_counterparty_tx_nondust_htlcs = on_counterparty_tx_accepted_nondust_htlcs
				+ on_counterparty_tx_offered_nondust_htlcs;
			on_counterparty_tx_dust_exposure_msat += commit_tx_fee_sat(
				excess_feerate,
				on_counterparty_tx_nondust_htlcs,
				&self.channel_type,
			) * 1000;
			if !self.channel_type.supports_anchors_zero_fee_htlc_tx() {
				on_counterparty_tx_dust_exposure_msat +=
					on_counterparty_tx_accepted_nondust_htlcs as u64
						* htlc_success_tx_weight(&self.channel_type)
						* excess_feerate as u64 / 1000;
				on_counterparty_tx_dust_exposure_msat +=
					on_counterparty_tx_offered_nondust_htlcs as u64
						* htlc_timeout_tx_weight(&self.channel_type)
						* excess_feerate as u64 / 1000;
			}
		}

		HTLCStats {
			pending_inbound_htlcs: self.pending_inbound_htlcs.len(),
			pending_outbound_htlcs,
			pending_inbound_htlcs_value_msat,
			pending_outbound_htlcs_value_msat,
			on_counterparty_tx_dust_exposure_msat,
			on_holder_tx_dust_exposure_msat,
			outbound_holding_cell_msat,
			on_holder_tx_outbound_holding_cell_htlcs_count,
		}
	}

	/// Returns information on all pending inbound HTLCs.
	pub fn get_pending_inbound_htlc_details(&self) -> Vec<InboundHTLCDetails> {
		let mut holding_cell_states = new_hash_map();
		for holding_cell_update in self.holding_cell_htlc_updates.iter() {
			match holding_cell_update {
				HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, .. } => {
					holding_cell_states.insert(
						htlc_id,
						InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFulfill,
					);
				},
				HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. } => {
					holding_cell_states
						.insert(htlc_id, InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail);
				},
				HTLCUpdateAwaitingACK::FailMalformedHTLC { htlc_id, .. } => {
					holding_cell_states
						.insert(htlc_id, InboundHTLCStateDetails::AwaitingRemoteRevokeToRemoveFail);
				},
				// Outbound HTLC.
				HTLCUpdateAwaitingACK::AddHTLC { .. } => {},
			}
		}
		let mut inbound_details = Vec::new();
		let htlc_success_dust_limit = if self.get_channel_type().supports_anchors_zero_fee_htlc_tx()
		{
			0
		} else {
			let dust_buffer_feerate = self.get_dust_buffer_feerate(None) as u64;
			dust_buffer_feerate * htlc_success_tx_weight(self.get_channel_type()) / 1000
		};
		let holder_dust_limit_success_sat =
			htlc_success_dust_limit + self.holder_dust_limit_satoshis;
		for htlc in self.pending_inbound_htlcs.iter() {
			if let Some(state_details) = (&htlc.state).into() {
				inbound_details.push(InboundHTLCDetails {
					htlc_id: htlc.htlc_id,
					amount_msat: htlc.amount_msat,
					cltv_expiry: htlc.cltv_expiry,
					payment_hash: htlc.payment_hash,
					state: Some(holding_cell_states.remove(&htlc.htlc_id).unwrap_or(state_details)),
					is_dust: htlc.amount_msat / 1000 < holder_dust_limit_success_sat,
				});
			}
		}
		inbound_details
	}

	/// Returns information on all pending outbound HTLCs.
	pub fn get_pending_outbound_htlc_details(&self) -> Vec<OutboundHTLCDetails> {
		let mut outbound_details = Vec::new();
		let htlc_timeout_dust_limit = if self.get_channel_type().supports_anchors_zero_fee_htlc_tx()
		{
			0
		} else {
			let dust_buffer_feerate = self.get_dust_buffer_feerate(None) as u64;
			dust_buffer_feerate * htlc_success_tx_weight(self.get_channel_type()) / 1000
		};
		let holder_dust_limit_timeout_sat =
			htlc_timeout_dust_limit + self.holder_dust_limit_satoshis;
		for htlc in self.pending_outbound_htlcs.iter() {
			outbound_details.push(OutboundHTLCDetails {
				htlc_id: Some(htlc.htlc_id),
				amount_msat: htlc.amount_msat,
				cltv_expiry: htlc.cltv_expiry,
				payment_hash: htlc.payment_hash,
				skimmed_fee_msat: htlc.skimmed_fee_msat,
				state: Some((&htlc.state).into()),
				is_dust: htlc.amount_msat / 1000 < holder_dust_limit_timeout_sat,
			});
		}
		for holding_cell_update in self.holding_cell_htlc_updates.iter() {
			if let HTLCUpdateAwaitingACK::AddHTLC {
				amount_msat,
				cltv_expiry,
				payment_hash,
				skimmed_fee_msat,
				..
			} = *holding_cell_update
			{
				outbound_details.push(OutboundHTLCDetails {
					htlc_id: None,
					amount_msat,
					cltv_expiry,
					payment_hash,
					skimmed_fee_msat,
					state: Some(OutboundHTLCStateDetails::AwaitingRemoteRevokeToAdd),
					is_dust: amount_msat / 1000 < holder_dust_limit_timeout_sat,
				});
			}
		}
		outbound_details
	}

	/// Get the available balances, see [`AvailableBalances`]'s fields for more info.
	/// Doesn't bother handling the
	/// if-we-removed-it-already-but-haven't-fully-resolved-they-can-still-send-an-inbound-HTLC
	/// corner case properly.
	pub fn get_available_balances<F: Deref>(
		&self, fee_estimator: &LowerBoundedFeeEstimator<F>,
	) -> AvailableBalances
	where
		F::Target: FeeEstimator,
	{
		let context = &self;
		// Note that we have to handle overflow due to the case mentioned in the docs in general
		// here.

		let dust_exposure_limiting_feerate =
			self.get_dust_exposure_limiting_feerate(&fee_estimator);
		let htlc_stats = context.get_pending_htlc_stats(None, dust_exposure_limiting_feerate);

		let mut balance_msat = context.value_to_self_msat;
		for ref htlc in context.pending_inbound_htlcs.iter() {
			if let InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::Fulfill(_)) = htlc.state
			{
				balance_msat += htlc.amount_msat;
			}
		}
		balance_msat -= htlc_stats.pending_outbound_htlcs_value_msat;

		let outbound_capacity_msat = context
			.value_to_self_msat
			.saturating_sub(htlc_stats.pending_outbound_htlcs_value_msat)
			.saturating_sub(
				context.counterparty_selected_channel_reserve_satoshis.unwrap_or(0) * 1000,
			);

		let mut available_capacity_msat = outbound_capacity_msat;

		let anchor_outputs_value_msat =
			if context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
				ANCHOR_OUTPUT_VALUE_SATOSHI * 2 * 1000
			} else {
				0
			};
		if context.is_outbound() {
			// We should mind channel commit tx fee when computing how much of the available capacity
			// can be used in the next htlc. Mirrors the logic in send_htlc.
			//
			// The fee depends on whether the amount we will be sending is above dust or not,
			// and the answer will in turn change the amount itself — making it a circular
			// dependency.
			// This complicates the computation around dust-values, up to the one-htlc-value.
			let mut real_dust_limit_timeout_sat = context.holder_dust_limit_satoshis;
			if !context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
				real_dust_limit_timeout_sat += context.feerate_per_kw as u64
					* htlc_timeout_tx_weight(context.get_channel_type())
					/ 1000;
			}

			let htlc_above_dust =
				HTLCCandidate::new(real_dust_limit_timeout_sat * 1000, HTLCInitiator::LocalOffered);
			let mut max_reserved_commit_tx_fee_msat =
				context.next_local_commit_tx_fee_msat(htlc_above_dust, Some(()));
			let htlc_dust = HTLCCandidate::new(
				real_dust_limit_timeout_sat * 1000 - 1,
				HTLCInitiator::LocalOffered,
			);
			let mut min_reserved_commit_tx_fee_msat =
				context.next_local_commit_tx_fee_msat(htlc_dust, Some(()));
			if !context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
				max_reserved_commit_tx_fee_msat *= FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE;
				min_reserved_commit_tx_fee_msat *= FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE;
			}

			// We will first subtract the fee as if we were above-dust. Then, if the resulting
			// value ends up being below dust, we have this fee available again. In that case,
			// match the value to right-below-dust.
			let mut capacity_minus_commitment_fee_msat: i64 = available_capacity_msat as i64
				- max_reserved_commit_tx_fee_msat as i64
				- anchor_outputs_value_msat as i64;
			if capacity_minus_commitment_fee_msat < (real_dust_limit_timeout_sat as i64) * 1000 {
				let one_htlc_difference_msat =
					max_reserved_commit_tx_fee_msat - min_reserved_commit_tx_fee_msat;
				debug_assert!(one_htlc_difference_msat != 0);
				capacity_minus_commitment_fee_msat += one_htlc_difference_msat as i64;
				capacity_minus_commitment_fee_msat = cmp::min(
					real_dust_limit_timeout_sat as i64 * 1000 - 1,
					capacity_minus_commitment_fee_msat,
				);
				available_capacity_msat = cmp::max(
					0,
					cmp::min(capacity_minus_commitment_fee_msat, available_capacity_msat as i64),
				) as u64;
			} else {
				available_capacity_msat = capacity_minus_commitment_fee_msat as u64;
			}
		} else {
			// If the channel is inbound (i.e. counterparty pays the fee), we need to make sure
			// sending a new HTLC won't reduce their balance below our reserve threshold.
			let mut real_dust_limit_success_sat = context.counterparty_dust_limit_satoshis;
			if !context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
				real_dust_limit_success_sat += context.feerate_per_kw as u64
					* htlc_success_tx_weight(context.get_channel_type())
					/ 1000;
			}

			let htlc_above_dust =
				HTLCCandidate::new(real_dust_limit_success_sat * 1000, HTLCInitiator::LocalOffered);
			let max_reserved_commit_tx_fee_msat =
				context.next_remote_commit_tx_fee_msat(htlc_above_dust, None);

			let holder_selected_chan_reserve_msat =
				context.holder_selected_channel_reserve_satoshis * 1000;
			let remote_balance_msat = (context.channel_value_satoshis * 1000
				- context.value_to_self_msat)
				.saturating_sub(htlc_stats.pending_inbound_htlcs_value_msat);

			if remote_balance_msat
				< max_reserved_commit_tx_fee_msat
					+ holder_selected_chan_reserve_msat
					+ anchor_outputs_value_msat
			{
				// If another HTLC's fee would reduce the remote's balance below the reserve limit
				// we've selected for them, we can only send dust HTLCs.
				available_capacity_msat =
					cmp::min(available_capacity_msat, real_dust_limit_success_sat * 1000 - 1);
			}
		}

		let mut next_outbound_htlc_minimum_msat = context.counterparty_htlc_minimum_msat;

		// If we get close to our maximum dust exposure, we end up in a situation where we can send
		// between zero and the remaining dust exposure limit remaining OR above the dust limit.
		// Because we cannot express this as a simple min/max, we prefer to tell the user they can
		// send above the dust limit (as the router can always overpay to meet the dust limit).
		let mut remaining_msat_below_dust_exposure_limit = None;
		let mut dust_exposure_dust_limit_msat = 0;
		let max_dust_htlc_exposure_msat =
			context.get_max_dust_htlc_exposure_msat(dust_exposure_limiting_feerate);

		let (htlc_success_dust_limit, htlc_timeout_dust_limit) =
			if context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
				(context.counterparty_dust_limit_satoshis, context.holder_dust_limit_satoshis)
			} else {
				let dust_buffer_feerate = context.get_dust_buffer_feerate(None) as u64;
				(
					context.counterparty_dust_limit_satoshis
						+ dust_buffer_feerate * htlc_success_tx_weight(context.get_channel_type())
							/ 1000,
					context.holder_dust_limit_satoshis
						+ dust_buffer_feerate * htlc_timeout_tx_weight(context.get_channel_type())
							/ 1000,
				)
			};

		let excess_feerate_opt = self.feerate_per_kw.checked_sub(dust_exposure_limiting_feerate);
		if let Some(excess_feerate) = excess_feerate_opt {
			let htlc_dust_exposure_msat = per_outbound_htlc_counterparty_commit_tx_fee_msat(
				excess_feerate,
				&context.channel_type,
			);
			let nondust_htlc_counterparty_tx_dust_exposure = htlc_stats
				.on_counterparty_tx_dust_exposure_msat
				.saturating_add(htlc_dust_exposure_msat);
			if nondust_htlc_counterparty_tx_dust_exposure > max_dust_htlc_exposure_msat {
				// If adding an extra HTLC would put us over the dust limit in total fees, we cannot
				// send any non-dust HTLCs.
				available_capacity_msat =
					cmp::min(available_capacity_msat, htlc_success_dust_limit * 1000);
			}
		}

		if htlc_stats
			.on_counterparty_tx_dust_exposure_msat
			.saturating_add(htlc_success_dust_limit * 1000)
			> max_dust_htlc_exposure_msat.saturating_add(1)
		{
			// Note that we don't use the `counterparty_tx_dust_exposure` (with
			// `htlc_dust_exposure_msat`) here as it only applies to non-dust HTLCs.
			remaining_msat_below_dust_exposure_limit = Some(
				max_dust_htlc_exposure_msat
					.saturating_sub(htlc_stats.on_counterparty_tx_dust_exposure_msat),
			);
			dust_exposure_dust_limit_msat =
				cmp::max(dust_exposure_dust_limit_msat, htlc_success_dust_limit * 1000);
		}

		if htlc_stats.on_holder_tx_dust_exposure_msat as i64 + htlc_timeout_dust_limit as i64 * 1000
			- 1 > max_dust_htlc_exposure_msat.try_into().unwrap_or(i64::max_value())
		{
			remaining_msat_below_dust_exposure_limit = Some(cmp::min(
				remaining_msat_below_dust_exposure_limit.unwrap_or(u64::max_value()),
				max_dust_htlc_exposure_msat
					.saturating_sub(htlc_stats.on_holder_tx_dust_exposure_msat),
			));
			dust_exposure_dust_limit_msat =
				cmp::max(dust_exposure_dust_limit_msat, htlc_timeout_dust_limit * 1000);
		}

		if let Some(remaining_limit_msat) = remaining_msat_below_dust_exposure_limit {
			if available_capacity_msat < dust_exposure_dust_limit_msat {
				available_capacity_msat = cmp::min(available_capacity_msat, remaining_limit_msat);
			} else {
				next_outbound_htlc_minimum_msat =
					cmp::max(next_outbound_htlc_minimum_msat, dust_exposure_dust_limit_msat);
			}
		}

		available_capacity_msat = cmp::min(
			available_capacity_msat,
			context.counterparty_max_htlc_value_in_flight_msat
				- htlc_stats.pending_outbound_htlcs_value_msat,
		);

		if htlc_stats.pending_outbound_htlcs + 1 > context.counterparty_max_accepted_htlcs as usize
		{
			available_capacity_msat = 0;
		}

		#[allow(deprecated)] // TODO: Remove once balance_msat is removed.
		AvailableBalances {
			inbound_capacity_msat: cmp::max(
				context.channel_value_satoshis as i64 * 1000
					- context.value_to_self_msat as i64
					- htlc_stats.pending_inbound_htlcs_value_msat as i64
					- context.holder_selected_channel_reserve_satoshis as i64 * 1000,
				0,
			) as u64,
			outbound_capacity_msat,
			next_outbound_htlc_limit_msat: available_capacity_msat,
			next_outbound_htlc_minimum_msat,
			balance_msat,
		}
	}

	pub fn get_holder_counterparty_selected_channel_reserve_satoshis(&self) -> (u64, Option<u64>) {
		let context = &self;
		(
			context.holder_selected_channel_reserve_satoshis,
			context.counterparty_selected_channel_reserve_satoshis,
		)
	}

	/// Get the commitment tx fee for the local's (i.e. our) next commitment transaction based on the
	/// number of pending HTLCs that are on track to be in our next commitment tx.
	///
	/// Optionally includes the `HTLCCandidate` given by `htlc` and an additional non-dust HTLC if
	/// `fee_spike_buffer_htlc` is `Some`.
	///
	/// The first extra HTLC is useful for determining whether we can accept a further HTLC, the
	/// second allows for creating a buffer to ensure a further HTLC can always be accepted/added.
	///
	/// Dust HTLCs are excluded.
	fn next_local_commit_tx_fee_msat(
		&self, htlc: HTLCCandidate, fee_spike_buffer_htlc: Option<()>,
	) -> u64 {
		let context = &self;
		assert!(context.is_outbound());

		let (htlc_success_dust_limit, htlc_timeout_dust_limit) = if context
			.get_channel_type()
			.supports_anchors_zero_fee_htlc_tx()
		{
			(0, 0)
		} else {
			(
				context.feerate_per_kw as u64 * htlc_success_tx_weight(context.get_channel_type())
					/ 1000,
				context.feerate_per_kw as u64 * htlc_timeout_tx_weight(context.get_channel_type())
					/ 1000,
			)
		};
		let real_dust_limit_success_sat =
			htlc_success_dust_limit + context.holder_dust_limit_satoshis;
		let real_dust_limit_timeout_sat =
			htlc_timeout_dust_limit + context.holder_dust_limit_satoshis;

		let mut addl_htlcs = 0;
		if fee_spike_buffer_htlc.is_some() {
			addl_htlcs += 1;
		}
		match htlc.origin {
			HTLCInitiator::LocalOffered => {
				if htlc.amount_msat / 1000 >= real_dust_limit_timeout_sat {
					addl_htlcs += 1;
				}
			},
			HTLCInitiator::RemoteOffered => {
				if htlc.amount_msat / 1000 >= real_dust_limit_success_sat {
					addl_htlcs += 1;
				}
			},
		}

		let mut included_htlcs = 0;
		for ref htlc in context.pending_inbound_htlcs.iter() {
			if htlc.amount_msat / 1000 < real_dust_limit_success_sat {
				continue;
			}
			// We include LocalRemoved HTLCs here because we may still need to broadcast a commitment
			// transaction including this HTLC if it times out before they RAA.
			included_htlcs += 1;
		}

		for ref htlc in context.pending_outbound_htlcs.iter() {
			if htlc.amount_msat / 1000 < real_dust_limit_timeout_sat {
				continue;
			}
			match htlc.state {
				OutboundHTLCState::LocalAnnounced { .. } => included_htlcs += 1,
				OutboundHTLCState::Committed => included_htlcs += 1,
				OutboundHTLCState::RemoteRemoved { .. } => included_htlcs += 1,
				// We don't include AwaitingRemoteRevokeToRemove HTLCs because our next commitment
				// transaction won't be generated until they send us their next RAA, which will mean
				// dropping any HTLCs in this state.
				_ => {},
			}
		}

		for htlc in context.holding_cell_htlc_updates.iter() {
			match htlc {
				&HTLCUpdateAwaitingACK::AddHTLC { amount_msat, .. } => {
					if amount_msat / 1000 < real_dust_limit_timeout_sat {
						continue;
					}
					included_htlcs += 1
				},
				_ => {}, // Don't include claims/fails that are awaiting ack, because once we get the
				         // ack we're guaranteed to never include them in commitment txs anymore.
			}
		}

		let num_htlcs = included_htlcs + addl_htlcs;
		let res =
			commit_tx_fee_sat(context.feerate_per_kw, num_htlcs, &context.channel_type) * 1000;
		#[cfg(any(test, fuzzing))]
		{
			let mut fee = res;
			if fee_spike_buffer_htlc.is_some() {
				fee =
					commit_tx_fee_sat(context.feerate_per_kw, num_htlcs - 1, &context.channel_type)
						* 1000;
			}
			let total_pending_htlcs = context.pending_inbound_htlcs.len()
				+ context.pending_outbound_htlcs.len()
				+ context.holding_cell_htlc_updates.len();
			let commitment_tx_info = CommitmentTxInfoCached {
				fee,
				total_pending_htlcs,
				next_holder_htlc_id: match htlc.origin {
					HTLCInitiator::LocalOffered => context.next_holder_htlc_id + 1,
					HTLCInitiator::RemoteOffered => context.next_holder_htlc_id,
				},
				next_counterparty_htlc_id: match htlc.origin {
					HTLCInitiator::LocalOffered => context.next_counterparty_htlc_id,
					HTLCInitiator::RemoteOffered => context.next_counterparty_htlc_id + 1,
				},
				feerate: context.feerate_per_kw,
			};
			*context.next_local_commitment_tx_fee_info_cached.lock().unwrap() =
				Some(commitment_tx_info);
		}
		res
	}

	/// Get the commitment tx fee for the remote's next commitment transaction based on the number of
	/// pending HTLCs that are on track to be in their next commitment tx
	///
	/// Optionally includes the `HTLCCandidate` given by `htlc` and an additional non-dust HTLC if
	/// `fee_spike_buffer_htlc` is `Some`.
	///
	/// The first extra HTLC is useful for determining whether we can accept a further HTLC, the
	/// second allows for creating a buffer to ensure a further HTLC can always be accepted/added.
	///
	/// Dust HTLCs are excluded.
	fn next_remote_commit_tx_fee_msat(
		&self, htlc: HTLCCandidate, fee_spike_buffer_htlc: Option<()>,
	) -> u64 {
		let context = &self;
		assert!(!context.is_outbound());

		let (htlc_success_dust_limit, htlc_timeout_dust_limit) = if context
			.get_channel_type()
			.supports_anchors_zero_fee_htlc_tx()
		{
			(0, 0)
		} else {
			(
				context.feerate_per_kw as u64 * htlc_success_tx_weight(context.get_channel_type())
					/ 1000,
				context.feerate_per_kw as u64 * htlc_timeout_tx_weight(context.get_channel_type())
					/ 1000,
			)
		};
		let real_dust_limit_success_sat =
			htlc_success_dust_limit + context.counterparty_dust_limit_satoshis;
		let real_dust_limit_timeout_sat =
			htlc_timeout_dust_limit + context.counterparty_dust_limit_satoshis;

		let mut addl_htlcs = 0;
		if fee_spike_buffer_htlc.is_some() {
			addl_htlcs += 1;
		}
		match htlc.origin {
			HTLCInitiator::LocalOffered => {
				if htlc.amount_msat / 1000 >= real_dust_limit_success_sat {
					addl_htlcs += 1;
				}
			},
			HTLCInitiator::RemoteOffered => {
				if htlc.amount_msat / 1000 >= real_dust_limit_timeout_sat {
					addl_htlcs += 1;
				}
			},
		}

		// When calculating the set of HTLCs which will be included in their next commitment_signed, all
		// non-dust inbound HTLCs are included (as all states imply it will be included) and only
		// committed outbound HTLCs, see below.
		let mut included_htlcs = 0;
		for ref htlc in context.pending_inbound_htlcs.iter() {
			if htlc.amount_msat / 1000 <= real_dust_limit_timeout_sat {
				continue;
			}
			included_htlcs += 1;
		}

		for ref htlc in context.pending_outbound_htlcs.iter() {
			if htlc.amount_msat / 1000 <= real_dust_limit_success_sat {
				continue;
			}
			// We only include outbound HTLCs if it will not be included in their next commitment_signed,
			// i.e. if they've responded to us with an RAA after announcement.
			match htlc.state {
				OutboundHTLCState::Committed => included_htlcs += 1,
				OutboundHTLCState::RemoteRemoved { .. } => included_htlcs += 1,
				OutboundHTLCState::LocalAnnounced { .. } => included_htlcs += 1,
				_ => {},
			}
		}

		let num_htlcs = included_htlcs + addl_htlcs;
		let res =
			commit_tx_fee_sat(context.feerate_per_kw, num_htlcs, &context.channel_type) * 1000;
		#[cfg(any(test, fuzzing))]
		{
			let mut fee = res;
			if fee_spike_buffer_htlc.is_some() {
				fee =
					commit_tx_fee_sat(context.feerate_per_kw, num_htlcs - 1, &context.channel_type)
						* 1000;
			}
			let total_pending_htlcs =
				context.pending_inbound_htlcs.len() + context.pending_outbound_htlcs.len();
			let commitment_tx_info = CommitmentTxInfoCached {
				fee,
				total_pending_htlcs,
				next_holder_htlc_id: match htlc.origin {
					HTLCInitiator::LocalOffered => context.next_holder_htlc_id + 1,
					HTLCInitiator::RemoteOffered => context.next_holder_htlc_id,
				},
				next_counterparty_htlc_id: match htlc.origin {
					HTLCInitiator::LocalOffered => context.next_counterparty_htlc_id,
					HTLCInitiator::RemoteOffered => context.next_counterparty_htlc_id + 1,
				},
				feerate: context.feerate_per_kw,
			};
			*context.next_remote_commitment_tx_fee_info_cached.lock().unwrap() =
				Some(commitment_tx_info);
		}
		res
	}

	fn if_unbroadcasted_funding<F, O>(&self, f: F) -> Option<O>
	where
		F: Fn() -> Option<O>,
	{
		match self.channel_state {
			ChannelState::FundingNegotiated => f(),
			ChannelState::AwaitingChannelReady(flags) => {
				if flags.is_set(AwaitingChannelReadyFlags::WAITING_FOR_BATCH)
					|| flags.is_set(FundedStateFlags::MONITOR_UPDATE_IN_PROGRESS.into())
				{
					f()
				} else {
					None
				}
			},
			_ => None,
		}
	}

	/// Returns the transaction if there is a pending funding transaction that is yet to be
	/// broadcast.
	///
	/// Note that if [`Self::is_manual_broadcast`] is true the transaction will be a dummy
	/// transaction.
	pub fn unbroadcasted_funding(&self) -> Option<Transaction> {
		self.if_unbroadcasted_funding(|| self.funding_transaction.clone())
	}

	/// Returns the transaction ID if there is a pending funding transaction that is yet to be
	/// broadcast.
	pub fn unbroadcasted_funding_txid(&self) -> Option<Txid> {
		self.if_unbroadcasted_funding(|| {
			self.channel_transaction_parameters.funding_outpoint.map(|txo| txo.txid)
		})
	}

	/// Returns whether the channel is funded in a batch.
	pub fn is_batch_funding(&self) -> bool {
		self.is_batch_funding.is_some()
	}

	/// Returns the transaction ID if there is a pending batch funding transaction that is yet to be
	/// broadcast.
	pub fn unbroadcasted_batch_funding_txid(&self) -> Option<Txid> {
		self.unbroadcasted_funding_txid().filter(|_| self.is_batch_funding())
	}

	/// Gets the latest commitment transaction and any dependent transactions for relay (forcing
	/// shutdown of this channel - no more calls into this Channel may be made afterwards except
	/// those explicitly stated to be allowed after shutdown completes, eg some simple getters).
	/// Also returns the list of payment_hashes for channels which we can safely fail backwards
	/// immediately (others we will have to allow to time out).
	pub fn force_shutdown(
		&mut self, should_broadcast: bool, closure_reason: ClosureReason,
	) -> ShutdownResult {
		// Note that we MUST only generate a monitor update that indicates force-closure - we're
		// called during initialization prior to the chain_monitor in the encompassing ChannelManager
		// being fully configured in some cases. Thus, its likely any monitor events we generate will
		// be delayed in being processed! See the docs for `ChannelManagerReadArgs` for more.
		assert!(!matches!(self.channel_state, ChannelState::ShutdownComplete));

		// We go ahead and "free" any holding cell HTLCs or HTLCs we haven't yet committed to and
		// return them to fail the payment.
		let mut dropped_outbound_htlcs = Vec::with_capacity(self.holding_cell_htlc_updates.len());
		let counterparty_node_id = self.get_counterparty_node_id();
		for htlc_update in self.holding_cell_htlc_updates.drain(..) {
			match htlc_update {
				HTLCUpdateAwaitingACK::AddHTLC { source, payment_hash, .. } => {
					dropped_outbound_htlcs.push((
						source,
						payment_hash,
						counterparty_node_id,
						self.channel_id,
					));
				},
				_ => {},
			}
		}
		let monitor_update = if let Some(funding_txo) = self.get_funding_txo() {
			// If we haven't yet exchanged funding signatures (ie channel_state < AwaitingChannelReady),
			// returning a channel monitor update here would imply a channel monitor update before
			// we even registered the channel monitor to begin with, which is invalid.
			// Thus, if we aren't actually at a point where we could conceivably broadcast the
			// funding transaction, don't return a funding txo (which prevents providing the
			// monitor update to the user, even if we return one).
			// See test_duplicate_chan_id and test_pre_lockin_no_chan_closed_update for more.
			if !self.channel_state.is_pre_funded_state() {
				self.latest_monitor_update_id = CLOSED_CHANNEL_UPDATE_ID;
				Some((
					self.get_counterparty_node_id(),
					funding_txo,
					self.channel_id(),
					ChannelMonitorUpdate {
						update_id: self.latest_monitor_update_id,
						counterparty_node_id: Some(self.counterparty_node_id),
						updates: vec![ChannelMonitorUpdateStep::ChannelForceClosed {
							should_broadcast,
						}],
						channel_id: Some(self.channel_id()),
					},
				))
			} else {
				None
			}
		} else {
			None
		};
		let unbroadcasted_batch_funding_txid = self.unbroadcasted_batch_funding_txid();
		let unbroadcasted_funding_tx = self.unbroadcasted_funding();

		self.channel_state = ChannelState::ShutdownComplete;
		self.update_time_counter += 1;
		ShutdownResult {
			closure_reason,
			monitor_update,
			dropped_outbound_htlcs,
			unbroadcasted_batch_funding_txid,
			channel_id: self.channel_id,
			user_channel_id: self.user_id,
			channel_capacity_satoshis: self.channel_value_satoshis,
			counterparty_node_id: self.counterparty_node_id,
			unbroadcasted_funding_tx,
			is_manual_broadcast: self.is_manual_broadcast,
			channel_funding_txo: self.get_funding_txo(),
		}
	}

	/// Only allowed after [`Self::channel_transaction_parameters`] is set.
	fn get_funding_signed_msg<L: Deref>(
		&mut self, logger: &L,
	) -> (CommitmentTransaction, Option<msgs::FundingSigned>)
	where
		L::Target: Logger,
	{
		let counterparty_keys = self.build_remote_transaction_keys();
		let counterparty_initial_commitment_tx = self
			.build_commitment_transaction(
				self.cur_counterparty_commitment_transaction_number + 1,
				&counterparty_keys,
				false,
				false,
				logger,
			)
			.tx;

		let counterparty_trusted_tx = counterparty_initial_commitment_tx.trust();
		let counterparty_initial_bitcoin_tx = counterparty_trusted_tx.built_transaction();
		log_trace!(
			logger,
			"Initial counterparty tx for channel {} is: txid {} tx {}",
			&self.channel_id(),
			counterparty_initial_bitcoin_tx.txid,
			encode::serialize_hex(&counterparty_initial_bitcoin_tx.transaction)
		);

		match &self.holder_signer {
			// TODO (arik): move match into calling method for Taproot
			ChannelSignerType::Ecdsa(ecdsa) => {
				let funding_signed = ecdsa
					.sign_counterparty_commitment(
						&counterparty_initial_commitment_tx,
						Vec::new(),
						Vec::new(),
						&self.secp_ctx,
					)
					.map(|(signature, _)| msgs::FundingSigned {
						channel_id: self.channel_id(),
						signature,
						#[cfg(taproot)]
						partial_signature_with_nonce: None,
					})
					.ok();

				if funding_signed.is_none() {
					#[cfg(not(async_signing))]
					{
						panic!("Failed to get signature for funding_signed");
					}
					#[cfg(async_signing)]
					{
						log_trace!(logger, "Counterparty commitment signature not available for funding_signed message; setting signer_pending_funding");
						self.signer_pending_funding = true;
					}
				} else if self.signer_pending_funding {
					log_trace!(logger, "Counterparty commitment signature available for funding_signed message; clearing signer_pending_funding");
					self.signer_pending_funding = false;
				}

				// We sign "counterparty" commitment transaction, allowing them to broadcast the tx if they wish.
				(counterparty_initial_commitment_tx, funding_signed)
			},
			// TODO (taproot|arik)
			#[cfg(taproot)]
			_ => todo!(),
		}
	}

	/// If we receive an error message when attempting to open a channel, it may only be a rejection
	/// of the channel type we tried, not of our ability to open any channel at all. We can see if a
	/// downgrade of channel features would be possible so that we can still open the channel.
	pub(crate) fn maybe_downgrade_channel_features<F: Deref>(
		&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>,
	) -> Result<(), ()>
	where
		F::Target: FeeEstimator,
	{
		if !self.is_outbound()
			|| !matches!(
				self.channel_state, ChannelState::NegotiatingFunding(flags)
				if flags == NegotiatingFundingFlags::OUR_INIT_SENT
			) {
			return Err(());
		}
		if self.channel_type == ChannelTypeFeatures::only_static_remote_key() {
			// We've exhausted our options
			return Err(());
		}
		// We support opening a few different types of channels. Try removing our additional
		// features one by one until we've either arrived at our default or the counterparty has
		// accepted one.
		//
		// Due to the order below, we may not negotiate `option_anchors_zero_fee_htlc_tx` if the
		// counterparty doesn't support `option_scid_privacy`. Since `get_initial_channel_type`
		// checks whether the counterparty supports every feature, this would only happen if the
		// counterparty is advertising the feature, but rejecting channels proposing the feature for
		// whatever reason.
		if self.channel_type.supports_anchors_zero_fee_htlc_tx() {
			self.channel_type.clear_anchors_zero_fee_htlc_tx();
			self.feerate_per_kw =
				fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee);
			assert!(!self
				.channel_transaction_parameters
				.channel_type_features
				.supports_anchors_nonzero_fee_htlc_tx());
		} else if self.channel_type.supports_scid_privacy() {
			self.channel_type.clear_scid_privacy();
		} else {
			self.channel_type = ChannelTypeFeatures::only_static_remote_key();
		}
		self.channel_transaction_parameters.channel_type_features = self.channel_type.clone();
		Ok(())
	}
}

// Internal utility functions for channels

/// Returns the value to use for `holder_max_htlc_value_in_flight_msat` as a percentage of the
/// `channel_value_satoshis` in msat, set through
/// [`ChannelHandshakeConfig::max_inbound_htlc_value_in_flight_percent_of_channel`]
///
/// The effective percentage is lower bounded by 1% and upper bounded by 100%.
///
/// [`ChannelHandshakeConfig::max_inbound_htlc_value_in_flight_percent_of_channel`]: crate::util::config::ChannelHandshakeConfig::max_inbound_htlc_value_in_flight_percent_of_channel
fn get_holder_max_htlc_value_in_flight_msat(
	channel_value_satoshis: u64, config: &ChannelHandshakeConfig,
) -> u64 {
	let configured_percent = if config.max_inbound_htlc_value_in_flight_percent_of_channel < 1 {
		1
	} else if config.max_inbound_htlc_value_in_flight_percent_of_channel > 100 {
		100
	} else {
		config.max_inbound_htlc_value_in_flight_percent_of_channel as u64
	};
	channel_value_satoshis * 10 * configured_percent
}

/// Returns a minimum channel reserve value the remote needs to maintain,
/// required by us according to the configured or default
/// [`ChannelHandshakeConfig::their_channel_reserve_proportional_millionths`]
///
/// Guaranteed to return a value no larger than channel_value_satoshis
///
/// This is used both for outbound and inbound channels and has lower bound
/// of `MIN_THEIR_CHAN_RESERVE_SATOSHIS`.
pub(crate) fn get_holder_selected_channel_reserve_satoshis(
	channel_value_satoshis: u64, config: &UserConfig,
) -> u64 {
	let calculated_reserve = channel_value_satoshis.saturating_mul(
		config.channel_handshake_config.their_channel_reserve_proportional_millionths as u64,
	) / 1_000_000;
	cmp::min(channel_value_satoshis, cmp::max(calculated_reserve, MIN_THEIR_CHAN_RESERVE_SATOSHIS))
}

/// This is for legacy reasons, present for forward-compatibility.
/// LDK versions older than 0.0.104 don't know how read/handle values other than default
/// from storage. Hence, we use this function to not persist default values of
/// `holder_selected_channel_reserve_satoshis` for channels into storage.
pub(crate) fn get_legacy_default_holder_selected_channel_reserve_satoshis(
	channel_value_satoshis: u64,
) -> u64 {
	let (q, _) = channel_value_satoshis.overflowing_div(100);
	cmp::min(channel_value_satoshis, cmp::max(q, 1000))
}

/// Returns a minimum channel reserve value each party needs to maintain, fixed in the spec to a
/// default of 1% of the total channel value.
///
/// Guaranteed to return a value no larger than channel_value_satoshis
///
/// This is used both for outbound and inbound channels and has lower bound
/// of `dust_limit_satoshis`.
#[cfg(any(dual_funding, splicing))]
fn get_v2_channel_reserve_satoshis(channel_value_satoshis: u64, dust_limit_satoshis: u64) -> u64 {
	// Fixed at 1% of channel value by spec.
	let (q, _) = channel_value_satoshis.overflowing_div(100);
	cmp::min(channel_value_satoshis, cmp::max(q, dust_limit_satoshis))
}

/// Context for dual-funded channels.
#[cfg(any(dual_funding, splicing))]
pub(super) struct DualFundingChannelContext {
	/// The amount in satoshis we will be contributing to the channel.
	pub our_funding_satoshis: u64,
	/// The amount in satoshis our counterparty will be contributing to the channel.
	pub their_funding_satoshis: u64,
	/// The funding transaction locktime suggested by the initiator. If set by us, it is always set
	/// to the current block height to align incentives against fee-sniping.
	pub funding_tx_locktime: u32,
	/// The feerate set by the initiator to be used for the funding transaction.
	pub funding_feerate_sat_per_1000_weight: u32,
}

// Holder designates channel data owned for the benefit of the user client.
// Counterparty designates channel data owned by the another channel participant entity.
pub(super) struct Channel<SP: Deref>
where
	SP::Target: SignerProvider,
{
	pub context: ChannelContext<SP>,
	#[cfg(any(dual_funding, splicing))]
	pub dual_funding_channel_context: Option<DualFundingChannelContext>,
}

#[cfg(any(test, fuzzing))]
struct CommitmentTxInfoCached {
	fee: u64,
	total_pending_htlcs: usize,
	next_holder_htlc_id: u64,
	next_counterparty_htlc_id: u64,
	feerate: u32,
}

/// Contents of a wire message that fails an HTLC backwards. Useful for [`Channel::fail_htlc`] to
/// fail with either [`msgs::UpdateFailMalformedHTLC`] or [`msgs::UpdateFailHTLC`] as needed.
trait FailHTLCContents {
	type Message: FailHTLCMessageName;
	fn to_message(self, htlc_id: u64, channel_id: ChannelId) -> Self::Message;
	fn to_inbound_htlc_state(self) -> InboundHTLCState;
	fn to_htlc_update_awaiting_ack(self, htlc_id: u64) -> HTLCUpdateAwaitingACK;
}
impl FailHTLCContents for msgs::OnionErrorPacket {
	type Message = msgs::UpdateFailHTLC;
	fn to_message(self, htlc_id: u64, channel_id: ChannelId) -> Self::Message {
		msgs::UpdateFailHTLC { htlc_id, channel_id, reason: self }
	}
	fn to_inbound_htlc_state(self) -> InboundHTLCState {
		InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::FailRelay(self))
	}
	fn to_htlc_update_awaiting_ack(self, htlc_id: u64) -> HTLCUpdateAwaitingACK {
		HTLCUpdateAwaitingACK::FailHTLC { htlc_id, err_packet: self }
	}
}
impl FailHTLCContents for ([u8; 32], u16) {
	type Message = msgs::UpdateFailMalformedHTLC;
	fn to_message(self, htlc_id: u64, channel_id: ChannelId) -> Self::Message {
		msgs::UpdateFailMalformedHTLC {
			htlc_id,
			channel_id,
			sha256_of_onion: self.0,
			failure_code: self.1,
		}
	}
	fn to_inbound_htlc_state(self) -> InboundHTLCState {
		InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::FailMalformed(self))
	}
	fn to_htlc_update_awaiting_ack(self, htlc_id: u64) -> HTLCUpdateAwaitingACK {
		HTLCUpdateAwaitingACK::FailMalformedHTLC {
			htlc_id,
			sha256_of_onion: self.0,
			failure_code: self.1,
		}
	}
}

trait FailHTLCMessageName {
	fn name() -> &'static str;
}
impl FailHTLCMessageName for msgs::UpdateFailHTLC {
	fn name() -> &'static str {
		"update_fail_htlc"
	}
}
impl FailHTLCMessageName for msgs::UpdateFailMalformedHTLC {
	fn name() -> &'static str {
		"update_fail_malformed_htlc"
	}
}

impl<SP: Deref> Channel<SP>
where
	SP::Target: SignerProvider,
	<SP::Target as SignerProvider>::EcdsaSigner: EcdsaChannelSigner,
{
	fn check_remote_fee<F: Deref, L: Deref>(
		channel_type: &ChannelTypeFeatures, fee_estimator: &LowerBoundedFeeEstimator<F>,
		feerate_per_kw: u32, cur_feerate_per_kw: Option<u32>, logger: &L,
	) -> Result<(), ChannelError>
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		let lower_limit_conf_target = if channel_type.supports_anchors_zero_fee_htlc_tx() {
			ConfirmationTarget::MinAllowedAnchorChannelRemoteFee
		} else {
			ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee
		};
		let lower_limit = fee_estimator.bounded_sat_per_1000_weight(lower_limit_conf_target);
		if feerate_per_kw < lower_limit {
			if let Some(cur_feerate) = cur_feerate_per_kw {
				if feerate_per_kw > cur_feerate {
					log_warn!(logger,
						"Accepting feerate that may prevent us from closing this channel because it's higher than what we have now. Had {} s/kW, now {} s/kW.",
						cur_feerate, feerate_per_kw);
					return Ok(());
				}
			}
			return Err(ChannelError::Close((
				format!(
					"Peer's feerate much too low. Actual: {}. Our expected lower limit: {}",
					feerate_per_kw, lower_limit
				),
				ClosureReason::PeerFeerateTooLow {
					peer_feerate_sat_per_kw: feerate_per_kw,
					required_feerate_sat_per_kw: lower_limit,
				},
			)));
		}
		Ok(())
	}

	#[inline]
	fn get_closing_scriptpubkey(&self) -> ScriptBuf {
		// The shutdown scriptpubkey is set on channel opening when option_upfront_shutdown_script
		// is signaled. Otherwise, it is set when sending a shutdown message. Calling this method
		// outside of those situations will fail.
		self.context.shutdown_scriptpubkey.clone().unwrap().into_inner()
	}

	#[inline]
	fn get_closing_transaction_weight(
		&self, a_scriptpubkey: Option<&Script>, b_scriptpubkey: Option<&Script>,
	) -> u64 {
		let mut ret = (4 +                                                   // version
		 1 +                                                   // input count
		 36 +                                                  // prevout
		 1 +                                                   // script length (0)
		 4 +                                                   // sequence
		 1 +                                                   // output count
		 4                                                     // lock time
		 )*4 +                                                 // * 4 for non-witness parts
		2 +                                                    // witness marker and flag
		1 +                                                    // witness element count
		4 +                                                    // 4 element lengths (2 sigs, multisig dummy, and witness script)
		self.context.get_funding_redeemscript().len() as u64 + // funding witness script
		2*(1 + 71); // two signatures + sighash type flags
		if let Some(spk) = a_scriptpubkey {
			ret += ((8+1) +                                    // output values and script length
				spk.len() as u64)
				* 4; // scriptpubkey and witness multiplier
		}
		if let Some(spk) = b_scriptpubkey {
			ret += ((8+1) +                                    // output values and script length
				spk.len() as u64)
				* 4; // scriptpubkey and witness multiplier
		}
		ret
	}

	#[inline]
	fn build_closing_transaction(
		&self, proposed_total_fee_satoshis: u64, skip_remote_output: bool,
	) -> (ClosingTransaction, u64) {
		assert!(self.context.pending_inbound_htlcs.is_empty());
		assert!(self.context.pending_outbound_htlcs.is_empty());
		assert!(self.context.pending_update_fee.is_none());

		let mut total_fee_satoshis = proposed_total_fee_satoshis;
		let mut value_to_holder: i64 = (self.context.value_to_self_msat as i64) / 1000
			- if self.context.is_outbound() { total_fee_satoshis as i64 } else { 0 };
		let mut value_to_counterparty: i64 =
			((self.context.channel_value_satoshis * 1000 - self.context.value_to_self_msat) as i64
				/ 1000) - if self.context.is_outbound() { 0 } else { total_fee_satoshis as i64 };

		if value_to_holder < 0 {
			assert!(self.context.is_outbound());
			total_fee_satoshis += (-value_to_holder) as u64;
		} else if value_to_counterparty < 0 {
			assert!(!self.context.is_outbound());
			total_fee_satoshis += (-value_to_counterparty) as u64;
		}

		if skip_remote_output
			|| value_to_counterparty as u64 <= self.context.holder_dust_limit_satoshis
		{
			value_to_counterparty = 0;
		}

		if value_to_holder as u64 <= self.context.holder_dust_limit_satoshis {
			value_to_holder = 0;
		}

		assert!(self.context.shutdown_scriptpubkey.is_some());
		let holder_shutdown_script = self.get_closing_scriptpubkey();
		let counterparty_shutdown_script =
			self.context.counterparty_shutdown_scriptpubkey.clone().unwrap();
		let funding_outpoint = self.funding_outpoint().into_bitcoin_outpoint();

		let mut closing_transaction = ClosingTransaction::new(
			value_to_holder as u64,
			value_to_counterparty as u64,
			holder_shutdown_script,
			counterparty_shutdown_script,
			funding_outpoint,
		);
		if self.context.is_colored() {
			color_closing(
				&self.context.channel_id,
				&self.context.channel_transaction_parameters.funding_outpoint.unwrap(),
				&mut closing_transaction,
				&self.context.ldk_data_dir,
			)
			.expect("successful closing TX coloring");
		}
		(closing_transaction, total_fee_satoshis)
	}

	fn funding_outpoint(&self) -> OutPoint {
		self.context.channel_transaction_parameters.funding_outpoint.unwrap()
	}

	/// Claims an HTLC while we're disconnected from a peer, dropping the [`ChannelMonitorUpdate`]
	/// entirely.
	///
	/// The [`ChannelMonitor`] for this channel MUST be updated out-of-band with the preimage
	/// provided (i.e. without calling [`crate::chain::Watch::update_channel`]).
	///
	/// The HTLC claim will end up in the holding cell (because the caller must ensure the peer is
	/// disconnected).
	pub fn claim_htlc_while_disconnected_dropping_mon_update<L: Deref>(
		&mut self, htlc_id_arg: u64, payment_preimage_arg: PaymentPreimage, logger: &L,
	) where
		L::Target: Logger,
	{
		// Assert that we'll add the HTLC claim to the holding cell in `get_update_fulfill_htlc`
		// (see equivalent if condition there).
		assert!(!self.context.channel_state.can_generate_new_commitment());
		let mon_update_id = self.context.latest_monitor_update_id; // Forget the ChannelMonitor update
		let fulfill_resp = self.get_update_fulfill_htlc(htlc_id_arg, payment_preimage_arg, logger);
		self.context.latest_monitor_update_id = mon_update_id;
		if let UpdateFulfillFetch::NewClaim { msg, .. } = fulfill_resp {
			assert!(msg.is_none()); // The HTLC must have ended up in the holding cell.
		}
	}

	fn get_update_fulfill_htlc<L: Deref>(
		&mut self, htlc_id_arg: u64, payment_preimage_arg: PaymentPreimage, logger: &L,
	) -> UpdateFulfillFetch
	where
		L::Target: Logger,
	{
		// Either ChannelReady got set (which means it won't be unset) or there is no way any
		// caller thought we could have something claimed (cause we wouldn't have accepted in an
		// incoming HTLC anyway). If we got to ShutdownComplete, callers aren't allowed to call us,
		// either.
		if !matches!(self.context.channel_state, ChannelState::ChannelReady(_)) {
			panic!("Was asked to fulfill an HTLC when channel was not in an operational state");
		}

		// ChannelManager may generate duplicate claims/fails due to HTLC update events from
		// on-chain ChannelsMonitors during block rescan. Ideally we'd figure out a way to drop
		// these, but for now we just have to treat them as normal.

		let mut pending_idx = core::usize::MAX;
		let mut htlc_value_msat = 0;
		for (idx, htlc) in self.context.pending_inbound_htlcs.iter().enumerate() {
			if htlc.htlc_id == htlc_id_arg {
				debug_assert_eq!(
					htlc.payment_hash,
					PaymentHash(Sha256::hash(&payment_preimage_arg.0[..]).to_byte_array())
				);
				log_debug!(
					logger,
					"Claiming inbound HTLC id {} with payment hash {} with preimage {}",
					htlc.htlc_id,
					htlc.payment_hash,
					payment_preimage_arg
				);
				match htlc.state {
					InboundHTLCState::Committed => {},
					InboundHTLCState::LocalRemoved(ref reason) => {
						if let &InboundHTLCRemovalReason::Fulfill(_) = reason {
						} else {
							log_warn!(logger, "Have preimage and want to fulfill HTLC with payment hash {} we already failed against channel {}", &htlc.payment_hash, &self.context.channel_id());
							debug_assert!(
								false,
								"Tried to fulfill an HTLC that was already failed"
							);
						}
						return UpdateFulfillFetch::DuplicateClaim {};
					},
					_ => {
						debug_assert!(false, "Have an inbound HTLC we tried to claim before it was fully committed to");
						// Don't return in release mode here so that we can update channel_monitor
					},
				}
				pending_idx = idx;
				htlc_value_msat = htlc.amount_msat;
				break;
			}
		}
		if pending_idx == core::usize::MAX {
			#[cfg(any(test, fuzzing))]
			// If we failed to find an HTLC to fulfill, make sure it was previously fulfilled and
			// this is simply a duplicate claim, not previously failed and we lost funds.
			debug_assert!(self.context.historical_inbound_htlc_fulfills.contains(&htlc_id_arg));
			return UpdateFulfillFetch::DuplicateClaim {};
		}

		// Now update local state:
		//
		// We have to put the payment_preimage in the channel_monitor right away here to ensure we
		// can claim it even if the channel hits the chain before we see their next commitment.
		self.context.latest_monitor_update_id += 1;
		let monitor_update = ChannelMonitorUpdate {
			update_id: self.context.latest_monitor_update_id,
			counterparty_node_id: Some(self.context.counterparty_node_id),
			updates: vec![ChannelMonitorUpdateStep::PaymentPreimage {
				payment_preimage: payment_preimage_arg.clone(),
			}],
			channel_id: Some(self.context.channel_id()),
		};

		if !self.context.channel_state.can_generate_new_commitment() {
			// Note that this condition is the same as the assertion in
			// `claim_htlc_while_disconnected_dropping_mon_update` and must match exactly -
			// `claim_htlc_while_disconnected_dropping_mon_update` would not work correctly if we
			// do not not get into this branch.
			for pending_update in self.context.holding_cell_htlc_updates.iter() {
				match pending_update {
					&HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							// Make sure we don't leave latest_monitor_update_id incremented here:
							self.context.latest_monitor_update_id -= 1;
							#[cfg(any(test, fuzzing))]
							debug_assert!(self
								.context
								.historical_inbound_htlc_fulfills
								.contains(&htlc_id_arg));
							return UpdateFulfillFetch::DuplicateClaim {};
						}
					},
					&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. }
					| &HTLCUpdateAwaitingACK::FailMalformedHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							log_warn!(logger, "Have preimage and want to fulfill HTLC with pending failure against channel {}", &self.context.channel_id());
							// TODO: We may actually be able to switch to a fulfill here, though its
							// rare enough it may not be worth the complexity burden.
							debug_assert!(
								false,
								"Tried to fulfill an HTLC that was already failed"
							);
							return UpdateFulfillFetch::NewClaim {
								monitor_update,
								htlc_value_msat,
								msg: None,
							};
						}
					},
					_ => {},
				}
			}
			log_trace!(
				logger,
				"Adding HTLC claim to holding_cell in channel {}! Current state: {}",
				&self.context.channel_id(),
				self.context.channel_state.to_u32()
			);
			self.context.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::ClaimHTLC {
				payment_preimage: payment_preimage_arg,
				htlc_id: htlc_id_arg,
			});
			#[cfg(any(test, fuzzing))]
			self.context.historical_inbound_htlc_fulfills.insert(htlc_id_arg);
			return UpdateFulfillFetch::NewClaim { monitor_update, htlc_value_msat, msg: None };
		}
		#[cfg(any(test, fuzzing))]
		self.context.historical_inbound_htlc_fulfills.insert(htlc_id_arg);

		{
			let htlc = &mut self.context.pending_inbound_htlcs[pending_idx];
			if let InboundHTLCState::Committed = htlc.state {
			} else {
				debug_assert!(
					false,
					"Have an inbound HTLC we tried to claim before it was fully committed to"
				);
				return UpdateFulfillFetch::NewClaim { monitor_update, htlc_value_msat, msg: None };
			}
			log_trace!(
				logger,
				"Upgrading HTLC {} to LocalRemoved with a Fulfill in channel {}!",
				&htlc.payment_hash,
				&self.context.channel_id
			);
			htlc.state = InboundHTLCState::LocalRemoved(InboundHTLCRemovalReason::Fulfill(
				payment_preimage_arg.clone(),
			));
		}

		UpdateFulfillFetch::NewClaim {
			monitor_update,
			htlc_value_msat,
			msg: Some(msgs::UpdateFulfillHTLC {
				channel_id: self.context.channel_id(),
				htlc_id: htlc_id_arg,
				payment_preimage: payment_preimage_arg,
			}),
		}
	}

	pub fn get_update_fulfill_htlc_and_commit<L: Deref>(
		&mut self, htlc_id: u64, payment_preimage: PaymentPreimage, logger: &L,
	) -> UpdateFulfillCommitFetch
	where
		L::Target: Logger,
	{
		let release_cs_monitor = self.context.blocked_monitor_updates.is_empty();
		match self.get_update_fulfill_htlc(htlc_id, payment_preimage, logger) {
			UpdateFulfillFetch::NewClaim { mut monitor_update, htlc_value_msat, msg } => {
				// Even if we aren't supposed to let new monitor updates with commitment state
				// updates run, we still need to push the preimage ChannelMonitorUpdateStep no
				// matter what. Sadly, to push a new monitor update which flies before others
				// already queued, we have to insert it into the pending queue and update the
				// update_ids of all the following monitors.
				if release_cs_monitor && msg.is_some() {
					let mut additional_update = self.build_commitment_no_status_check(logger);
					// build_commitment_no_status_check may bump latest_monitor_id but we want them
					// to be strictly increasing by one, so decrement it here.
					self.context.latest_monitor_update_id = monitor_update.update_id;
					monitor_update.updates.append(&mut additional_update.updates);
				} else {
					let new_mon_id = self
						.context
						.blocked_monitor_updates
						.get(0)
						.map(|upd| upd.update.update_id)
						.unwrap_or(monitor_update.update_id);
					monitor_update.update_id = new_mon_id;
					for held_update in self.context.blocked_monitor_updates.iter_mut() {
						held_update.update.update_id += 1;
					}
					if msg.is_some() {
						debug_assert!(false, "If there is a pending blocked monitor we should have MonitorUpdateInProgress set");
						let update = self.build_commitment_no_status_check(logger);
						self.context
							.blocked_monitor_updates
							.push(PendingChannelMonitorUpdate { update });
					}
				}

				self.monitor_updating_paused(
					false,
					msg.is_some(),
					false,
					Vec::new(),
					Vec::new(),
					Vec::new(),
				);
				UpdateFulfillCommitFetch::NewClaim { monitor_update, htlc_value_msat }
			},
			UpdateFulfillFetch::DuplicateClaim {} => UpdateFulfillCommitFetch::DuplicateClaim {},
		}
	}

	/// We can only have one resolution per HTLC. In some cases around reconnect, we may fulfill
	/// an HTLC more than once or fulfill once and then attempt to fail after reconnect. We cannot,
	/// however, fail more than once as we wait for an upstream failure to be irrevocably committed
	/// before we fail backwards.
	///
	/// If we do fail twice, we `debug_assert!(false)` and return `Ok(None)`. Thus, this will always
	/// return `Ok(_)` if preconditions are met. In any case, `Err`s will only be
	/// [`ChannelError::Ignore`].
	pub fn queue_fail_htlc<L: Deref>(
		&mut self, htlc_id_arg: u64, err_packet: msgs::OnionErrorPacket, logger: &L,
	) -> Result<(), ChannelError>
	where
		L::Target: Logger,
	{
		self.fail_htlc(htlc_id_arg, err_packet, true, logger)
			.map(|msg_opt| assert!(msg_opt.is_none(), "We forced holding cell?"))
	}

	/// Used for failing back with [`msgs::UpdateFailMalformedHTLC`]. For now, this is used when we
	/// want to fail blinded HTLCs where we are not the intro node.
	///
	/// See [`Self::queue_fail_htlc`] for more info.
	pub fn queue_fail_malformed_htlc<L: Deref>(
		&mut self, htlc_id_arg: u64, failure_code: u16, sha256_of_onion: [u8; 32], logger: &L,
	) -> Result<(), ChannelError>
	where
		L::Target: Logger,
	{
		self.fail_htlc(htlc_id_arg, (sha256_of_onion, failure_code), true, logger)
			.map(|msg_opt| assert!(msg_opt.is_none(), "We forced holding cell?"))
	}

	/// We can only have one resolution per HTLC. In some cases around reconnect, we may fulfill
	/// an HTLC more than once or fulfill once and then attempt to fail after reconnect. We cannot,
	/// however, fail more than once as we wait for an upstream failure to be irrevocably committed
	/// before we fail backwards.
	///
	/// If we do fail twice, we `debug_assert!(false)` and return `Ok(None)`. Thus, this will always
	/// return `Ok(_)` if preconditions are met. In any case, `Err`s will only be
	/// [`ChannelError::Ignore`].
	fn fail_htlc<L: Deref, E: FailHTLCContents + Clone>(
		&mut self, htlc_id_arg: u64, err_contents: E, mut force_holding_cell: bool, logger: &L,
	) -> Result<Option<E::Message>, ChannelError>
	where
		L::Target: Logger,
	{
		if !matches!(self.context.channel_state, ChannelState::ChannelReady(_)) {
			panic!("Was asked to fail an HTLC when channel was not in an operational state");
		}

		// ChannelManager may generate duplicate claims/fails due to HTLC update events from
		// on-chain ChannelsMonitors during block rescan. Ideally we'd figure out a way to drop
		// these, but for now we just have to treat them as normal.

		let mut pending_idx = core::usize::MAX;
		for (idx, htlc) in self.context.pending_inbound_htlcs.iter().enumerate() {
			if htlc.htlc_id == htlc_id_arg {
				match htlc.state {
					InboundHTLCState::Committed => {},
					InboundHTLCState::LocalRemoved(ref reason) => {
						if let &InboundHTLCRemovalReason::Fulfill(_) = reason {
						} else {
							debug_assert!(false, "Tried to fail an HTLC that was already failed");
						}
						return Ok(None);
					},
					_ => {
						debug_assert!(false, "Have an inbound HTLC we tried to claim before it was fully committed to");
						return Err(ChannelError::Ignore(format!(
							"Unable to find a pending HTLC which matched the given HTLC ID ({})",
							htlc.htlc_id
						)));
					},
				}
				pending_idx = idx;
			}
		}
		if pending_idx == core::usize::MAX {
			#[cfg(any(test, fuzzing))]
			// If we failed to find an HTLC to fail, make sure it was previously fulfilled and this
			// is simply a duplicate fail, not previously failed and we failed-back too early.
			debug_assert!(self.context.historical_inbound_htlc_fulfills.contains(&htlc_id_arg));
			return Ok(None);
		}

		if !self.context.channel_state.can_generate_new_commitment() {
			debug_assert!(force_holding_cell, "!force_holding_cell is only called when emptying the holding cell, so we shouldn't end up back in it!");
			force_holding_cell = true;
		}

		// Now update local state:
		if force_holding_cell {
			for pending_update in self.context.holding_cell_htlc_updates.iter() {
				match pending_update {
					&HTLCUpdateAwaitingACK::ClaimHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							#[cfg(any(test, fuzzing))]
							debug_assert!(self
								.context
								.historical_inbound_htlc_fulfills
								.contains(&htlc_id_arg));
							return Ok(None);
						}
					},
					&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, .. }
					| &HTLCUpdateAwaitingACK::FailMalformedHTLC { htlc_id, .. } => {
						if htlc_id_arg == htlc_id {
							debug_assert!(false, "Tried to fail an HTLC that was already failed");
							return Err(ChannelError::Ignore(
								"Unable to find a pending HTLC which matched the given HTLC ID"
									.to_owned(),
							));
						}
					},
					_ => {},
				}
			}
			log_trace!(
				logger,
				"Placing failure for HTLC ID {} in holding cell in channel {}.",
				htlc_id_arg,
				&self.context.channel_id()
			);
			self.context
				.holding_cell_htlc_updates
				.push(err_contents.to_htlc_update_awaiting_ack(htlc_id_arg));
			return Ok(None);
		}

		log_trace!(
			logger,
			"Failing HTLC ID {} back with {} message in channel {}.",
			htlc_id_arg,
			E::Message::name(),
			&self.context.channel_id()
		);
		{
			let htlc = &mut self.context.pending_inbound_htlcs[pending_idx];
			htlc.state = err_contents.clone().to_inbound_htlc_state();
		}

		Ok(Some(err_contents.to_message(htlc_id_arg, self.context.channel_id())))
	}

	// Message handlers:
	/// Updates the state of the channel to indicate that all channels in the batch have received
	/// funding_signed and persisted their monitors.
	/// The funding transaction is consequently allowed to be broadcast, and the channel can be
	/// treated as a non-batch channel going forward.
	pub fn set_batch_ready(&mut self) {
		self.context.is_batch_funding = None;
		self.context.channel_state.clear_waiting_for_batch();
	}

	/// Unsets the existing funding information.
	///
	/// This must only be used if the channel has not yet completed funding and has not been used.
	///
	/// Further, the channel must be immediately shut down after this with a call to
	/// [`ChannelContext::force_shutdown`].
	pub fn unset_funding_info(&mut self, temporary_channel_id: ChannelId) {
		debug_assert!(matches!(self.context.channel_state, ChannelState::AwaitingChannelReady(_)));
		self.context.channel_transaction_parameters.funding_outpoint = None;
		self.context.channel_id = temporary_channel_id;
	}

	/// Handles a channel_ready message from our peer. If we've already sent our channel_ready
	/// and the channel is now usable (and public), this may generate an announcement_signatures to
	/// reply with.
	pub fn channel_ready<NS: Deref, L: Deref>(
		&mut self, msg: &msgs::ChannelReady, node_signer: &NS, chain_hash: ChainHash,
		user_config: &UserConfig, best_block: &BestBlock, logger: &L,
	) -> Result<Option<msgs::AnnouncementSignatures>, ChannelError>
	where
		NS::Target: NodeSigner,
		L::Target: Logger,
	{
		if self.context.channel_state.is_peer_disconnected() {
			self.context.workaround_lnd_bug_4006 = Some(msg.clone());
			return Err(ChannelError::Ignore("Peer sent channel_ready when we needed a channel_reestablish. The peer is likely lnd, see https://github.com/lightningnetwork/lnd/issues/4006".to_owned()));
		}

		if let Some(scid_alias) = msg.short_channel_id_alias {
			if Some(scid_alias) != self.context.short_channel_id {
				// The scid alias provided can be used to route payments *from* our counterparty,
				// i.e. can be used for inbound payments and provided in invoices, but is not used
				// when routing outbound payments.
				self.context.latest_inbound_scid_alias = Some(scid_alias);
			}
		}

		// Our channel_ready shouldn't have been sent if we are waiting for other channels in the
		// batch, but we can receive channel_ready messages.
		let mut check_reconnection = false;
		match &self.context.channel_state {
			ChannelState::AwaitingChannelReady(flags) => {
				let flags = flags.clone().clear(FundedStateFlags::ALL.into());
				debug_assert!(
					!flags.is_set(AwaitingChannelReadyFlags::OUR_CHANNEL_READY)
						|| !flags.is_set(AwaitingChannelReadyFlags::WAITING_FOR_BATCH)
				);
				if flags.clone().clear(AwaitingChannelReadyFlags::WAITING_FOR_BATCH)
					== AwaitingChannelReadyFlags::THEIR_CHANNEL_READY
				{
					// If we reconnected before sending our `channel_ready` they may still resend theirs.
					check_reconnection = true;
				} else if flags
					.clone()
					.clear(AwaitingChannelReadyFlags::WAITING_FOR_BATCH)
					.is_empty()
				{
					self.context.channel_state.set_their_channel_ready();
				} else if flags == AwaitingChannelReadyFlags::OUR_CHANNEL_READY {
					self.context.channel_state = ChannelState::ChannelReady(
						self.context.channel_state.with_funded_state_flags_mask().into(),
					);
					self.context.update_time_counter += 1;
				} else {
					// We're in `WAITING_FOR_BATCH`, so we should wait until we're ready.
					debug_assert!(flags.is_set(AwaitingChannelReadyFlags::WAITING_FOR_BATCH));
				}
			},
			// If we reconnected before sending our `channel_ready` they may still resend theirs.
			ChannelState::ChannelReady(_) => check_reconnection = true,
			_ => {
				return Err(ChannelError::close(
					"Peer sent a channel_ready at a strange time".to_owned(),
				))
			},
		}
		if check_reconnection {
			// They probably disconnected/reconnected and re-sent the channel_ready, which is
			// required, or they're sending a fresh SCID alias.
			let expected_point = if self.context.cur_counterparty_commitment_transaction_number
				== INITIAL_COMMITMENT_NUMBER - 1
			{
				// If they haven't ever sent an updated point, the point they send should match
				// the current one.
				self.context.counterparty_cur_commitment_point
			} else if self.context.cur_counterparty_commitment_transaction_number
				== INITIAL_COMMITMENT_NUMBER - 2
			{
				// If we've advanced the commitment number once, the second commitment point is
				// at `counterparty_prev_commitment_point`, which is not yet revoked.
				debug_assert!(self.context.counterparty_prev_commitment_point.is_some());
				self.context.counterparty_prev_commitment_point
			} else {
				// If they have sent updated points, channel_ready is always supposed to match
				// their "first" point, which we re-derive here.
				Some(PublicKey::from_secret_key(&self.context.secp_ctx, &SecretKey::from_slice(
							&self.context.commitment_secrets.get_secret(INITIAL_COMMITMENT_NUMBER - 1).expect("We should have all prev secrets available")
						).expect("We already advanced, so previous secret keys should have been validated already")))
			};
			if expected_point != Some(msg.next_per_commitment_point) {
				return Err(ChannelError::close(
					"Peer sent a reconnect channel_ready with a different point".to_owned(),
				));
			}
			return Ok(None);
		}

		self.context.counterparty_prev_commitment_point =
			self.context.counterparty_cur_commitment_point;
		self.context.counterparty_cur_commitment_point = Some(msg.next_per_commitment_point);

		log_info!(
			logger,
			"Received channel_ready from peer for channel {}",
			&self.context.channel_id()
		);

		Ok(self.get_announcement_sigs(
			node_signer,
			chain_hash,
			user_config,
			best_block.height,
			logger,
		))
	}

	pub fn update_add_htlc<F: Deref>(
		&mut self, msg: &msgs::UpdateAddHTLC, pending_forward_status: PendingHTLCStatus,
		fee_estimator: &LowerBoundedFeeEstimator<F>,
	) -> Result<(), ChannelError>
	where
		F::Target: FeeEstimator,
	{
		if !matches!(self.context.channel_state, ChannelState::ChannelReady(_)) {
			return Err(ChannelError::close(
				"Got add HTLC message when channel was not in an operational state".to_owned(),
			));
		}
		// If the remote has sent a shutdown prior to adding this HTLC, then they are in violation of the spec.
		if self.context.channel_state.is_remote_shutdown_sent() {
			return Err(ChannelError::close(
				"Got add HTLC message when channel was not in an operational state".to_owned(),
			));
		}
		if self.context.channel_state.is_peer_disconnected() {
			return Err(ChannelError::close(
				"Peer sent update_add_htlc when we needed a channel_reestablish".to_owned(),
			));
		}
		if msg.amount_msat > self.context.channel_value_satoshis * 1000 {
			return Err(ChannelError::close(
				"Remote side tried to send more than the total value of the channel".to_owned(),
			));
		}
		if msg.amount_msat == 0 {
			return Err(ChannelError::close("Remote side tried to send a 0-msat HTLC".to_owned()));
		}
		if msg.amount_msat < self.context.holder_htlc_minimum_msat {
			return Err(ChannelError::close(format!("Remote side tried to send less than our minimum HTLC value. Lower limit: ({}). Actual: ({})", self.context.holder_htlc_minimum_msat, msg.amount_msat)));
		}

		let dust_exposure_limiting_feerate =
			self.context.get_dust_exposure_limiting_feerate(&fee_estimator);
		let htlc_stats = self.context.get_pending_htlc_stats(None, dust_exposure_limiting_feerate);
		if htlc_stats.pending_inbound_htlcs + 1 > self.context.holder_max_accepted_htlcs as usize {
			return Err(ChannelError::close(format!(
				"Remote tried to push more than our max accepted HTLCs ({})",
				self.context.holder_max_accepted_htlcs
			)));
		}
		if htlc_stats.pending_inbound_htlcs_value_msat + msg.amount_msat
			> self.context.holder_max_htlc_value_in_flight_msat
		{
			return Err(ChannelError::close(format!(
				"Remote HTLC add would put them over our max HTLC value ({})",
				self.context.holder_max_htlc_value_in_flight_msat
			)));
		}

		// Check holder_selected_channel_reserve_satoshis (we're getting paid, so they have to at least meet
		// the reserve_satoshis we told them to always have as direct payment so that they lose
		// something if we punish them for broadcasting an old state).
		// Note that we don't really care about having a small/no to_remote output in our local
		// commitment transactions, as the purpose of the channel reserve is to ensure we can
		// punish *them* if they misbehave, so we discount any outbound HTLCs which will not be
		// present in the next commitment transaction we send them (at least for fulfilled ones,
		// failed ones won't modify value_to_self).
		// Note that we will send HTLCs which another instance of rust-lightning would think
		// violate the reserve value if we do not do this (as we forget inbound HTLCs from the
		// Channel state once they will not be present in the next received commitment
		// transaction).
		let mut removed_outbound_total_msat = 0;
		for ref htlc in self.context.pending_outbound_htlcs.iter() {
			if let OutboundHTLCState::AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome::Success(
				_,
			)) = htlc.state
			{
				removed_outbound_total_msat += htlc.amount_msat;
			} else if let OutboundHTLCState::AwaitingRemovedRemoteRevoke(
				OutboundHTLCOutcome::Success(_),
			) = htlc.state
			{
				removed_outbound_total_msat += htlc.amount_msat;
			}
		}

		let pending_value_to_self_msat = self.context.value_to_self_msat
			+ htlc_stats.pending_inbound_htlcs_value_msat
			- removed_outbound_total_msat;
		let pending_remote_value_msat =
			self.context.channel_value_satoshis * 1000 - pending_value_to_self_msat;
		if pending_remote_value_msat < msg.amount_msat {
			return Err(ChannelError::close(
				"Remote HTLC add would overdraw remaining funds".to_owned(),
			));
		}
		if msg.amount_rgb > Some(self.context.get_remote_rgb_amount()) {
			return Err(ChannelError::Close("Not enough RGB funds to accept this HTLC".to_owned()));
		}

		// Check that the remote can afford to pay for this HTLC on-chain at the current
		// feerate_per_kw, while maintaining their channel reserve (as required by the spec).
		{
			let remote_commit_tx_fee_msat = if self.context.is_outbound() {
				0
			} else {
				let htlc_candidate =
					HTLCCandidate::new(msg.amount_msat, HTLCInitiator::RemoteOffered);
				self.context.next_remote_commit_tx_fee_msat(htlc_candidate, None) // Don't include the extra fee spike buffer HTLC in calculations
			};
			let anchor_outputs_value_msat = if !self.context.is_outbound()
				&& self.context.get_channel_type().supports_anchors_zero_fee_htlc_tx()
			{
				ANCHOR_OUTPUT_VALUE_SATOSHI * 2 * 1000
			} else {
				0
			};
			if pending_remote_value_msat
				.saturating_sub(msg.amount_msat)
				.saturating_sub(anchor_outputs_value_msat)
				< remote_commit_tx_fee_msat
			{
				return Err(ChannelError::close(
					"Remote HTLC add would not leave enough to pay for fees".to_owned(),
				));
			};
			if pending_remote_value_msat
				.saturating_sub(msg.amount_msat)
				.saturating_sub(remote_commit_tx_fee_msat)
				.saturating_sub(anchor_outputs_value_msat)
				< self.context.holder_selected_channel_reserve_satoshis * 1000
			{
				return Err(ChannelError::close(
					"Remote HTLC add would put them under remote reserve value".to_owned(),
				));
			}
		}

		let anchor_outputs_value_msat =
			if self.context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
				ANCHOR_OUTPUT_VALUE_SATOSHI * 2 * 1000
			} else {
				0
			};
		if self.context.is_outbound() {
			// Check that they won't violate our local required channel reserve by adding this HTLC.
			let htlc_candidate = HTLCCandidate::new(msg.amount_msat, HTLCInitiator::RemoteOffered);
			let local_commit_tx_fee_msat =
				self.context.next_local_commit_tx_fee_msat(htlc_candidate, None);
			if self.context.value_to_self_msat
				< self.context.counterparty_selected_channel_reserve_satoshis.unwrap() * 1000
					+ local_commit_tx_fee_msat
					+ anchor_outputs_value_msat
			{
				return Err(ChannelError::close("Cannot accept HTLC that would put our balance under counterparty-announced channel reserve value".to_owned()));
			}
		}
		if self.context.next_counterparty_htlc_id != msg.htlc_id {
			return Err(ChannelError::close(format!(
				"Remote skipped HTLC ID (skipped ID: {})",
				self.context.next_counterparty_htlc_id
			)));
		}
		if msg.cltv_expiry >= 500000000 {
			return Err(ChannelError::close(
				"Remote provided CLTV expiry in seconds instead of block height".to_owned(),
			));
		}

		if self.context.channel_state.is_local_shutdown_sent() {
			if let PendingHTLCStatus::Forward(_) = pending_forward_status {
				panic!("ChannelManager shouldn't be trying to add a forwardable HTLC after we've started closing");
			}
		}

		// Now update local state:
		self.context.next_counterparty_htlc_id += 1;
		self.context.pending_inbound_htlcs.push(InboundHTLCOutput {
			htlc_id: msg.htlc_id,
			amount_msat: msg.amount_msat,
			payment_hash: msg.payment_hash,
			cltv_expiry: msg.cltv_expiry,
			state: InboundHTLCState::RemoteAnnounced(InboundHTLCResolution::Resolved {
				pending_htlc_status: pending_forward_status,
			}),
			amount_rgb: msg.amount_rgb,
		});
		Ok(())
	}

	/// Marks an outbound HTLC which we have received update_fail/fulfill/malformed
	#[inline]
	fn mark_outbound_htlc_removed(
		&mut self, htlc_id: u64, check_preimage: Option<PaymentPreimage>,
		fail_reason: Option<HTLCFailReason>,
	) -> Result<&OutboundHTLCOutput, ChannelError> {
		assert!(
			!(check_preimage.is_some() && fail_reason.is_some()),
			"cannot fail while we have a preimage"
		);
		for htlc in self.context.pending_outbound_htlcs.iter_mut() {
			if htlc.htlc_id == htlc_id {
				let outcome = match check_preimage {
					None => fail_reason.into(),
					Some(payment_preimage) => {
						let payment_hash =
							PaymentHash(Sha256::hash(&payment_preimage.0[..]).to_byte_array());
						if payment_hash != htlc.payment_hash {
							return Err(ChannelError::close(format!(
								"Remote tried to fulfill HTLC ({}) with an incorrect preimage",
								htlc_id
							)));
						}
						OutboundHTLCOutcome::Success(Some(payment_preimage))
					},
				};
				match htlc.state {
					OutboundHTLCState::LocalAnnounced(_) =>
						return Err(ChannelError::close(format!("Remote tried to fulfill/fail HTLC ({}) before it had been committed", htlc_id))),
					OutboundHTLCState::Committed => {
						htlc.state = OutboundHTLCState::RemoteRemoved(outcome);
					},
					OutboundHTLCState::AwaitingRemoteRevokeToRemove(_) | OutboundHTLCState::AwaitingRemovedRemoteRevoke(_) | OutboundHTLCState::RemoteRemoved(_) =>
						return Err(ChannelError::close(format!("Remote tried to fulfill/fail HTLC ({}) that they'd already fulfilled/failed", htlc_id))),
				}
				return Ok(htlc);
			}
		}
		Err(ChannelError::close("Remote tried to fulfill/fail an HTLC we couldn't find".to_owned()))
	}

	pub fn update_fulfill_htlc(
		&mut self, msg: &msgs::UpdateFulfillHTLC,
	) -> Result<(HTLCSource, u64, Option<u64>, Option<u64>), ChannelError> {
		if !matches!(self.context.channel_state, ChannelState::ChannelReady(_)) {
			return Err(ChannelError::close(
				"Got fulfill HTLC message when channel was not in an operational state".to_owned(),
			));
		}
		if self.context.channel_state.is_peer_disconnected() {
			return Err(ChannelError::close(
				"Peer sent update_fulfill_htlc when we needed a channel_reestablish".to_owned(),
			));
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, Some(msg.payment_preimage), None).map(|htlc| {
			(htlc.source.clone(), htlc.amount_msat, htlc.skimmed_fee_msat, htlc.amount_rgb)
		})
	}

	pub fn update_fail_htlc(
		&mut self, msg: &msgs::UpdateFailHTLC, fail_reason: HTLCFailReason,
	) -> Result<(), ChannelError> {
		if !matches!(self.context.channel_state, ChannelState::ChannelReady(_)) {
			return Err(ChannelError::close(
				"Got fail HTLC message when channel was not in an operational state".to_owned(),
			));
		}
		if self.context.channel_state.is_peer_disconnected() {
			return Err(ChannelError::close(
				"Peer sent update_fail_htlc when we needed a channel_reestablish".to_owned(),
			));
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, None, Some(fail_reason))?;
		Ok(())
	}

	pub fn update_fail_malformed_htlc(
		&mut self, msg: &msgs::UpdateFailMalformedHTLC, fail_reason: HTLCFailReason,
	) -> Result<(), ChannelError> {
		if !matches!(self.context.channel_state, ChannelState::ChannelReady(_)) {
			return Err(ChannelError::close(
				"Got fail malformed HTLC message when channel was not in an operational state"
					.to_owned(),
			));
		}
		if self.context.channel_state.is_peer_disconnected() {
			return Err(ChannelError::close(
				"Peer sent update_fail_malformed_htlc when we needed a channel_reestablish"
					.to_owned(),
			));
		}

		self.mark_outbound_htlc_removed(msg.htlc_id, None, Some(fail_reason))?;
		Ok(())
	}

	pub fn commitment_signed<L: Deref>(
		&mut self, msg: &msgs::CommitmentSigned, logger: &L,
	) -> Result<Option<ChannelMonitorUpdate>, ChannelError>
	where
		L::Target: Logger,
	{
		if !matches!(self.context.channel_state, ChannelState::ChannelReady(_)) {
			return Err(ChannelError::close(
				"Got commitment signed message when channel was not in an operational state"
					.to_owned(),
			));
		}
		if self.context.channel_state.is_peer_disconnected() {
			return Err(ChannelError::close(
				"Peer sent commitment_signed when we needed a channel_reestablish".to_owned(),
			));
		}
		if self.context.channel_state.is_both_sides_shutdown()
			&& self.context.last_sent_closing_fee.is_some()
		{
			return Err(ChannelError::close(
				"Peer sent commitment_signed after we'd started exchanging closing_signeds"
					.to_owned(),
			));
		}

		let funding_script = self.context.get_funding_redeemscript();

		let keys = self.context.build_holder_transaction_keys();

		let mut commitment_stats = self.context.build_commitment_transaction(
			self.context.holder_commitment_point.transaction_number(),
			&keys,
			true,
			false,
			logger,
		);
		if self.context.is_colored() {
			color_commitment(&self.context, &mut commitment_stats.tx, false)?;
		}

		let commitment_txid = {
			let trusted_tx = commitment_stats.tx.trust();
			let bitcoin_tx = trusted_tx.built_transaction();
			let sighash =
				bitcoin_tx.get_sighash_all(&funding_script, self.context.channel_value_satoshis);

			log_trace!(logger, "Checking commitment tx signature {} by key {} against tx {} (sighash {}) with redeemscript {} in channel {}",
				log_bytes!(msg.signature.serialize_compact()[..]),
				log_bytes!(self.context.counterparty_funding_pubkey().serialize()), encode::serialize_hex(&bitcoin_tx.transaction),
				log_bytes!(sighash[..]), encode::serialize_hex(&funding_script), &self.context.channel_id());
			if let Err(_) = self.context.secp_ctx.verify_ecdsa(
				&sighash,
				&msg.signature,
				&self.context.counterparty_funding_pubkey(),
			) {
				return Err(ChannelError::close(
					"Invalid commitment tx signature from peer".to_owned(),
				));
			}
			bitcoin_tx.txid
		};
		let mut htlcs_cloned: Vec<_> = commitment_stats
			.htlcs_included
			.iter()
			.map(|htlc| (htlc.0.clone(), htlc.1.map(|h| h.clone())))
			.collect();

		// If our counterparty updated the channel fee in this commitment transaction, check that
		// they can actually afford the new fee now.
		let update_fee = if let Some((_, update_state)) = self.context.pending_update_fee {
			update_state == FeeUpdateState::RemoteAnnounced
		} else {
			false
		};
		if update_fee {
			debug_assert!(!self.context.is_outbound());
			let counterparty_reserve_we_require_msat =
				self.context.holder_selected_channel_reserve_satoshis * 1000;
			if commitment_stats.remote_balance_msat
				< commitment_stats.total_fee_sat * 1000 + counterparty_reserve_we_require_msat
			{
				return Err(ChannelError::close(
					"Funding remote cannot afford proposed new fee".to_owned(),
				));
			}
		}
		#[cfg(any(test, fuzzing))]
		{
			if self.context.is_outbound() {
				let projected_commit_tx_info =
					self.context.next_local_commitment_tx_fee_info_cached.lock().unwrap().take();
				*self.context.next_remote_commitment_tx_fee_info_cached.lock().unwrap() = None;
				if let Some(info) = projected_commit_tx_info {
					let total_pending_htlcs = self.context.pending_inbound_htlcs.len()
						+ self.context.pending_outbound_htlcs.len()
						+ self.context.holding_cell_htlc_updates.len();
					if info.total_pending_htlcs == total_pending_htlcs
						&& info.next_holder_htlc_id == self.context.next_holder_htlc_id
						&& info.next_counterparty_htlc_id == self.context.next_counterparty_htlc_id
						&& info.feerate == self.context.feerate_per_kw
					{
						assert_eq!(commitment_stats.total_fee_sat, info.fee / 1000);
					}
				}
			}
		}

		if msg.htlc_signatures.len() != commitment_stats.num_nondust_htlcs {
			return Err(ChannelError::close(format!(
				"Got wrong number of HTLC signatures ({}) from remote. It must be {}",
				msg.htlc_signatures.len(),
				commitment_stats.num_nondust_htlcs
			)));
		}

		// Up to LDK 0.0.115, HTLC information was required to be duplicated in the
		// `htlcs_and_sigs` vec and in the `holder_commitment_tx` itself, both of which were passed
		// in the `ChannelMonitorUpdate`. In 0.0.115, support for having a separate set of
		// outbound-non-dust-HTLCSources in the `ChannelMonitorUpdate` was added, however for
		// backwards compatibility, we never use it in production. To provide test coverage, here,
		// we randomly decide (in test/fuzzing builds) to use the new vec sometimes.
		#[allow(unused_assignments, unused_mut)]
		let mut separate_nondust_htlc_sources = false;
		#[cfg(all(feature = "std", any(test, fuzzing)))]
		{
			use core::hash::{BuildHasher, Hasher};
			// Get a random value using the only std API to do so - the DefaultHasher
			let rand_val = std::collections::hash_map::RandomState::new().build_hasher().finish();
			separate_nondust_htlc_sources = rand_val % 2 == 0;
		}

		let mut nondust_htlc_sources = Vec::with_capacity(htlcs_cloned.len());
		let mut htlcs_and_sigs = Vec::with_capacity(htlcs_cloned.len());
		for (idx, (htlc, mut source_opt)) in htlcs_cloned.drain(..).enumerate() {
			if let Some(_) = htlc.transaction_output_index {
				let mut htlc_tx = chan_utils::build_htlc_transaction(
					&commitment_txid,
					commitment_stats.feerate_per_kw,
					self.context.get_counterparty_selected_contest_delay().unwrap(),
					&htlc,
					&self.context.channel_type,
					&keys.broadcaster_delayed_payment_key,
					&keys.revocation_key,
				);
				if self.context.is_colored() {
					color_htlc(&mut htlc_tx, &htlc, &self.context.ldk_data_dir)?;
				}

				let htlc_redeemscript =
					chan_utils::get_htlc_redeemscript(&htlc, &self.context.channel_type, &keys);
				let htlc_sighashtype =
					if self.context.channel_type.supports_anchors_zero_fee_htlc_tx() {
						EcdsaSighashType::SinglePlusAnyoneCanPay
					} else {
						EcdsaSighashType::All
					};
				let htlc_sighash = hash_to_message!(
					&sighash::SighashCache::new(&htlc_tx)
						.p2wsh_signature_hash(
							0,
							&htlc_redeemscript,
							htlc.to_bitcoin_amount(),
							htlc_sighashtype
						)
						.unwrap()[..]
				);
				log_trace!(logger, "Checking HTLC tx signature {} by key {} against tx {} (sighash {}) with redeemscript {} in channel {}.",
					log_bytes!(msg.htlc_signatures[idx].serialize_compact()[..]), log_bytes!(keys.countersignatory_htlc_key.to_public_key().serialize()),
					encode::serialize_hex(&htlc_tx), log_bytes!(htlc_sighash[..]), encode::serialize_hex(&htlc_redeemscript), &self.context.channel_id());
				if let Err(_) = self.context.secp_ctx.verify_ecdsa(
					&htlc_sighash,
					&msg.htlc_signatures[idx],
					&keys.countersignatory_htlc_key.to_public_key(),
				) {
					return Err(ChannelError::close(
						"Invalid HTLC tx signature from peer".to_owned(),
					));
				}
				if !separate_nondust_htlc_sources {
					htlcs_and_sigs.push((htlc, Some(msg.htlc_signatures[idx]), source_opt.take()));
				}
			} else {
				htlcs_and_sigs.push((htlc, None, source_opt.take()));
			}
			if separate_nondust_htlc_sources {
				if let Some(source) = source_opt.take() {
					nondust_htlc_sources.push(source);
				}
			}
			debug_assert!(source_opt.is_none(), "HTLCSource should have been put somewhere");
		}

		let holder_commitment_tx = HolderCommitmentTransaction::new(
			commitment_stats.tx,
			msg.signature,
			msg.htlc_signatures.clone(),
			&self.context.get_holder_pubkeys().funding_pubkey,
			self.context.counterparty_funding_pubkey(),
		);

		self.context
			.holder_signer
			.as_ref()
			.validate_holder_commitment(
				&holder_commitment_tx,
				commitment_stats.outbound_htlc_preimages,
			)
			.map_err(|_| ChannelError::close("Failed to validate our commitment".to_owned()))?;

		// Update state now that we've passed all the can-fail calls...
		let mut need_commitment = false;
		if let &mut Some((_, ref mut update_state)) = &mut self.context.pending_update_fee {
			if *update_state == FeeUpdateState::RemoteAnnounced {
				*update_state = FeeUpdateState::AwaitingRemoteRevokeToAnnounce;
				need_commitment = true;
			}
		}

		for htlc in self.context.pending_inbound_htlcs.iter_mut() {
			let htlc_resolution =
				if let &InboundHTLCState::RemoteAnnounced(ref resolution) = &htlc.state {
					Some(resolution.clone())
				} else {
					None
				};
			if let Some(htlc_resolution) = htlc_resolution {
				log_trace!(logger, "Updating HTLC {} to AwaitingRemoteRevokeToAnnounce due to commitment_signed in channel {}.",
					&htlc.payment_hash, &self.context.channel_id);
				htlc.state = InboundHTLCState::AwaitingRemoteRevokeToAnnounce(htlc_resolution);
				need_commitment = true;
			}
		}
		let mut claimed_htlcs = Vec::new();
		for htlc in self.context.pending_outbound_htlcs.iter_mut() {
			if let &mut OutboundHTLCState::RemoteRemoved(ref mut outcome) = &mut htlc.state {
				log_trace!(logger, "Updating HTLC {} to AwaitingRemoteRevokeToRemove due to commitment_signed in channel {}.",
					&htlc.payment_hash, &self.context.channel_id);
				// Grab the preimage, if it exists, instead of cloning
				let mut reason = OutboundHTLCOutcome::Success(None);
				mem::swap(outcome, &mut reason);
				if let OutboundHTLCOutcome::Success(Some(preimage)) = reason {
					// If a user (a) receives an HTLC claim using LDK 0.0.104 or before, then (b)
					// upgrades to LDK 0.0.114 or later before the HTLC is fully resolved, we could
					// have a `Success(None)` reason. In this case we could forget some HTLC
					// claims, but such an upgrade is unlikely and including claimed HTLCs here
					// fixes a bug which the user was exposed to on 0.0.104 when they started the
					// claim anyway.
					claimed_htlcs.push((SentHTLCId::from_source(&htlc.source), preimage));
				}
				htlc.state = OutboundHTLCState::AwaitingRemoteRevokeToRemove(reason);
				need_commitment = true;
			}
		}

		self.context.latest_monitor_update_id += 1;
		let mut monitor_update = ChannelMonitorUpdate {
			update_id: self.context.latest_monitor_update_id,
			counterparty_node_id: Some(self.context.counterparty_node_id),
			updates: vec![ChannelMonitorUpdateStep::LatestHolderCommitmentTXInfo {
				commitment_tx: holder_commitment_tx,
				htlc_outputs: htlcs_and_sigs,
				claimed_htlcs,
				nondust_htlc_sources,
			}],
			channel_id: Some(self.context.channel_id()),
		};

		if self
			.context
			.holder_commitment_point
			.advance(&self.context.holder_signer, &self.context.secp_ctx, logger)
			.is_err()
		{
			// We only fail to advance our commitment point/number if we're currently
			// waiting for our signer to unblock and provide a commitment point.
			// During post-funding channel operation, we only advance our point upon
			// receiving a commitment_signed, and our counterparty cannot send us
			// another commitment signed until we've provided a new commitment point
			// in revoke_and_ack, which requires unblocking our signer and completing
			// the advance to the next point. This should be unreachable since
			// a new commitment_signed should fail at our signature checks above.
			debug_assert!(false, "We should be ready to advance our commitment point by the time we receive commitment_signed");
			return Err(ChannelError::close("Failed to advance our commitment point".to_owned()));
		}
		self.context.expecting_peer_commitment_signed = false;
		// Note that if we need_commitment & !AwaitingRemoteRevoke we'll call
		// build_commitment_no_status_check() next which will reset this to RAAFirst.
		self.context.resend_order = RAACommitmentOrder::CommitmentFirst;

		if self.context.channel_state.is_monitor_update_in_progress() {
			// In case we initially failed monitor updating without requiring a response, we need
			// to make sure the RAA gets sent first.
			self.context.monitor_pending_revoke_and_ack = true;
			if need_commitment && !self.context.channel_state.is_awaiting_remote_revoke() {
				// If we were going to send a commitment_signed after the RAA, go ahead and do all
				// the corresponding HTLC status updates so that
				// get_last_commitment_update_for_send includes the right HTLCs.
				self.context.monitor_pending_commitment_signed = true;
				let mut additional_update = self.build_commitment_no_status_check(logger);
				// build_commitment_no_status_check may bump latest_monitor_id but we want them to be
				// strictly increasing by one, so decrement it here.
				self.context.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);
			}
			log_debug!(logger, "Received valid commitment_signed from peer in channel {}, updated HTLC state but awaiting a monitor update resolution to reply.",
				&self.context.channel_id);
			return Ok(self.push_ret_blockable_mon_update(monitor_update));
		}

		let need_commitment_signed =
			if need_commitment && !self.context.channel_state.is_awaiting_remote_revoke() {
				// If we're AwaitingRemoteRevoke we can't send a new commitment here, but that's ok -
				// we'll send one right away when we get the revoke_and_ack when we
				// free_holding_cell_htlcs().
				let mut additional_update = self.build_commitment_no_status_check(logger);
				// build_commitment_no_status_check may bump latest_monitor_id but we want them to be
				// strictly increasing by one, so decrement it here.
				self.context.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);
				true
			} else {
				false
			};

		log_debug!(logger, "Received valid commitment_signed from peer in channel {}, updating HTLC state and responding with{} a revoke_and_ack.",
			&self.context.channel_id(), if need_commitment_signed { " our own commitment_signed and" } else { "" });
		self.monitor_updating_paused(
			true,
			need_commitment_signed,
			false,
			Vec::new(),
			Vec::new(),
			Vec::new(),
		);
		return Ok(self.push_ret_blockable_mon_update(monitor_update));
	}

	/// Public version of the below, checking relevant preconditions first.
	/// If we're not in a state where freeing the holding cell makes sense, this is a no-op and
	/// returns `(None, Vec::new())`.
	pub fn maybe_free_holding_cell_htlcs<F: Deref, L: Deref>(
		&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
	) -> (Option<ChannelMonitorUpdate>, Vec<(HTLCSource, PaymentHash)>)
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		if matches!(self.context.channel_state, ChannelState::ChannelReady(_))
			&& self.context.channel_state.can_generate_new_commitment()
		{
			self.free_holding_cell_htlcs(fee_estimator, logger)
		} else {
			(None, Vec::new())
		}
	}

	/// Frees any pending commitment updates in the holding cell, generating the relevant messages
	/// for our counterparty.
	fn free_holding_cell_htlcs<F: Deref, L: Deref>(
		&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
	) -> (Option<ChannelMonitorUpdate>, Vec<(HTLCSource, PaymentHash)>)
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		assert!(!self.context.channel_state.is_monitor_update_in_progress());
		if self.context.holding_cell_htlc_updates.len() != 0
			|| self.context.holding_cell_update_fee.is_some()
		{
			log_trace!(
				logger,
				"Freeing holding cell with {} HTLC updates{} in channel {}",
				self.context.holding_cell_htlc_updates.len(),
				if self.context.holding_cell_update_fee.is_some() {
					" and a fee update"
				} else {
					""
				},
				&self.context.channel_id()
			);

			let mut monitor_update = ChannelMonitorUpdate {
				update_id: self.context.latest_monitor_update_id + 1, // We don't increment this yet!
				counterparty_node_id: Some(self.context.counterparty_node_id),
				updates: Vec::new(),
				channel_id: Some(self.context.channel_id()),
			};

			let mut htlc_updates = Vec::new();
			mem::swap(&mut htlc_updates, &mut self.context.holding_cell_htlc_updates);
			let mut update_add_count = 0;
			let mut update_fulfill_count = 0;
			let mut update_fail_count = 0;
			let mut htlcs_to_fail = Vec::new();
			for htlc_update in htlc_updates.drain(..) {
				// Note that this *can* fail, though it should be due to rather-rare conditions on
				// fee races with adding too many outputs which push our total payments just over
				// the limit. In case it's less rare than I anticipate, we may want to revisit
				// handling this case better and maybe fulfilling some of the HTLCs while attempting
				// to rebalance channels.
				let fail_htlc_res = match &htlc_update {
					&HTLCUpdateAwaitingACK::AddHTLC {
						amount_msat,
						cltv_expiry,
						ref payment_hash,
						ref source,
						ref onion_routing_packet,
						skimmed_fee_msat,
						blinding_point,
						amount_rgb,
						..
					} => {
						match self.send_htlc(
							amount_msat,
							*payment_hash,
							cltv_expiry,
							source.clone(),
							onion_routing_packet.clone(),
							false,
							skimmed_fee_msat,
							blinding_point,
							fee_estimator,
							logger,
							amount_rgb,
						) {
							Ok(_) => update_add_count += 1,
							Err(e) => {
								match e {
									ChannelError::Ignore(ref msg) => {
										log_info!(logger, "Failed to send HTLC with payment_hash {} due to {} in channel {}", &payment_hash, msg, &self.context.channel_id());
										// If we fail to send here, then this HTLC should
										// be failed backwards. Failing to send here
										// indicates that this HTLC may keep being put back
										// into the holding cell without ever being
										// successfully forwarded/failed/fulfilled, causing
										// our counterparty to eventually close on us.
										htlcs_to_fail.push((source.clone(), *payment_hash));
									},
									_ => {
										panic!("Got a non-IgnoreError action trying to send holding cell HTLC");
									},
								}
							},
						}
						None
					},
					&HTLCUpdateAwaitingACK::ClaimHTLC { ref payment_preimage, htlc_id, .. } => {
						// If an HTLC claim was previously added to the holding cell (via
						// `get_update_fulfill_htlc`, then generating the claim message itself must
						// not fail - any in between attempts to claim the HTLC will have resulted
						// in it hitting the holding cell again and we cannot change the state of a
						// holding cell HTLC from fulfill to anything else.
						let mut additional_monitor_update =
							if let UpdateFulfillFetch::NewClaim { monitor_update, .. } =
								self.get_update_fulfill_htlc(htlc_id, *payment_preimage, logger)
							{
								monitor_update
							} else {
								unreachable!()
							};
						update_fulfill_count += 1;
						monitor_update.updates.append(&mut additional_monitor_update.updates);
						None
					},
					&HTLCUpdateAwaitingACK::FailHTLC { htlc_id, ref err_packet } => Some(
						self.fail_htlc(htlc_id, err_packet.clone(), false, logger)
							.map(|fail_msg_opt| fail_msg_opt.map(|_| ())),
					),
					&HTLCUpdateAwaitingACK::FailMalformedHTLC {
						htlc_id,
						failure_code,
						sha256_of_onion,
					} => Some(
						self.fail_htlc(htlc_id, (sha256_of_onion, failure_code), false, logger)
							.map(|fail_msg_opt| fail_msg_opt.map(|_| ())),
					),
				};
				if let Some(res) = fail_htlc_res {
					match res {
						Ok(fail_msg_opt) => {
							// If an HTLC failure was previously added to the holding cell (via
							// `queue_fail_{malformed_}htlc`) then generating the fail message itself must
							// not fail - we should never end up in a state where we double-fail
							// an HTLC or fail-then-claim an HTLC as it indicates we didn't wait
							// for a full revocation before failing.
							debug_assert!(fail_msg_opt.is_some());
							update_fail_count += 1;
						},
						Err(ChannelError::Ignore(_)) => {},
						Err(_) => {
							panic!("Got a non-IgnoreError action trying to fail holding cell HTLC");
						},
					}
				}
			}
			if update_add_count == 0
				&& update_fulfill_count == 0
				&& update_fail_count == 0
				&& self.context.holding_cell_update_fee.is_none()
			{
				return (None, htlcs_to_fail);
			}
			let update_fee = if let Some(feerate) = self.context.holding_cell_update_fee.take() {
				self.send_update_fee(feerate, false, fee_estimator, logger)
			} else {
				None
			};

			let mut additional_update = self.build_commitment_no_status_check(logger);
			// build_commitment_no_status_check and get_update_fulfill_htlc may bump latest_monitor_id
			// but we want them to be strictly increasing by one, so reset it here.
			self.context.latest_monitor_update_id = monitor_update.update_id;
			monitor_update.updates.append(&mut additional_update.updates);

			log_debug!(logger, "Freeing holding cell in channel {} resulted in {}{} HTLCs added, {} HTLCs fulfilled, and {} HTLCs failed.",
				&self.context.channel_id(), if update_fee.is_some() { "a fee update, " } else { "" },
				update_add_count, update_fulfill_count, update_fail_count);

			self.monitor_updating_paused(false, true, false, Vec::new(), Vec::new(), Vec::new());
			(self.push_ret_blockable_mon_update(monitor_update), htlcs_to_fail)
		} else {
			(None, Vec::new())
		}
	}

	/// Handles receiving a remote's revoke_and_ack. Note that we may return a new
	/// commitment_signed message here in case we had pending outbound HTLCs to add which were
	/// waiting on this revoke_and_ack. The generation of this new commitment_signed may also fail,
	/// generating an appropriate error *after* the channel state has been updated based on the
	/// revoke_and_ack message.
	pub fn revoke_and_ack<F: Deref, L: Deref>(
		&mut self, msg: &msgs::RevokeAndACK, fee_estimator: &LowerBoundedFeeEstimator<F>,
		logger: &L, hold_mon_update: bool,
	) -> Result<(Vec<(HTLCSource, PaymentHash)>, Option<ChannelMonitorUpdate>), ChannelError>
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		if !matches!(self.context.channel_state, ChannelState::ChannelReady(_)) {
			return Err(ChannelError::close(
				"Got revoke/ACK message when channel was not in an operational state".to_owned(),
			));
		}
		if self.context.channel_state.is_peer_disconnected() {
			return Err(ChannelError::close(
				"Peer sent revoke_and_ack when we needed a channel_reestablish".to_owned(),
			));
		}
		if self.context.channel_state.is_both_sides_shutdown()
			&& self.context.last_sent_closing_fee.is_some()
		{
			return Err(ChannelError::close(
				"Peer sent revoke_and_ack after we'd started exchanging closing_signeds".to_owned(),
			));
		}

		let secret = secp_check!(
			SecretKey::from_slice(&msg.per_commitment_secret),
			"Peer provided an invalid per_commitment_secret".to_owned()
		);

		if let Some(counterparty_prev_commitment_point) =
			self.context.counterparty_prev_commitment_point
		{
			if PublicKey::from_secret_key(&self.context.secp_ctx, &secret)
				!= counterparty_prev_commitment_point
			{
				return Err(ChannelError::close("Got a revoke commitment secret which didn't correspond to their current pubkey".to_owned()));
			}
		}

		if !self.context.channel_state.is_awaiting_remote_revoke() {
			// Our counterparty seems to have burned their coins to us (by revoking a state when we
			// haven't given them a new commitment transaction to broadcast). We should probably
			// take advantage of this by updating our channel monitor, sending them an error, and
			// waiting for them to broadcast their latest (now-revoked claim). But, that would be a
			// lot of work, and there's some chance this is all a misunderstanding anyway.
			// We have to do *something*, though, since our signer may get mad at us for otherwise
			// jumping a remote commitment number, so best to just force-close and move on.
			return Err(ChannelError::close("Received an unexpected revoke_and_ack".to_owned()));
		}

		#[cfg(any(test, fuzzing))]
		{
			*self.context.next_local_commitment_tx_fee_info_cached.lock().unwrap() = None;
			*self.context.next_remote_commitment_tx_fee_info_cached.lock().unwrap() = None;
		}

		match &self.context.holder_signer {
			ChannelSignerType::Ecdsa(ecdsa) => {
				ecdsa
					.validate_counterparty_revocation(
						self.context.cur_counterparty_commitment_transaction_number + 1,
						&secret,
					)
					.map_err(|_| {
						ChannelError::close("Failed to validate revocation from peer".to_owned())
					})?;
			},
			// TODO (taproot|arik)
			#[cfg(taproot)]
			_ => todo!(),
		};

		self.context
			.commitment_secrets
			.provide_secret(
				self.context.cur_counterparty_commitment_transaction_number + 1,
				msg.per_commitment_secret,
			)
			.map_err(|_| {
				ChannelError::close("Previous secrets did not match new one".to_owned())
			})?;
		self.context.latest_monitor_update_id += 1;
		let mut monitor_update = ChannelMonitorUpdate {
			update_id: self.context.latest_monitor_update_id,
			counterparty_node_id: Some(self.context.counterparty_node_id),
			updates: vec![ChannelMonitorUpdateStep::CommitmentSecret {
				idx: self.context.cur_counterparty_commitment_transaction_number + 1,
				secret: msg.per_commitment_secret,
			}],
			channel_id: Some(self.context.channel_id()),
		};

		// Update state now that we've passed all the can-fail calls...
		// (note that we may still fail to generate the new commitment_signed message, but that's
		// OK, we step the channel here and *then* if the new generation fails we can fail the
		// channel based on that, but stepping stuff here should be safe either way.
		self.context.channel_state.clear_awaiting_remote_revoke();
		self.context.sent_message_awaiting_response = None;
		self.context.counterparty_prev_commitment_point =
			self.context.counterparty_cur_commitment_point;
		self.context.counterparty_cur_commitment_point = Some(msg.next_per_commitment_point);
		self.context.cur_counterparty_commitment_transaction_number -= 1;

		if self.context.announcement_sigs_state == AnnouncementSigsState::Committed {
			self.context.announcement_sigs_state = AnnouncementSigsState::PeerReceived;
		}

		log_trace!(
			logger,
			"Updating HTLCs on receipt of RAA in channel {}...",
			&self.context.channel_id()
		);
		let mut to_forward_infos = Vec::new();
		let mut pending_update_adds = Vec::new();
		let mut revoked_htlcs = Vec::new();
		let mut finalized_claimed_htlcs = Vec::new();
		let mut update_fail_htlcs = Vec::new();
		let mut update_fail_malformed_htlcs = Vec::new();
		let mut require_commitment = false;
		let mut value_to_self_msat_diff: i64 = 0;
		let mut rgb_offered_htlc = 0;
		let mut rgb_received_htlc = 0;

		{
			// Take references explicitly so that we can hold multiple references to self.context.
			let pending_inbound_htlcs: &mut Vec<_> = &mut self.context.pending_inbound_htlcs;
			let pending_outbound_htlcs: &mut Vec<_> = &mut self.context.pending_outbound_htlcs;
			let expecting_peer_commitment_signed =
				&mut self.context.expecting_peer_commitment_signed;

			// We really shouldnt have two passes here, but retain gives a non-mutable ref (Rust bug)
			pending_inbound_htlcs.retain(|htlc| {
				if let &InboundHTLCState::LocalRemoved(ref reason) = &htlc.state {
					log_trace!(logger, " ...removing inbound LocalRemoved {}", &htlc.payment_hash);
					if let &InboundHTLCRemovalReason::Fulfill(_) = reason {
						value_to_self_msat_diff += htlc.amount_msat as i64;
					}
					*expecting_peer_commitment_signed = true;
					false
				} else {
					true
				}
			});
			pending_outbound_htlcs.retain(|htlc| {
				if let &OutboundHTLCState::AwaitingRemovedRemoteRevoke(ref outcome) = &htlc.state {
					log_trace!(
						logger,
						" ...removing outbound AwaitingRemovedRemoteRevoke {}",
						&htlc.payment_hash
					);
					if let OutboundHTLCOutcome::Failure(reason) = outcome.clone() {
						// We really want take() here, but, again, non-mut ref :(
						revoked_htlcs.push((htlc.source.clone(), htlc.payment_hash, reason));
					} else {
						finalized_claimed_htlcs.push(htlc.source.clone());
						// They fulfilled, so we sent them money
						value_to_self_msat_diff -= htlc.amount_msat as i64;
					}
					false
				} else {
					true
				}
			});
			for htlc in pending_inbound_htlcs.iter_mut() {
				let swap = if let &InboundHTLCState::AwaitingRemoteRevokeToAnnounce(_) = &htlc.state
				{
					true
				} else if let &InboundHTLCState::AwaitingAnnouncedRemoteRevoke(_) = &htlc.state {
					true
				} else {
					false
				};
				if swap {
					let mut state = InboundHTLCState::Committed;
					mem::swap(&mut state, &mut htlc.state);

					if let InboundHTLCState::AwaitingRemoteRevokeToAnnounce(resolution) = state {
						log_trace!(logger, " ...promoting inbound AwaitingRemoteRevokeToAnnounce {} to AwaitingAnnouncedRemoteRevoke", &htlc.payment_hash);
						htlc.state = InboundHTLCState::AwaitingAnnouncedRemoteRevoke(resolution);
						require_commitment = true;
						if let Some(amount_rgb) = htlc.amount_rgb {
							rgb_received_htlc += amount_rgb;
						}
					} else if let InboundHTLCState::AwaitingAnnouncedRemoteRevoke(resolution) =
						state
					{
						match resolution {
							InboundHTLCResolution::Resolved { pending_htlc_status } => {
								match pending_htlc_status {
									PendingHTLCStatus::Fail(fail_msg) => {
										log_trace!(logger, " ...promoting inbound AwaitingAnnouncedRemoteRevoke {} to LocalRemoved due to PendingHTLCStatus indicating failure", &htlc.payment_hash);
										require_commitment = true;
										match fail_msg {
											HTLCFailureMsg::Relay(msg) => {
												htlc.state = InboundHTLCState::LocalRemoved(
													InboundHTLCRemovalReason::FailRelay(
														msg.reason.clone(),
													),
												);
												update_fail_htlcs.push(msg)
											},
											HTLCFailureMsg::Malformed(msg) => {
												htlc.state = InboundHTLCState::LocalRemoved(
													InboundHTLCRemovalReason::FailMalformed((
														msg.sha256_of_onion,
														msg.failure_code,
													)),
												);
												update_fail_malformed_htlcs.push(msg)
											},
										}
									},
									PendingHTLCStatus::Forward(forward_info) => {
										log_trace!(logger, " ...promoting inbound AwaitingAnnouncedRemoteRevoke {} to Committed, attempting to forward", &htlc.payment_hash);
										to_forward_infos.push((forward_info, htlc.htlc_id));
										htlc.state = InboundHTLCState::Committed;
									},
								}
							},
							InboundHTLCResolution::Pending { update_add_htlc } => {
								log_trace!(logger, " ...promoting inbound AwaitingAnnouncedRemoteRevoke {} to Committed", &htlc.payment_hash);
								pending_update_adds.push(update_add_htlc);
								htlc.state = InboundHTLCState::Committed;
							},
						}
					}
				}
			}
			for htlc in pending_outbound_htlcs.iter_mut() {
				if let OutboundHTLCState::LocalAnnounced(_) = htlc.state {
					log_trace!(
						logger,
						" ...promoting outbound LocalAnnounced {} to Committed",
						&htlc.payment_hash
					);
					htlc.state = OutboundHTLCState::Committed;
					if let Some(amount_rgb) = htlc.amount_rgb {
						rgb_offered_htlc += amount_rgb;
					}

					*expecting_peer_commitment_signed = true;
				}
				if let &mut OutboundHTLCState::AwaitingRemoteRevokeToRemove(ref mut outcome) =
					&mut htlc.state
				{
					log_trace!(logger, " ...promoting outbound AwaitingRemoteRevokeToRemove {} to AwaitingRemovedRemoteRevoke", &htlc.payment_hash);
					// Grab the preimage, if it exists, instead of cloning
					let mut reason = OutboundHTLCOutcome::Success(None);
					mem::swap(outcome, &mut reason);
					htlc.state = OutboundHTLCState::AwaitingRemovedRemoteRevoke(reason);
					require_commitment = true;
				}
			}
		}
		self.context.value_to_self_msat =
			(self.context.value_to_self_msat as i64 + value_to_self_msat_diff) as u64;
		if self.context.is_colored() && (rgb_offered_htlc > 0 || rgb_received_htlc > 0) {
			update_rgb_channel_amount_pending(
				&self.context.channel_id,
				rgb_offered_htlc,
				rgb_received_htlc,
				&self.context.ldk_data_dir,
			);
		}

		if let Some((feerate, update_state)) = self.context.pending_update_fee {
			match update_state {
				FeeUpdateState::Outbound => {
					debug_assert!(self.context.is_outbound());
					log_trace!(
						logger,
						" ...promoting outbound fee update {} to Committed",
						feerate
					);
					self.context.feerate_per_kw = feerate;
					self.context.pending_update_fee = None;
					self.context.expecting_peer_commitment_signed = true;
				},
				FeeUpdateState::RemoteAnnounced => {
					debug_assert!(!self.context.is_outbound());
				},
				FeeUpdateState::AwaitingRemoteRevokeToAnnounce => {
					debug_assert!(!self.context.is_outbound());
					log_trace!(logger, " ...promoting inbound AwaitingRemoteRevokeToAnnounce fee update {} to Committed", feerate);
					require_commitment = true;
					self.context.feerate_per_kw = feerate;
					self.context.pending_update_fee = None;
				},
			}
		}

		let release_monitor = self.context.blocked_monitor_updates.is_empty() && !hold_mon_update;
		let release_state_str = if hold_mon_update {
			"Holding"
		} else if release_monitor {
			"Releasing"
		} else {
			"Blocked"
		};
		macro_rules! return_with_htlcs_to_fail {
			($htlcs_to_fail: expr) => {
				if !release_monitor {
					self.context
						.blocked_monitor_updates
						.push(PendingChannelMonitorUpdate { update: monitor_update });
					return Ok(($htlcs_to_fail, None));
				} else {
					return Ok(($htlcs_to_fail, Some(monitor_update)));
				}
			};
		}

		self.context.monitor_pending_update_adds.append(&mut pending_update_adds);

		if self.context.channel_state.is_monitor_update_in_progress() {
			// We can't actually generate a new commitment transaction (incl by freeing holding
			// cells) while we can't update the monitor, so we just return what we have.
			if require_commitment {
				self.context.monitor_pending_commitment_signed = true;
				// When the monitor updating is restored we'll call
				// get_last_commitment_update_for_send(), which does not update state, but we're
				// definitely now awaiting a remote revoke before we can step forward any more, so
				// set it here.
				let mut additional_update = self.build_commitment_no_status_check(logger);
				// build_commitment_no_status_check may bump latest_monitor_id but we want them to be
				// strictly increasing by one, so decrement it here.
				self.context.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);
			}
			self.context.monitor_pending_forwards.append(&mut to_forward_infos);
			self.context.monitor_pending_failures.append(&mut revoked_htlcs);
			self.context.monitor_pending_finalized_fulfills.append(&mut finalized_claimed_htlcs);
			log_debug!(logger, "Received a valid revoke_and_ack for channel {} but awaiting a monitor update resolution to reply.", &self.context.channel_id());
			return_with_htlcs_to_fail!(Vec::new());
		}

		match self.free_holding_cell_htlcs(fee_estimator, logger) {
			(Some(mut additional_update), htlcs_to_fail) => {
				// free_holding_cell_htlcs may bump latest_monitor_id multiple times but we want them to be
				// strictly increasing by one, so decrement it here.
				self.context.latest_monitor_update_id = monitor_update.update_id;
				monitor_update.updates.append(&mut additional_update.updates);

				log_debug!(logger, "Received a valid revoke_and_ack for channel {} with holding cell HTLCs freed. {} monitor update.",
					&self.context.channel_id(), release_state_str);

				self.monitor_updating_paused(
					false,
					true,
					false,
					to_forward_infos,
					revoked_htlcs,
					finalized_claimed_htlcs,
				);
				return_with_htlcs_to_fail!(htlcs_to_fail);
			},
			(None, htlcs_to_fail) => {
				if require_commitment {
					let mut additional_update = self.build_commitment_no_status_check(logger);

					// build_commitment_no_status_check may bump latest_monitor_id but we want them to be
					// strictly increasing by one, so decrement it here.
					self.context.latest_monitor_update_id = monitor_update.update_id;
					monitor_update.updates.append(&mut additional_update.updates);

					log_debug!(logger, "Received a valid revoke_and_ack for channel {}. Responding with a commitment update with {} HTLCs failed. {} monitor update.",
						&self.context.channel_id(),
						update_fail_htlcs.len() + update_fail_malformed_htlcs.len(),
						release_state_str);

					self.monitor_updating_paused(
						false,
						true,
						false,
						to_forward_infos,
						revoked_htlcs,
						finalized_claimed_htlcs,
					);
					return_with_htlcs_to_fail!(htlcs_to_fail);
				} else {
					log_debug!(logger, "Received a valid revoke_and_ack for channel {} with no reply necessary. {} monitor update.",
						&self.context.channel_id(), release_state_str);

					self.monitor_updating_paused(
						false,
						false,
						false,
						to_forward_infos,
						revoked_htlcs,
						finalized_claimed_htlcs,
					);
					return_with_htlcs_to_fail!(htlcs_to_fail);
				}
			},
		}
	}

	/// Queues up an outbound update fee by placing it in the holding cell. You should call
	/// [`Self::maybe_free_holding_cell_htlcs`] in order to actually generate and send the
	/// commitment update.
	pub fn queue_update_fee<F: Deref, L: Deref>(
		&mut self, feerate_per_kw: u32, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
	) where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		let msg_opt = self.send_update_fee(feerate_per_kw, true, fee_estimator, logger);
		assert!(msg_opt.is_none(), "We forced holding cell?");
	}

	/// Adds a pending update to this channel. See the doc for send_htlc for
	/// further details on the optionness of the return value.
	/// If our balance is too low to cover the cost of the next commitment transaction at the
	/// new feerate, the update is cancelled.
	///
	/// You MUST call [`Self::send_commitment_no_state_update`] prior to any other calls on this
	/// [`Channel`] if `force_holding_cell` is false.
	fn send_update_fee<F: Deref, L: Deref>(
		&mut self, feerate_per_kw: u32, mut force_holding_cell: bool,
		fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
	) -> Option<msgs::UpdateFee>
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		if !self.context.is_outbound() {
			panic!("Cannot send fee from inbound channel");
		}
		if !self.context.is_usable() {
			panic!("Cannot update fee until channel is fully established and we haven't started shutting down");
		}
		if !self.context.is_live() {
			panic!("Cannot update fee while peer is disconnected/we're awaiting a monitor update (ChannelManager should have caught this)");
		}

		// Before proposing a feerate update, check that we can actually afford the new fee.
		let dust_exposure_limiting_feerate =
			self.context.get_dust_exposure_limiting_feerate(&fee_estimator);
		let htlc_stats = self
			.context
			.get_pending_htlc_stats(Some(feerate_per_kw), dust_exposure_limiting_feerate);
		let keys = self.context.build_holder_transaction_keys();
		let mut commitment_stats = self.context.build_commitment_transaction(
			self.context.holder_commitment_point.transaction_number(),
			&keys,
			true,
			true,
			logger,
		);
		if self.context.is_colored() {
			if let Err(e) = color_commitment(&self.context, &mut commitment_stats.tx, false) {
				log_error!(logger, "Cannot color commitment: {e:?}");
				return None;
			}
		}

		let buffer_fee_msat = commit_tx_fee_sat(
			feerate_per_kw,
			commitment_stats.num_nondust_htlcs
				+ htlc_stats.on_holder_tx_outbound_holding_cell_htlcs_count as usize
				+ CONCURRENT_INBOUND_HTLC_FEE_BUFFER as usize,
			self.context.get_channel_type(),
		) * 1000;
		let holder_balance_msat =
			commitment_stats.local_balance_msat - htlc_stats.outbound_holding_cell_msat;
		if holder_balance_msat
			< buffer_fee_msat
				+ self.context.counterparty_selected_channel_reserve_satoshis.unwrap() * 1000
		{
			//TODO: auto-close after a number of failures?
			log_debug!(logger, "Cannot afford to send new feerate at {}", feerate_per_kw);
			return None;
		}

		// Note, we evaluate pending htlc "preemptive" trimmed-to-dust threshold at the proposed `feerate_per_kw`.
		let max_dust_htlc_exposure_msat =
			self.context.get_max_dust_htlc_exposure_msat(dust_exposure_limiting_feerate);
		if htlc_stats.on_holder_tx_dust_exposure_msat > max_dust_htlc_exposure_msat {
			log_debug!(
				logger,
				"Cannot afford to send new feerate at {} without infringing max dust htlc exposure",
				feerate_per_kw
			);
			return None;
		}
		if htlc_stats.on_counterparty_tx_dust_exposure_msat > max_dust_htlc_exposure_msat {
			log_debug!(
				logger,
				"Cannot afford to send new feerate at {} without infringing max dust htlc exposure",
				feerate_per_kw
			);
			return None;
		}

		if self.context.channel_state.is_awaiting_remote_revoke()
			|| self.context.channel_state.is_monitor_update_in_progress()
		{
			force_holding_cell = true;
		}

		if force_holding_cell {
			self.context.holding_cell_update_fee = Some(feerate_per_kw);
			return None;
		}

		debug_assert!(self.context.pending_update_fee.is_none());
		self.context.pending_update_fee = Some((feerate_per_kw, FeeUpdateState::Outbound));

		Some(msgs::UpdateFee { channel_id: self.context.channel_id, feerate_per_kw })
	}

	/// Removes any uncommitted inbound HTLCs and resets the state of uncommitted outbound HTLC
	/// updates, to be used on peer disconnection. After this, update_*_htlc messages need to be
	/// resent.
	/// No further message handling calls may be made until a channel_reestablish dance has
	/// completed.
	/// May return `Err(())`, which implies [`ChannelContext::force_shutdown`] should be called immediately.
	pub fn remove_uncommitted_htlcs_and_mark_paused<L: Deref>(
		&mut self, logger: &L,
	) -> Result<(), ()>
	where
		L::Target: Logger,
	{
		assert!(!matches!(self.context.channel_state, ChannelState::ShutdownComplete));
		if self.context.channel_state.is_pre_funded_state() {
			return Err(());
		}

		if self.context.channel_state.is_peer_disconnected() {
			// While the below code should be idempotent, it's simpler to just return early, as
			// redundant disconnect events can fire, though they should be rare.
			return Ok(());
		}

		if self.context.announcement_sigs_state == AnnouncementSigsState::MessageSent
			|| self.context.announcement_sigs_state == AnnouncementSigsState::Committed
		{
			self.context.announcement_sigs_state = AnnouncementSigsState::NotSent;
		}

		// Upon reconnect we have to start the closing_signed dance over, but shutdown messages
		// will be retransmitted.
		self.context.last_sent_closing_fee = None;
		self.context.pending_counterparty_closing_signed = None;
		self.context.closing_fee_limits = None;

		let mut inbound_drop_count = 0;
		self.context.pending_inbound_htlcs.retain(|htlc| {
			match htlc.state {
				InboundHTLCState::RemoteAnnounced(_) => {
					// They sent us an update_add_htlc but we never got the commitment_signed.
					// We'll tell them what commitment_signed we're expecting next and they'll drop
					// this HTLC accordingly
					inbound_drop_count += 1;
					false
				},
				InboundHTLCState::AwaitingRemoteRevokeToAnnounce(_)
				| InboundHTLCState::AwaitingAnnouncedRemoteRevoke(_) => {
					// We received a commitment_signed updating this HTLC and (at least hopefully)
					// sent a revoke_and_ack (which we can re-transmit) and have heard nothing
					// in response to it yet, so don't touch it.
					true
				},
				InboundHTLCState::Committed => true,
				InboundHTLCState::LocalRemoved(_) => {
					// We (hopefully) sent a commitment_signed updating this HTLC (which we can
					// re-transmit if needed) and they may have even sent a revoke_and_ack back
					// (that we missed). Keep this around for now and if they tell us they missed
					// the commitment_signed we can re-transmit the update then.
					true
				},
			}
		});
		self.context.next_counterparty_htlc_id -= inbound_drop_count;

		if let Some((_, update_state)) = self.context.pending_update_fee {
			if update_state == FeeUpdateState::RemoteAnnounced {
				debug_assert!(!self.context.is_outbound());
				self.context.pending_update_fee = None;
			}
		}

		for htlc in self.context.pending_outbound_htlcs.iter_mut() {
			if let OutboundHTLCState::RemoteRemoved(_) = htlc.state {
				// They sent us an update to remove this but haven't yet sent the corresponding
				// commitment_signed, we need to move it back to Committed and they can re-send
				// the update upon reconnection.
				htlc.state = OutboundHTLCState::Committed;
			}
		}

		self.context.sent_message_awaiting_response = None;

		self.context.channel_state.set_peer_disconnected();
		log_trace!(
			logger,
			"Peer disconnection resulted in {} remote-announced HTLC drops on channel {}",
			inbound_drop_count,
			&self.context.channel_id()
		);
		Ok(())
	}

	/// Indicates that a ChannelMonitor update is in progress and has not yet been fully persisted.
	/// This must be called before we return the [`ChannelMonitorUpdate`] back to the
	/// [`ChannelManager`], which will call [`Self::monitor_updating_restored`] once the monitor
	/// update completes (potentially immediately).
	/// The messages which were generated with the monitor update must *not* have been sent to the
	/// remote end, and must instead have been dropped. They will be regenerated when
	/// [`Self::monitor_updating_restored`] is called.
	///
	/// [`ChannelManager`]: super::channelmanager::ChannelManager
	/// [`chain::Watch`]: crate::chain::Watch
	/// [`ChannelMonitorUpdateStatus::InProgress`]: crate::chain::ChannelMonitorUpdateStatus::InProgress
	fn monitor_updating_paused(
		&mut self, resend_raa: bool, resend_commitment: bool, resend_channel_ready: bool,
		mut pending_forwards: Vec<(PendingHTLCInfo, u64)>,
		mut pending_fails: Vec<(HTLCSource, PaymentHash, HTLCFailReason)>,
		mut pending_finalized_claimed_htlcs: Vec<HTLCSource>,
	) {
		self.context.monitor_pending_revoke_and_ack |= resend_raa;
		self.context.monitor_pending_commitment_signed |= resend_commitment;
		self.context.monitor_pending_channel_ready |= resend_channel_ready;
		self.context.monitor_pending_forwards.append(&mut pending_forwards);
		self.context.monitor_pending_failures.append(&mut pending_fails);
		self.context
			.monitor_pending_finalized_fulfills
			.append(&mut pending_finalized_claimed_htlcs);
		self.context.channel_state.set_monitor_update_in_progress();
	}

	/// Indicates that the latest ChannelMonitor update has been committed by the client
	/// successfully and we should restore normal operation. Returns messages which should be sent
	/// to the remote side.
	pub fn monitor_updating_restored<L: Deref, NS: Deref>(
		&mut self, logger: &L, node_signer: &NS, chain_hash: ChainHash, user_config: &UserConfig,
		best_block_height: u32,
	) -> MonitorRestoreUpdates
	where
		L::Target: Logger,
		NS::Target: NodeSigner,
	{
		assert!(self.context.channel_state.is_monitor_update_in_progress());
		self.context.channel_state.clear_monitor_update_in_progress();

		// If we're past (or at) the AwaitingChannelReady stage on an outbound channel, try to
		// (re-)broadcast the funding transaction as we may have declined to broadcast it when we
		// first received the funding_signed.
		let mut funding_broadcastable = if self.context.is_outbound()
			&& (matches!(self.context.channel_state, ChannelState::AwaitingChannelReady(flags) if !flags.is_set(AwaitingChannelReadyFlags::WAITING_FOR_BATCH))
				|| matches!(self.context.channel_state, ChannelState::ChannelReady(_)))
		{
			self.context.funding_transaction.take()
		} else {
			None
		};
		// That said, if the funding transaction is already confirmed (ie we're active with a
		// minimum_depth over 0) don't bother re-broadcasting the confirmed funding tx.
		if matches!(self.context.channel_state, ChannelState::ChannelReady(_))
			&& self.context.minimum_depth != Some(0)
		{
			funding_broadcastable = None;
		}

		// We will never broadcast the funding transaction when we're in MonitorUpdateInProgress
		// (and we assume the user never directly broadcasts the funding transaction and waits for
		// us to do it). Thus, we can only ever hit monitor_pending_channel_ready when we're
		// * an inbound channel that failed to persist the monitor on funding_created and we got
		//   the funding transaction confirmed before the monitor was persisted, or
		// * a 0-conf channel and intended to send the channel_ready before any broadcast at all.
		let channel_ready = if self.context.monitor_pending_channel_ready {
			assert!(!self.context.is_outbound() || self.context.minimum_depth == Some(0),
				"Funding transaction broadcast by the local client before it should have - LDK didn't do it!");
			self.context.monitor_pending_channel_ready = false;
			Some(self.get_channel_ready())
		} else {
			None
		};

		let announcement_sigs = self.get_announcement_sigs(
			node_signer,
			chain_hash,
			user_config,
			best_block_height,
			logger,
		);

		let mut accepted_htlcs = Vec::new();
		mem::swap(&mut accepted_htlcs, &mut self.context.monitor_pending_forwards);
		let mut failed_htlcs = Vec::new();
		mem::swap(&mut failed_htlcs, &mut self.context.monitor_pending_failures);
		let mut finalized_claimed_htlcs = Vec::new();
		mem::swap(
			&mut finalized_claimed_htlcs,
			&mut self.context.monitor_pending_finalized_fulfills,
		);
		let mut pending_update_adds = Vec::new();
		mem::swap(&mut pending_update_adds, &mut self.context.monitor_pending_update_adds);

		if self.context.channel_state.is_peer_disconnected() {
			self.context.monitor_pending_revoke_and_ack = false;
			self.context.monitor_pending_commitment_signed = false;
			return MonitorRestoreUpdates {
				raa: None,
				commitment_update: None,
				order: RAACommitmentOrder::RevokeAndACKFirst,
				accepted_htlcs,
				failed_htlcs,
				finalized_claimed_htlcs,
				pending_update_adds,
				funding_broadcastable,
				channel_ready,
				announcement_sigs,
			};
		}

		let mut raa = if self.context.monitor_pending_revoke_and_ack {
			self.get_last_revoke_and_ack(logger)
		} else {
			None
		};
		let mut commitment_update = if self.context.monitor_pending_commitment_signed {
			self.get_last_commitment_update_for_send(logger).ok()
		} else {
			None
		};
		if self.context.resend_order == RAACommitmentOrder::CommitmentFirst
			&& self.context.signer_pending_commitment_update
			&& raa.is_some()
		{
			self.context.signer_pending_revoke_and_ack = true;
			raa = None;
		}
		if self.context.resend_order == RAACommitmentOrder::RevokeAndACKFirst
			&& self.context.signer_pending_revoke_and_ack
			&& commitment_update.is_some()
		{
			self.context.signer_pending_commitment_update = true;
			commitment_update = None;
		}

		if commitment_update.is_some() {
			self.mark_awaiting_response();
		}

		self.context.monitor_pending_revoke_and_ack = false;
		self.context.monitor_pending_commitment_signed = false;
		let order = self.context.resend_order.clone();
		log_debug!(logger, "Restored monitor updating in channel {} resulting in {}{} commitment update and {} RAA, with {} first",
			&self.context.channel_id(), if funding_broadcastable.is_some() { "a funding broadcastable, " } else { "" },
			if commitment_update.is_some() { "a" } else { "no" }, if raa.is_some() { "an" } else { "no" },
			match order { RAACommitmentOrder::CommitmentFirst => "commitment", RAACommitmentOrder::RevokeAndACKFirst => "RAA"});
		MonitorRestoreUpdates {
			raa,
			commitment_update,
			order,
			accepted_htlcs,
			failed_htlcs,
			finalized_claimed_htlcs,
			pending_update_adds,
			funding_broadcastable,
			channel_ready,
			announcement_sigs,
		}
	}

	pub fn check_for_stale_feerate<L: Logger>(
		&mut self, logger: &L, min_feerate: u32,
	) -> Result<(), ClosureReason> {
		if self.context.is_outbound() {
			// While its possible our fee is too low for an outbound channel because we've been
			// unable to increase the fee, we don't try to force-close directly here.
			return Ok(());
		}
		if self.context.feerate_per_kw < min_feerate {
			log_info!(logger,
				"Closing channel as feerate of {} is below required {} (the minimum required rate over the past day)",
				self.context.feerate_per_kw, min_feerate
			);
			Err(ClosureReason::PeerFeerateTooLow {
				peer_feerate_sat_per_kw: self.context.feerate_per_kw,
				required_feerate_sat_per_kw: min_feerate,
			})
		} else {
			Ok(())
		}
	}

	pub fn update_fee<F: Deref, L: Deref>(
		&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>, msg: &msgs::UpdateFee, logger: &L,
	) -> Result<(), ChannelError>
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		if self.context.is_outbound() {
			return Err(ChannelError::close(
				"Non-funding remote tried to update channel fee".to_owned(),
			));
		}
		if self.context.channel_state.is_peer_disconnected() {
			return Err(ChannelError::close(
				"Peer sent update_fee when we needed a channel_reestablish".to_owned(),
			));
		}
		Channel::<SP>::check_remote_fee(
			&self.context.channel_type,
			fee_estimator,
			msg.feerate_per_kw,
			Some(self.context.feerate_per_kw),
			logger,
		)?;

		self.context.pending_update_fee =
			Some((msg.feerate_per_kw, FeeUpdateState::RemoteAnnounced));
		self.context.update_time_counter += 1;
		// Check that we won't be pushed over our dust exposure limit by the feerate increase.
		let dust_exposure_limiting_feerate =
			self.context.get_dust_exposure_limiting_feerate(&fee_estimator);
		let htlc_stats = self.context.get_pending_htlc_stats(None, dust_exposure_limiting_feerate);
		let max_dust_htlc_exposure_msat =
			self.context.get_max_dust_htlc_exposure_msat(dust_exposure_limiting_feerate);
		if htlc_stats.on_holder_tx_dust_exposure_msat > max_dust_htlc_exposure_msat {
			return Err(ChannelError::close(format!("Peer sent update_fee with a feerate ({}) which may over-expose us to dust-in-flight on our own transactions (totaling {} msat)",
				msg.feerate_per_kw, htlc_stats.on_holder_tx_dust_exposure_msat)));
		}
		if htlc_stats.on_counterparty_tx_dust_exposure_msat > max_dust_htlc_exposure_msat {
			return Err(ChannelError::close(format!("Peer sent update_fee with a feerate ({}) which may over-expose us to dust-in-flight on our counterparty's transactions (totaling {} msat)",
				msg.feerate_per_kw, htlc_stats.on_counterparty_tx_dust_exposure_msat)));
		}
		Ok(())
	}

	/// Indicates that the signer may have some signatures for us, so we should retry if we're
	/// blocked.
	#[cfg(async_signing)]
	pub fn signer_maybe_unblocked<L: Deref>(&mut self, logger: &L) -> SignerResumeUpdates
	where
		L::Target: Logger,
	{
		if !self.context.holder_commitment_point.is_available() {
			log_trace!(logger, "Attempting to update holder per-commitment point...");
			self.context.holder_commitment_point.try_resolve_pending(
				&self.context.holder_signer,
				&self.context.secp_ctx,
				logger,
			);
		}
		let funding_signed = if self.context.signer_pending_funding && !self.context.is_outbound() {
			self.context.get_funding_signed_msg(logger).1
		} else {
			None
		};
		let channel_ready =
			if funding_signed.is_some() { self.check_get_channel_ready(0, logger) } else { None };

		let mut commitment_update = if self.context.signer_pending_commitment_update {
			log_trace!(logger, "Attempting to generate pending commitment update...");
			self.get_last_commitment_update_for_send(logger).ok()
		} else {
			None
		};
		let mut revoke_and_ack = if self.context.signer_pending_revoke_and_ack {
			log_trace!(logger, "Attempting to generate pending revoke and ack...");
			self.get_last_revoke_and_ack(logger)
		} else {
			None
		};

		if self.context.resend_order == RAACommitmentOrder::CommitmentFirst
			&& self.context.signer_pending_commitment_update
			&& revoke_and_ack.is_some()
		{
			log_trace!(logger, "Signer unblocked for revoke and ack, but unable to send due to resend order, waiting on signer for commitment update");
			self.context.signer_pending_revoke_and_ack = true;
			revoke_and_ack = None;
		}
		if self.context.resend_order == RAACommitmentOrder::RevokeAndACKFirst
			&& self.context.signer_pending_revoke_and_ack
			&& commitment_update.is_some()
		{
			log_trace!(logger, "Signer unblocked for commitment update, but unable to send due to resend order, waiting on signer for revoke and ack");
			self.context.signer_pending_commitment_update = true;
			commitment_update = None;
		}

		let (closing_signed, signed_closing_tx) = if self.context.signer_pending_closing {
			debug_assert!(self.context.last_sent_closing_fee.is_some());
			if let Some((fee, skip_remote_output, fee_range, holder_sig)) =
				self.context.last_sent_closing_fee.clone()
			{
				debug_assert!(holder_sig.is_none());
				log_trace!(logger, "Attempting to generate pending closing_signed...");
				let (closing_tx, fee) = self.build_closing_transaction(fee, skip_remote_output);
				let closing_signed = self.get_closing_signed_msg(
					&closing_tx,
					skip_remote_output,
					fee,
					fee_range.min_fee_satoshis,
					fee_range.max_fee_satoshis,
					logger,
				);
				let signed_tx =
					if let (Some(ClosingSigned { signature, .. }), Some(counterparty_sig)) =
						(closing_signed.as_ref(), self.context.last_received_closing_sig)
					{
						let funding_redeemscript = self.context.get_funding_redeemscript();
						let sighash = closing_tx.trust().get_sighash_all(
							&funding_redeemscript,
							self.context.channel_value_satoshis,
						);
						debug_assert!(self
							.context
							.secp_ctx
							.verify_ecdsa(
								&sighash,
								&counterparty_sig,
								&self.context.get_counterparty_pubkeys().funding_pubkey
							)
							.is_ok());
						Some(self.build_signed_closing_transaction(
							&closing_tx,
							&counterparty_sig,
							signature,
						))
					} else {
						None
					};
				(closing_signed, signed_tx)
			} else {
				(None, None)
			}
		} else {
			(None, None)
		};

		log_trace!(logger, "Signer unblocked with {} commitment_update, {} revoke_and_ack, with resend order {:?}, {} funding_signed, {} channel_ready,
					{} closing_signed, and {} signed_closing_tx",
			if commitment_update.is_some() { "a" } else { "no" },
			if revoke_and_ack.is_some() { "a" } else { "no" },
			self.context.resend_order,
			if funding_signed.is_some() { "a" } else { "no" },
			if channel_ready.is_some() { "a" } else { "no" },
			if closing_signed.is_some() { "a" } else { "no" },
			if signed_closing_tx.is_some() { "a" } else { "no" });

		SignerResumeUpdates {
			commitment_update,
			revoke_and_ack,
			funding_signed,
			channel_ready,
			order: self.context.resend_order.clone(),
			closing_signed,
			signed_closing_tx,
		}
	}

	fn get_last_revoke_and_ack<L: Deref>(&mut self, logger: &L) -> Option<msgs::RevokeAndACK>
	where
		L::Target: Logger,
	{
		debug_assert!(
			self.context.holder_commitment_point.transaction_number()
				<= INITIAL_COMMITMENT_NUMBER - 2
		);
		self.context.holder_commitment_point.try_resolve_pending(
			&self.context.holder_signer,
			&self.context.secp_ctx,
			logger,
		);
		let per_commitment_secret = self
			.context
			.holder_signer
			.as_ref()
			.release_commitment_secret(
				self.context.holder_commitment_point.transaction_number() + 2,
			)
			.ok();
		if let (HolderCommitmentPoint::Available { current, .. }, Some(per_commitment_secret)) =
			(self.context.holder_commitment_point, per_commitment_secret)
		{
			self.context.signer_pending_revoke_and_ack = false;
			return Some(msgs::RevokeAndACK {
				channel_id: self.context.channel_id,
				per_commitment_secret,
				next_per_commitment_point: current,
				#[cfg(taproot)]
				next_local_nonce: None,
			});
		}
		if !self.context.holder_commitment_point.is_available() {
			log_trace!(logger, "Last revoke-and-ack pending in channel {} for sequence {} because the next per-commitment point is not available",
				&self.context.channel_id(), self.context.holder_commitment_point.transaction_number());
		}
		if per_commitment_secret.is_none() {
			log_trace!(logger, "Last revoke-and-ack pending in channel {} for sequence {} because the next per-commitment secret for {} is not available",
				&self.context.channel_id(), self.context.holder_commitment_point.transaction_number(),
				self.context.holder_commitment_point.transaction_number() + 2);
		}
		#[cfg(not(async_signing))]
		{
			panic!("Holder commitment point and per commitment secret must be available when generating revoke_and_ack");
		}
		#[cfg(async_signing)]
		{
			// Technically if we're at HolderCommitmentPoint::PendingNext,
			// we have a commitment point ready to send in an RAA, however we
			// choose to wait since if we send RAA now, we could get another
			// CS before we have any commitment point available. Blocking our
			// RAA here is a convenient way to make sure that post-funding
			// we're only ever waiting on one commitment point at a time.
			log_trace!(logger, "Last revoke-and-ack pending in channel {} for sequence {} because the next per-commitment point is not available",
				&self.context.channel_id(), self.context.holder_commitment_point.transaction_number());
			self.context.signer_pending_revoke_and_ack = true;
			None
		}
	}

	/// Gets the last commitment update for immediate sending to our peer.
	fn get_last_commitment_update_for_send<L: Deref>(
		&mut self, logger: &L,
	) -> Result<msgs::CommitmentUpdate, ()>
	where
		L::Target: Logger,
	{
		let mut update_add_htlcs = Vec::new();
		let mut update_fulfill_htlcs = Vec::new();
		let mut update_fail_htlcs = Vec::new();
		let mut update_fail_malformed_htlcs = Vec::new();

		for htlc in self.context.pending_outbound_htlcs.iter() {
			if let &OutboundHTLCState::LocalAnnounced(ref onion_packet) = &htlc.state {
				update_add_htlcs.push(msgs::UpdateAddHTLC {
					channel_id: self.context.channel_id(),
					htlc_id: htlc.htlc_id,
					amount_msat: htlc.amount_msat,
					payment_hash: htlc.payment_hash,
					cltv_expiry: htlc.cltv_expiry,
					onion_routing_packet: (**onion_packet).clone(),
					skimmed_fee_msat: htlc.skimmed_fee_msat,
					blinding_point: htlc.blinding_point,
					amount_rgb: htlc.amount_rgb,
				});
			}
		}

		for htlc in self.context.pending_inbound_htlcs.iter() {
			if let &InboundHTLCState::LocalRemoved(ref reason) = &htlc.state {
				match reason {
					&InboundHTLCRemovalReason::FailRelay(ref err_packet) => {
						update_fail_htlcs.push(msgs::UpdateFailHTLC {
							channel_id: self.context.channel_id(),
							htlc_id: htlc.htlc_id,
							reason: err_packet.clone(),
						});
					},
					&InboundHTLCRemovalReason::FailMalformed((
						ref sha256_of_onion,
						ref failure_code,
					)) => {
						update_fail_malformed_htlcs.push(msgs::UpdateFailMalformedHTLC {
							channel_id: self.context.channel_id(),
							htlc_id: htlc.htlc_id,
							sha256_of_onion: sha256_of_onion.clone(),
							failure_code: failure_code.clone(),
						});
					},
					&InboundHTLCRemovalReason::Fulfill(ref payment_preimage) => {
						update_fulfill_htlcs.push(msgs::UpdateFulfillHTLC {
							channel_id: self.context.channel_id(),
							htlc_id: htlc.htlc_id,
							payment_preimage: payment_preimage.clone(),
						});
					},
				}
			}
		}

		let update_fee = if self.context.is_outbound() && self.context.pending_update_fee.is_some()
		{
			Some(msgs::UpdateFee {
				channel_id: self.context.channel_id(),
				feerate_per_kw: self.context.pending_update_fee.unwrap().0,
			})
		} else {
			None
		};

		log_trace!(logger, "Regenerating latest commitment update in channel {} with{} {} update_adds, {} update_fulfills, {} update_fails, and {} update_fail_malformeds",
				&self.context.channel_id(), if update_fee.is_some() { " update_fee," } else { "" },
				update_add_htlcs.len(), update_fulfill_htlcs.len(), update_fail_htlcs.len(), update_fail_malformed_htlcs.len());
		let commitment_signed =
			if let Ok(update) = self.send_commitment_no_state_update(logger).map(|(cu, _)| cu) {
				if self.context.signer_pending_commitment_update {
					log_trace!(
						logger,
						"Commitment update generated: clearing signer_pending_commitment_update"
					);
					self.context.signer_pending_commitment_update = false;
				}
				update
			} else {
				#[cfg(not(async_signing))]
				{
					panic!("Failed to get signature for new commitment state");
				}
				#[cfg(async_signing)]
				{
					if !self.context.signer_pending_commitment_update {
						log_trace!(logger, "Commitment update awaiting signer: setting signer_pending_commitment_update");
						self.context.signer_pending_commitment_update = true;
					}
					return Err(());
				}
			};
		Ok(msgs::CommitmentUpdate {
			update_add_htlcs,
			update_fulfill_htlcs,
			update_fail_htlcs,
			update_fail_malformed_htlcs,
			update_fee,
			commitment_signed,
		})
	}

	/// Gets the `Shutdown` message we should send our peer on reconnect, if any.
	pub fn get_outbound_shutdown(&self) -> Option<msgs::Shutdown> {
		if self.context.channel_state.is_local_shutdown_sent() {
			assert!(self.context.shutdown_scriptpubkey.is_some());
			Some(msgs::Shutdown {
				channel_id: self.context.channel_id,
				scriptpubkey: self.get_closing_scriptpubkey(),
			})
		} else {
			None
		}
	}

	/// May panic if some calls other than message-handling calls (which will all Err immediately)
	/// have been called between remove_uncommitted_htlcs_and_mark_paused and this call.
	///
	/// Some links printed in log lines are included here to check them during build (when run with
	/// `cargo doc --document-private-items`):
	/// [`super::channelmanager::ChannelManager::force_close_without_broadcasting_txn`] and
	/// [`super::channelmanager::ChannelManager::force_close_all_channels_without_broadcasting_txn`].
	pub fn channel_reestablish<L: Deref, NS: Deref>(
		&mut self, msg: &msgs::ChannelReestablish, logger: &L, node_signer: &NS,
		chain_hash: ChainHash, user_config: &UserConfig, best_block: &BestBlock,
	) -> Result<ReestablishResponses, ChannelError>
	where
		L::Target: Logger,
		NS::Target: NodeSigner,
	{
		if !self.context.channel_state.is_peer_disconnected() {
			// While BOLT 2 doesn't indicate explicitly we should error this channel here, it
			// almost certainly indicates we are going to end up out-of-sync in some way, so we
			// just close here instead of trying to recover.
			return Err(ChannelError::close(
				"Peer sent a loose channel_reestablish not after reconnect".to_owned(),
			));
		}

		if msg.next_local_commitment_number >= INITIAL_COMMITMENT_NUMBER
			|| msg.next_remote_commitment_number >= INITIAL_COMMITMENT_NUMBER
			|| msg.next_local_commitment_number == 0
		{
			return Err(ChannelError::close(
				"Peer sent an invalid channel_reestablish to force close in a non-standard way"
					.to_owned(),
			));
		}

		let our_commitment_transaction = INITIAL_COMMITMENT_NUMBER
			- self.context.holder_commitment_point.transaction_number()
			- 1;
		if msg.next_remote_commitment_number > 0 {
			let expected_point = self.context.holder_signer.as_ref()
				.get_per_commitment_point(INITIAL_COMMITMENT_NUMBER - msg.next_remote_commitment_number + 1, &self.context.secp_ctx)
				.expect("TODO: async signing is not yet supported for per commitment points upon channel reestablishment");
			let given_secret = SecretKey::from_slice(&msg.your_last_per_commitment_secret)
				.map_err(|_| {
					ChannelError::close(
						"Peer sent a garbage channel_reestablish with unparseable secret key"
							.to_owned(),
					)
				})?;
			if expected_point != PublicKey::from_secret_key(&self.context.secp_ctx, &given_secret) {
				return Err(ChannelError::close("Peer sent a garbage channel_reestablish with secret key not matching the commitment height provided".to_owned()));
			}
			if msg.next_remote_commitment_number > our_commitment_transaction {
				macro_rules! log_and_panic {
					($err_msg: expr) => {
						log_error!(
							logger,
							$err_msg,
							&self.context.channel_id,
							log_pubkey!(self.context.counterparty_node_id)
						);
						panic!(
							$err_msg,
							&self.context.channel_id,
							log_pubkey!(self.context.counterparty_node_id)
						);
					};
				}
				log_and_panic!("We have fallen behind - we have received proof that if we broadcast our counterparty is going to claim all our funds.\n\
					This implies you have restarted with lost ChannelMonitor and ChannelManager state, the first of which is a violation of the LDK chain::Watch requirements.\n\
					More specifically, this means you have a bug in your implementation that can cause loss of funds, or you are running with an old backup, which is unsafe.\n\
					If you have restored from an old backup and wish to force-close channels and return to operation, you should start up, call\n\
					ChannelManager::force_close_without_broadcasting_txn on channel {} with counterparty {} or\n\
					ChannelManager::force_close_all_channels_without_broadcasting_txn, then reconnect to peer(s).\n\
					Note that due to a long-standing bug in lnd you may have to reach out to peers running lnd-based nodes to ask them to manually force-close channels\n\
					See https://github.com/lightningdevkit/rust-lightning/issues/1565 for more info.");
			}
		}

		// Before we change the state of the channel, we check if the peer is sending a very old
		// commitment transaction number, if yes we send a warning message.
		if msg.next_remote_commitment_number + 1 < our_commitment_transaction {
			return Err(ChannelError::Warn(format!(
				"Peer attempted to reestablish channel with a very old local commitment transaction: {} (received) vs {} (expected)",
				msg.next_remote_commitment_number,
				our_commitment_transaction
			)));
		}

		// Go ahead and unmark PeerDisconnected as various calls we may make check for it (and all
		// remaining cases either succeed or ErrorMessage-fail).
		self.context.channel_state.clear_peer_disconnected();
		self.context.sent_message_awaiting_response = None;

		let shutdown_msg = self.get_outbound_shutdown();

		let announcement_sigs = self.get_announcement_sigs(
			node_signer,
			chain_hash,
			user_config,
			best_block.height,
			logger,
		);

		if matches!(self.context.channel_state, ChannelState::AwaitingChannelReady(_)) {
			// If we're waiting on a monitor update, we shouldn't re-send any channel_ready's.
			if !self.context.channel_state.is_our_channel_ready()
				|| self.context.channel_state.is_monitor_update_in_progress()
			{
				if msg.next_remote_commitment_number != 0 {
					return Err(ChannelError::close("Peer claimed they saw a revoke_and_ack but we haven't sent channel_ready yet".to_owned()));
				}
				// Short circuit the whole handler as there is nothing we can resend them
				return Ok(ReestablishResponses {
					channel_ready: None,
					raa: None,
					commitment_update: None,
					order: RAACommitmentOrder::CommitmentFirst,
					shutdown_msg,
					announcement_sigs,
				});
			}

			// We have OurChannelReady set!
			return Ok(ReestablishResponses {
				channel_ready: Some(self.get_channel_ready()),
				raa: None,
				commitment_update: None,
				order: RAACommitmentOrder::CommitmentFirst,
				shutdown_msg,
				announcement_sigs,
			});
		}

		let required_revoke = if msg.next_remote_commitment_number == our_commitment_transaction {
			// Remote isn't waiting on any RevokeAndACK from us!
			// Note that if we need to repeat our ChannelReady we'll do that in the next if block.
			None
		} else if msg.next_remote_commitment_number + 1 == our_commitment_transaction {
			if self.context.channel_state.is_monitor_update_in_progress() {
				self.context.monitor_pending_revoke_and_ack = true;
				None
			} else {
				self.get_last_revoke_and_ack(logger)
			}
		} else {
			debug_assert!(false, "All values should have been handled in the four cases above");
			return Err(ChannelError::close(format!(
				"Peer attempted to reestablish channel expecting a future local commitment transaction: {} (received) vs {} (expected)",
				msg.next_remote_commitment_number,
				our_commitment_transaction
			)));
		};

		// We increment cur_counterparty_commitment_transaction_number only upon receipt of
		// revoke_and_ack, not on sending commitment_signed, so we add one if have
		// AwaitingRemoteRevoke set, which indicates we sent a commitment_signed but haven't gotten
		// the corresponding revoke_and_ack back yet.
		let is_awaiting_remote_revoke = self.context.channel_state.is_awaiting_remote_revoke();
		if is_awaiting_remote_revoke && !self.is_awaiting_monitor_update() {
			self.mark_awaiting_response();
		}
		let next_counterparty_commitment_number = INITIAL_COMMITMENT_NUMBER
			- self.context.cur_counterparty_commitment_transaction_number
			+ if is_awaiting_remote_revoke { 1 } else { 0 };

		let channel_ready = if msg.next_local_commitment_number == 1
			&& INITIAL_COMMITMENT_NUMBER - self.context.holder_commitment_point.transaction_number()
				== 1
		{
			// We should never have to worry about MonitorUpdateInProgress resending ChannelReady
			Some(self.get_channel_ready())
		} else {
			None
		};

		if msg.next_local_commitment_number == next_counterparty_commitment_number {
			if required_revoke.is_some() || self.context.signer_pending_revoke_and_ack {
				log_debug!(
					logger,
					"Reconnected channel {} with only lost outbound RAA",
					&self.context.channel_id()
				);
			} else {
				log_debug!(
					logger,
					"Reconnected channel {} with no loss",
					&self.context.channel_id()
				);
			}

			Ok(ReestablishResponses {
				channel_ready,
				shutdown_msg,
				announcement_sigs,
				raa: required_revoke,
				commitment_update: None,
				order: self.context.resend_order.clone(),
			})
		} else if msg.next_local_commitment_number == next_counterparty_commitment_number - 1 {
			if required_revoke.is_some() || self.context.signer_pending_revoke_and_ack {
				log_debug!(
					logger,
					"Reconnected channel {} with lost outbound RAA and lost remote commitment tx",
					&self.context.channel_id()
				);
			} else {
				log_debug!(
					logger,
					"Reconnected channel {} with only lost remote commitment tx",
					&self.context.channel_id()
				);
			}

			if self.context.channel_state.is_monitor_update_in_progress() {
				self.context.monitor_pending_commitment_signed = true;
				Ok(ReestablishResponses {
					channel_ready,
					shutdown_msg,
					announcement_sigs,
					commitment_update: None,
					raa: None,
					order: self.context.resend_order.clone(),
				})
			} else {
				let commitment_update = if self.context.resend_order
					== RAACommitmentOrder::RevokeAndACKFirst
					&& self.context.signer_pending_revoke_and_ack
				{
					log_trace!(logger, "Reconnected channel {} with lost outbound RAA and lost remote commitment tx, but unable to send due to resend order, waiting on signer for revoke and ack", &self.context.channel_id());
					self.context.signer_pending_commitment_update = true;
					None
				} else {
					self.get_last_commitment_update_for_send(logger).ok()
				};
				let raa = if self.context.resend_order == RAACommitmentOrder::CommitmentFirst
					&& self.context.signer_pending_commitment_update
					&& required_revoke.is_some()
				{
					log_trace!(logger, "Reconnected channel {} with lost outbound RAA and lost remote commitment tx, but unable to send due to resend order, waiting on signer for commitment update", &self.context.channel_id());
					self.context.signer_pending_revoke_and_ack = true;
					None
				} else {
					required_revoke
				};
				Ok(ReestablishResponses {
					channel_ready,
					shutdown_msg,
					announcement_sigs,
					raa,
					commitment_update,
					order: self.context.resend_order.clone(),
				})
			}
		} else if msg.next_local_commitment_number < next_counterparty_commitment_number {
			Err(ChannelError::close(format!(
				"Peer attempted to reestablish channel with a very old remote commitment transaction: {} (received) vs {} (expected)",
				msg.next_local_commitment_number,
				next_counterparty_commitment_number,
			)))
		} else {
			Err(ChannelError::close(format!(
				"Peer attempted to reestablish channel with a future remote commitment transaction: {} (received) vs {} (expected)",
				msg.next_local_commitment_number,
				next_counterparty_commitment_number,
			)))
		}
	}

	/// Calculates and returns our minimum and maximum closing transaction fee amounts, in whole
	/// satoshis. The amounts remain consistent unless a peer disconnects/reconnects or we restart,
	/// at which point they will be recalculated.
	fn calculate_closing_fee_limits<F: Deref>(
		&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>,
	) -> (u64, u64)
	where
		F::Target: FeeEstimator,
	{
		if let Some((min, max)) = self.context.closing_fee_limits {
			return (min, max);
		}

		// Propose a range from our current Background feerate to our Normal feerate plus our
		// force_close_avoidance_max_fee_satoshis.
		// If we fail to come to consensus, we'll have to force-close.
		let mut proposed_feerate =
			fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::ChannelCloseMinimum);
		// Use NonAnchorChannelFee because this should be an estimate for a channel close
		// that we don't expect to need fee bumping
		let normal_feerate =
			fee_estimator.bounded_sat_per_1000_weight(ConfirmationTarget::NonAnchorChannelFee);
		let mut proposed_max_feerate =
			if self.context.is_outbound() { normal_feerate } else { u32::max_value() };

		// The spec requires that (when the channel does not have anchors) we only send absolute
		// channel fees no greater than the absolute channel fee on the current commitment
		// transaction. It's unclear *which* commitment transaction this refers to, and there isn't
		// very good reason to apply such a limit in any case. We don't bother doing so, risking
		// some force-closure by old nodes, but we wanted to close the channel anyway.

		if let Some(target_feerate) = self.context.target_closing_feerate_sats_per_kw {
			let min_feerate = if self.context.is_outbound() {
				target_feerate
			} else {
				cmp::min(self.context.feerate_per_kw, target_feerate)
			};
			proposed_feerate = cmp::max(proposed_feerate, min_feerate);
			proposed_max_feerate = cmp::max(proposed_max_feerate, min_feerate);
		}

		// Note that technically we could end up with a lower minimum fee if one sides' balance is
		// below our dust limit, causing the output to disappear. We don't bother handling this
		// case, however, as this should only happen if a channel is closed before any (material)
		// payments have been made on it. This may cause slight fee overpayment and/or failure to
		// come to consensus with our counterparty on appropriate fees, however it should be a
		// relatively rare case. We can revisit this later, though note that in order to determine
		// if the funders' output is dust we have to know the absolute fee we're going to use.
		let tx_weight = self.get_closing_transaction_weight(
			Some(&self.get_closing_scriptpubkey()),
			Some(self.context.counterparty_shutdown_scriptpubkey.as_ref().unwrap()),
		);
		let proposed_total_fee_satoshis = proposed_feerate as u64 * tx_weight / 1000;
		let proposed_max_total_fee_satoshis = if self.context.is_outbound() {
			// We always add force_close_avoidance_max_fee_satoshis to our normal
			// feerate-calculated fee, but allow the max to be overridden if we're using a
			// target feerate-calculated fee.
			cmp::max(
				normal_feerate as u64 * tx_weight / 1000
					+ self.context.config.options.force_close_avoidance_max_fee_satoshis,
				proposed_max_feerate as u64 * tx_weight / 1000,
			)
		} else {
			self.context.channel_value_satoshis - (self.context.value_to_self_msat + 999) / 1000
		};

		self.context.closing_fee_limits =
			Some((proposed_total_fee_satoshis, proposed_max_total_fee_satoshis));
		self.context.closing_fee_limits.clone().unwrap()
	}

	/// Returns true if we're ready to commence the closing_signed negotiation phase. This is true
	/// after both sides have exchanged a `shutdown` message and all HTLCs have been drained. At
	/// this point if we're the funder we should send the initial closing_signed, and in any case
	/// shutdown should complete within a reasonable timeframe.
	fn closing_negotiation_ready(&self) -> bool {
		self.context.closing_negotiation_ready()
	}

	/// Checks if the closing_signed negotiation is making appropriate progress, possibly returning
	/// an Err if no progress is being made and the channel should be force-closed instead.
	/// Should be called on a one-minute timer.
	pub fn timer_check_closing_negotiation_progress(&mut self) -> Result<(), ChannelError> {
		if self.closing_negotiation_ready() {
			if self.context.closing_signed_in_flight {
				return Err(ChannelError::close(
					"closing_signed negotiation failed to finish within two timer ticks".to_owned(),
				));
			} else {
				self.context.closing_signed_in_flight = true;
			}
		}
		Ok(())
	}

	pub fn maybe_propose_closing_signed<F: Deref, L: Deref>(
		&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
	) -> Result<
		(Option<msgs::ClosingSigned>, Option<Transaction>, Option<ShutdownResult>),
		ChannelError,
	>
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		// If we're waiting on a monitor persistence, that implies we're also waiting to send some
		// message to our counterparty (probably a `revoke_and_ack`). In such a case, we shouldn't
		// initiate `closing_signed` negotiation until we're clear of all pending messages. Note
		// that closing_negotiation_ready checks this case (as well as a few others).
		if self.context.last_sent_closing_fee.is_some() || !self.closing_negotiation_ready() {
			return Ok((None, None, None));
		}

		if !self.context.is_outbound() {
			if let Some(msg) = &self.context.pending_counterparty_closing_signed.take() {
				return self.closing_signed(fee_estimator, &msg, logger);
			}
			return Ok((None, None, None));
		}

		// If we're waiting on a counterparty `commitment_signed` to clear some updates from our
		// local commitment transaction, we can't yet initiate `closing_signed` negotiation.
		if self.context.expecting_peer_commitment_signed {
			return Ok((None, None, None));
		}

		let (our_min_fee, our_max_fee) = self.calculate_closing_fee_limits(fee_estimator);

		assert!(self.context.shutdown_scriptpubkey.is_some());
		let (closing_tx, total_fee_satoshis) = self.build_closing_transaction(our_min_fee, false);
		log_trace!(logger, "Proposing initial closing_signed for our counterparty with a fee range of {}-{} sat (with initial proposal {} sats)",
			our_min_fee, our_max_fee, total_fee_satoshis);

		let closing_signed = self.get_closing_signed_msg(
			&closing_tx,
			false,
			total_fee_satoshis,
			our_min_fee,
			our_max_fee,
			logger,
		);
		Ok((closing_signed, None, None))
	}

	// Marks a channel as waiting for a response from the counterparty. If it's not received
	// [`DISCONNECT_PEER_AWAITING_RESPONSE_TICKS`] after sending our own to them, then we'll attempt
	// a reconnection.
	fn mark_awaiting_response(&mut self) {
		self.context.sent_message_awaiting_response = Some(0);
	}

	/// Determines whether we should disconnect the counterparty due to not receiving a response
	/// within our expected timeframe.
	///
	/// This should be called on every [`super::channelmanager::ChannelManager::timer_tick_occurred`].
	pub fn should_disconnect_peer_awaiting_response(&mut self) -> bool {
		let ticks_elapsed =
			if let Some(ticks_elapsed) = self.context.sent_message_awaiting_response.as_mut() {
				ticks_elapsed
			} else {
				// Don't disconnect when we're not waiting on a response.
				return false;
			};
		*ticks_elapsed += 1;
		*ticks_elapsed >= DISCONNECT_PEER_AWAITING_RESPONSE_TICKS
	}

	pub fn shutdown(
		&mut self, signer_provider: &SP, their_features: &InitFeatures, msg: &msgs::Shutdown,
	) -> Result<
		(Option<msgs::Shutdown>, Option<ChannelMonitorUpdate>, Vec<(HTLCSource, PaymentHash)>),
		ChannelError,
	> {
		if self.context.channel_state.is_peer_disconnected() {
			return Err(ChannelError::close(
				"Peer sent shutdown when we needed a channel_reestablish".to_owned(),
			));
		}
		if self.context.channel_state.is_pre_funded_state() {
			// Spec says we should fail the connection, not the channel, but that's nonsense, there
			// are plenty of reasons you may want to fail a channel pre-funding, and spec says you
			// can do that via error message without getting a connection fail anyway...
			return Err(ChannelError::close(
				"Peer sent shutdown pre-funding generation".to_owned(),
			));
		}
		for htlc in self.context.pending_inbound_htlcs.iter() {
			if let InboundHTLCState::RemoteAnnounced(_) = htlc.state {
				return Err(ChannelError::close(
					"Got shutdown with remote pending HTLCs".to_owned(),
				));
			}
		}
		assert!(!matches!(self.context.channel_state, ChannelState::ShutdownComplete));

		if !script::is_bolt2_compliant(&msg.scriptpubkey, their_features) {
			return Err(ChannelError::Warn(format!(
				"Got a nonstandard scriptpubkey ({}) from remote peer",
				msg.scriptpubkey.to_hex_string()
			)));
		}

		if self.context.counterparty_shutdown_scriptpubkey.is_some() {
			if Some(&msg.scriptpubkey) != self.context.counterparty_shutdown_scriptpubkey.as_ref() {
				return Err(ChannelError::Warn(format!("Got shutdown request with a scriptpubkey ({}) which did not match their previous scriptpubkey.", msg.scriptpubkey.to_hex_string())));
			}
		} else {
			self.context.counterparty_shutdown_scriptpubkey = Some(msg.scriptpubkey.clone());
		}

		// If we have any LocalAnnounced updates we'll probably just get back an update_fail_htlc
		// immediately after the commitment dance, but we can send a Shutdown because we won't send
		// any further commitment updates after we set LocalShutdownSent.
		let send_shutdown = !self.context.channel_state.is_local_shutdown_sent();

		let update_shutdown_script = match self.context.shutdown_scriptpubkey {
			Some(_) => false,
			None => {
				assert!(send_shutdown);
				let shutdown_scriptpubkey = match signer_provider.get_shutdown_scriptpubkey() {
					Ok(scriptpubkey) => scriptpubkey,
					Err(_) => {
						return Err(ChannelError::close(
							"Failed to get shutdown scriptpubkey".to_owned(),
						))
					},
				};
				if !shutdown_scriptpubkey.is_compatible(their_features) {
					return Err(ChannelError::close(format!(
						"Provided a scriptpubkey format not accepted by peer: {}",
						shutdown_scriptpubkey
					)));
				}
				self.context.shutdown_scriptpubkey = Some(shutdown_scriptpubkey);
				true
			},
		};

		// From here on out, we may not fail!

		self.context.channel_state.set_remote_shutdown_sent();
		self.context.update_time_counter += 1;

		let monitor_update = if update_shutdown_script {
			self.context.latest_monitor_update_id += 1;
			let monitor_update = ChannelMonitorUpdate {
				update_id: self.context.latest_monitor_update_id,
				counterparty_node_id: Some(self.context.counterparty_node_id),
				updates: vec![ChannelMonitorUpdateStep::ShutdownScript {
					scriptpubkey: self.get_closing_scriptpubkey(),
				}],
				channel_id: Some(self.context.channel_id()),
			};
			self.monitor_updating_paused(false, false, false, Vec::new(), Vec::new(), Vec::new());
			self.push_ret_blockable_mon_update(monitor_update)
		} else {
			None
		};
		let shutdown = if send_shutdown {
			Some(msgs::Shutdown {
				channel_id: self.context.channel_id,
				scriptpubkey: self.get_closing_scriptpubkey(),
			})
		} else {
			None
		};

		// We can't send our shutdown until we've committed all of our pending HTLCs, but the
		// remote side is unlikely to accept any new HTLCs, so we go ahead and "free" any holding
		// cell HTLCs and return them to fail the payment.
		self.context.holding_cell_update_fee = None;
		let mut dropped_outbound_htlcs =
			Vec::with_capacity(self.context.holding_cell_htlc_updates.len());
		self.context.holding_cell_htlc_updates.retain(|htlc_update| match htlc_update {
			&HTLCUpdateAwaitingACK::AddHTLC { ref payment_hash, ref source, .. } => {
				dropped_outbound_htlcs.push((source.clone(), payment_hash.clone()));
				false
			},
			_ => true,
		});

		self.context.channel_state.set_local_shutdown_sent();
		self.context.update_time_counter += 1;

		Ok((shutdown, monitor_update, dropped_outbound_htlcs))
	}

	fn build_signed_closing_transaction(
		&self, closing_tx: &ClosingTransaction, counterparty_sig: &Signature, sig: &Signature,
	) -> Transaction {
		let mut tx = closing_tx.trust().built_transaction().clone();

		tx.input[0].witness.push(Vec::new()); // First is the multisig dummy

		let funding_key = self.context.get_holder_pubkeys().funding_pubkey.serialize();
		let counterparty_funding_key = self.context.counterparty_funding_pubkey().serialize();
		let mut holder_sig = sig.serialize_der().to_vec();
		holder_sig.push(EcdsaSighashType::All as u8);
		let mut cp_sig = counterparty_sig.serialize_der().to_vec();
		cp_sig.push(EcdsaSighashType::All as u8);
		if funding_key[..] < counterparty_funding_key[..] {
			tx.input[0].witness.push(holder_sig);
			tx.input[0].witness.push(cp_sig);
		} else {
			tx.input[0].witness.push(cp_sig);
			tx.input[0].witness.push(holder_sig);
		}

		tx.input[0].witness.push(self.context.get_funding_redeemscript().into_bytes());
		tx
	}

	fn get_closing_signed_msg<L: Deref>(
		&mut self, closing_tx: &ClosingTransaction, skip_remote_output: bool, fee_satoshis: u64,
		min_fee_satoshis: u64, max_fee_satoshis: u64, logger: &L,
	) -> Option<msgs::ClosingSigned>
	where
		L::Target: Logger,
	{
		let sig = match &self.context.holder_signer {
			ChannelSignerType::Ecdsa(ecdsa) => {
				ecdsa.sign_closing_transaction(closing_tx, &self.context.secp_ctx).ok()
			},
			// TODO (taproot|arik)
			#[cfg(taproot)]
			_ => todo!(),
		};
		if sig.is_none() {
			log_trace!(logger, "Closing transaction signature unavailable, waiting on signer");
			self.context.signer_pending_closing = true;
		} else {
			self.context.signer_pending_closing = false;
		}
		let fee_range = msgs::ClosingSignedFeeRange { min_fee_satoshis, max_fee_satoshis };
		self.context.last_sent_closing_fee =
			Some((fee_satoshis, skip_remote_output, fee_range.clone(), sig.clone()));
		sig.map(|signature| msgs::ClosingSigned {
			channel_id: self.context.channel_id,
			fee_satoshis,
			signature,
			fee_range: Some(fee_range),
		})
	}

	pub fn closing_signed<F: Deref, L: Deref>(
		&mut self, fee_estimator: &LowerBoundedFeeEstimator<F>, msg: &msgs::ClosingSigned,
		logger: &L,
	) -> Result<
		(Option<msgs::ClosingSigned>, Option<Transaction>, Option<ShutdownResult>),
		ChannelError,
	>
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		if self.is_shutdown_pending_signature() {
			return Err(ChannelError::Warn(String::from("Remote end sent us a closing_signed while fully shutdown and just waiting on the final closing signature")));
		}
		if !self.context.channel_state.is_both_sides_shutdown() {
			return Err(ChannelError::close(
				"Remote end sent us a closing_signed before both sides provided a shutdown"
					.to_owned(),
			));
		}
		if self.context.channel_state.is_peer_disconnected() {
			return Err(ChannelError::close(
				"Peer sent closing_signed when we needed a channel_reestablish".to_owned(),
			));
		}
		if !self.context.pending_inbound_htlcs.is_empty()
			|| !self.context.pending_outbound_htlcs.is_empty()
		{
			return Err(ChannelError::close(
				"Remote end sent us a closing_signed while there were still pending HTLCs"
					.to_owned(),
			));
		}
		if msg.fee_satoshis > TOTAL_BITCOIN_SUPPLY_SATOSHIS {
			// this is required to stop potential overflow in build_closing_transaction
			return Err(ChannelError::close(
				"Remote tried to send us a closing tx with > 21 million BTC fee".to_owned(),
			));
		}

		if self.context.is_outbound() && self.context.last_sent_closing_fee.is_none() {
			return Err(ChannelError::close("Remote tried to send a closing_signed when we were supposed to propose the first one".to_owned()));
		}

		if self.context.channel_state.is_monitor_update_in_progress() {
			self.context.pending_counterparty_closing_signed = Some(msg.clone());
			return Ok((None, None, None));
		}

		let funding_redeemscript = self.context.get_funding_redeemscript();
		let mut skip_remote_output = false;
		let (mut closing_tx, used_total_fee) =
			self.build_closing_transaction(msg.fee_satoshis, skip_remote_output);
		if used_total_fee != msg.fee_satoshis {
			return Err(ChannelError::close(format!("Remote sent us a closing_signed with a fee other than the value they can claim. Fee in message: {}. Actual closing tx fee: {}", msg.fee_satoshis, used_total_fee)));
		}
		let sighash = closing_tx
			.trust()
			.get_sighash_all(&funding_redeemscript, self.context.channel_value_satoshis);

		match self.context.secp_ctx.verify_ecdsa(
			&sighash,
			&msg.signature,
			&self.context.get_counterparty_pubkeys().funding_pubkey,
		) {
			Ok(_) => {},
			Err(_e) => {
				// The remote end may have decided to revoke their output due to inconsistent dust
				// limits, so check for that case by re-checking the signature here.
				skip_remote_output = true;
				closing_tx = self.build_closing_transaction(msg.fee_satoshis, skip_remote_output).0;
				let sighash = closing_tx
					.trust()
					.get_sighash_all(&funding_redeemscript, self.context.channel_value_satoshis);
				secp_check!(
					self.context.secp_ctx.verify_ecdsa(
						&sighash,
						&msg.signature,
						self.context.counterparty_funding_pubkey()
					),
					"Invalid closing tx signature from peer".to_owned()
				);
			},
		};

		for (idx, outp) in closing_tx.trust().built_transaction().output.iter().enumerate() {
			// skip OP_RETURN
			if idx < 2
				&& !outp.script_pubkey.is_witness_program()
				&& outp.value < MAX_STD_OUTPUT_DUST_LIMIT_SATOSHIS
			{
				return Err(ChannelError::Close("Remote sent us a closing_signed with a dust output. Always use segwit closing scripts!".to_owned()));
			}
		}

		let closure_reason = if self.initiated_shutdown() {
			ClosureReason::LocallyInitiatedCooperativeClosure
		} else {
			ClosureReason::CounterpartyInitiatedCooperativeClosure
		};

		assert!(self.context.shutdown_scriptpubkey.is_some());
		if let Some((last_fee, _, _, Some(sig))) = self.context.last_sent_closing_fee {
			if last_fee == msg.fee_satoshis {
				let shutdown_result = ShutdownResult {
					closure_reason,
					monitor_update: None,
					dropped_outbound_htlcs: Vec::new(),
					unbroadcasted_batch_funding_txid: self
						.context
						.unbroadcasted_batch_funding_txid(),
					channel_id: self.context.channel_id,
					user_channel_id: self.context.user_id,
					channel_capacity_satoshis: self.context.channel_value_satoshis,
					counterparty_node_id: self.context.counterparty_node_id,
					unbroadcasted_funding_tx: self.context.unbroadcasted_funding(),
					is_manual_broadcast: self.context.is_manual_broadcast,
					channel_funding_txo: self.context.get_funding_txo(),
				};
				let tx =
					self.build_signed_closing_transaction(&mut closing_tx, &msg.signature, &sig);
				self.context.channel_state = ChannelState::ShutdownComplete;
				self.context.update_time_counter += 1;
				return Ok((None, Some(tx), Some(shutdown_result)));
			}
		}

		let (our_min_fee, our_max_fee) = self.calculate_closing_fee_limits(fee_estimator);

		macro_rules! propose_fee {
			($new_fee: expr) => {
				let (closing_tx, used_fee) = if $new_fee == msg.fee_satoshis {
					(closing_tx, $new_fee)
				} else {
					skip_remote_output = false;
					self.build_closing_transaction($new_fee, skip_remote_output)
				};

				let closing_signed = self.get_closing_signed_msg(
					&closing_tx,
					skip_remote_output,
					used_fee,
					our_min_fee,
					our_max_fee,
					logger,
				);
				let (signed_tx, shutdown_result) = if $new_fee == msg.fee_satoshis {
					let shutdown_result = ShutdownResult {
						closure_reason,
						monitor_update: None,
						dropped_outbound_htlcs: Vec::new(),
						unbroadcasted_batch_funding_txid: self
							.context
							.unbroadcasted_batch_funding_txid(),
						channel_id: self.context.channel_id,
						user_channel_id: self.context.user_id,
						channel_capacity_satoshis: self.context.channel_value_satoshis,
						counterparty_node_id: self.context.counterparty_node_id,
						unbroadcasted_funding_tx: self.context.unbroadcasted_funding(),
						is_manual_broadcast: self.context.is_manual_broadcast,
						channel_funding_txo: self.context.get_funding_txo(),
					};
					if closing_signed.is_some() {
						self.context.channel_state = ChannelState::ShutdownComplete;
					}
					self.context.update_time_counter += 1;
					self.context.last_received_closing_sig = Some(msg.signature.clone());
					let tx = closing_signed.as_ref().map(|ClosingSigned { signature, .. }| {
						self.build_signed_closing_transaction(
							&closing_tx,
							&msg.signature,
							signature,
						)
					});
					(tx, Some(shutdown_result))
				} else {
					(None, None)
				};
				return Ok((closing_signed, signed_tx, shutdown_result))
			};
		}

		if let Some(msgs::ClosingSignedFeeRange { min_fee_satoshis, max_fee_satoshis }) =
			msg.fee_range
		{
			if msg.fee_satoshis < min_fee_satoshis || msg.fee_satoshis > max_fee_satoshis {
				return Err(ChannelError::close(format!("Peer sent a bogus closing_signed - suggested fee of {} sat was not in their desired range of {} sat - {} sat", msg.fee_satoshis, min_fee_satoshis, max_fee_satoshis)));
			}
			if max_fee_satoshis < our_min_fee {
				return Err(ChannelError::Warn(format!("Unable to come to consensus about closing feerate, remote's max fee ({} sat) was smaller than our min fee ({} sat)", max_fee_satoshis, our_min_fee)));
			}
			if min_fee_satoshis > our_max_fee {
				return Err(ChannelError::Warn(format!("Unable to come to consensus about closing feerate, remote's min fee ({} sat) was greater than our max fee ({} sat)", min_fee_satoshis, our_max_fee)));
			}

			if !self.context.is_outbound() {
				// They have to pay, so pick the highest fee in the overlapping range.
				// We should never set an upper bound aside from their full balance
				debug_assert_eq!(
					our_max_fee,
					self.context.channel_value_satoshis
						- (self.context.value_to_self_msat + 999) / 1000
				);
				propose_fee!(cmp::min(max_fee_satoshis, our_max_fee));
			} else {
				if msg.fee_satoshis < our_min_fee || msg.fee_satoshis > our_max_fee {
					return Err(ChannelError::close(format!("Peer sent a bogus closing_signed - suggested fee of {} sat was not in our desired range of {} sat - {} sat after we informed them of our range.",
						msg.fee_satoshis, our_min_fee, our_max_fee)));
				}
				// The proposed fee is in our acceptable range, accept it and broadcast!
				propose_fee!(msg.fee_satoshis);
			}
		} else {
			// Old fee style negotiation. We don't bother to enforce whether they are complying
			// with the "making progress" requirements, we just comply and hope for the best.
			if let Some((last_fee, _, _, _)) = self.context.last_sent_closing_fee {
				if msg.fee_satoshis > last_fee {
					if msg.fee_satoshis < our_max_fee {
						propose_fee!(msg.fee_satoshis);
					} else if last_fee < our_max_fee {
						propose_fee!(our_max_fee);
					} else {
						return Err(ChannelError::close(format!("Unable to come to consensus about closing feerate, remote wants something ({} sat) higher than our max fee ({} sat)", msg.fee_satoshis, our_max_fee)));
					}
				} else {
					if msg.fee_satoshis > our_min_fee {
						propose_fee!(msg.fee_satoshis);
					} else if last_fee > our_min_fee {
						propose_fee!(our_min_fee);
					} else {
						return Err(ChannelError::close(format!("Unable to come to consensus about closing feerate, remote wants something ({} sat) lower than our min fee ({} sat)", msg.fee_satoshis, our_min_fee)));
					}
				}
			} else {
				if msg.fee_satoshis < our_min_fee {
					propose_fee!(our_min_fee);
				} else if msg.fee_satoshis > our_max_fee {
					propose_fee!(our_max_fee);
				} else {
					propose_fee!(msg.fee_satoshis);
				}
			}
		}
	}

	fn internal_htlc_satisfies_config(
		&self, htlc: &msgs::UpdateAddHTLC, amt_to_forward: u64, outgoing_cltv_value: u32,
		config: &ChannelConfig,
	) -> Result<(), (&'static str, u16)> {
		let fee = amt_to_forward
			.checked_mul(config.forwarding_fee_proportional_millionths as u64)
			.and_then(|prop_fee| {
				(prop_fee / 1000000).checked_add(config.forwarding_fee_base_msat as u64)
			});
		if fee.is_none()
			|| htlc.amount_msat < fee.unwrap()
			|| (htlc.amount_msat - fee.unwrap()) < amt_to_forward
		{
			return Err((
				"Prior hop has deviated from specified fees parameters or origin node has obsolete ones",
				0x1000 | 12, // fee_insufficient
			));
		}
		if (htlc.cltv_expiry as u64) < outgoing_cltv_value as u64 + config.cltv_expiry_delta as u64
		{
			return Err((
				"Forwarding node has tampered with the intended HTLC values or origin node has an obsolete cltv_expiry_delta",
				0x1000 | 13, // incorrect_cltv_expiry
			));
		}
		Ok(())
	}

	/// Determines whether the parameters of an incoming HTLC to be forwarded satisfy the channel's
	/// [`ChannelConfig`]. This first looks at the channel's current [`ChannelConfig`], and if
	/// unsuccessful, falls back to the previous one if one exists.
	pub fn htlc_satisfies_config(
		&self, htlc: &msgs::UpdateAddHTLC, amt_to_forward: u64, outgoing_cltv_value: u32,
	) -> Result<(), (&'static str, u16)> {
		self.internal_htlc_satisfies_config(
			&htlc,
			amt_to_forward,
			outgoing_cltv_value,
			&self.context.config(),
		)
		.or_else(|err| {
			if let Some(prev_config) = self.context.prev_config() {
				self.internal_htlc_satisfies_config(
					htlc,
					amt_to_forward,
					outgoing_cltv_value,
					&prev_config,
				)
			} else {
				Err(err)
			}
		})
	}

	pub fn can_accept_incoming_htlc<F: Deref, L: Deref>(
		&self, msg: &msgs::UpdateAddHTLC, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: L,
	) -> Result<(), (&'static str, u16)>
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		if self.context.channel_state.is_local_shutdown_sent() {
			return Err(("Shutdown was already sent", 0x4000 | 8));
		}

		let dust_exposure_limiting_feerate =
			self.context.get_dust_exposure_limiting_feerate(&fee_estimator);
		let htlc_stats = self.context.get_pending_htlc_stats(None, dust_exposure_limiting_feerate);
		let max_dust_htlc_exposure_msat =
			self.context.get_max_dust_htlc_exposure_msat(dust_exposure_limiting_feerate);
		let (htlc_timeout_dust_limit, htlc_success_dust_limit) =
			if self.context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
				(0, 0)
			} else {
				let dust_buffer_feerate = self.context.get_dust_buffer_feerate(None) as u64;
				(
					dust_buffer_feerate * htlc_timeout_tx_weight(self.context.get_channel_type())
						/ 1000,
					dust_buffer_feerate * htlc_success_tx_weight(self.context.get_channel_type())
						/ 1000,
				)
			};
		let exposure_dust_limit_timeout_sats =
			htlc_timeout_dust_limit + self.context.counterparty_dust_limit_satoshis;
		if msg.amount_msat / 1000 < exposure_dust_limit_timeout_sats {
			let on_counterparty_tx_dust_htlc_exposure_msat =
				htlc_stats.on_counterparty_tx_dust_exposure_msat + msg.amount_msat;
			if on_counterparty_tx_dust_htlc_exposure_msat > max_dust_htlc_exposure_msat {
				log_info!(logger, "Cannot accept value that would put our exposure to dust HTLCs at {} over the limit {} on counterparty commitment tx",
					on_counterparty_tx_dust_htlc_exposure_msat, max_dust_htlc_exposure_msat);
				return Err((
					"Exceeded our dust exposure limit on counterparty commitment tx",
					0x1000 | 7,
				));
			}
		} else {
			let htlc_dust_exposure_msat = per_outbound_htlc_counterparty_commit_tx_fee_msat(
				self.context.feerate_per_kw,
				&self.context.channel_type,
			);
			let counterparty_tx_dust_exposure = htlc_stats
				.on_counterparty_tx_dust_exposure_msat
				.saturating_add(htlc_dust_exposure_msat);
			if counterparty_tx_dust_exposure > max_dust_htlc_exposure_msat {
				log_info!(logger, "Cannot accept value that would put our exposure to tx fee dust at {} over the limit {} on counterparty commitment tx",
					counterparty_tx_dust_exposure, max_dust_htlc_exposure_msat);
				return Err((
					"Exceeded our tx fee dust exposure limit on counterparty commitment tx",
					0x1000 | 7,
				));
			}
		}

		let exposure_dust_limit_success_sats =
			htlc_success_dust_limit + self.context.holder_dust_limit_satoshis;
		if msg.amount_msat / 1000 < exposure_dust_limit_success_sats {
			let on_holder_tx_dust_htlc_exposure_msat =
				htlc_stats.on_holder_tx_dust_exposure_msat + msg.amount_msat;
			if on_holder_tx_dust_htlc_exposure_msat > max_dust_htlc_exposure_msat {
				log_info!(logger, "Cannot accept value that would put our exposure to dust HTLCs at {} over the limit {} on holder commitment tx",
					on_holder_tx_dust_htlc_exposure_msat, max_dust_htlc_exposure_msat);
				return Err((
					"Exceeded our dust exposure limit on holder commitment tx",
					0x1000 | 7,
				));
			}
		}

		let anchor_outputs_value_msat =
			if self.context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
				ANCHOR_OUTPUT_VALUE_SATOSHI * 2 * 1000
			} else {
				0
			};

		let mut removed_outbound_total_msat = 0;
		for ref htlc in self.context.pending_outbound_htlcs.iter() {
			if let OutboundHTLCState::AwaitingRemoteRevokeToRemove(OutboundHTLCOutcome::Success(
				_,
			)) = htlc.state
			{
				removed_outbound_total_msat += htlc.amount_msat;
			} else if let OutboundHTLCState::AwaitingRemovedRemoteRevoke(
				OutboundHTLCOutcome::Success(_),
			) = htlc.state
			{
				removed_outbound_total_msat += htlc.amount_msat;
			}
		}

		let pending_value_to_self_msat = self.context.value_to_self_msat
			+ htlc_stats.pending_inbound_htlcs_value_msat
			- removed_outbound_total_msat;
		let pending_remote_value_msat =
			self.context.channel_value_satoshis * 1000 - pending_value_to_self_msat;

		if !self.context.is_outbound() {
			// `Some(())` is for the fee spike buffer we keep for the remote. This deviates from
			// the spec because the fee spike buffer requirement doesn't exist on the receiver's
			// side, only on the sender's. Note that with anchor outputs we are no longer as
			// sensitive to fee spikes, so we need to account for them.
			let htlc_candidate = HTLCCandidate::new(msg.amount_msat, HTLCInitiator::RemoteOffered);
			let mut remote_fee_cost_incl_stuck_buffer_msat =
				self.context.next_remote_commit_tx_fee_msat(htlc_candidate, Some(()));
			if !self.context.get_channel_type().supports_anchors_zero_fee_htlc_tx() {
				remote_fee_cost_incl_stuck_buffer_msat *= FEE_SPIKE_BUFFER_FEE_INCREASE_MULTIPLE;
			}
			if pending_remote_value_msat
				.saturating_sub(msg.amount_msat)
				.saturating_sub(self.context.holder_selected_channel_reserve_satoshis * 1000)
				.saturating_sub(anchor_outputs_value_msat)
				< remote_fee_cost_incl_stuck_buffer_msat
			{
				log_info!(logger, "Attempting to fail HTLC due to fee spike buffer violation in channel {}. Rebalancing is required.", &self.context.channel_id());
				return Err(("Fee spike buffer violation", 0x1000 | 7));
			}
		}

		Ok(())
	}

	pub fn get_cur_holder_commitment_transaction_number(&self) -> u64 {
		self.context.holder_commitment_point.transaction_number() + 1
	}

	pub fn get_cur_counterparty_commitment_transaction_number(&self) -> u64 {
		self.context.cur_counterparty_commitment_transaction_number + 1
			- if self.context.channel_state.is_awaiting_remote_revoke() { 1 } else { 0 }
	}

	pub fn get_revoked_counterparty_commitment_transaction_number(&self) -> u64 {
		self.context.cur_counterparty_commitment_transaction_number + 2
	}

	#[cfg(test)]
	pub fn get_signer(&self) -> &ChannelSignerType<SP> {
		&self.context.holder_signer
	}

	#[cfg(test)]
	pub fn get_value_stat(&self) -> ChannelValueStat {
		ChannelValueStat {
			value_to_self_msat: self.context.value_to_self_msat,
			channel_value_msat: self.context.channel_value_satoshis * 1000,
			channel_reserve_msat: self
				.context
				.counterparty_selected_channel_reserve_satoshis
				.unwrap() * 1000,
			pending_outbound_htlcs_amount_msat: self
				.context
				.pending_outbound_htlcs
				.iter()
				.map(|ref h| h.amount_msat)
				.sum::<u64>(),
			pending_inbound_htlcs_amount_msat: self
				.context
				.pending_inbound_htlcs
				.iter()
				.map(|ref h| h.amount_msat)
				.sum::<u64>(),
			holding_cell_outbound_amount_msat: {
				let mut res = 0;
				for h in self.context.holding_cell_htlc_updates.iter() {
					match h {
						&HTLCUpdateAwaitingACK::AddHTLC { amount_msat, .. } => {
							res += amount_msat;
						},
						_ => {},
					}
				}
				res
			},
			counterparty_max_htlc_value_in_flight_msat: self
				.context
				.counterparty_max_htlc_value_in_flight_msat,
			counterparty_dust_limit_msat: self.context.counterparty_dust_limit_satoshis * 1000,
		}
	}

	/// Returns true if this channel has been marked as awaiting a monitor update to move forward.
	/// Allowed in any state (including after shutdown)
	pub fn is_awaiting_monitor_update(&self) -> bool {
		self.context.channel_state.is_monitor_update_in_progress()
	}

	/// Gets the latest [`ChannelMonitorUpdate`] ID which has been released and is in-flight.
	pub fn get_latest_unblocked_monitor_update_id(&self) -> u64 {
		if self.context.blocked_monitor_updates.is_empty() {
			return self.context.get_latest_monitor_update_id();
		}
		self.context.blocked_monitor_updates[0].update.update_id - 1
	}

	/// Returns the next blocked monitor update, if one exists, and a bool which indicates a
	/// further blocked monitor update exists after the next.
	pub fn unblock_next_blocked_monitor_update(&mut self) -> Option<(ChannelMonitorUpdate, bool)> {
		if self.context.blocked_monitor_updates.is_empty() {
			return None;
		}
		Some((
			self.context.blocked_monitor_updates.remove(0).update,
			!self.context.blocked_monitor_updates.is_empty(),
		))
	}

	/// Pushes a new monitor update into our monitor update queue, returning it if it should be
	/// immediately given to the user for persisting or `None` if it should be held as blocked.
	fn push_ret_blockable_mon_update(
		&mut self, update: ChannelMonitorUpdate,
	) -> Option<ChannelMonitorUpdate> {
		let release_monitor = self.context.blocked_monitor_updates.is_empty();
		if !release_monitor {
			self.context.blocked_monitor_updates.push(PendingChannelMonitorUpdate { update });
			None
		} else {
			Some(update)
		}
	}

	/// On startup, its possible we detect some monitor updates have actually completed (and the
	/// ChannelManager was simply stale). In that case, we should simply drop them, which we do
	/// here after logging them.
	pub fn on_startup_drop_completed_blocked_mon_updates_through<L: Logger>(
		&mut self, logger: &L, loaded_mon_update_id: u64,
	) {
		let channel_id = self.context.channel_id();
		self.context.blocked_monitor_updates.retain(|update| {
			if update.update.update_id <= loaded_mon_update_id {
				log_info!(
					logger,
					"Dropping completed ChannelMonitorUpdate id {} on channel {} due to a stale ChannelManager",
					update.update.update_id,
					channel_id,
				);
				false
			} else {
				true
			}
		});
	}

	pub fn blocked_monitor_updates_pending(&self) -> usize {
		self.context.blocked_monitor_updates.len()
	}

	/// Returns true if the channel is awaiting the persistence of the initial ChannelMonitor.
	/// If the channel is outbound, this implies we have not yet broadcasted the funding
	/// transaction. If the channel is inbound, this implies simply that the channel has not
	/// advanced state.
	pub fn is_awaiting_initial_mon_persist(&self) -> bool {
		if !self.is_awaiting_monitor_update() {
			return false;
		}
		if matches!(
			self.context.channel_state, ChannelState::AwaitingChannelReady(flags)
			if flags.clone().clear(AwaitingChannelReadyFlags::THEIR_CHANNEL_READY | FundedStateFlags::PEER_DISCONNECTED | FundedStateFlags::MONITOR_UPDATE_IN_PROGRESS | AwaitingChannelReadyFlags::WAITING_FOR_BATCH).is_empty()
		) {
			// If we're not a 0conf channel, we'll be waiting on a monitor update with only
			// AwaitingChannelReady set, though our peer could have sent their channel_ready.
			debug_assert!(self.context.minimum_depth.unwrap_or(1) > 0);
			return true;
		}
		if self.context.holder_commitment_point.transaction_number()
			== INITIAL_COMMITMENT_NUMBER - 1
			&& self.context.cur_counterparty_commitment_transaction_number
				== INITIAL_COMMITMENT_NUMBER - 1
		{
			// If we're a 0-conf channel, we'll move beyond AwaitingChannelReady immediately even while
			// waiting for the initial monitor persistence. Thus, we check if our commitment
			// transaction numbers have both been iterated only exactly once (for the
			// funding_signed), and we're awaiting monitor update.
			//
			// If we got here, we shouldn't have yet broadcasted the funding transaction (as the
			// only way to get an awaiting-monitor-update state during initial funding is if the
			// initial monitor persistence is still pending).
			//
			// Because deciding we're awaiting initial broadcast spuriously could result in
			// funds-loss (as we don't have a monitor, but have the funding transaction confirmed),
			// we hard-assert here, even in production builds.
			if self.context.is_outbound() {
				assert!(self.context.funding_transaction.is_some());
			}
			assert!(self.context.monitor_pending_channel_ready);
			assert_eq!(self.context.latest_monitor_update_id, 0);
			return true;
		}
		false
	}

	/// Returns true if our channel_ready has been sent
	pub fn is_our_channel_ready(&self) -> bool {
		matches!(self.context.channel_state, ChannelState::AwaitingChannelReady(flags) if flags.is_set(AwaitingChannelReadyFlags::OUR_CHANNEL_READY))
			|| matches!(self.context.channel_state, ChannelState::ChannelReady(_))
	}

	/// Returns true if our peer has either initiated or agreed to shut down the channel.
	pub fn received_shutdown(&self) -> bool {
		self.context.channel_state.is_remote_shutdown_sent()
	}

	/// Returns true if we either initiated or agreed to shut down the channel.
	pub fn sent_shutdown(&self) -> bool {
		self.context.channel_state.is_local_shutdown_sent()
	}

	/// Returns true if we initiated to shut down the channel.
	pub fn initiated_shutdown(&self) -> bool {
		self.context.local_initiated_shutdown.is_some()
	}

	/// Returns true if this channel is fully shut down. True here implies that no further actions
	/// may/will be taken on this channel, and thus this object should be freed. Any future changes
	/// will be handled appropriately by the chain monitor.
	pub fn is_shutdown(&self) -> bool {
		matches!(self.context.channel_state, ChannelState::ShutdownComplete)
	}

	pub fn is_shutdown_pending_signature(&self) -> bool {
		matches!(self.context.channel_state, ChannelState::ChannelReady(_))
			&& self.context.signer_pending_closing
			&& self.context.last_received_closing_sig.is_some()
	}

	pub fn channel_update_status(&self) -> ChannelUpdateStatus {
		self.context.channel_update_status
	}

	pub fn set_channel_update_status(&mut self, status: ChannelUpdateStatus) {
		self.context.update_time_counter += 1;
		self.context.channel_update_status = status;
	}

	fn check_get_channel_ready<L: Deref>(
		&mut self, height: u32, logger: &L,
	) -> Option<msgs::ChannelReady>
	where
		L::Target: Logger,
	{
		// Called:
		//  * always when a new block/transactions are confirmed with the new height
		//  * when funding is signed with a height of 0
		if self.context.funding_tx_confirmation_height == 0 && self.context.minimum_depth != Some(0)
		{
			return None;
		}

		let funding_tx_confirmations =
			height as i64 - self.context.funding_tx_confirmation_height as i64 + 1;
		if funding_tx_confirmations <= 0 {
			self.context.funding_tx_confirmation_height = 0;
		}

		if funding_tx_confirmations < self.context.minimum_depth.unwrap_or(0) as i64 {
			return None;
		}

		// If we're still pending the signature on a funding transaction, then we're not ready to send a
		// channel_ready yet.
		if self.context.signer_pending_funding {
			// TODO: set signer_pending_channel_ready
			log_debug!(logger, "Can't produce channel_ready: the signer is pending funding.");
			return None;
		}

		// Note that we don't include ChannelState::WaitingForBatch as we don't want to send
		// channel_ready until the entire batch is ready.
		let need_commitment_update = if matches!(self.context.channel_state, ChannelState::AwaitingChannelReady(f) if f.clone().clear(FundedStateFlags::ALL.into()).is_empty())
		{
			self.context.channel_state.set_our_channel_ready();
			true
		} else if matches!(self.context.channel_state, ChannelState::AwaitingChannelReady(f) if f.clone().clear(FundedStateFlags::ALL.into()) == AwaitingChannelReadyFlags::THEIR_CHANNEL_READY)
		{
			self.context.channel_state = ChannelState::ChannelReady(
				self.context.channel_state.with_funded_state_flags_mask().into(),
			);
			self.context.update_time_counter += 1;
			true
		} else if matches!(self.context.channel_state, ChannelState::AwaitingChannelReady(f) if f.clone().clear(FundedStateFlags::ALL.into()) == AwaitingChannelReadyFlags::OUR_CHANNEL_READY)
		{
			// We got a reorg but not enough to trigger a force close, just ignore.
			false
		} else {
			if self.context.funding_tx_confirmation_height != 0
				&& self.context.channel_state < ChannelState::ChannelReady(ChannelReadyFlags::new())
			{
				// We should never see a funding transaction on-chain until we've received
				// funding_signed (if we're an outbound channel), or seen funding_generated (if we're
				// an inbound channel - before that we have no known funding TXID). The fuzzer,
				// however, may do this and we shouldn't treat it as a bug.
				#[cfg(not(fuzzing))]
				panic!(
					"Started confirming a channel in a state pre-AwaitingChannelReady: {}.\n\
					Do NOT broadcast a funding transaction manually - let LDK do it for you!",
					self.context.channel_state.to_u32()
				);
			}
			// We got a reorg but not enough to trigger a force close, just ignore.
			false
		};

		if !need_commitment_update {
			log_debug!(logger, "Not producing channel_ready: we do not need a commitment update");
			return None;
		}

		if self.context.channel_state.is_monitor_update_in_progress() {
			log_debug!(logger, "Not producing channel_ready: a monitor update is in progress. Setting monitor_pending_channel_ready.");
			self.context.monitor_pending_channel_ready = true;
			return None;
		}

		if self.context.channel_state.is_peer_disconnected() {
			log_debug!(logger, "Not producing channel_ready: the peer is disconnected.");
			return None;
		}

		// TODO: when get_per_commiment_point becomes async, check if the point is
		// available, if not, set signer_pending_channel_ready and return None

		Some(self.get_channel_ready())
	}

	fn get_channel_ready(&self) -> msgs::ChannelReady {
		debug_assert!(self.context.holder_commitment_point.is_available());
		msgs::ChannelReady {
			channel_id: self.context.channel_id(),
			next_per_commitment_point: self.context.holder_commitment_point.current_point(),
			short_channel_id_alias: Some(self.context.outbound_scid_alias),
		}
	}

	/// When a transaction is confirmed, we check whether it is or spends the funding transaction
	/// In the first case, we store the confirmation height and calculating the short channel id.
	/// In the second, we simply return an Err indicating we need to be force-closed now.
	pub fn transactions_confirmed<NS: Deref, L: Deref>(
		&mut self, block_hash: &BlockHash, height: u32, txdata: &TransactionData,
		chain_hash: ChainHash, node_signer: &NS, user_config: &UserConfig, logger: &L,
	) -> Result<(Option<msgs::ChannelReady>, Option<msgs::AnnouncementSignatures>), ClosureReason>
	where
		NS::Target: NodeSigner,
		L::Target: Logger,
	{
		let mut msgs = (None, None);
		if let Some(funding_txo) = self.context.get_funding_txo() {
			for &(index_in_block, tx) in txdata.iter() {
				// Check if the transaction is the expected funding transaction, and if it is,
				// check that it pays the right amount to the right script.
				if self.context.funding_tx_confirmation_height == 0 {
					if tx.compute_txid() == funding_txo.txid {
						let txo_idx = funding_txo.index as usize;
						if txo_idx >= tx.output.len()
							|| tx.output[txo_idx].script_pubkey
								!= self.context.get_funding_redeemscript().to_p2wsh()
							|| tx.output[txo_idx].value.to_sat()
								!= self.context.channel_value_satoshis
						{
							if self.context.is_outbound() {
								// If we generated the funding transaction and it doesn't match what it
								// should, the client is really broken and we should just panic and
								// tell them off. That said, because hash collisions happen with high
								// probability in fuzzing mode, if we're fuzzing we just close the
								// channel and move on.
								#[cfg(not(fuzzing))]
								panic!("Client called ChannelManager::funding_transaction_generated with bogus transaction!");
							}
							self.context.update_time_counter += 1;
							let err_reason = "funding tx had wrong script/value or output index";
							return Err(ClosureReason::ProcessingError {
								err: err_reason.to_owned(),
							});
						} else {
							if self.context.is_outbound() {
								if !tx.is_coinbase() {
									for input in tx.input.iter() {
										if input.witness.is_empty() {
											// We generated a malleable funding transaction, implying we've
											// just exposed ourselves to funds loss to our counterparty.
											#[cfg(not(fuzzing))]
											panic!("Client called ChannelManager::funding_transaction_generated with bogus transaction!");
										}
									}
								}
							}
							self.context.funding_tx_confirmation_height = height;
							self.context.funding_tx_confirmed_in = Some(*block_hash);
							self.context.short_channel_id = match scid_from_parts(height as u64, index_in_block as u64, txo_idx as u64) {
								Ok(scid) => Some(scid),
								Err(_) => panic!("Block was bogus - either height was > 16 million, had > 16 million transactions, or had > 65k outputs"),
							}
						}
						// If this is a coinbase transaction and not a 0-conf channel
						// we should update our min_depth to 100 to handle coinbase maturity
						if tx.is_coinbase()
							&& self.context.minimum_depth.unwrap_or(0) > 0
							&& self.context.minimum_depth.unwrap_or(0) < COINBASE_MATURITY
						{
							self.context.minimum_depth = Some(COINBASE_MATURITY);
						}
					}
					// If we allow 1-conf funding, we may need to check for channel_ready here and
					// send it immediately instead of waiting for a best_block_updated call (which
					// may have already happened for this block).
					if let Some(channel_ready) = self.check_get_channel_ready(height, logger) {
						log_info!(
							logger,
							"Sending a channel_ready to our peer for channel {}",
							&self.context.channel_id
						);
						let announcement_sigs = self.get_announcement_sigs(
							node_signer,
							chain_hash,
							user_config,
							height,
							logger,
						);
						msgs = (Some(channel_ready), announcement_sigs);
					}
				}
				for inp in tx.input.iter() {
					if inp.previous_output == funding_txo.into_bitcoin_outpoint() {
						log_info!(
							logger,
							"Detected channel-closing tx {} spending {}:{}, closing channel {}",
							tx.compute_txid(),
							inp.previous_output.txid,
							inp.previous_output.vout,
							&self.context.channel_id()
						);
						return Err(ClosureReason::CommitmentTxConfirmed);
					}
				}
			}
		}
		Ok(msgs)
	}

	/// When a new block is connected, we check the height of the block against outbound holding
	/// cell HTLCs in case we need to give up on them prematurely and time them out. Everything
	/// else (e.g. commitment transaction broadcasts, HTLC transaction broadcasting, etc) is
	/// handled by the ChannelMonitor.
	///
	/// If we return Err, the channel may have been closed, at which point the standard
	/// requirements apply - no calls may be made except those explicitly stated to be allowed
	/// post-shutdown.
	///
	/// May return some HTLCs (and their payment_hash) which have timed out and should be failed
	/// back.
	pub fn best_block_updated<NS: Deref, L: Deref>(
		&mut self, height: u32, highest_header_time: u32, chain_hash: ChainHash, node_signer: &NS,
		user_config: &UserConfig, logger: &L,
	) -> Result<
		(
			Option<msgs::ChannelReady>,
			Vec<(HTLCSource, PaymentHash)>,
			Option<msgs::AnnouncementSignatures>,
		),
		ClosureReason,
	>
	where
		NS::Target: NodeSigner,
		L::Target: Logger,
	{
		self.do_best_block_updated(
			height,
			highest_header_time,
			Some((chain_hash, node_signer, user_config)),
			logger,
		)
	}

	fn do_best_block_updated<NS: Deref, L: Deref>(
		&mut self, height: u32, highest_header_time: u32,
		chain_node_signer: Option<(ChainHash, &NS, &UserConfig)>, logger: &L,
	) -> Result<
		(
			Option<msgs::ChannelReady>,
			Vec<(HTLCSource, PaymentHash)>,
			Option<msgs::AnnouncementSignatures>,
		),
		ClosureReason,
	>
	where
		NS::Target: NodeSigner,
		L::Target: Logger,
	{
		let mut timed_out_htlcs = Vec::new();
		// This mirrors the check in ChannelManager::decode_update_add_htlc_onion, refusing to
		// forward an HTLC when our counterparty should almost certainly just fail it for expiring
		// ~now.
		let unforwarded_htlc_cltv_limit = height + LATENCY_GRACE_PERIOD_BLOCKS;
		self.context.holding_cell_htlc_updates.retain(|htlc_update| match htlc_update {
			&HTLCUpdateAwaitingACK::AddHTLC {
				ref payment_hash,
				ref source,
				ref cltv_expiry,
				..
			} => {
				if *cltv_expiry <= unforwarded_htlc_cltv_limit {
					timed_out_htlcs.push((source.clone(), payment_hash.clone()));
					false
				} else {
					true
				}
			},
			_ => true,
		});

		self.context.update_time_counter =
			cmp::max(self.context.update_time_counter, highest_header_time);

		if let Some(channel_ready) = self.check_get_channel_ready(height, logger) {
			let announcement_sigs =
				if let Some((chain_hash, node_signer, user_config)) = chain_node_signer {
					self.get_announcement_sigs(node_signer, chain_hash, user_config, height, logger)
				} else {
					None
				};
			log_info!(
				logger,
				"Sending a channel_ready to our peer for channel {}",
				&self.context.channel_id
			);
			return Ok((Some(channel_ready), timed_out_htlcs, announcement_sigs));
		}

		if matches!(self.context.channel_state, ChannelState::ChannelReady(_))
			|| self.context.channel_state.is_our_channel_ready()
		{
			let mut funding_tx_confirmations =
				height as i64 - self.context.funding_tx_confirmation_height as i64 + 1;
			if self.context.funding_tx_confirmation_height == 0 {
				// Note that check_get_channel_ready may reset funding_tx_confirmation_height to
				// zero if it has been reorged out, however in either case, our state flags
				// indicate we've already sent a channel_ready
				funding_tx_confirmations = 0;
			}

			// If we've sent channel_ready (or have both sent and received channel_ready), and
			// the funding transaction has become unconfirmed,
			// close the channel and hope we can get the latest state on chain (because presumably
			// the funding transaction is at least still in the mempool of most nodes).
			//
			// Note that ideally we wouldn't force-close if we see *any* reorg on a 1-conf or
			// 0-conf channel, but not doing so may lead to the
			// `ChannelManager::short_to_chan_info` map  being inconsistent, so we currently have
			// to.
			if funding_tx_confirmations == 0 && self.context.funding_tx_confirmed_in.is_some() {
				let err_reason = format!(
					"Funding transaction was un-confirmed. Locked at {} confs, now have {} confs.",
					self.context.minimum_depth.unwrap(),
					funding_tx_confirmations
				);
				return Err(ClosureReason::ProcessingError { err: err_reason });
			}
		} else if !self.context.is_outbound()
			&& self.context.funding_tx_confirmed_in.is_none()
			&& height >= self.context.channel_creation_height + FUNDING_CONF_DEADLINE_BLOCKS
		{
			log_info!(
				logger,
				"Closing channel {} due to funding timeout",
				&self.context.channel_id
			);
			// If funding_tx_confirmed_in is unset, the channel must not be active
			assert!(
				self.context.channel_state <= ChannelState::ChannelReady(ChannelReadyFlags::new())
			);
			assert!(!self.context.channel_state.is_our_channel_ready());
			return Err(ClosureReason::FundingTimedOut);
		}

		let announcement_sigs =
			if let Some((chain_hash, node_signer, user_config)) = chain_node_signer {
				self.get_announcement_sigs(node_signer, chain_hash, user_config, height, logger)
			} else {
				None
			};
		Ok((None, timed_out_htlcs, announcement_sigs))
	}

	/// Indicates the funding transaction is no longer confirmed in the main chain. This may
	/// force-close the channel, but may also indicate a harmless reorganization of a block or two
	/// before the channel has reached channel_ready and we can just wait for more blocks.
	pub fn funding_transaction_unconfirmed<L: Deref>(
		&mut self, logger: &L,
	) -> Result<(), ClosureReason>
	where
		L::Target: Logger,
	{
		if self.context.funding_tx_confirmation_height != 0 {
			// We handle the funding disconnection by calling best_block_updated with a height one
			// below where our funding was connected, implying a reorg back to conf_height - 1.
			let reorg_height = self.context.funding_tx_confirmation_height - 1;
			// We use the time field to bump the current time we set on channel updates if its
			// larger. If we don't know that time has moved forward, we can just set it to the last
			// time we saw and it will be ignored.
			let best_time = self.context.update_time_counter;
			match self.do_best_block_updated(
				reorg_height,
				best_time,
				None::<(ChainHash, &&dyn NodeSigner, &UserConfig)>,
				logger,
			) {
				Ok((channel_ready, timed_out_htlcs, announcement_sigs)) => {
					assert!(
						channel_ready.is_none(),
						"We can't generate a funding with 0 confirmations?"
					);
					assert!(timed_out_htlcs.is_empty(), "We can't have accepted HTLCs with a timeout before our funding confirmation?");
					assert!(
						announcement_sigs.is_none(),
						"We can't generate an announcement_sigs with 0 confirmations?"
					);
					Ok(())
				},
				Err(e) => Err(e),
			}
		} else {
			// We never learned about the funding confirmation anyway, just ignore
			Ok(())
		}
	}

	// Methods to get unprompted messages to send to the remote end (or where we already returned
	// something in the handler for the message that prompted this message):

	/// Gets an UnsignedChannelAnnouncement for this channel. The channel must be publicly
	/// announceable and available for use (have exchanged [`ChannelReady`] messages in both
	/// directions). Should be used for both broadcasted announcements and in response to an
	/// AnnouncementSignatures message from the remote peer.
	///
	/// Will only fail if we're not in a state where channel_announcement may be sent (including
	/// closing).
	///
	/// This will only return ChannelError::Ignore upon failure.
	///
	/// [`ChannelReady`]: crate::ln::msgs::ChannelReady
	fn get_channel_announcement<NS: Deref>(
		&self, node_signer: &NS, chain_hash: ChainHash, user_config: &UserConfig,
	) -> Result<msgs::UnsignedChannelAnnouncement, ChannelError>
	where
		NS::Target: NodeSigner,
	{
		if !self.context.config.announce_for_forwarding {
			return Err(ChannelError::Ignore(
				"Channel is not available for public announcements".to_owned(),
			));
		}
		if !self.context.is_usable() {
			return Err(ChannelError::Ignore(
				"Cannot get a ChannelAnnouncement if the channel is not currently usable"
					.to_owned(),
			));
		}

		let short_channel_id = self.context.get_short_channel_id().ok_or(ChannelError::Ignore(
			"Cannot get a ChannelAnnouncement if the channel has not been confirmed yet".to_owned(),
		))?;
		let node_id =
			NodeId::from_pubkey(&node_signer.get_node_id(Recipient::Node).map_err(|_| {
				ChannelError::Ignore("Failed to retrieve own public key".to_owned())
			})?);
		let counterparty_node_id = NodeId::from_pubkey(&self.context.get_counterparty_node_id());
		let were_node_one = node_id.as_slice() < counterparty_node_id.as_slice();
		let contract_id = if self.context.is_colored() {
			let (rgb_info, _) =
				get_rgb_channel_info_pending(&self.context.channel_id, &self.context.ldk_data_dir);
			Some(rgb_info.contract_id)
		} else {
			None
		};

		let msg = msgs::UnsignedChannelAnnouncement {
			features: channelmanager::provided_channel_features(&user_config),
			chain_hash,
			short_channel_id,
			node_id_1: if were_node_one { node_id } else { counterparty_node_id },
			node_id_2: if were_node_one { counterparty_node_id } else { node_id },
			bitcoin_key_1: NodeId::from_pubkey(if were_node_one {
				&self.context.get_holder_pubkeys().funding_pubkey
			} else {
				self.context.counterparty_funding_pubkey()
			}),
			bitcoin_key_2: NodeId::from_pubkey(if were_node_one {
				self.context.counterparty_funding_pubkey()
			} else {
				&self.context.get_holder_pubkeys().funding_pubkey
			}),
			contract_id,

			excess_data: Vec::new(),
		};

		Ok(msg)
	}

	fn get_announcement_sigs<NS: Deref, L: Deref>(
		&mut self, node_signer: &NS, chain_hash: ChainHash, user_config: &UserConfig,
		best_block_height: u32, logger: &L,
	) -> Option<msgs::AnnouncementSignatures>
	where
		NS::Target: NodeSigner,
		L::Target: Logger,
	{
		if self.context.funding_tx_confirmation_height == 0
			|| self.context.funding_tx_confirmation_height + 5 > best_block_height
		{
			return None;
		}

		if !self.context.is_usable() {
			return None;
		}

		if self.context.channel_state.is_peer_disconnected() {
			log_trace!(
				logger,
				"Cannot create an announcement_signatures as our peer is disconnected"
			);
			return None;
		}

		if self.context.announcement_sigs_state != AnnouncementSigsState::NotSent {
			return None;
		}

		log_trace!(
			logger,
			"Creating an announcement_signatures message for channel {}",
			&self.context.channel_id()
		);
		let announcement = match self.get_channel_announcement(node_signer, chain_hash, user_config)
		{
			Ok(a) => a,
			Err(e) => {
				log_trace!(logger, "{:?}", e);
				return None;
			},
		};
		let our_node_sig = match node_signer
			.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelAnnouncement(&announcement))
		{
			Err(_) => {
				log_error!(logger, "Failed to generate node signature for channel_announcement. Channel will not be announced!");
				return None;
			},
			Ok(v) => v,
		};
		match &self.context.holder_signer {
			ChannelSignerType::Ecdsa(ecdsa) => {
				let our_bitcoin_sig = match ecdsa.sign_channel_announcement_with_funding_key(
					&announcement,
					&self.context.secp_ctx,
				) {
					Err(_) => {
						log_error!(logger, "Signer rejected channel_announcement signing. Channel will not be announced!");
						return None;
					},
					Ok(v) => v,
				};
				let short_channel_id = match self.context.get_short_channel_id() {
					Some(scid) => scid,
					None => return None,
				};

				self.context.announcement_sigs_state = AnnouncementSigsState::MessageSent;

				Some(msgs::AnnouncementSignatures {
					channel_id: self.context.channel_id(),
					short_channel_id,
					node_signature: our_node_sig,
					bitcoin_signature: our_bitcoin_sig,
				})
			},
			// TODO (taproot|arik)
			#[cfg(taproot)]
			_ => todo!(),
		}
	}

	/// Signs the given channel announcement, returning a ChannelError::Ignore if no keys are
	/// available.
	fn sign_channel_announcement<NS: Deref>(
		&self, node_signer: &NS, announcement: msgs::UnsignedChannelAnnouncement,
	) -> Result<msgs::ChannelAnnouncement, ChannelError>
	where
		NS::Target: NodeSigner,
	{
		if let Some((their_node_sig, their_bitcoin_sig)) = self.context.announcement_sigs {
			let our_node_key =
				NodeId::from_pubkey(&node_signer.get_node_id(Recipient::Node).map_err(|_| {
					ChannelError::Ignore("Signer failed to retrieve own public key".to_owned())
				})?);
			let were_node_one = announcement.node_id_1 == our_node_key;

			let our_node_sig = node_signer
				.sign_gossip_message(msgs::UnsignedGossipMessage::ChannelAnnouncement(
					&announcement,
				))
				.map_err(|_| {
					ChannelError::Ignore(
						"Failed to generate node signature for channel_announcement".to_owned(),
					)
				})?;
			match &self.context.holder_signer {
				ChannelSignerType::Ecdsa(ecdsa) => {
					let our_bitcoin_sig = ecdsa
						.sign_channel_announcement_with_funding_key(
							&announcement,
							&self.context.secp_ctx,
						)
						.map_err(|_| {
							ChannelError::Ignore("Signer rejected channel_announcement".to_owned())
						})?;
					Ok(msgs::ChannelAnnouncement {
						node_signature_1: if were_node_one { our_node_sig } else { their_node_sig },
						node_signature_2: if were_node_one { their_node_sig } else { our_node_sig },
						bitcoin_signature_1: if were_node_one {
							our_bitcoin_sig
						} else {
							their_bitcoin_sig
						},
						bitcoin_signature_2: if were_node_one {
							their_bitcoin_sig
						} else {
							our_bitcoin_sig
						},
						contents: announcement,
					})
				},
				// TODO (taproot|arik)
				#[cfg(taproot)]
				_ => todo!(),
			}
		} else {
			Err(ChannelError::Ignore("Attempted to sign channel announcement before we'd received announcement_signatures".to_string()))
		}
	}

	/// Processes an incoming announcement_signatures message, providing a fully-signed
	/// channel_announcement message which we can broadcast and storing our counterparty's
	/// signatures for later reconstruction/rebroadcast of the channel_announcement.
	pub fn announcement_signatures<NS: Deref>(
		&mut self, node_signer: &NS, chain_hash: ChainHash, best_block_height: u32,
		msg: &msgs::AnnouncementSignatures, user_config: &UserConfig,
	) -> Result<msgs::ChannelAnnouncement, ChannelError>
	where
		NS::Target: NodeSigner,
	{
		let announcement = self.get_channel_announcement(node_signer, chain_hash, user_config)?;

		let msghash = hash_to_message!(&Sha256d::hash(&announcement.encode()[..])[..]);

		if self
			.context
			.secp_ctx
			.verify_ecdsa(&msghash, &msg.node_signature, &self.context.get_counterparty_node_id())
			.is_err()
		{
			return Err(ChannelError::close(format!(
				"Bad announcement_signatures. Failed to verify node_signature. UnsignedChannelAnnouncement used for verification is {:?}. their_node_key is {:?}",
				 &announcement, self.context.get_counterparty_node_id())));
		}
		if self
			.context
			.secp_ctx
			.verify_ecdsa(
				&msghash,
				&msg.bitcoin_signature,
				self.context.counterparty_funding_pubkey(),
			)
			.is_err()
		{
			return Err(ChannelError::close(format!(
				"Bad announcement_signatures. Failed to verify bitcoin_signature. UnsignedChannelAnnouncement used for verification is {:?}. their_bitcoin_key is ({:?})",
				&announcement, self.context.counterparty_funding_pubkey())));
		}

		self.context.announcement_sigs = Some((msg.node_signature, msg.bitcoin_signature));
		if self.context.funding_tx_confirmation_height == 0
			|| self.context.funding_tx_confirmation_height + 5 > best_block_height
		{
			return Err(ChannelError::Ignore(
				"Got announcement_signatures prior to the required six confirmations - we may not have received a block yet that our peer has".to_owned()));
		}

		self.sign_channel_announcement(node_signer, announcement)
	}

	/// Gets a signed channel_announcement for this channel, if we previously received an
	/// announcement_signatures from our counterparty.
	pub fn get_signed_channel_announcement<NS: Deref>(
		&self, node_signer: &NS, chain_hash: ChainHash, best_block_height: u32,
		user_config: &UserConfig,
	) -> Option<msgs::ChannelAnnouncement>
	where
		NS::Target: NodeSigner,
	{
		if self.context.funding_tx_confirmation_height == 0
			|| self.context.funding_tx_confirmation_height + 5 > best_block_height
		{
			return None;
		}
		let announcement = match self.get_channel_announcement(node_signer, chain_hash, user_config)
		{
			Ok(res) => res,
			Err(_) => return None,
		};
		match self.sign_channel_announcement(node_signer, announcement) {
			Ok(res) => Some(res),
			Err(_) => None,
		}
	}

	/// May panic if called on a channel that wasn't immediately-previously
	/// self.remove_uncommitted_htlcs_and_mark_paused()'d
	pub fn get_channel_reestablish<L: Deref>(&mut self, logger: &L) -> msgs::ChannelReestablish
	where
		L::Target: Logger,
	{
		assert!(self.context.channel_state.is_peer_disconnected());
		assert_ne!(
			self.context.cur_counterparty_commitment_transaction_number,
			INITIAL_COMMITMENT_NUMBER
		);
		// Prior to static_remotekey, my_current_per_commitment_point was critical to claiming
		// current to_remote balances. However, it no longer has any use, and thus is now simply
		// set to a dummy (but valid, as required by the spec) public key.
		// fuzzing mode marks a subset of pubkeys as invalid so that we can hit "invalid pubkey"
		// branches, but we unwrap it below, so we arbitrarily select a dummy pubkey which is both
		// valid, and valid in fuzzing mode's arbitrary validity criteria:
		let mut pk = [2; 33];
		pk[1] = 0xff;
		let dummy_pubkey = PublicKey::from_slice(&pk).unwrap();
		let remote_last_secret = if self.context.cur_counterparty_commitment_transaction_number + 1
			< INITIAL_COMMITMENT_NUMBER
		{
			let remote_last_secret = self
				.context
				.commitment_secrets
				.get_secret(self.context.cur_counterparty_commitment_transaction_number + 2)
				.unwrap();
			log_trace!(logger, "Enough info to generate a Data Loss Protect with per_commitment_secret {} for channel {}", log_bytes!(remote_last_secret), &self.context.channel_id());
			remote_last_secret
		} else {
			log_info!(logger, "Sending a data_loss_protect with no previous remote per_commitment_secret for channel {}", &self.context.channel_id());
			[0; 32]
		};
		self.mark_awaiting_response();
		msgs::ChannelReestablish {
			channel_id: self.context.channel_id(),
			// The protocol has two different commitment number concepts - the "commitment
			// transaction number", which starts from 0 and counts up, and the "revocation key
			// index" which starts at INITIAL_COMMITMENT_NUMBER and counts down. We track
			// commitment transaction numbers by the index which will be used to reveal the
			// revocation key for that commitment transaction, which means we have to convert them
			// to protocol-level commitment numbers here...

			// next_local_commitment_number is the next commitment_signed number we expect to
			// receive (indicating if they need to resend one that we missed).
			next_local_commitment_number: INITIAL_COMMITMENT_NUMBER
				- self.context.holder_commitment_point.transaction_number(),
			// We have to set next_remote_commitment_number to the next revoke_and_ack we expect to
			// receive, however we track it by the next commitment number for a remote transaction
			// (which is one further, as they always revoke previous commitment transaction, not
			// the one we send) so we have to decrement by 1. Note that if
			// cur_counterparty_commitment_transaction_number is INITIAL_COMMITMENT_NUMBER we will have
			// dropped this channel on disconnect as it hasn't yet reached AwaitingChannelReady so we can't
			// overflow here.
			next_remote_commitment_number: INITIAL_COMMITMENT_NUMBER
				- self.context.cur_counterparty_commitment_transaction_number
				- 1,
			your_last_per_commitment_secret: remote_last_secret,
			my_current_per_commitment_point: dummy_pubkey,
			// TODO(dual_funding): If we've sent `commtiment_signed` for an interactive transaction
			// construction but have not received `tx_signatures` we MUST set `next_funding_txid` to the
			// txid of that interactive transaction, else we MUST NOT set it.
			next_funding_txid: None,
		}
	}

	// Send stuff to our remote peers:

	/// Queues up an outbound HTLC to send by placing it in the holding cell. You should call
	/// [`Self::maybe_free_holding_cell_htlcs`] in order to actually generate and send the
	/// commitment update.
	///
	/// `Err`s will only be [`ChannelError::Ignore`].
	pub fn queue_add_htlc<F: Deref, L: Deref>(
		&mut self, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32,
		source: HTLCSource, onion_routing_packet: msgs::OnionPacket, skimmed_fee_msat: Option<u64>,
		blinding_point: Option<PublicKey>, fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L,
		amount_rgb: Option<u64>,
	) -> Result<(), ChannelError>
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		self.send_htlc(
			amount_msat,
			payment_hash,
			cltv_expiry,
			source,
			onion_routing_packet,
			true,
			skimmed_fee_msat,
			blinding_point,
			fee_estimator,
			logger,
			amount_rgb,
		)
		.map(|msg_opt| assert!(msg_opt.is_none(), "We forced holding cell?"))
		.map_err(|err| {
			if let ChannelError::Ignore(_) = err { /* fine */
			} else {
				debug_assert!(false, "Queueing cannot trigger channel failure");
			}
			err
		})
	}

	/// Adds a pending outbound HTLC to this channel, note that you probably want
	/// [`Self::send_htlc_and_commit`] instead cause you'll want both messages at once.
	///
	/// This returns an optional UpdateAddHTLC as we may be in a state where we cannot add HTLCs on
	/// the wire:
	/// * In cases where we're waiting on the remote peer to send us a revoke_and_ack, we
	///   wouldn't be able to determine what they actually ACK'ed if we have two sets of updates
	///   awaiting ACK.
	/// * In cases where we're marked MonitorUpdateInProgress, we cannot commit to a new state as
	///   we may not yet have sent the previous commitment update messages and will need to
	///   regenerate them.
	///
	/// You MUST call [`Self::send_commitment_no_state_update`] prior to calling any other methods
	/// on this [`Channel`] if `force_holding_cell` is false.
	///
	/// `Err`s will only be [`ChannelError::Ignore`].
	fn send_htlc<F: Deref, L: Deref>(
		&mut self, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32,
		source: HTLCSource, onion_routing_packet: msgs::OnionPacket, mut force_holding_cell: bool,
		skimmed_fee_msat: Option<u64>, blinding_point: Option<PublicKey>,
		fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L, amount_rgb: Option<u64>,
	) -> Result<Option<msgs::UpdateAddHTLC>, ChannelError>
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		if !matches!(self.context.channel_state, ChannelState::ChannelReady(_))
			|| self.context.channel_state.is_local_shutdown_sent()
			|| self.context.channel_state.is_remote_shutdown_sent()
		{
			return Err(ChannelError::Ignore("Cannot send HTLC until channel is fully established and we haven't started shutting down".to_owned()));
		}
		let channel_total_msat = self.context.channel_value_satoshis * 1000;
		if amount_msat > channel_total_msat {
			return Err(ChannelError::Ignore(format!(
				"Cannot send amount {}, because it is more than the total value of the channel {}",
				amount_msat, channel_total_msat
			)));
		}

		if amount_msat == 0 {
			return Err(ChannelError::Ignore("Cannot send 0-msat HTLC".to_owned()));
		}

		let available_balances = self.context.get_available_balances(fee_estimator);
		if amount_msat < available_balances.next_outbound_htlc_minimum_msat {
			return Err(ChannelError::Ignore(format!(
				"Cannot send less than our next-HTLC minimum - {} msat",
				available_balances.next_outbound_htlc_minimum_msat
			)));
		}

		if amount_msat > available_balances.next_outbound_htlc_limit_msat {
			return Err(ChannelError::Ignore(format!(
				"Cannot send more than our next-HTLC maximum - {} msat",
				available_balances.next_outbound_htlc_limit_msat
			)));
		}
		let local_rgb_amount = self.context.get_local_rgb_amount();
		if amount_rgb > Some(local_rgb_amount) {
			return Err(ChannelError::Ignore(format!(
				"Cannot send more than our next-HTLC RGB maximum - {}",
				local_rgb_amount
			)));
		}

		if self.context.channel_state.is_peer_disconnected() {
			// Note that this should never really happen, if we're !is_live() on receipt of an
			// incoming HTLC for relay will result in us rejecting the HTLC and we won't allow
			// the user to send directly into a !is_live() channel. However, if we
			// disconnected during the time the previous hop was doing the commitment dance we may
			// end up getting here after the forwarding delay. In any case, returning an
			// IgnoreError will get ChannelManager to do the right thing and fail backwards now.
			return Err(ChannelError::Ignore(
				"Cannot send an HTLC while disconnected from channel counterparty".to_owned(),
			));
		}

		let need_holding_cell = !self.context.channel_state.can_generate_new_commitment();
		log_debug!(
			logger,
			"Pushing new outbound HTLC with hash {} for {} msat {}",
			payment_hash,
			amount_msat,
			if force_holding_cell {
				"into holding cell"
			} else if need_holding_cell {
				"into holding cell as we're awaiting an RAA or monitor"
			} else {
				"to peer"
			}
		);

		if need_holding_cell {
			force_holding_cell = true;
		}

		// Now update local state:
		if force_holding_cell {
			self.context.holding_cell_htlc_updates.push(HTLCUpdateAwaitingACK::AddHTLC {
				amount_msat,
				payment_hash,
				cltv_expiry,
				source,
				onion_routing_packet,
				skimmed_fee_msat,
				blinding_point,
				amount_rgb,
			});
			return Ok(None);
		}

		self.context.pending_outbound_htlcs.push(OutboundHTLCOutput {
			htlc_id: self.context.next_holder_htlc_id,
			amount_msat,
			payment_hash: payment_hash.clone(),
			cltv_expiry,
			state: OutboundHTLCState::LocalAnnounced(Box::new(onion_routing_packet.clone())),
			source,
			blinding_point,
			skimmed_fee_msat,
			amount_rgb,
			amount_rgb,
		});

		let res = msgs::UpdateAddHTLC {
			channel_id: self.context.channel_id,
			htlc_id: self.context.next_holder_htlc_id,
			amount_msat,
			payment_hash,
			cltv_expiry,
			onion_routing_packet,
			skimmed_fee_msat,
			blinding_point,
			amount_rgb,
		};
		self.context.next_holder_htlc_id += 1;

		Ok(Some(res))
	}

	fn build_commitment_no_status_check<L: Deref>(&mut self, logger: &L) -> ChannelMonitorUpdate
	where
		L::Target: Logger,
	{
		log_trace!(logger, "Updating HTLC state for a newly-sent commitment_signed...");
		// We can upgrade the status of some HTLCs that are waiting on a commitment, even if we
		// fail to generate this, we still are at least at a position where upgrading their status
		// is acceptable.
		let mut rgb_received_htlc = 0;
		for htlc in self.context.pending_inbound_htlcs.iter_mut() {
			let new_state =
				if let &InboundHTLCState::AwaitingRemoteRevokeToAnnounce(ref forward_info) =
					&htlc.state
				{
					Some(InboundHTLCState::AwaitingAnnouncedRemoteRevoke(forward_info.clone()))
				} else {
					None
				};
			if let Some(state) = new_state {
				log_trace!(logger, " ...promoting inbound AwaitingRemoteRevokeToAnnounce {} to AwaitingAnnouncedRemoteRevoke", &htlc.payment_hash);
				htlc.state = state;
				if let Some(amount_rgb) = htlc.amount_rgb {
					rgb_received_htlc += amount_rgb;
				}
			}
		}
		for htlc in self.context.pending_outbound_htlcs.iter_mut() {
			if let &mut OutboundHTLCState::AwaitingRemoteRevokeToRemove(ref mut outcome) =
				&mut htlc.state
			{
				log_trace!(logger, " ...promoting outbound AwaitingRemoteRevokeToRemove {} to AwaitingRemovedRemoteRevoke", &htlc.payment_hash);
				// Grab the preimage, if it exists, instead of cloning
				let mut reason = OutboundHTLCOutcome::Success(None);
				mem::swap(outcome, &mut reason);
				htlc.state = OutboundHTLCState::AwaitingRemovedRemoteRevoke(reason);
			}
		}
		if self.context.is_colored() && rgb_received_htlc > 0 {
			update_rgb_channel_amount_pending(
				&self.context.channel_id,
				0,
				rgb_received_htlc,
				&self.context.ldk_data_dir,
			);
		}

		if let Some((feerate, update_state)) = self.context.pending_update_fee {
			if update_state == FeeUpdateState::AwaitingRemoteRevokeToAnnounce {
				debug_assert!(!self.context.is_outbound());
				log_trace!(logger, " ...promoting inbound AwaitingRemoteRevokeToAnnounce fee update {} to Committed", feerate);
				self.context.feerate_per_kw = feerate;
				self.context.pending_update_fee = None;
			}
		}
		self.context.resend_order = RAACommitmentOrder::RevokeAndACKFirst;

		let (mut htlcs_ref, counterparty_commitment_tx) =
			self.build_commitment_no_state_update(logger);
		let counterparty_commitment_txid = counterparty_commitment_tx.trust().txid();
		let htlcs: Vec<(HTLCOutputInCommitment, Option<Box<HTLCSource>>)> = htlcs_ref
			.drain(..)
			.map(|(htlc, htlc_source)| {
				(htlc, htlc_source.map(|source_ref| Box::new(source_ref.clone())))
			})
			.collect();

		if self.context.announcement_sigs_state == AnnouncementSigsState::MessageSent {
			self.context.announcement_sigs_state = AnnouncementSigsState::Committed;
		}

		self.context.latest_monitor_update_id += 1;
		let monitor_update = ChannelMonitorUpdate {
			update_id: self.context.latest_monitor_update_id,
			counterparty_node_id: Some(self.context.counterparty_node_id),
			updates: vec![ChannelMonitorUpdateStep::LatestCounterpartyCommitmentTXInfo {
				commitment_txid: counterparty_commitment_txid,
				htlc_outputs: htlcs.clone(),
				commitment_number: self.context.cur_counterparty_commitment_transaction_number,
				their_per_commitment_point: self.context.counterparty_cur_commitment_point.unwrap(),
				feerate_per_kw: Some(counterparty_commitment_tx.feerate_per_kw()),
				to_broadcaster_value_sat: Some(
					counterparty_commitment_tx.to_broadcaster_value_sat(),
				),
				to_countersignatory_value_sat: Some(
					counterparty_commitment_tx.to_countersignatory_value_sat(),
				),
			}],
			channel_id: Some(self.context.channel_id()),
		};
		self.context.channel_state.set_awaiting_remote_revoke();
		monitor_update
	}

	fn build_commitment_no_state_update<L: Deref>(
		&self, logger: &L,
	) -> (Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)>, CommitmentTransaction)
	where
		L::Target: Logger,
	{
		let counterparty_keys = self.context.build_remote_transaction_keys();
		let mut commitment_stats = self.context.build_commitment_transaction(
			self.context.cur_counterparty_commitment_transaction_number,
			&counterparty_keys,
			false,
			true,
			logger,
		);
		if self.context.is_colored() {
			color_commitment(&self.context, &mut commitment_stats.tx, true)
				.expect("successful commitment coloring");
		}

		let counterparty_commitment_tx = commitment_stats.tx;

		#[cfg(any(test, fuzzing))]
		{
			if !self.context.is_outbound() {
				let projected_commit_tx_info =
					self.context.next_remote_commitment_tx_fee_info_cached.lock().unwrap().take();
				*self.context.next_local_commitment_tx_fee_info_cached.lock().unwrap() = None;
				if let Some(info) = projected_commit_tx_info {
					let total_pending_htlcs = self.context.pending_inbound_htlcs.len()
						+ self.context.pending_outbound_htlcs.len();
					if info.total_pending_htlcs == total_pending_htlcs
						&& info.next_holder_htlc_id == self.context.next_holder_htlc_id
						&& info.next_counterparty_htlc_id == self.context.next_counterparty_htlc_id
						&& info.feerate == self.context.feerate_per_kw
					{
						let actual_fee = commit_tx_fee_sat(
							self.context.feerate_per_kw,
							commitment_stats.num_nondust_htlcs,
							self.context.get_channel_type(),
						) * 1000;
						assert_eq!(actual_fee, info.fee);
					}
				}
			}
		}

		(commitment_stats.htlcs_included, counterparty_commitment_tx)
	}

	/// Only fails in case of signer rejection. Used for channel_reestablish commitment_signed
	/// generation when we shouldn't change HTLC/channel state.
	fn send_commitment_no_state_update<L: Deref>(
		&self, logger: &L,
	) -> Result<
		(msgs::CommitmentSigned, (Txid, Vec<(HTLCOutputInCommitment, Option<&HTLCSource>)>)),
		ChannelError,
	>
	where
		L::Target: Logger,
	{
		// Get the fee tests from `build_commitment_no_state_update`
		#[cfg(any(test, fuzzing))]
		self.build_commitment_no_state_update(logger);

		let counterparty_keys = self.context.build_remote_transaction_keys();
		let mut commitment_stats = self.context.build_commitment_transaction(
			self.context.cur_counterparty_commitment_transaction_number,
			&counterparty_keys,
			false,
			true,
			logger,
		);
		if self.context.is_colored() {
			color_commitment(&self.context, &mut commitment_stats.tx, true)?;
		}

		let counterparty_commitment_txid = commitment_stats.tx.trust().txid();

		match &self.context.holder_signer {
			ChannelSignerType::Ecdsa(ecdsa) => {
				let (signature, htlc_signatures);

				{
					let mut htlcs = Vec::with_capacity(commitment_stats.htlcs_included.len());
					for &(ref htlc, _) in commitment_stats.htlcs_included.iter() {
						htlcs.push(htlc);
					}

					let res = ecdsa
						.sign_counterparty_commitment(
							&commitment_stats.tx,
							commitment_stats.inbound_htlc_preimages,
							commitment_stats.outbound_htlc_preimages,
							&self.context.secp_ctx,
						)
						.map_err(|_| {
							ChannelError::Ignore(
								"Failed to get signatures for new commitment_signed".to_owned(),
							)
						})?;
					signature = res.0;
					htlc_signatures = res.1;

					log_trace!(logger, "Signed remote commitment tx {} (txid {}) with redeemscript {} -> {} in channel {}",
						encode::serialize_hex(&commitment_stats.tx.trust().built_transaction().transaction),
						&counterparty_commitment_txid, encode::serialize_hex(&self.context.get_funding_redeemscript()),
						log_bytes!(signature.serialize_compact()[..]), &self.context.channel_id());

					for (ref htlc_sig, ref htlc) in htlc_signatures.iter().zip(htlcs) {
						log_trace!(logger, "Signed remote HTLC tx {} with redeemscript {} with pubkey {} -> {} in channel {}",
							encode::serialize_hex(&chan_utils::build_htlc_transaction(&counterparty_commitment_txid, commitment_stats.feerate_per_kw, self.context.get_holder_selected_contest_delay(), htlc, &self.context.channel_type, &counterparty_keys.broadcaster_delayed_payment_key, &counterparty_keys.revocation_key)),
							encode::serialize_hex(&chan_utils::get_htlc_redeemscript(&htlc, &self.context.channel_type, &counterparty_keys)),
							log_bytes!(counterparty_keys.broadcaster_htlc_key.to_public_key().serialize()),
							log_bytes!(htlc_sig.serialize_compact()[..]), &self.context.channel_id());
					}
				}

				Ok((
					msgs::CommitmentSigned {
						channel_id: self.context.channel_id,
						signature,
						htlc_signatures,
						batch: None,
						#[cfg(taproot)]
						partial_signature_with_nonce: None,
					},
					(counterparty_commitment_txid, commitment_stats.htlcs_included),
				))
			},
			// TODO (taproot|arik)
			#[cfg(taproot)]
			_ => todo!(),
		}
	}

	/// Adds a pending outbound HTLC to this channel, and builds a new remote commitment
	/// transaction and generates the corresponding [`ChannelMonitorUpdate`] in one go.
	///
	/// Shorthand for calling [`Self::send_htlc`] followed by a commitment update, see docs on
	/// [`Self::send_htlc`] and [`Self::build_commitment_no_state_update`] for more info.
	pub fn send_htlc_and_commit<F: Deref, L: Deref>(
		&mut self, amount_msat: u64, payment_hash: PaymentHash, cltv_expiry: u32,
		source: HTLCSource, onion_routing_packet: msgs::OnionPacket, skimmed_fee_msat: Option<u64>,
		fee_estimator: &LowerBoundedFeeEstimator<F>, logger: &L, amount_rgb: Option<u64>,
	) -> Result<Option<ChannelMonitorUpdate>, ChannelError>
	where
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		let send_res = self.send_htlc(
			amount_msat,
			payment_hash,
			cltv_expiry,
			source,
			onion_routing_packet,
			false,
			skimmed_fee_msat,
			None,
			fee_estimator,
			logger,
			amount_rgb,
		);
		if let Err(e) = &send_res {
			if let ChannelError::Ignore(_) = e {
			} else {
				debug_assert!(false, "Sending cannot trigger channel failure");
			}
		}
		match send_res? {
			Some(_) => {
				let monitor_update = self.build_commitment_no_status_check(logger);
				self.monitor_updating_paused(
					false,
					true,
					false,
					Vec::new(),
					Vec::new(),
					Vec::new(),
				);
				Ok(self.push_ret_blockable_mon_update(monitor_update))
			},
			None => Ok(None),
		}
	}

	/// Applies the `ChannelUpdate` and returns a boolean indicating whether a change actually
	/// happened.
	pub fn channel_update(&mut self, msg: &msgs::ChannelUpdate) -> Result<bool, ChannelError> {
		let new_forwarding_info = Some(CounterpartyForwardingInfo {
			fee_base_msat: msg.contents.fee_base_msat,
			fee_proportional_millionths: msg.contents.fee_proportional_millionths,
			cltv_expiry_delta: msg.contents.cltv_expiry_delta,
		});
		let did_change = self.context.counterparty_forwarding_info != new_forwarding_info;
		if did_change {
			self.context.counterparty_forwarding_info = new_forwarding_info;
		}

		Ok(did_change)
	}

	/// Begins the shutdown process, getting a message for the remote peer and returning all
	/// holding cell HTLCs for payment failure.
	pub fn get_shutdown(
		&mut self, signer_provider: &SP, their_features: &InitFeatures,
		target_feerate_sats_per_kw: Option<u32>, override_shutdown_script: Option<ShutdownScript>,
	) -> Result<
		(msgs::Shutdown, Option<ChannelMonitorUpdate>, Vec<(HTLCSource, PaymentHash)>),
		APIError,
	> {
		for htlc in self.context.pending_outbound_htlcs.iter() {
			if let OutboundHTLCState::LocalAnnounced(_) = htlc.state {
				return Err(APIError::APIMisuseError {
					err: "Cannot begin shutdown with pending HTLCs. Process pending events first"
						.to_owned(),
				});
			}
		}
		if self.context.channel_state.is_local_shutdown_sent() {
			return Err(APIError::APIMisuseError {
				err: "Shutdown already in progress".to_owned(),
			});
		} else if self.context.channel_state.is_remote_shutdown_sent() {
			return Err(APIError::ChannelUnavailable {
				err: "Shutdown already in progress by remote".to_owned(),
			});
		}
		if self.context.shutdown_scriptpubkey.is_some() && override_shutdown_script.is_some() {
			return Err(APIError::APIMisuseError {
				err: "Cannot override shutdown script for a channel with one already set"
					.to_owned(),
			});
		}
		assert!(!matches!(self.context.channel_state, ChannelState::ShutdownComplete));
		if self.context.channel_state.is_peer_disconnected()
			|| self.context.channel_state.is_monitor_update_in_progress()
		{
			return Err(APIError::ChannelUnavailable{err: "Cannot begin shutdown while peer is disconnected or we're waiting on a monitor update, maybe force-close instead?".to_owned()});
		}

		let update_shutdown_script = match self.context.shutdown_scriptpubkey {
			Some(_) => false,
			None => {
				// use override shutdown script if provided
				let shutdown_scriptpubkey = match override_shutdown_script {
					Some(script) => script,
					None => {
						// otherwise, use the shutdown scriptpubkey provided by the signer
						match signer_provider.get_shutdown_scriptpubkey() {
							Ok(scriptpubkey) => scriptpubkey,
							Err(_) => {
								return Err(APIError::ChannelUnavailable {
									err: "Failed to get shutdown scriptpubkey".to_owned(),
								})
							},
						}
					},
				};
				if !shutdown_scriptpubkey.is_compatible(their_features) {
					return Err(APIError::IncompatibleShutdownScript {
						script: shutdown_scriptpubkey.clone(),
					});
				}
				self.context.shutdown_scriptpubkey = Some(shutdown_scriptpubkey);
				true
			},
		};

		// From here on out, we may not fail!
		self.context.target_closing_feerate_sats_per_kw = target_feerate_sats_per_kw;
		self.context.channel_state.set_local_shutdown_sent();
		self.context.local_initiated_shutdown = Some(());
		self.context.update_time_counter += 1;

		let monitor_update = if update_shutdown_script {
			self.context.latest_monitor_update_id += 1;
			let monitor_update = ChannelMonitorUpdate {
				update_id: self.context.latest_monitor_update_id,
				counterparty_node_id: Some(self.context.counterparty_node_id),
				updates: vec![ChannelMonitorUpdateStep::ShutdownScript {
					scriptpubkey: self.get_closing_scriptpubkey(),
				}],
				channel_id: Some(self.context.channel_id()),
			};
			self.monitor_updating_paused(false, false, false, Vec::new(), Vec::new(), Vec::new());
			self.push_ret_blockable_mon_update(monitor_update)
		} else {
			None
		};
		let shutdown = msgs::Shutdown {
			channel_id: self.context.channel_id,
			scriptpubkey: self.get_closing_scriptpubkey(),
		};

		// Go ahead and drop holding cell updates as we'd rather fail payments than wait to send
		// our shutdown until we've committed all of the pending changes.
		self.context.holding_cell_update_fee = None;
		let mut dropped_outbound_htlcs =
			Vec::with_capacity(self.context.holding_cell_htlc_updates.len());
		self.context.holding_cell_htlc_updates.retain(|htlc_update| match htlc_update {
			&HTLCUpdateAwaitingACK::AddHTLC { ref payment_hash, ref source, .. } => {
				dropped_outbound_htlcs.push((source.clone(), payment_hash.clone()));
				false
			},
			_ => true,
		});

		debug_assert!(
			!self.is_shutdown() || monitor_update.is_none(),
			"we can't both complete shutdown and return a monitor update"
		);

		Ok((shutdown, monitor_update, dropped_outbound_htlcs))
	}

	pub fn inflight_htlc_sources(&self) -> impl Iterator<Item = (&HTLCSource, &PaymentHash)> {
		self.context
			.holding_cell_htlc_updates
			.iter()
			.flat_map(|htlc_update| match htlc_update {
				HTLCUpdateAwaitingACK::AddHTLC { source, payment_hash, .. } => {
					Some((source, payment_hash))
				},
				_ => None,
			})
			.chain(
				self.context
					.pending_outbound_htlcs
					.iter()
					.map(|htlc| (&htlc.source, &htlc.payment_hash)),
			)
	}
}

/// A not-yet-funded outbound (from holder) channel using V1 channel establishment.
pub(super) struct OutboundV1Channel<SP: Deref>
where
	SP::Target: SignerProvider,
{
	pub context: ChannelContext<SP>,
	pub unfunded_context: UnfundedChannelContext,
}

impl<SP: Deref> OutboundV1Channel<SP>
where
	SP::Target: SignerProvider,
{
	pub fn new<ES: Deref, F: Deref, L: Deref>(
		fee_estimator: &LowerBoundedFeeEstimator<F>, entropy_source: &ES, signer_provider: &SP,
		counterparty_node_id: PublicKey, their_features: &InitFeatures,
		channel_value_satoshis: u64, push_msat: u64, user_id: u128, config: &UserConfig,
		current_chain_height: u32, outbound_scid_alias: u64,
		temporary_channel_id: Option<ChannelId>, consignment_endpoint: Option<RgbTransport>,
		ldk_data_dir: PathBuf, logger: L,
	) -> Result<OutboundV1Channel<SP>, APIError>
	where
		ES::Target: EntropySource,
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		let holder_selected_channel_reserve_satoshis =
			get_holder_selected_channel_reserve_satoshis(channel_value_satoshis, config);
		if holder_selected_channel_reserve_satoshis < MIN_CHAN_DUST_LIMIT_SATOSHIS {
			// Protocol level safety check in place, although it should never happen because
			// of `MIN_THEIR_CHAN_RESERVE_SATOSHIS`
			return Err(APIError::APIMisuseError {
				err: format!(
					"Holder selected channel reserve below \
				implemention limit dust_limit_satoshis {}",
					holder_selected_channel_reserve_satoshis
				),
			});
		}

		let channel_keys_id =
			signer_provider.generate_channel_keys_id(false, channel_value_satoshis, user_id);
		let holder_signer =
			signer_provider.derive_channel_signer(channel_value_satoshis, channel_keys_id);
		let pubkeys = holder_signer.pubkeys().clone();

		let chan = Self {
			context: ChannelContext::new_for_outbound_channel(
				fee_estimator,
				entropy_source,
				signer_provider,
				counterparty_node_id,
				their_features,
				channel_value_satoshis,
				push_msat,
				user_id,
				config,
				current_chain_height,
				outbound_scid_alias,
				temporary_channel_id,
				holder_selected_channel_reserve_satoshis,
				channel_keys_id,
				holder_signer,
				pubkeys,
				consignment_endpoint,
				ldk_data_dir,
				logger,
			)?,
			unfunded_context: UnfundedChannelContext { unfunded_channel_age_ticks: 0 },
		};
		Ok(chan)
	}

	/// Only allowed after [`ChannelContext::channel_transaction_parameters`] is set.
	fn get_funding_created_msg<L: Deref>(&mut self, logger: &L) -> Option<msgs::FundingCreated>
	where
		L::Target: Logger,
	{
		let counterparty_keys = self.context.build_remote_transaction_keys();
		let mut counterparty_initial_commitment_tx = self
			.context
			.build_commitment_transaction(
				self.context.cur_counterparty_commitment_transaction_number,
				&counterparty_keys,
				false,
				false,
				logger,
			)
			.tx;
		if self.context.is_colored() {
			color_commitment(&self.context, &mut counterparty_initial_commitment_tx, true).unwrap();
		}

		let signature = match &self.context.holder_signer {
			// TODO (taproot|arik): move match into calling method for Taproot
			ChannelSignerType::Ecdsa(ecdsa) => ecdsa
				.sign_counterparty_commitment(
					&counterparty_initial_commitment_tx,
					Vec::new(),
					Vec::new(),
					&self.context.secp_ctx,
				)
				.map(|(sig, _)| sig)
				.ok()?,
			// TODO (taproot|arik)
			#[cfg(taproot)]
			_ => todo!(),
		};

		if self.context.signer_pending_funding {
			log_trace!(logger, "Counterparty commitment signature ready for funding_created message: clearing signer_pending_funding");
			self.context.signer_pending_funding = false;
		}

		Some(msgs::FundingCreated {
			temporary_channel_id: self.context.temporary_channel_id.unwrap(),
			funding_txid: self
				.context
				.channel_transaction_parameters
				.funding_outpoint
				.as_ref()
				.unwrap()
				.txid,
			funding_output_index: self
				.context
				.channel_transaction_parameters
				.funding_outpoint
				.as_ref()
				.unwrap()
				.index,
			signature,
			#[cfg(taproot)]
			partial_signature_with_nonce: None,
			#[cfg(taproot)]
			next_local_nonce: None,
		})
	}

	/// Updates channel state with knowledge of the funding transaction's txid/index, and generates
	/// a funding_created message for the remote peer.
	/// Panics if called at some time other than immediately after initial handshake, if called twice,
	/// or if called on an inbound channel.
	/// Note that channel_id changes during this call!
	/// Do NOT broadcast the funding transaction until after a successful funding_signed call!
	/// If an Err is returned, it is a ChannelError::Close.
	pub fn get_funding_created<L: Deref>(
		&mut self, funding_transaction: Transaction, funding_txo: OutPoint, is_batch_funding: bool,
		logger: &L,
	) -> Result<Option<msgs::FundingCreated>, (Self, ChannelError)>
	where
		L::Target: Logger,
	{
		if !self.context.is_outbound() {
			panic!("Tried to create outbound funding_created message on an inbound channel!");
		}
		if !matches!(
			self.context.channel_state, ChannelState::NegotiatingFunding(flags)
			if flags == (NegotiatingFundingFlags::OUR_INIT_SENT | NegotiatingFundingFlags::THEIR_INIT_SENT)
		) {
			panic!("Tried to get a funding_created messsage at a time other than immediately after initial handshake completion (or tried to get funding_created twice)");
		}
		if self.context.commitment_secrets.get_min_seen_secret() != (1 << 48)
			|| self.context.cur_counterparty_commitment_transaction_number
				!= INITIAL_COMMITMENT_NUMBER
			|| self.context.holder_commitment_point.transaction_number()
				!= INITIAL_COMMITMENT_NUMBER
		{
			panic!(
				"Should not have advanced channel commitment tx numbers prior to funding_created"
			);
		}

		self.context.channel_transaction_parameters.funding_outpoint = Some(funding_txo);
		self.context
			.holder_signer
			.as_mut()
			.provide_channel_parameters(&self.context.channel_transaction_parameters);

		// Now that we're past error-generating stuff, update our local state:

		self.context.channel_state = ChannelState::FundingNegotiated;
		let temporary_channel_id = self.context.channel_id;

		self.context.channel_id = ChannelId::v1_from_funding_outpoint(funding_txo);
		if self.context.is_colored() {
			rename_rgb_files(
				&self.context.channel_id,
				&temporary_channel_id,
				&self.context.ldk_data_dir,
			);
		}

		// If the funding transaction is a coinbase transaction, we need to set the minimum depth to 100.
		// We can skip this if it is a zero-conf channel.
		if funding_transaction.is_coinbase()
			&& self.context.minimum_depth.unwrap_or(0) > 0
			&& self.context.minimum_depth.unwrap_or(0) < COINBASE_MATURITY
		{
			self.context.minimum_depth = Some(COINBASE_MATURITY);
		}

		self.context.funding_transaction = Some(funding_transaction);
		self.context.is_batch_funding = Some(()).filter(|_| is_batch_funding);

		let funding_created = self.get_funding_created_msg(logger);
		if funding_created.is_none() {
			#[cfg(not(async_signing))]
			{
				panic!("Failed to get signature for new funding creation");
			}
			#[cfg(async_signing)]
			{
				if !self.context.signer_pending_funding {
					log_trace!(
						logger,
						"funding_created awaiting signer; setting signer_pending_funding"
					);
					self.context.signer_pending_funding = true;
				}
			}
		}

		Ok(funding_created)
	}

	/// If we receive an error message, it may only be a rejection of the channel type we tried,
	/// not of our ability to open any channel at all. Thus, on error, we should first call this
	/// and see if we get a new `OpenChannel` message, otherwise the channel is failed.
	pub(crate) fn maybe_handle_error_without_close<F: Deref>(
		&mut self, chain_hash: ChainHash, fee_estimator: &LowerBoundedFeeEstimator<F>,
	) -> Result<msgs::OpenChannel, ()>
	where
		F::Target: FeeEstimator,
	{
		self.context.maybe_downgrade_channel_features(fee_estimator)?;
		Ok(self.get_open_channel(chain_hash))
	}

	/// Returns true if we can resume the channel by sending the [`msgs::OpenChannel`] again.
	pub fn is_resumable(&self) -> bool {
		!self.context.have_received_message()
			&& self.context.holder_commitment_point.transaction_number()
				== INITIAL_COMMITMENT_NUMBER
	}

	pub fn get_open_channel(&self, chain_hash: ChainHash) -> msgs::OpenChannel {
		if !self.context.is_outbound() {
			panic!("Tried to open a channel for an inbound channel?");
		}
		if self.context.have_received_message() {
			panic!("Cannot generate an open_channel after we've moved forward");
		}

		if self.context.holder_commitment_point.transaction_number() != INITIAL_COMMITMENT_NUMBER {
			panic!("Tried to send an open_channel for a channel that has already advanced");
		}

		debug_assert!(self.context.holder_commitment_point.is_available());
		let first_per_commitment_point = self.context.holder_commitment_point.current_point();
		let keys = self.context.get_holder_pubkeys();

		msgs::OpenChannel {
			common_fields: msgs::CommonOpenChannelFields {
				chain_hash,
				temporary_channel_id: self.context.channel_id,
				funding_satoshis: self.context.channel_value_satoshis,
				dust_limit_satoshis: self.context.holder_dust_limit_satoshis,
				max_htlc_value_in_flight_msat: self.context.holder_max_htlc_value_in_flight_msat,
				htlc_minimum_msat: self.context.holder_htlc_minimum_msat,
				commitment_feerate_sat_per_1000_weight: self.context.feerate_per_kw as u32,
				to_self_delay: self.context.get_holder_selected_contest_delay(),
				max_accepted_htlcs: self.context.holder_max_accepted_htlcs,
				funding_pubkey: keys.funding_pubkey,
				revocation_basepoint: keys.revocation_basepoint.to_public_key(),
				payment_basepoint: keys.payment_point,
				delayed_payment_basepoint: keys.delayed_payment_basepoint.to_public_key(),
				htlc_basepoint: keys.htlc_basepoint.to_public_key(),
				first_per_commitment_point,
				channel_flags: if self.context.config.announce_for_forwarding { 1 } else { 0 },
				shutdown_scriptpubkey: Some(match &self.context.shutdown_scriptpubkey {
					Some(script) => script.clone().into_inner(),
					None => Builder::new().into_script(),
				}),
				channel_type: Some(self.context.channel_type.clone()),
				consignment_endpoint: self.context.consignment_endpoint.clone(),
			},
			push_msat: self.context.channel_value_satoshis * 1000 - self.context.value_to_self_msat,
			channel_reserve_satoshis: self.context.holder_selected_channel_reserve_satoshis,
		}
	}

	// Message handlers
	pub fn accept_channel(
		&mut self, msg: &msgs::AcceptChannel, default_limits: &ChannelHandshakeLimits,
		their_features: &InitFeatures,
	) -> Result<(), ChannelError> {
		self.context.do_accept_channel_checks(
			default_limits,
			their_features,
			&msg.common_fields,
			msg.channel_reserve_satoshis,
		)
	}

	/// Handles a funding_signed message from the remote end.
	/// If this call is successful, broadcast the funding transaction (and not before!)
	pub fn funding_signed<L: Deref>(
		mut self, msg: &msgs::FundingSigned, best_block: BestBlock, signer_provider: &SP,
		logger: &L,
	) -> Result<
		(Channel<SP>, ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>),
		(OutboundV1Channel<SP>, ChannelError),
	>
	where
		L::Target: Logger,
	{
		if !self.context.is_outbound() {
			return Err((
				self,
				ChannelError::close("Received funding_signed for an inbound channel?".to_owned()),
			));
		}
		if !matches!(self.context.channel_state, ChannelState::FundingNegotiated) {
			return Err((
				self,
				ChannelError::close("Received funding_signed in strange state!".to_owned()),
			));
		}
		if self.context.commitment_secrets.get_min_seen_secret() != (1 << 48)
			|| self.context.cur_counterparty_commitment_transaction_number
				!= INITIAL_COMMITMENT_NUMBER
			|| self.context.holder_commitment_point.transaction_number()
				!= INITIAL_COMMITMENT_NUMBER
		{
			panic!(
				"Should not have advanced channel commitment tx numbers prior to funding_created"
			);
		}

		let funding_script = self.context.get_funding_redeemscript();

		let counterparty_keys = self.context.build_remote_transaction_keys();
		let counterparty_initial_commitment_tx = self
			.context
			.build_commitment_transaction(
				self.context.cur_counterparty_commitment_transaction_number,
				&counterparty_keys,
				false,
				false,
				logger,
			)
			.tx;
		let counterparty_trusted_tx = counterparty_initial_commitment_tx.trust();
		let counterparty_initial_bitcoin_tx = counterparty_trusted_tx.built_transaction();

		log_trace!(
			logger,
			"Initial counterparty tx for channel {} is: txid {} tx {}",
			&self.context.channel_id(),
			counterparty_initial_bitcoin_tx.txid,
			encode::serialize_hex(&counterparty_initial_bitcoin_tx.transaction)
		);

		let holder_signer = self.context.build_holder_transaction_keys();
		let initial_commitment_tx = self
			.context
			.build_commitment_transaction(
				self.context.holder_commitment_point.transaction_number(),
				&holder_signer,
				true,
				false,
				logger,
			)
			.tx;
		{
			let trusted_tx = initial_commitment_tx.trust();
			let initial_commitment_bitcoin_tx = trusted_tx.built_transaction();
			let sighash = initial_commitment_bitcoin_tx
				.get_sighash_all(&funding_script, self.context.channel_value_satoshis);
			// They sign our commitment transaction, allowing us to broadcast the tx if we wish.
			if let Err(_) = self.context.secp_ctx.verify_ecdsa(
				&sighash,
				&msg.signature,
				&self.context.get_counterparty_pubkeys().funding_pubkey,
			) {
				return Err((
					self,
					ChannelError::close("Invalid funding_signed signature from peer".to_owned()),
				));
			}
		}

		let holder_commitment_tx = HolderCommitmentTransaction::new(
			initial_commitment_tx,
			msg.signature,
			Vec::new(),
			&self.context.get_holder_pubkeys().funding_pubkey,
			self.context.counterparty_funding_pubkey(),
		);

		let validated = self
			.context
			.holder_signer
			.as_ref()
			.validate_holder_commitment(&holder_commitment_tx, Vec::new());
		if validated.is_err() {
			return Err((
				self,
				ChannelError::close("Failed to validate our commitment".to_owned()),
			));
		}

		let funding_redeemscript = self.context.get_funding_redeemscript();
		let funding_txo = self.context.get_funding_txo().unwrap();
		let funding_txo_script = funding_redeemscript.to_p2wsh();
		let obscure_factor = get_commitment_transaction_number_obscure_factor(
			&self.context.get_holder_pubkeys().payment_point,
			&self.context.get_counterparty_pubkeys().payment_point,
			self.context.is_outbound(),
		);
		let shutdown_script =
			self.context.shutdown_scriptpubkey.clone().map(|script| script.into_inner());
		let mut monitor_signer = signer_provider.derive_channel_signer(
			self.context.channel_value_satoshis,
			self.context.channel_keys_id,
		);
		monitor_signer.provide_channel_parameters(&self.context.channel_transaction_parameters);
		let channel_monitor = ChannelMonitor::new(
			self.context.secp_ctx.clone(),
			monitor_signer,
			shutdown_script,
			self.context.get_holder_selected_contest_delay(),
			&self.context.destination_script,
			(funding_txo, funding_txo_script),
			&self.context.channel_transaction_parameters,
			self.context.is_outbound(),
			funding_redeemscript.clone(),
			self.context.channel_value_satoshis,
			obscure_factor,
			holder_commitment_tx,
			best_block,
			self.context.counterparty_node_id,
			self.context.channel_id(),
			self.context.ldk_data_dir.clone(),
		);
		channel_monitor.provide_initial_counterparty_commitment_tx(
			counterparty_initial_bitcoin_tx.txid,
			Vec::new(),
			self.context.cur_counterparty_commitment_transaction_number,
			self.context.counterparty_cur_commitment_point.unwrap(),
			counterparty_initial_commitment_tx.feerate_per_kw(),
			counterparty_initial_commitment_tx.to_broadcaster_value_sat(),
			counterparty_initial_commitment_tx.to_countersignatory_value_sat(),
			logger,
		);

		assert!(!self.context.channel_state.is_monitor_update_in_progress()); // We have no had any monitor(s) yet to fail update!
		if self.context.is_batch_funding() {
			self.context.channel_state =
				ChannelState::AwaitingChannelReady(AwaitingChannelReadyFlags::WAITING_FOR_BATCH);
		} else {
			self.context.channel_state =
				ChannelState::AwaitingChannelReady(AwaitingChannelReadyFlags::new());
		}
		if self
			.context
			.holder_commitment_point
			.advance(&self.context.holder_signer, &self.context.secp_ctx, logger)
			.is_err()
		{
			// We only fail to advance our commitment point/number if we're currently
			// waiting for our signer to unblock and provide a commitment point.
			// We cannot send open_channel before this has occurred, so if we
			// err here by the time we receive funding_signed, something has gone wrong.
			debug_assert!(false, "We should be ready to advance our commitment point by the time we receive funding_signed");
			return Err((
				self,
				ChannelError::close("Failed to advance holder commitment point".to_owned()),
			));
		}
		self.context.cur_counterparty_commitment_transaction_number -= 1;

		log_info!(
			logger,
			"Received funding_signed from peer for channel {}",
			&self.context.channel_id()
		);

		let mut channel = Channel {
			context: self.context,
			#[cfg(any(dual_funding, splicing))]
			dual_funding_channel_context: None,
		};

		let need_channel_ready = channel.check_get_channel_ready(0, logger).is_some();
		channel.monitor_updating_paused(
			false,
			false,
			need_channel_ready,
			Vec::new(),
			Vec::new(),
			Vec::new(),
		);
		Ok((channel, channel_monitor))
	}

	/// Indicates that the signer may have some signatures for us, so we should retry if we're
	/// blocked.
	#[cfg(async_signing)]
	pub fn signer_maybe_unblocked<L: Deref>(&mut self, logger: &L) -> Option<msgs::FundingCreated>
	where
		L::Target: Logger,
	{
		if self.context.signer_pending_funding && self.context.is_outbound() {
			log_trace!(logger, "Signer unblocked a funding_created");
			self.get_funding_created_msg(logger)
		} else {
			None
		}
	}
}

/// A not-yet-funded inbound (from counterparty) channel using V1 channel establishment.
pub(super) struct InboundV1Channel<SP: Deref>
where
	SP::Target: SignerProvider,
{
	pub context: ChannelContext<SP>,
	pub unfunded_context: UnfundedChannelContext,
}

/// Fetches the [`ChannelTypeFeatures`] that will be used for a channel built from a given
/// [`msgs::CommonOpenChannelFields`].
pub(super) fn channel_type_from_open_channel(
	common_fields: &msgs::CommonOpenChannelFields, their_features: &InitFeatures,
	our_supported_features: &ChannelTypeFeatures,
) -> Result<ChannelTypeFeatures, ChannelError> {
	if let Some(channel_type) = &common_fields.channel_type {
		if channel_type.supports_any_optional_bits() {
			return Err(ChannelError::close(
				"Channel Type field contained optional bits - this is not allowed".to_owned(),
			));
		}

		// We only support the channel types defined by the `ChannelManager` in
		// `provided_channel_type_features`. The channel type must always support
		// `static_remote_key`.
		if !channel_type.requires_static_remote_key() {
			return Err(ChannelError::close(
				"Channel Type was not understood - we require static remote key".to_owned(),
			));
		}
		// Make sure we support all of the features behind the channel type.
		if channel_type.requires_unknown_bits_from(&our_supported_features) {
			return Err(ChannelError::close(
				"Channel Type contains unsupported features".to_owned(),
			));
		}
		let announce_for_forwarding =
			if (common_fields.channel_flags & 1) == 1 { true } else { false };
		if channel_type.requires_scid_privacy() && announce_for_forwarding {
			return Err(ChannelError::close(
				"SCID Alias/Privacy Channel Type cannot be set on a public channel".to_owned(),
			));
		}
		Ok(channel_type.clone())
	} else {
		let channel_type = ChannelTypeFeatures::from_init(&their_features);
		if channel_type != ChannelTypeFeatures::only_static_remote_key() {
			return Err(ChannelError::close(
				"Only static_remote_key is supported for non-negotiated channel types".to_owned(),
			));
		}
		Ok(channel_type)
	}
}

impl<SP: Deref> InboundV1Channel<SP>
where
	SP::Target: SignerProvider,
{
	/// Creates a new channel from a remote sides' request for one.
	/// Assumes chain_hash has already been checked and corresponds with what we expect!
	pub fn new<ES: Deref, F: Deref, L: Deref>(
		fee_estimator: &LowerBoundedFeeEstimator<F>, entropy_source: &ES, signer_provider: &SP,
		counterparty_node_id: PublicKey, our_supported_features: &ChannelTypeFeatures,
		their_features: &InitFeatures, msg: &msgs::OpenChannel, user_id: u128, config: &UserConfig,
		current_chain_height: u32, logger: &L, is_0conf: bool, ldk_data_dir: PathBuf,
	) -> Result<InboundV1Channel<SP>, ChannelError>
	where
		ES::Target: EntropySource,
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		let logger = WithContext::from(
			logger,
			Some(counterparty_node_id),
			Some(msg.common_fields.temporary_channel_id),
			None,
		);

		// First check the channel type is known, failing before we do anything else if we don't
		// support this channel type.
		let channel_type = channel_type_from_open_channel(
			&msg.common_fields,
			their_features,
			our_supported_features,
		)?;

		let holder_selected_channel_reserve_satoshis = get_holder_selected_channel_reserve_satoshis(
			msg.common_fields.funding_satoshis,
			config,
		);
		let counterparty_pubkeys = ChannelPublicKeys {
			funding_pubkey: msg.common_fields.funding_pubkey,
			revocation_basepoint: RevocationBasepoint::from(msg.common_fields.revocation_basepoint),
			payment_point: msg.common_fields.payment_basepoint,
			delayed_payment_basepoint: DelayedPaymentBasepoint::from(
				msg.common_fields.delayed_payment_basepoint,
			),
			htlc_basepoint: HtlcBasepoint::from(msg.common_fields.htlc_basepoint),
		};

		let chan = Self {
			context: ChannelContext::new_for_inbound_channel(
				fee_estimator,
				entropy_source,
				signer_provider,
				counterparty_node_id,
				their_features,
				user_id,
				config,
				current_chain_height,
				&&logger,
				is_0conf,
				0,
				counterparty_pubkeys,
				channel_type,
				holder_selected_channel_reserve_satoshis,
				msg.channel_reserve_satoshis,
				msg.push_msat,
				msg.common_fields.clone(),
				msg.common_fields.consignment_endpoint.clone(),
				ldk_data_dir,
			)?,
			unfunded_context: UnfundedChannelContext { unfunded_channel_age_ticks: 0 },
		};
		Ok(chan)
	}

	/// Marks an inbound channel as accepted and generates a [`msgs::AcceptChannel`] message which
	/// should be sent back to the counterparty node.
	///
	/// [`msgs::AcceptChannel`]: crate::ln::msgs::AcceptChannel
	pub fn accept_inbound_channel(&mut self) -> msgs::AcceptChannel {
		if self.context.is_outbound() {
			panic!("Tried to send accept_channel for an outbound channel?");
		}
		if !matches!(
			self.context.channel_state, ChannelState::NegotiatingFunding(flags)
			if flags == (NegotiatingFundingFlags::OUR_INIT_SENT | NegotiatingFundingFlags::THEIR_INIT_SENT)
		) {
			panic!("Tried to send accept_channel after channel had moved forward");
		}
		if self.context.holder_commitment_point.transaction_number() != INITIAL_COMMITMENT_NUMBER {
			panic!("Tried to send an accept_channel for a channel that has already advanced");
		}

		self.generate_accept_channel_message()
	}

	/// This function is used to explicitly generate a [`msgs::AcceptChannel`] message for an
	/// inbound channel. If the intention is to accept an inbound channel, use
	/// [`InboundV1Channel::accept_inbound_channel`] instead.
	///
	/// [`msgs::AcceptChannel`]: crate::ln::msgs::AcceptChannel
	fn generate_accept_channel_message(&self) -> msgs::AcceptChannel {
		debug_assert!(self.context.holder_commitment_point.is_available());
		let first_per_commitment_point = self.context.holder_commitment_point.current_point();
		let keys = self.context.get_holder_pubkeys();

		msgs::AcceptChannel {
			common_fields: msgs::CommonAcceptChannelFields {
				temporary_channel_id: self.context.channel_id,
				dust_limit_satoshis: self.context.holder_dust_limit_satoshis,
				max_htlc_value_in_flight_msat: self.context.holder_max_htlc_value_in_flight_msat,
				htlc_minimum_msat: self.context.holder_htlc_minimum_msat,
				minimum_depth: self.context.minimum_depth.unwrap(),
				to_self_delay: self.context.get_holder_selected_contest_delay(),
				max_accepted_htlcs: self.context.holder_max_accepted_htlcs,
				funding_pubkey: keys.funding_pubkey,
				revocation_basepoint: keys.revocation_basepoint.to_public_key(),
				payment_basepoint: keys.payment_point,
				delayed_payment_basepoint: keys.delayed_payment_basepoint.to_public_key(),
				htlc_basepoint: keys.htlc_basepoint.to_public_key(),
				first_per_commitment_point,
				shutdown_scriptpubkey: Some(match &self.context.shutdown_scriptpubkey {
					Some(script) => script.clone().into_inner(),
					None => Builder::new().into_script(),
				}),
				channel_type: Some(self.context.channel_type.clone()),
			},
			channel_reserve_satoshis: self.context.holder_selected_channel_reserve_satoshis,
			#[cfg(taproot)]
			next_local_nonce: None,
		}
	}

	/// Enables the possibility for tests to extract a [`msgs::AcceptChannel`] message for an
	/// inbound channel without accepting it.
	///
	/// [`msgs::AcceptChannel`]: crate::ln::msgs::AcceptChannel
	#[cfg(test)]
	pub fn get_accept_channel_message(&self) -> msgs::AcceptChannel {
		self.generate_accept_channel_message()
	}

	fn check_funding_created_signature<L: Deref>(
		&mut self, sig: &Signature, logger: &L,
	) -> Result<CommitmentTransaction, ChannelError>
	where
		L::Target: Logger,
	{
		let funding_script = self.context.get_funding_redeemscript();

		let keys = self.context.build_holder_transaction_keys();
		let mut initial_commitment_tx = self
			.context
			.build_commitment_transaction(
				self.context.holder_commitment_point.transaction_number(),
				&keys,
				true,
				false,
				logger,
			)
			.tx;
		if self.context.is_colored() {
			color_commitment(&self.context, &mut initial_commitment_tx, false)?;
		}

		let trusted_tx = initial_commitment_tx.trust();
		let initial_commitment_bitcoin_tx = trusted_tx.built_transaction();
		let sighash = initial_commitment_bitcoin_tx
			.get_sighash_all(&funding_script, self.context.channel_value_satoshis);
		// They sign the holder commitment transaction...
		log_trace!(logger, "Checking funding_created tx signature {} by key {} against tx {} (sighash {}) with redeemscript {} for channel {}.",
			log_bytes!(sig.serialize_compact()[..]), log_bytes!(self.context.counterparty_funding_pubkey().serialize()),
			encode::serialize_hex(&initial_commitment_bitcoin_tx.transaction), log_bytes!(sighash[..]),
			encode::serialize_hex(&funding_script), &self.context.channel_id());
		secp_check!(
			self.context.secp_ctx.verify_ecdsa(
				&sighash,
				&sig,
				self.context.counterparty_funding_pubkey()
			),
			"Invalid funding_created signature from peer".to_owned()
		);

		Ok(initial_commitment_tx)
	}

	pub fn funding_created<L: Deref>(
		mut self, msg: &msgs::FundingCreated, best_block: BestBlock, signer_provider: &SP,
		logger: &L,
	) -> Result<
		(
			Channel<SP>,
			Option<msgs::FundingSigned>,
			ChannelMonitor<<SP::Target as SignerProvider>::EcdsaSigner>,
		),
		(Self, ChannelError),
	>
	where
		L::Target: Logger,
	{
		if self.context.is_outbound() {
			return Err((
				self,
				ChannelError::close("Received funding_created for an outbound channel?".to_owned()),
			));
		}
		if !matches!(
			self.context.channel_state, ChannelState::NegotiatingFunding(flags)
			if flags == (NegotiatingFundingFlags::OUR_INIT_SENT | NegotiatingFundingFlags::THEIR_INIT_SENT)
		) {
			// BOLT 2 says that if we disconnect before we send funding_signed we SHOULD NOT
			// remember the channel, so it's safe to just send an error_message here and drop the
			// channel.
			return Err((
				self,
				ChannelError::close(
					"Received funding_created after we got the channel!".to_owned(),
				),
			));
		}
		if self.context.commitment_secrets.get_min_seen_secret() != (1 << 48)
			|| self.context.cur_counterparty_commitment_transaction_number
				!= INITIAL_COMMITMENT_NUMBER
			|| self.context.holder_commitment_point.transaction_number()
				!= INITIAL_COMMITMENT_NUMBER
		{
			panic!(
				"Should not have advanced channel commitment tx numbers prior to funding_created"
			);
		}

		let funding_txo = OutPoint { txid: msg.funding_txid, index: msg.funding_output_index };
		self.context.channel_transaction_parameters.funding_outpoint = Some(funding_txo);
		// This is an externally observable change before we finish all our checks.  In particular
		// check_funding_created_signature may fail.
		self.context
			.holder_signer
			.as_mut()
			.provide_channel_parameters(&self.context.channel_transaction_parameters);

		let initial_commitment_tx =
			match self.check_funding_created_signature(&msg.signature, logger) {
				Ok(res) => res,
				Err(ChannelError::Close(e)) => {
					self.context.channel_transaction_parameters.funding_outpoint = None;
					return Err((self, ChannelError::Close(e)));
				},
				Err(e) => {
					// The only error we know how to handle is ChannelError::Close, so we fall over here
					// to make sure we don't continue with an inconsistent state.
					panic!("unexpected error type from check_funding_created_signature {:?}", e);
				},
			};

		let holder_commitment_tx = HolderCommitmentTransaction::new(
			initial_commitment_tx,
			msg.signature,
			Vec::new(),
			&self.context.get_holder_pubkeys().funding_pubkey,
			self.context.counterparty_funding_pubkey(),
		);

		if let Err(_) = self
			.context
			.holder_signer
			.as_ref()
			.validate_holder_commitment(&holder_commitment_tx, Vec::new())
		{
			return Err((
				self,
				ChannelError::close("Failed to validate our commitment".to_owned()),
			));
		}

		// Now that we're past error-generating stuff, update our local state:

		self.context.channel_state =
			ChannelState::AwaitingChannelReady(AwaitingChannelReadyFlags::new());
		let temporary_channel_id = self.context.channel_id;

		self.context.channel_id = ChannelId::v1_from_funding_outpoint(funding_txo);
		if self.context.is_colored() {
			rename_rgb_files(
				&self.context.channel_id,
				&temporary_channel_id,
				&self.context.ldk_data_dir,
			);
		}

		self.context.cur_counterparty_commitment_transaction_number -= 1;
		if self
			.context
			.holder_commitment_point
			.advance(&self.context.holder_signer, &self.context.secp_ctx, logger)
			.is_err()
		{
			// We only fail to advance our commitment point/number if we're currently
			// waiting for our signer to unblock and provide a commitment point.
			// We cannot send accept_channel before this has occurred, so if we
			// err here by the time we receive funding_created, something has gone wrong.
			debug_assert!(false, "We should be ready to advance our commitment point by the time we receive funding_created");
			return Err((
				self,
				ChannelError::close("Failed to advance holder commitment point".to_owned()),
			));
		}

		let (counterparty_initial_commitment_tx, funding_signed) =
			self.context.get_funding_signed_msg(logger);

		let funding_redeemscript = self.context.get_funding_redeemscript();
		let funding_txo_script = funding_redeemscript.to_p2wsh();
		let obscure_factor = get_commitment_transaction_number_obscure_factor(
			&self.context.get_holder_pubkeys().payment_point,
			&self.context.get_counterparty_pubkeys().payment_point,
			self.context.is_outbound(),
		);
		let shutdown_script =
			self.context.shutdown_scriptpubkey.clone().map(|script| script.into_inner());
		let mut monitor_signer = signer_provider.derive_channel_signer(
			self.context.channel_value_satoshis,
			self.context.channel_keys_id,
		);
		monitor_signer.provide_channel_parameters(&self.context.channel_transaction_parameters);
		let channel_monitor = ChannelMonitor::new(
			self.context.secp_ctx.clone(),
			monitor_signer,
			shutdown_script,
			self.context.get_holder_selected_contest_delay(),
			&self.context.destination_script,
			(funding_txo, funding_txo_script.clone()),
			&self.context.channel_transaction_parameters,
			self.context.is_outbound(),
			funding_redeemscript.clone(),
			self.context.channel_value_satoshis,
			obscure_factor,
			holder_commitment_tx,
			best_block,
			self.context.counterparty_node_id,
			self.context.channel_id(),
			self.context.ldk_data_dir.clone(),
		);
		channel_monitor.provide_initial_counterparty_commitment_tx(
			counterparty_initial_commitment_tx.trust().txid(),
			Vec::new(),
			self.context.cur_counterparty_commitment_transaction_number + 1,
			self.context.counterparty_cur_commitment_point.unwrap(),
			self.context.feerate_per_kw,
			counterparty_initial_commitment_tx.to_broadcaster_value_sat(),
			counterparty_initial_commitment_tx.to_countersignatory_value_sat(),
			logger,
		);

		log_info!(
			logger,
			"{} funding_signed for peer for channel {}",
			if funding_signed.is_some() { "Generated" } else { "Waiting for signature on" },
			&self.context.channel_id()
		);

		// Promote the channel to a full-fledged one now that we have updated the state and have a
		// `ChannelMonitor`.
		let mut channel = Channel {
			context: self.context,
			#[cfg(any(dual_funding, splicing))]
			dual_funding_channel_context: None,
		};
		let need_channel_ready = channel.check_get_channel_ready(0, logger).is_some();
		channel.monitor_updating_paused(
			false,
			false,
			need_channel_ready,
			Vec::new(),
			Vec::new(),
			Vec::new(),
		);

		Ok((channel, funding_signed, channel_monitor))
	}
}

// A not-yet-funded outbound (from holder) channel using V2 channel establishment.
#[cfg(any(dual_funding, splicing))]
pub(super) struct OutboundV2Channel<SP: Deref>
where
	SP::Target: SignerProvider,
{
	pub context: ChannelContext<SP>,
	pub unfunded_context: UnfundedChannelContext,
	#[cfg(any(dual_funding, splicing))]
	pub dual_funding_context: DualFundingChannelContext,
}

#[cfg(any(dual_funding, splicing))]
impl<SP: Deref> OutboundV2Channel<SP>
where
	SP::Target: SignerProvider,
{
	pub fn new<ES: Deref, F: Deref, L: Deref>(
		fee_estimator: &LowerBoundedFeeEstimator<F>, entropy_source: &ES, signer_provider: &SP,
		counterparty_node_id: PublicKey, their_features: &InitFeatures, funding_satoshis: u64,
		user_id: u128, config: &UserConfig, current_chain_height: u32, outbound_scid_alias: u64,
		funding_confirmation_target: ConfirmationTarget, logger: L,
	) -> Result<OutboundV2Channel<SP>, APIError>
	where
		ES::Target: EntropySource,
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		let channel_keys_id =
			signer_provider.generate_channel_keys_id(false, funding_satoshis, user_id);
		let holder_signer =
			signer_provider.derive_channel_signer(funding_satoshis, channel_keys_id);
		let pubkeys = holder_signer.pubkeys().clone();

		let temporary_channel_id =
			Some(ChannelId::temporary_v2_from_revocation_basepoint(&pubkeys.revocation_basepoint));

		let holder_selected_channel_reserve_satoshis =
			get_v2_channel_reserve_satoshis(funding_satoshis, MIN_CHAN_DUST_LIMIT_SATOSHIS);

		let funding_feerate_sat_per_1000_weight =
			fee_estimator.bounded_sat_per_1000_weight(funding_confirmation_target);
		let funding_tx_locktime = current_chain_height;

		let chan = Self {
			context: ChannelContext::new_for_outbound_channel(
				fee_estimator,
				entropy_source,
				signer_provider,
				counterparty_node_id,
				their_features,
				funding_satoshis,
				0,
				user_id,
				config,
				current_chain_height,
				outbound_scid_alias,
				temporary_channel_id,
				holder_selected_channel_reserve_satoshis,
				channel_keys_id,
				holder_signer,
				pubkeys,
				logger,
			)?,
			unfunded_context: UnfundedChannelContext { unfunded_channel_age_ticks: 0 },
			dual_funding_context: DualFundingChannelContext {
				our_funding_satoshis: funding_satoshis,
				their_funding_satoshis: 0,
				funding_tx_locktime,
				funding_feerate_sat_per_1000_weight,
			},
		};
		Ok(chan)
	}

	/// If we receive an error message, it may only be a rejection of the channel type we tried,
	/// not of our ability to open any channel at all. Thus, on error, we should first call this
	/// and see if we get a new `OpenChannelV2` message, otherwise the channel is failed.
	pub(crate) fn maybe_handle_error_without_close<F: Deref>(
		&mut self, chain_hash: ChainHash, fee_estimator: &LowerBoundedFeeEstimator<F>,
	) -> Result<msgs::OpenChannelV2, ()>
	where
		F::Target: FeeEstimator,
	{
		self.context.maybe_downgrade_channel_features(fee_estimator)?;
		Ok(self.get_open_channel_v2(chain_hash))
	}

	pub fn get_open_channel_v2(&self, chain_hash: ChainHash) -> msgs::OpenChannelV2 {
		if self.context.have_received_message() {
			debug_assert!(false, "Cannot generate an open_channel2 after we've moved forward");
		}

		if self.context.holder_commitment_point.transaction_number() != INITIAL_COMMITMENT_NUMBER {
			debug_assert!(
				false,
				"Tried to send an open_channel2 for a channel that has already advanced"
			);
		}

		let first_per_commitment_point = self.context.holder_signer.as_ref()
			.get_per_commitment_point(self.context.holder_commitment_point.transaction_number(),
				&self.context.secp_ctx)
				.expect("TODO: async signing is not yet supported for commitment points in v2 channel establishment");
		let second_per_commitment_point = self.context.holder_signer.as_ref()
			.get_per_commitment_point(self.context.holder_commitment_point.transaction_number() - 1,
				&self.context.secp_ctx)
				.expect("TODO: async signing is not yet supported for commitment points in v2 channel establishment");
		let keys = self.context.get_holder_pubkeys();

		msgs::OpenChannelV2 {
			common_fields: msgs::CommonOpenChannelFields {
				chain_hash,
				temporary_channel_id: self.context.temporary_channel_id.unwrap(),
				funding_satoshis: self.context.channel_value_satoshis,
				dust_limit_satoshis: self.context.holder_dust_limit_satoshis,
				max_htlc_value_in_flight_msat: self.context.holder_max_htlc_value_in_flight_msat,
				htlc_minimum_msat: self.context.holder_htlc_minimum_msat,
				commitment_feerate_sat_per_1000_weight: self.context.feerate_per_kw,
				to_self_delay: self.context.get_holder_selected_contest_delay(),
				max_accepted_htlcs: self.context.holder_max_accepted_htlcs,
				funding_pubkey: keys.funding_pubkey,
				revocation_basepoint: keys.revocation_basepoint.to_public_key(),
				payment_basepoint: keys.payment_point,
				delayed_payment_basepoint: keys.delayed_payment_basepoint.to_public_key(),
				htlc_basepoint: keys.htlc_basepoint.to_public_key(),
				first_per_commitment_point,
				channel_flags: if self.context.config.announce_for_forwarding { 1 } else { 0 },
				shutdown_scriptpubkey: Some(match &self.context.shutdown_scriptpubkey {
					Some(script) => script.clone().into_inner(),
					None => Builder::new().into_script(),
				}),
				channel_type: Some(self.context.channel_type.clone()),
			},
			funding_feerate_sat_per_1000_weight: self.context.feerate_per_kw,
			second_per_commitment_point,
			locktime: self.dual_funding_context.funding_tx_locktime,
			require_confirmed_inputs: None,
		}
	}
}

// A not-yet-funded inbound (from counterparty) channel using V2 channel establishment.
#[cfg(any(dual_funding, splicing))]
pub(super) struct InboundV2Channel<SP: Deref>
where
	SP::Target: SignerProvider,
{
	pub context: ChannelContext<SP>,
	pub unfunded_context: UnfundedChannelContext,
	pub dual_funding_context: DualFundingChannelContext,
}

#[cfg(any(dual_funding, splicing))]
impl<SP: Deref> InboundV2Channel<SP>
where
	SP::Target: SignerProvider,
{
	/// Creates a new dual-funded channel from a remote side's request for one.
	/// Assumes chain_hash has already been checked and corresponds with what we expect!
	pub fn new<ES: Deref, F: Deref, L: Deref>(
		fee_estimator: &LowerBoundedFeeEstimator<F>, entropy_source: &ES, signer_provider: &SP,
		counterparty_node_id: PublicKey, our_supported_features: &ChannelTypeFeatures,
		their_features: &InitFeatures, msg: &msgs::OpenChannelV2, funding_satoshis: u64,
		user_id: u128, config: &UserConfig, current_chain_height: u32, logger: &L,
	) -> Result<InboundV2Channel<SP>, ChannelError>
	where
		ES::Target: EntropySource,
		F::Target: FeeEstimator,
		L::Target: Logger,
	{
		let channel_value_satoshis =
			funding_satoshis.saturating_add(msg.common_fields.funding_satoshis);
		let counterparty_selected_channel_reserve_satoshis = get_v2_channel_reserve_satoshis(
			channel_value_satoshis,
			msg.common_fields.dust_limit_satoshis,
		);
		let holder_selected_channel_reserve_satoshis =
			get_v2_channel_reserve_satoshis(channel_value_satoshis, MIN_CHAN_DUST_LIMIT_SATOSHIS);

		// First check the channel type is known, failing before we do anything else if we don't
		// support this channel type.
		if msg.common_fields.channel_type.is_none() {
			return Err(ChannelError::close(format!(
				"Rejecting V2 channel {} missing channel_type",
				msg.common_fields.temporary_channel_id
			)));
		}
		let channel_type = channel_type_from_open_channel(
			&msg.common_fields,
			their_features,
			our_supported_features,
		)?;

		let counterparty_pubkeys = ChannelPublicKeys {
			funding_pubkey: msg.common_fields.funding_pubkey,
			revocation_basepoint: RevocationBasepoint(msg.common_fields.revocation_basepoint),
			payment_point: msg.common_fields.payment_basepoint,
			delayed_payment_basepoint: DelayedPaymentBasepoint(
				msg.common_fields.delayed_payment_basepoint,
			),
			htlc_basepoint: HtlcBasepoint(msg.common_fields.htlc_basepoint),
		};

		let mut context = ChannelContext::new_for_inbound_channel(
			fee_estimator,
			entropy_source,
			signer_provider,
			counterparty_node_id,
			their_features,
			user_id,
			config,
			current_chain_height,
			logger,
			false,
			funding_satoshis,
			counterparty_pubkeys,
			channel_type,
			holder_selected_channel_reserve_satoshis,
			counterparty_selected_channel_reserve_satoshis,
			0, /* push_msat not used in dual-funding */
			msg.common_fields.clone(),
		)?;
		let channel_id = ChannelId::v2_from_revocation_basepoints(
			&context.get_holder_pubkeys().revocation_basepoint,
			&context.get_counterparty_pubkeys().revocation_basepoint,
		);
		context.channel_id = channel_id;

		let chan = Self {
			context,
			unfunded_context: UnfundedChannelContext { unfunded_channel_age_ticks: 0 },
			dual_funding_context: DualFundingChannelContext {
				our_funding_satoshis: funding_satoshis,
				their_funding_satoshis: msg.common_fields.funding_satoshis,
				funding_tx_locktime: msg.locktime,
				funding_feerate_sat_per_1000_weight: msg.funding_feerate_sat_per_1000_weight,
			},
		};

		Ok(chan)
	}

	/// Marks an inbound channel as accepted and generates a [`msgs::AcceptChannelV2`] message which
	/// should be sent back to the counterparty node.
	///
	/// [`msgs::AcceptChannelV2`]: crate::ln::msgs::AcceptChannelV2
	pub fn accept_inbound_dual_funded_channel(&mut self) -> msgs::AcceptChannelV2 {
		if self.context.is_outbound() {
			debug_assert!(false, "Tried to send accept_channel for an outbound channel?");
		}
		if !matches!(
			self.context.channel_state, ChannelState::NegotiatingFunding(flags)
			if flags == (NegotiatingFundingFlags::OUR_INIT_SENT | NegotiatingFundingFlags::THEIR_INIT_SENT)
		) {
			debug_assert!(false, "Tried to send accept_channel2 after channel had moved forward");
		}
		if self.context.holder_commitment_point.transaction_number() != INITIAL_COMMITMENT_NUMBER {
			debug_assert!(
				false,
				"Tried to send an accept_channel2 for a channel that has already advanced"
			);
		}

		self.generate_accept_channel_v2_message()
	}

	/// This function is used to explicitly generate a [`msgs::AcceptChannel`] message for an
	/// inbound channel. If the intention is to accept an inbound channel, use
	/// [`InboundV1Channel::accept_inbound_channel`] instead.
	///
	/// [`msgs::AcceptChannelV2`]: crate::ln::msgs::AcceptChannelV2
	fn generate_accept_channel_v2_message(&self) -> msgs::AcceptChannelV2 {
		let first_per_commitment_point = self.context.holder_signer.as_ref().get_per_commitment_point(
			self.context.holder_commitment_point.transaction_number(), &self.context.secp_ctx)
			.expect("TODO: async signing is not yet supported for commitment points in v2 channel establishment");
		let second_per_commitment_point = self.context.holder_signer.as_ref().get_per_commitment_point(
			self.context.holder_commitment_point.transaction_number() - 1, &self.context.secp_ctx)
			.expect("TODO: async signing is not yet supported for commitment points in v2 channel establishment");
		let keys = self.context.get_holder_pubkeys();

		msgs::AcceptChannelV2 {
			common_fields: msgs::CommonAcceptChannelFields {
				temporary_channel_id: self.context.temporary_channel_id.unwrap(),
				dust_limit_satoshis: self.context.holder_dust_limit_satoshis,
				max_htlc_value_in_flight_msat: self.context.holder_max_htlc_value_in_flight_msat,
				htlc_minimum_msat: self.context.holder_htlc_minimum_msat,
				minimum_depth: self.context.minimum_depth.unwrap(),
				to_self_delay: self.context.get_holder_selected_contest_delay(),
				max_accepted_htlcs: self.context.holder_max_accepted_htlcs,
				funding_pubkey: keys.funding_pubkey,
				revocation_basepoint: keys.revocation_basepoint.to_public_key(),
				payment_basepoint: keys.payment_point,
				delayed_payment_basepoint: keys.delayed_payment_basepoint.to_public_key(),
				htlc_basepoint: keys.htlc_basepoint.to_public_key(),
				first_per_commitment_point,
				shutdown_scriptpubkey: Some(match &self.context.shutdown_scriptpubkey {
					Some(script) => script.clone().into_inner(),
					None => Builder::new().into_script(),
				}),
				channel_type: Some(self.context.channel_type.clone()),
			},
			funding_satoshis: self.dual_funding_context.our_funding_satoshis,
			second_per_commitment_point,
			require_confirmed_inputs: None,
		}
	}

	/// Enables the possibility for tests to extract a [`msgs::AcceptChannelV2`] message for an
	/// inbound channel without accepting it.
	///
	/// [`msgs::AcceptChannelV2`]: crate::ln::msgs::AcceptChannelV2
	#[cfg(test)]
	pub fn get_accept_channel_v2_message(&self) -> msgs::AcceptChannelV2 {
		self.generate_accept_channel_v2_message()
	}
}

// Unfunded channel utilities

fn get_initial_channel_type(
	config: &UserConfig, their_features: &InitFeatures,
) -> ChannelTypeFeatures {
	// The default channel type (ie the first one we try) depends on whether the channel is
	// public - if it is, we just go with `only_static_remotekey` as it's the only option
	// available. If it's private, we first try `scid_privacy` as it provides better privacy
	// with no other changes, and fall back to `only_static_remotekey`.
	let mut ret = ChannelTypeFeatures::only_static_remote_key();
	if !config.channel_handshake_config.announce_for_forwarding
		&& config.channel_handshake_config.negotiate_scid_privacy
		&& their_features.supports_scid_privacy()
	{
		ret.set_scid_privacy_required();
	}

	// Optionally, if the user would like to negotiate the `anchors_zero_fee_htlc_tx` option, we
	// set it now. If they don't understand it, we'll fall back to our default of
	// `only_static_remotekey`.
	if config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx
		&& their_features.supports_anchors_zero_fee_htlc_tx()
	{
		ret.set_anchors_zero_fee_htlc_tx_required();
	}

	ret
}

const SERIALIZATION_VERSION: u8 = 4;
const MIN_SERIALIZATION_VERSION: u8 = 3;

impl_writeable_tlv_based_enum_legacy!(InboundHTLCRemovalReason,;
	(0, FailRelay),
	(1, FailMalformed),
	(2, Fulfill),
);

impl Writeable for ChannelUpdateStatus {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// We only care about writing out the current state as it was announced, ie only either
		// Enabled or Disabled. In the case of DisabledStaged, we most recently announced the
		// channel as enabled, so we write 0. For EnabledStaged, we similarly write a 1.
		match self {
			ChannelUpdateStatus::Enabled => 0u8.write(writer)?,
			ChannelUpdateStatus::DisabledStaged(_) => 0u8.write(writer)?,
			ChannelUpdateStatus::EnabledStaged(_) => 1u8.write(writer)?,
			ChannelUpdateStatus::Disabled => 1u8.write(writer)?,
		}
		Ok(())
	}
}

impl Readable for ChannelUpdateStatus {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(match <u8 as Readable>::read(reader)? {
			0 => ChannelUpdateStatus::Enabled,
			1 => ChannelUpdateStatus::Disabled,
			_ => return Err(DecodeError::InvalidValue),
		})
	}
}

impl Writeable for AnnouncementSigsState {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// We only care about writing out the current state as if we had just disconnected, at
		// which point we always set anything but AnnouncementSigsReceived to NotSent.
		match self {
			AnnouncementSigsState::NotSent => 0u8.write(writer),
			AnnouncementSigsState::MessageSent => 0u8.write(writer),
			AnnouncementSigsState::Committed => 0u8.write(writer),
			AnnouncementSigsState::PeerReceived => 1u8.write(writer),
		}
	}
}

impl Readable for AnnouncementSigsState {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		Ok(match <u8 as Readable>::read(reader)? {
			0 => AnnouncementSigsState::NotSent,
			1 => AnnouncementSigsState::PeerReceived,
			_ => return Err(DecodeError::InvalidValue),
		})
	}
}

impl<SP: Deref> Writeable for Channel<SP>
where
	SP::Target: SignerProvider,
{
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// Note that we write out as if remove_uncommitted_htlcs_and_mark_paused had just been
		// called.

		let version_to_write =
			if self.context.pending_inbound_htlcs.iter().any(|htlc| match htlc.state {
				InboundHTLCState::AwaitingRemoteRevokeToAnnounce(ref htlc_resolution)
				| InboundHTLCState::AwaitingAnnouncedRemoteRevoke(ref htlc_resolution) => {
					matches!(htlc_resolution, InboundHTLCResolution::Pending { .. })
				},
				_ => false,
			}) {
				SERIALIZATION_VERSION
			} else {
				MIN_SERIALIZATION_VERSION
			};
		write_ver_prefix!(writer, version_to_write, MIN_SERIALIZATION_VERSION);

		// `user_id` used to be a single u64 value. In order to remain backwards compatible with
		// versions prior to 0.0.113, the u128 is serialized as two separate u64 values. We write
		// the low bytes now and the optional high bytes later.
		let user_id_low = self.context.user_id as u64;
		user_id_low.write(writer)?;

		// Version 1 deserializers expected to read parts of the config object here. Version 2
		// deserializers (0.0.99) now read config through TLVs, and as we now require them for
		// `minimum_depth` we simply write dummy values here.
		writer.write_all(&[0; 8])?;

		self.context.channel_id.write(writer)?;
		{
			let mut channel_state = self.context.channel_state;
			if matches!(
				channel_state,
				ChannelState::AwaitingChannelReady(_) | ChannelState::ChannelReady(_)
			) {
				channel_state.set_peer_disconnected();
			} else {
				debug_assert!(false, "Pre-funded/shutdown channels should not be written");
			}
			channel_state.to_u32().write(writer)?;
		}
		self.context.channel_value_satoshis.write(writer)?;

		self.context.latest_monitor_update_id.write(writer)?;

		// Write out the old serialization for shutdown_pubkey for backwards compatibility, if
		// deserialized from that format.
		match self
			.context
			.shutdown_scriptpubkey
			.as_ref()
			.and_then(|script| script.as_legacy_pubkey())
		{
			Some(shutdown_pubkey) => shutdown_pubkey.write(writer)?,
			None => [0u8; PUBLIC_KEY_SIZE].write(writer)?,
		}
		self.context.destination_script.write(writer)?;

		self.context.holder_commitment_point.transaction_number().write(writer)?;
		self.context.cur_counterparty_commitment_transaction_number.write(writer)?;
		self.context.value_to_self_msat.write(writer)?;

		let mut dropped_inbound_htlcs = 0;
		for htlc in self.context.pending_inbound_htlcs.iter() {
			if let InboundHTLCState::RemoteAnnounced(_) = htlc.state {
				dropped_inbound_htlcs += 1;
			}
		}
		(self.context.pending_inbound_htlcs.len() as u64 - dropped_inbound_htlcs).write(writer)?;
		for htlc in self.context.pending_inbound_htlcs.iter() {
			if let &InboundHTLCState::RemoteAnnounced(_) = &htlc.state {
				continue; // Drop
			}
			htlc.htlc_id.write(writer)?;
			htlc.amount_msat.write(writer)?;
			htlc.cltv_expiry.write(writer)?;
			htlc.payment_hash.write(writer)?;
			match &htlc.state {
				&InboundHTLCState::RemoteAnnounced(_) => unreachable!(),
				&InboundHTLCState::AwaitingRemoteRevokeToAnnounce(ref htlc_resolution) => {
					1u8.write(writer)?;
					if version_to_write <= 3 {
						if let InboundHTLCResolution::Resolved { pending_htlc_status } =
							htlc_resolution
						{
							pending_htlc_status.write(writer)?;
						} else {
							panic!();
						}
					} else {
						htlc_resolution.write(writer)?;
					}
				},
				&InboundHTLCState::AwaitingAnnouncedRemoteRevoke(ref htlc_resolution) => {
					2u8.write(writer)?;
					if version_to_write <= 3 {
						if let InboundHTLCResolution::Resolved { pending_htlc_status } =
							htlc_resolution
						{
							pending_htlc_status.write(writer)?;
						} else {
							panic!();
						}
					} else {
						htlc_resolution.write(writer)?;
					}
				},
				&InboundHTLCState::Committed => {
					3u8.write(writer)?;
				},
				&InboundHTLCState::LocalRemoved(ref removal_reason) => {
					4u8.write(writer)?;
					removal_reason.write(writer)?;
				},
			}
		}

		let mut preimages: Vec<&Option<PaymentPreimage>> = vec![];
		let mut pending_outbound_skimmed_fees: Vec<Option<u64>> = Vec::new();
		let mut pending_outbound_blinding_points: Vec<Option<PublicKey>> = Vec::new();

		(self.context.pending_outbound_htlcs.len() as u64).write(writer)?;
		for htlc in self.context.pending_outbound_htlcs.iter() {
			htlc.htlc_id.write(writer)?;
			htlc.amount_msat.write(writer)?;
			htlc.cltv_expiry.write(writer)?;
			htlc.payment_hash.write(writer)?;
			htlc.source.write(writer)?;
			match &htlc.state {
				&OutboundHTLCState::LocalAnnounced(ref onion_packet) => {
					0u8.write(writer)?;
					onion_packet.write(writer)?;
				},
				&OutboundHTLCState::Committed => {
					1u8.write(writer)?;
				},
				&OutboundHTLCState::RemoteRemoved(_) => {
					// Treat this as a Committed because we haven't received the CS - they'll
					// resend the claim/fail on reconnect as we all (hopefully) the missing CS.
					1u8.write(writer)?;
				},
				&OutboundHTLCState::AwaitingRemoteRevokeToRemove(ref outcome) => {
					3u8.write(writer)?;
					if let OutboundHTLCOutcome::Success(preimage) = outcome {
						preimages.push(preimage);
					}
					let reason: Option<&HTLCFailReason> = outcome.into();
					reason.write(writer)?;
				},
				&OutboundHTLCState::AwaitingRemovedRemoteRevoke(ref outcome) => {
					4u8.write(writer)?;
					if let OutboundHTLCOutcome::Success(preimage) = outcome {
						preimages.push(preimage);
					}
					let reason: Option<&HTLCFailReason> = outcome.into();
					reason.write(writer)?;
				},
			}
			pending_outbound_skimmed_fees.push(htlc.skimmed_fee_msat);
			pending_outbound_blinding_points.push(htlc.blinding_point);
		}

		let mut holding_cell_skimmed_fees: Vec<Option<u64>> = Vec::new();
		let mut holding_cell_blinding_points: Vec<Option<PublicKey>> = Vec::new();
		// Vec of (htlc_id, failure_code, sha256_of_onion)
		let mut malformed_htlcs: Vec<(u64, u16, [u8; 32])> = Vec::new();
		(self.context.holding_cell_htlc_updates.len() as u64).write(writer)?;
		for update in self.context.holding_cell_htlc_updates.iter() {
			match update {
				&HTLCUpdateAwaitingACK::AddHTLC {
					ref amount_msat,
					ref cltv_expiry,
					ref payment_hash,
					ref source,
					ref onion_routing_packet,
					blinding_point,
					skimmed_fee_msat,
					amount_rgb,
				} => {
					0u8.write(writer)?;
					amount_msat.write(writer)?;
					cltv_expiry.write(writer)?;
					payment_hash.write(writer)?;
					source.write(writer)?;
					onion_routing_packet.write(writer)?;

					holding_cell_skimmed_fees.push(skimmed_fee_msat);
					holding_cell_blinding_points.push(blinding_point);
					amount_rgb.write(writer)?;
				},
				&HTLCUpdateAwaitingACK::ClaimHTLC { ref payment_preimage, ref htlc_id } => {
					1u8.write(writer)?;
					payment_preimage.write(writer)?;
					htlc_id.write(writer)?;
				},
				&HTLCUpdateAwaitingACK::FailHTLC { ref htlc_id, ref err_packet } => {
					2u8.write(writer)?;
					htlc_id.write(writer)?;
					err_packet.write(writer)?;
				},
				&HTLCUpdateAwaitingACK::FailMalformedHTLC {
					htlc_id,
					failure_code,
					sha256_of_onion,
				} => {
					// We don't want to break downgrading by adding a new variant, so write a dummy
					// `::FailHTLC` variant and write the real malformed error as an optional TLV.
					malformed_htlcs.push((htlc_id, failure_code, sha256_of_onion));

					let dummy_err_packet = msgs::OnionErrorPacket { data: Vec::new() };
					2u8.write(writer)?;
					htlc_id.write(writer)?;
					dummy_err_packet.write(writer)?;
				},
			}
		}

		match self.context.resend_order {
			RAACommitmentOrder::CommitmentFirst => 0u8.write(writer)?,
			RAACommitmentOrder::RevokeAndACKFirst => 1u8.write(writer)?,
		}

		self.context.monitor_pending_channel_ready.write(writer)?;
		self.context.monitor_pending_revoke_and_ack.write(writer)?;
		self.context.monitor_pending_commitment_signed.write(writer)?;

		(self.context.monitor_pending_forwards.len() as u64).write(writer)?;
		for &(ref pending_forward, ref htlc_id) in self.context.monitor_pending_forwards.iter() {
			pending_forward.write(writer)?;
			htlc_id.write(writer)?;
		}

		(self.context.monitor_pending_failures.len() as u64).write(writer)?;
		for &(ref htlc_source, ref payment_hash, ref fail_reason) in
			self.context.monitor_pending_failures.iter()
		{
			htlc_source.write(writer)?;
			payment_hash.write(writer)?;
			fail_reason.write(writer)?;
		}

		if self.context.is_outbound() {
			self.context.pending_update_fee.map(|(a, _)| a).write(writer)?;
		} else if let Some((feerate, FeeUpdateState::AwaitingRemoteRevokeToAnnounce)) =
			self.context.pending_update_fee
		{
			Some(feerate).write(writer)?;
		} else {
			// As for inbound HTLCs, if the update was only announced and never committed in a
			// commitment_signed, drop it.
			None::<u32>.write(writer)?;
		}
		self.context.holding_cell_update_fee.write(writer)?;

		self.context.next_holder_htlc_id.write(writer)?;
		(self.context.next_counterparty_htlc_id - dropped_inbound_htlcs).write(writer)?;
		self.context.update_time_counter.write(writer)?;
		self.context.feerate_per_kw.write(writer)?;

		// Versions prior to 0.0.100 expected to read the fields of `last_sent_closing_fee` here,
		// however we are supposed to restart shutdown fee negotiation on reconnect (and wipe
		// `last_send_closing_fee` in `remove_uncommitted_htlcs_and_mark_paused`) so we should never
		// consider the stale state on reload.
		0u8.write(writer)?;

		self.context.funding_tx_confirmed_in.write(writer)?;
		self.context.funding_tx_confirmation_height.write(writer)?;
		self.context.short_channel_id.write(writer)?;

		self.context.counterparty_dust_limit_satoshis.write(writer)?;
		self.context.holder_dust_limit_satoshis.write(writer)?;
		self.context.counterparty_max_htlc_value_in_flight_msat.write(writer)?;

		// Note that this field is ignored by 0.0.99+ as the TLV Optional variant is used instead.
		self.context.counterparty_selected_channel_reserve_satoshis.unwrap_or(0).write(writer)?;

		self.context.counterparty_htlc_minimum_msat.write(writer)?;
		self.context.holder_htlc_minimum_msat.write(writer)?;
		self.context.counterparty_max_accepted_htlcs.write(writer)?;

		// Note that this field is ignored by 0.0.99+ as the TLV Optional variant is used instead.
		self.context.minimum_depth.unwrap_or(0).write(writer)?;

		match &self.context.counterparty_forwarding_info {
			Some(info) => {
				1u8.write(writer)?;
				info.fee_base_msat.write(writer)?;
				info.fee_proportional_millionths.write(writer)?;
				info.cltv_expiry_delta.write(writer)?;
			},
			None => 0u8.write(writer)?,
		}

		self.context.channel_transaction_parameters.write(writer)?;
		self.context.funding_transaction.write(writer)?;

		self.context.counterparty_cur_commitment_point.write(writer)?;
		self.context.counterparty_prev_commitment_point.write(writer)?;
		self.context.counterparty_node_id.write(writer)?;

		self.context.counterparty_shutdown_scriptpubkey.write(writer)?;

		self.context.commitment_secrets.write(writer)?;

		self.context.channel_update_status.write(writer)?;

		#[cfg(any(test, fuzzing))]
		(self.context.historical_inbound_htlc_fulfills.len() as u64).write(writer)?;
		#[cfg(any(test, fuzzing))]
		for htlc in self.context.historical_inbound_htlc_fulfills.iter() {
			htlc.write(writer)?;
		}

		// If the channel type is something other than only-static-remote-key, then we need to have
		// older clients fail to deserialize this channel at all. If the type is
		// only-static-remote-key, we simply consider it "default" and don't write the channel type
		// out at all.
		let chan_type =
			if self.context.channel_type != ChannelTypeFeatures::only_static_remote_key() {
				Some(&self.context.channel_type)
			} else {
				None
			};

		// The same logic applies for `holder_selected_channel_reserve_satoshis` values other than
		// the default, and when `holder_max_htlc_value_in_flight_msat` is configured to be set to
		// a different percentage of the channel value then 10%, which older versions of LDK used
		// to set it to before the percentage was made configurable.
		let serialized_holder_selected_reserve =
			if self.context.holder_selected_channel_reserve_satoshis
				!= get_legacy_default_holder_selected_channel_reserve_satoshis(
					self.context.channel_value_satoshis,
				) {
				Some(self.context.holder_selected_channel_reserve_satoshis)
			} else {
				None
			};

		let mut old_max_in_flight_percent_config = UserConfig::default().channel_handshake_config;
		old_max_in_flight_percent_config.max_inbound_htlc_value_in_flight_percent_of_channel =
			MAX_IN_FLIGHT_PERCENT_LEGACY;
		let serialized_holder_htlc_max_in_flight =
			if self.context.holder_max_htlc_value_in_flight_msat
				!= get_holder_max_htlc_value_in_flight_msat(
					self.context.channel_value_satoshis,
					&old_max_in_flight_percent_config,
				) {
				Some(self.context.holder_max_htlc_value_in_flight_msat)
			} else {
				None
			};

		let channel_pending_event_emitted = Some(self.context.channel_pending_event_emitted);
		let channel_ready_event_emitted = Some(self.context.channel_ready_event_emitted);
		let funding_tx_broadcast_safe_event_emitted =
			Some(self.context.funding_tx_broadcast_safe_event_emitted);

		// `user_id` used to be a single u64 value. In order to remain backwards compatible with
		// versions prior to 0.0.113, the u128 is serialized as two separate u64 values. Therefore,
		// we write the high bytes as an option here.
		let user_id_high_opt = Some((self.context.user_id >> 64) as u64);

		let holder_max_accepted_htlcs =
			if self.context.holder_max_accepted_htlcs == DEFAULT_MAX_HTLCS {
				None
			} else {
				Some(self.context.holder_max_accepted_htlcs)
			};

		let mut monitor_pending_update_adds = None;
		if !self.context.monitor_pending_update_adds.is_empty() {
			monitor_pending_update_adds = Some(&self.context.monitor_pending_update_adds);
		}
		let is_manual_broadcast = Some(self.context.is_manual_broadcast);

		// `current_point` will become optional when async signing is implemented.
		let cur_holder_commitment_point =
			Some(self.context.holder_commitment_point.current_point());
		let next_holder_commitment_point = self.context.holder_commitment_point.next_point();

		write_tlv_fields!(writer, {
				   (0, self.context.announcement_sigs, option),
				   // minimum_depth and counterparty_selected_channel_reserve_satoshis used to have a
				   // default value instead of being Option<>al. Thus, to maintain compatibility we write
				   // them twice, once with their original default values above, and once as an option
				   // here. On the read side, old versions will simply ignore the odd-type entries here,
				   // and new versions map the default values to None and allow the TLV entries here to
				   // override that.
				   (1, self.context.minimum_depth, option),
				   (2, chan_type, option),
				   (3, self.context.counterparty_selected_channel_reserve_satoshis, option),
				   (4, serialized_holder_selected_reserve, option),
				   (5, self.context.config, required),
				   (6, serialized_holder_htlc_max_in_flight, option),
				   (7, self.context.shutdown_scriptpubkey, option),
				   (8, self.context.blocked_monitor_updates, optional_vec),
				   (9, self.context.target_closing_feerate_sats_per_kw, option),
				   (10, monitor_pending_update_adds, option), // Added in 0.0.122
				   (11, self.context.monitor_pending_finalized_fulfills, required_vec),
				   (13, self.context.channel_creation_height, required),
				   (15, preimages, required_vec),
				   (17, self.context.announcement_sigs_state, required),
				   (19, self.context.latest_inbound_scid_alias, option),
				   (21, self.context.outbound_scid_alias, required),
				   (23, channel_ready_event_emitted, option),
				   (25, user_id_high_opt, option),
				   (27, self.context.channel_keys_id, required),
				   (28, holder_max_accepted_htlcs, option),
				   (29, self.context.temporary_channel_id, option),
				   (31, channel_pending_event_emitted, option),
				   (35, pending_outbound_skimmed_fees, optional_vec),
				   (37, holding_cell_skimmed_fees, optional_vec),
				   (38, self.context.is_batch_funding, option),
				   (39, pending_outbound_blinding_points, optional_vec),
				   (41, holding_cell_blinding_points, optional_vec),
				   (43, malformed_htlcs, optional_vec), // Added in 0.0.119
				   (45, cur_holder_commitment_point, option),
				   (47, next_holder_commitment_point, option),
				   (49, self.context.local_initiated_shutdown, option),(51, self.context.consignment_endpoint, option),
		// Added in 0.0.122
				   (51, is_manual_broadcast, option), // Added in 0.0.124
				   (53, funding_tx_broadcast_safe_event_emitted, option) // Added in 0.0.124
			   });

		Ok(())
	}
}

const MAX_ALLOC_SIZE: usize = 64 * 1024;
impl<'a, 'b, 'c, ES: Deref, SP: Deref>
	ReadableArgs<(&'a ES, &'b SP, u32, &'c ChannelTypeFeatures, PathBuf)> for Channel<SP>
where
	ES::Target: EntropySource,
	SP::Target: SignerProvider,
{
	fn read<R: io::Read>(
		reader: &mut R, args: (&'a ES, &'b SP, u32, &'c ChannelTypeFeatures, PathBuf),
	) -> Result<Self, DecodeError> {
		let (
			entropy_source,
			signer_provider,
			serialized_height,
			our_supported_features,
			ldk_data_dir,
		) = args;
		let ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);

		// `user_id` used to be a single u64 value. In order to remain backwards compatible with
		// versions prior to 0.0.113, the u128 is serialized as two separate u64 values. We read
		// the low bytes now and the high bytes later.
		let user_id_low: u64 = Readable::read(reader)?;

		let mut config = Some(LegacyChannelConfig::default());
		if ver == 1 {
			// Read the old serialization of the ChannelConfig from version 0.0.98.
			config.as_mut().unwrap().options.forwarding_fee_proportional_millionths =
				Readable::read(reader)?;
			config.as_mut().unwrap().options.cltv_expiry_delta = Readable::read(reader)?;
			config.as_mut().unwrap().announce_for_forwarding = Readable::read(reader)?;
			config.as_mut().unwrap().commit_upfront_shutdown_pubkey = Readable::read(reader)?;
		} else {
			// Read the 8 bytes of backwards-compatibility ChannelConfig data.
			let mut _val: u64 = Readable::read(reader)?;
		}

		let channel_id = Readable::read(reader)?;
		let channel_state = ChannelState::from_u32(Readable::read(reader)?)
			.map_err(|_| DecodeError::InvalidValue)?;
		let channel_value_satoshis = Readable::read(reader)?;

		let latest_monitor_update_id = Readable::read(reader)?;

		let mut keys_data = None;
		if ver <= 2 {
			// Read the serialize signer bytes. We'll choose to deserialize them or not based on whether
			// the `channel_keys_id` TLV is present below.
			let keys_len: u32 = Readable::read(reader)?;
			keys_data = Some(Vec::with_capacity(cmp::min(keys_len as usize, MAX_ALLOC_SIZE)));
			while keys_data.as_ref().unwrap().len() != keys_len as usize {
				// Read 1KB at a time to avoid accidentally allocating 4GB on corrupted channel keys
				let mut data = [0; 1024];
				let read_slice = &mut data
					[0..cmp::min(1024, keys_len as usize - keys_data.as_ref().unwrap().len())];
				reader.read_exact(read_slice)?;
				keys_data.as_mut().unwrap().extend_from_slice(read_slice);
			}
		}

		// Read the old serialization for shutdown_pubkey, preferring the TLV field later if set.
		let mut shutdown_scriptpubkey = match <PublicKey as Readable>::read(reader) {
			Ok(pubkey) => Some(ShutdownScript::new_p2wpkh_from_pubkey(pubkey)),
			Err(_) => None,
		};
		let destination_script = Readable::read(reader)?;

		let cur_holder_commitment_transaction_number = Readable::read(reader)?;
		let cur_counterparty_commitment_transaction_number = Readable::read(reader)?;
		let value_to_self_msat = Readable::read(reader)?;

		let pending_inbound_htlc_count: u64 = Readable::read(reader)?;

		let mut pending_inbound_htlcs = Vec::with_capacity(cmp::min(
			pending_inbound_htlc_count as usize,
			DEFAULT_MAX_HTLCS as usize,
		));
		for _ in 0..pending_inbound_htlc_count {
			pending_inbound_htlcs.push(InboundHTLCOutput {
				htlc_id: Readable::read(reader)?,
				amount_msat: Readable::read(reader)?,
				cltv_expiry: Readable::read(reader)?,
				payment_hash: Readable::read(reader)?,
				state: match <u8 as Readable>::read(reader)? {
					1 => {
						let resolution = if ver <= 3 {
							InboundHTLCResolution::Resolved {
								pending_htlc_status: Readable::read(reader)?,
							}
						} else {
							Readable::read(reader)?
						};
						InboundHTLCState::AwaitingRemoteRevokeToAnnounce(resolution)
					},
					2 => {
						let resolution = if ver <= 3 {
							InboundHTLCResolution::Resolved {
								pending_htlc_status: Readable::read(reader)?,
							}
						} else {
							Readable::read(reader)?
						};
						InboundHTLCState::AwaitingAnnouncedRemoteRevoke(resolution)
					},
					3 => InboundHTLCState::Committed,
					4 => InboundHTLCState::LocalRemoved(Readable::read(reader)?),
					_ => return Err(DecodeError::InvalidValue),
				},
				amount_rgb: Readable::read(reader)?,
			});
		}

		let pending_outbound_htlc_count: u64 = Readable::read(reader)?;
		let mut pending_outbound_htlcs = Vec::with_capacity(cmp::min(
			pending_outbound_htlc_count as usize,
			DEFAULT_MAX_HTLCS as usize,
		));
		for _ in 0..pending_outbound_htlc_count {
			pending_outbound_htlcs.push(OutboundHTLCOutput {
				htlc_id: Readable::read(reader)?,
				amount_msat: Readable::read(reader)?,
				cltv_expiry: Readable::read(reader)?,
				payment_hash: Readable::read(reader)?,
				source: Readable::read(reader)?,
				state: match <u8 as Readable>::read(reader)? {
					0 => OutboundHTLCState::LocalAnnounced(Box::new(Readable::read(reader)?)),
					1 => OutboundHTLCState::Committed,
					2 => {
						let option: Option<HTLCFailReason> = Readable::read(reader)?;
						OutboundHTLCState::RemoteRemoved(option.into())
					},
					3 => {
						let option: Option<HTLCFailReason> = Readable::read(reader)?;
						OutboundHTLCState::AwaitingRemoteRevokeToRemove(option.into())
					},
					4 => {
						let option: Option<HTLCFailReason> = Readable::read(reader)?;
						OutboundHTLCState::AwaitingRemovedRemoteRevoke(option.into())
					},
					_ => return Err(DecodeError::InvalidValue),
				},
				skimmed_fee_msat: None,
				blinding_point: None,
				amount_rgb: Readable::read(reader)?,
			});
		}

		let holding_cell_htlc_update_count: u64 = Readable::read(reader)?;
		let mut holding_cell_htlc_updates = Vec::with_capacity(cmp::min(
			holding_cell_htlc_update_count as usize,
			DEFAULT_MAX_HTLCS as usize * 2,
		));
		for _ in 0..holding_cell_htlc_update_count {
			holding_cell_htlc_updates.push(match <u8 as Readable>::read(reader)? {
				0 => HTLCUpdateAwaitingACK::AddHTLC {
					amount_msat: Readable::read(reader)?,
					cltv_expiry: Readable::read(reader)?,
					payment_hash: Readable::read(reader)?,
					source: Readable::read(reader)?,
					onion_routing_packet: Readable::read(reader)?,
					skimmed_fee_msat: None,
					blinding_point: None,
					amount_rgb: Readable::read(reader)?,
				},
				1 => HTLCUpdateAwaitingACK::ClaimHTLC {
					payment_preimage: Readable::read(reader)?,
					htlc_id: Readable::read(reader)?,
				},
				2 => HTLCUpdateAwaitingACK::FailHTLC {
					htlc_id: Readable::read(reader)?,
					err_packet: Readable::read(reader)?,
				},
				_ => return Err(DecodeError::InvalidValue),
			});
		}

		let resend_order = match <u8 as Readable>::read(reader)? {
			0 => RAACommitmentOrder::CommitmentFirst,
			1 => RAACommitmentOrder::RevokeAndACKFirst,
			_ => return Err(DecodeError::InvalidValue),
		};

		let monitor_pending_channel_ready = Readable::read(reader)?;
		let monitor_pending_revoke_and_ack = Readable::read(reader)?;
		let monitor_pending_commitment_signed = Readable::read(reader)?;

		let monitor_pending_forwards_count: u64 = Readable::read(reader)?;
		let mut monitor_pending_forwards = Vec::with_capacity(cmp::min(
			monitor_pending_forwards_count as usize,
			DEFAULT_MAX_HTLCS as usize,
		));
		for _ in 0..monitor_pending_forwards_count {
			monitor_pending_forwards.push((Readable::read(reader)?, Readable::read(reader)?));
		}

		let monitor_pending_failures_count: u64 = Readable::read(reader)?;
		let mut monitor_pending_failures = Vec::with_capacity(cmp::min(
			monitor_pending_failures_count as usize,
			DEFAULT_MAX_HTLCS as usize,
		));
		for _ in 0..monitor_pending_failures_count {
			monitor_pending_failures.push((
				Readable::read(reader)?,
				Readable::read(reader)?,
				Readable::read(reader)?,
			));
		}

		let pending_update_fee_value: Option<u32> = Readable::read(reader)?;

		let holding_cell_update_fee = Readable::read(reader)?;

		let next_holder_htlc_id = Readable::read(reader)?;
		let next_counterparty_htlc_id = Readable::read(reader)?;
		let update_time_counter = Readable::read(reader)?;
		let feerate_per_kw = Readable::read(reader)?;

		// Versions prior to 0.0.100 expected to read the fields of `last_sent_closing_fee` here,
		// however we are supposed to restart shutdown fee negotiation on reconnect (and wipe
		// `last_send_closing_fee` in `remove_uncommitted_htlcs_and_mark_paused`) so we should never
		// consider the stale state on reload.
		match <u8 as Readable>::read(reader)? {
			0 => {},
			1 => {
				let _: u32 = Readable::read(reader)?;
				let _: u64 = Readable::read(reader)?;
				let _: Signature = Readable::read(reader)?;
			},
			_ => return Err(DecodeError::InvalidValue),
		}

		let funding_tx_confirmed_in = Readable::read(reader)?;
		let funding_tx_confirmation_height = Readable::read(reader)?;
		let short_channel_id = Readable::read(reader)?;

		let counterparty_dust_limit_satoshis = Readable::read(reader)?;
		let holder_dust_limit_satoshis = Readable::read(reader)?;
		let counterparty_max_htlc_value_in_flight_msat = Readable::read(reader)?;
		let mut counterparty_selected_channel_reserve_satoshis = None;
		if ver == 1 {
			// Read the old serialization from version 0.0.98.
			counterparty_selected_channel_reserve_satoshis = Some(Readable::read(reader)?);
		} else {
			// Read the 8 bytes of backwards-compatibility data.
			let _dummy: u64 = Readable::read(reader)?;
		}
		let counterparty_htlc_minimum_msat = Readable::read(reader)?;
		let holder_htlc_minimum_msat = Readable::read(reader)?;
		let counterparty_max_accepted_htlcs = Readable::read(reader)?;

		let mut minimum_depth = None;
		if ver == 1 {
			// Read the old serialization from version 0.0.98.
			minimum_depth = Some(Readable::read(reader)?);
		} else {
			// Read the 4 bytes of backwards-compatibility data.
			let _dummy: u32 = Readable::read(reader)?;
		}

		let counterparty_forwarding_info = match <u8 as Readable>::read(reader)? {
			0 => None,
			1 => Some(CounterpartyForwardingInfo {
				fee_base_msat: Readable::read(reader)?,
				fee_proportional_millionths: Readable::read(reader)?,
				cltv_expiry_delta: Readable::read(reader)?,
			}),
			_ => return Err(DecodeError::InvalidValue),
		};

		let mut channel_parameters: ChannelTransactionParameters = Readable::read(reader)?;
		let funding_transaction: Option<Transaction> = Readable::read(reader)?;

		let counterparty_cur_commitment_point = Readable::read(reader)?;

		let counterparty_prev_commitment_point = Readable::read(reader)?;
		let counterparty_node_id = Readable::read(reader)?;

		let counterparty_shutdown_scriptpubkey = Readable::read(reader)?;
		let commitment_secrets = Readable::read(reader)?;

		let channel_update_status = Readable::read(reader)?;

		#[cfg(any(test, fuzzing))]
		let mut historical_inbound_htlc_fulfills = new_hash_set();
		#[cfg(any(test, fuzzing))]
		{
			let htlc_fulfills_len: u64 = Readable::read(reader)?;
			for _ in 0..htlc_fulfills_len {
				assert!(historical_inbound_htlc_fulfills.insert(Readable::read(reader)?));
			}
		}

		let pending_update_fee = if let Some(feerate) = pending_update_fee_value {
			Some((
				feerate,
				if channel_parameters.is_outbound_from_holder {
					FeeUpdateState::Outbound
				} else {
					FeeUpdateState::AwaitingRemoteRevokeToAnnounce
				},
			))
		} else {
			None
		};

		let mut announcement_sigs = None;
		let mut target_closing_feerate_sats_per_kw = None;
		let mut monitor_pending_finalized_fulfills = Some(Vec::new());
		let mut holder_selected_channel_reserve_satoshis = Some(
			get_legacy_default_holder_selected_channel_reserve_satoshis(channel_value_satoshis),
		);
		let mut holder_max_htlc_value_in_flight_msat =
			Some(get_holder_max_htlc_value_in_flight_msat(
				channel_value_satoshis,
				&UserConfig::default().channel_handshake_config,
			));
		// Prior to supporting channel type negotiation, all of our channels were static_remotekey
		// only, so we default to that if none was written.
		let mut channel_type = Some(ChannelTypeFeatures::only_static_remote_key());
		let mut channel_creation_height = Some(serialized_height);
		let mut preimages_opt: Option<Vec<Option<PaymentPreimage>>> = None;

		// If we read an old Channel, for simplicity we just treat it as "we never sent an
		// AnnouncementSignatures" which implies we'll re-send it on reconnect, but that's fine.
		let mut announcement_sigs_state = Some(AnnouncementSigsState::NotSent);
		let mut latest_inbound_scid_alias = None;
		let mut outbound_scid_alias = None;
		let mut channel_pending_event_emitted = None;
		let mut channel_ready_event_emitted = None;
		let mut funding_tx_broadcast_safe_event_emitted = None;

		let mut user_id_high_opt: Option<u64> = None;
		let mut channel_keys_id: Option<[u8; 32]> = None;
		let mut temporary_channel_id: Option<ChannelId> = None;
		let mut holder_max_accepted_htlcs: Option<u16> = None;
		let mut consignment_endpoint: Option<RgbTransport> = None;

		let mut blocked_monitor_updates = Some(Vec::new());

		let mut pending_outbound_skimmed_fees_opt: Option<Vec<Option<u64>>> = None;
		let mut holding_cell_skimmed_fees_opt: Option<Vec<Option<u64>>> = None;

		let mut is_batch_funding: Option<()> = None;

		let mut local_initiated_shutdown: Option<()> = None;

		let mut pending_outbound_blinding_points_opt: Option<Vec<Option<PublicKey>>> = None;
		let mut holding_cell_blinding_points_opt: Option<Vec<Option<PublicKey>>> = None;

		let mut malformed_htlcs: Option<Vec<(u64, u16, [u8; 32])>> = None;
		let mut monitor_pending_update_adds: Option<Vec<msgs::UpdateAddHTLC>> = None;

		let mut cur_holder_commitment_point_opt: Option<PublicKey> = None;
		let mut next_holder_commitment_point_opt: Option<PublicKey> = None;
		let mut is_manual_broadcast = None;

		read_tlv_fields!(reader, {
			(0, announcement_sigs, option),
			(1, minimum_depth, option),
			(2, channel_type, option),
			(3, counterparty_selected_channel_reserve_satoshis, option),
			(4, holder_selected_channel_reserve_satoshis, option),
			(5, config, option), // Note that if none is provided we will *not* overwrite the existing one.
			(6, holder_max_htlc_value_in_flight_msat, option),
			(7, shutdown_scriptpubkey, option),
			(8, blocked_monitor_updates, optional_vec),
			(9, target_closing_feerate_sats_per_kw, option),
			(10, monitor_pending_update_adds, option), // Added in 0.0.122
			(11, monitor_pending_finalized_fulfills, optional_vec),
			(13, channel_creation_height, option),
			(15, preimages_opt, optional_vec),
			(17, announcement_sigs_state, option),
			(19, latest_inbound_scid_alias, option),
			(21, outbound_scid_alias, option),
			(23, channel_ready_event_emitted, option),
			(25, user_id_high_opt, option),
			(27, channel_keys_id, option),
			(28, holder_max_accepted_htlcs, option),
			(29, temporary_channel_id, option),
			(31, channel_pending_event_emitted, option),
			(35, pending_outbound_skimmed_fees_opt, optional_vec),
			(37, holding_cell_skimmed_fees_opt, optional_vec),
			(38, is_batch_funding, option),
			(39, pending_outbound_blinding_points_opt, optional_vec),
			(41, holding_cell_blinding_points_opt, optional_vec),
			(43, malformed_htlcs, optional_vec), // Added in 0.0.119
			(45, cur_holder_commitment_point_opt, option),
			(47, next_holder_commitment_point_opt, option),
			(49, local_initiated_shutdown, option),(51, consignment_endpoint, option),
			(51, is_manual_broadcast, option),
			(53, funding_tx_broadcast_safe_event_emitted, option),
		});

		let (channel_keys_id, holder_signer) = if let Some(channel_keys_id) = channel_keys_id {
			let mut holder_signer =
				signer_provider.derive_channel_signer(channel_value_satoshis, channel_keys_id);
			// If we've gotten to the funding stage of the channel, populate the signer with its
			// required channel parameters.
			if channel_state >= ChannelState::FundingNegotiated {
				holder_signer.provide_channel_parameters(&channel_parameters);
			}
			(channel_keys_id, holder_signer)
		} else {
			// `keys_data` can be `None` if we had corrupted data.
			let keys_data = keys_data.ok_or(DecodeError::InvalidValue)?;
			let holder_signer = signer_provider.read_chan_signer(&keys_data)?;
			(holder_signer.channel_keys_id(), holder_signer)
		};

		if let Some(preimages) = preimages_opt {
			let mut iter = preimages.into_iter();
			for htlc in pending_outbound_htlcs.iter_mut() {
				match &htlc.state {
					OutboundHTLCState::AwaitingRemoteRevokeToRemove(
						OutboundHTLCOutcome::Success(None),
					) => {
						htlc.state = OutboundHTLCState::AwaitingRemoteRevokeToRemove(
							OutboundHTLCOutcome::Success(
								iter.next().ok_or(DecodeError::InvalidValue)?,
							),
						);
					},
					OutboundHTLCState::AwaitingRemovedRemoteRevoke(
						OutboundHTLCOutcome::Success(None),
					) => {
						htlc.state = OutboundHTLCState::AwaitingRemovedRemoteRevoke(
							OutboundHTLCOutcome::Success(
								iter.next().ok_or(DecodeError::InvalidValue)?,
							),
						);
					},
					_ => {},
				}
			}
			// We expect all preimages to be consumed above
			if iter.next().is_some() {
				return Err(DecodeError::InvalidValue);
			}
		}

		let chan_features = channel_type.as_ref().unwrap();
		if chan_features.supports_any_optional_bits()
			|| chan_features.requires_unknown_bits_from(&our_supported_features)
		{
			// If the channel was written by a new version and negotiated with features we don't
			// understand yet, refuse to read it.
			return Err(DecodeError::UnknownRequiredFeature);
		}

		// ChannelTransactionParameters may have had an empty features set upon deserialization.
		// To account for that, we're proactively setting/overriding the field here.
		channel_parameters.channel_type_features = chan_features.clone();

		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		// `user_id` used to be a single u64 value. In order to remain backwards
		// compatible with versions prior to 0.0.113, the u128 is serialized as two
		// separate u64 values.
		let user_id = user_id_low as u128 + ((user_id_high_opt.unwrap_or(0) as u128) << 64);

		let holder_max_accepted_htlcs = holder_max_accepted_htlcs.unwrap_or(DEFAULT_MAX_HTLCS);

		if let Some(skimmed_fees) = pending_outbound_skimmed_fees_opt {
			let mut iter = skimmed_fees.into_iter();
			for htlc in pending_outbound_htlcs.iter_mut() {
				htlc.skimmed_fee_msat = iter.next().ok_or(DecodeError::InvalidValue)?;
			}
			// We expect all skimmed fees to be consumed above
			if iter.next().is_some() {
				return Err(DecodeError::InvalidValue);
			}
		}
		if let Some(skimmed_fees) = holding_cell_skimmed_fees_opt {
			let mut iter = skimmed_fees.into_iter();
			for htlc in holding_cell_htlc_updates.iter_mut() {
				if let HTLCUpdateAwaitingACK::AddHTLC { ref mut skimmed_fee_msat, .. } = htlc {
					*skimmed_fee_msat = iter.next().ok_or(DecodeError::InvalidValue)?;
				}
			}
			// We expect all skimmed fees to be consumed above
			if iter.next().is_some() {
				return Err(DecodeError::InvalidValue);
			}
		}
		if let Some(blinding_pts) = pending_outbound_blinding_points_opt {
			let mut iter = blinding_pts.into_iter();
			for htlc in pending_outbound_htlcs.iter_mut() {
				htlc.blinding_point = iter.next().ok_or(DecodeError::InvalidValue)?;
			}
			// We expect all blinding points to be consumed above
			if iter.next().is_some() {
				return Err(DecodeError::InvalidValue);
			}
		}
		if let Some(blinding_pts) = holding_cell_blinding_points_opt {
			let mut iter = blinding_pts.into_iter();
			for htlc in holding_cell_htlc_updates.iter_mut() {
				if let HTLCUpdateAwaitingACK::AddHTLC { ref mut blinding_point, .. } = htlc {
					*blinding_point = iter.next().ok_or(DecodeError::InvalidValue)?;
				}
			}
			// We expect all blinding points to be consumed above
			if iter.next().is_some() {
				return Err(DecodeError::InvalidValue);
			}
		}

		if let Some(malformed_htlcs) = malformed_htlcs {
			for (malformed_htlc_id, failure_code, sha256_of_onion) in malformed_htlcs {
				let htlc_idx = holding_cell_htlc_updates
					.iter()
					.position(|htlc| {
						if let HTLCUpdateAwaitingACK::FailHTLC { htlc_id, err_packet } = htlc {
							let matches = *htlc_id == malformed_htlc_id;
							if matches {
								debug_assert!(err_packet.data.is_empty())
							}
							matches
						} else {
							false
						}
					})
					.ok_or(DecodeError::InvalidValue)?;
				let malformed_htlc = HTLCUpdateAwaitingACK::FailMalformedHTLC {
					htlc_id: malformed_htlc_id,
					failure_code,
					sha256_of_onion,
				};
				let _ =
					core::mem::replace(&mut holding_cell_htlc_updates[htlc_idx], malformed_htlc);
			}
		}

		// If we're restoring this channel for the first time after an upgrade, then we require that the
		// signer be available so that we can immediately populate the current commitment point. Channel
		// restoration will fail if this is not possible.
		let holder_commitment_point = match (
			cur_holder_commitment_point_opt,
			next_holder_commitment_point_opt,
		) {
			(Some(current), Some(next)) => HolderCommitmentPoint::Available {
				transaction_number: cur_holder_commitment_transaction_number,
				current,
				next,
			},
			(Some(current), _) => HolderCommitmentPoint::PendingNext {
				transaction_number: cur_holder_commitment_transaction_number,
				current,
			},
			(_, _) => {
				// TODO(async_signing): remove this expect with the Uninitialized variant
				let current = holder_signer.get_per_commitment_point(cur_holder_commitment_transaction_number, &secp_ctx)
					.expect("Must be able to derive the current commitment point upon channel restoration");
				HolderCommitmentPoint::PendingNext {
					transaction_number: cur_holder_commitment_transaction_number,
					current,
				}
			},
		};

		Ok(Channel {
			context: ChannelContext {
				user_id,

				config: config.unwrap(),

				prev_config: None,

				// Note that we don't care about serializing handshake limits as we only ever serialize
				// channel data after the handshake has completed.
				inbound_handshake_limits_override: None,

				channel_id,
				temporary_channel_id,
				channel_state,
				announcement_sigs_state: announcement_sigs_state.unwrap(),
				secp_ctx,
				channel_value_satoshis,

				latest_monitor_update_id,

				holder_signer: ChannelSignerType::Ecdsa(holder_signer),
				shutdown_scriptpubkey,
				destination_script,

				holder_commitment_point,
				cur_counterparty_commitment_transaction_number,
				value_to_self_msat,

				holder_max_accepted_htlcs,
				pending_inbound_htlcs,
				pending_outbound_htlcs,
				holding_cell_htlc_updates,

				resend_order,

				monitor_pending_channel_ready,
				monitor_pending_revoke_and_ack,
				monitor_pending_commitment_signed,
				monitor_pending_forwards,
				monitor_pending_failures,
				monitor_pending_finalized_fulfills: monitor_pending_finalized_fulfills.unwrap(),
				monitor_pending_update_adds: monitor_pending_update_adds.unwrap_or_default(),

				signer_pending_revoke_and_ack: false,
				signer_pending_commitment_update: false,
				signer_pending_funding: false,
				signer_pending_closing: false,

				pending_update_fee,
				holding_cell_update_fee,
				next_holder_htlc_id,
				next_counterparty_htlc_id,
				update_time_counter,
				feerate_per_kw,

				#[cfg(debug_assertions)]
				holder_max_commitment_tx_output: Mutex::new((0, 0)),
				#[cfg(debug_assertions)]
				counterparty_max_commitment_tx_output: Mutex::new((0, 0)),

				last_sent_closing_fee: None,
				last_received_closing_sig: None,
				pending_counterparty_closing_signed: None,
				expecting_peer_commitment_signed: false,
				closing_fee_limits: None,
				target_closing_feerate_sats_per_kw,

				funding_tx_confirmed_in,
				funding_tx_confirmation_height,
				short_channel_id,
				channel_creation_height: channel_creation_height.unwrap(),

				counterparty_dust_limit_satoshis,
				holder_dust_limit_satoshis,
				counterparty_max_htlc_value_in_flight_msat,
				holder_max_htlc_value_in_flight_msat: holder_max_htlc_value_in_flight_msat.unwrap(),
				counterparty_selected_channel_reserve_satoshis,
				holder_selected_channel_reserve_satoshis: holder_selected_channel_reserve_satoshis
					.unwrap(),
				counterparty_htlc_minimum_msat,
				holder_htlc_minimum_msat,
				counterparty_max_accepted_htlcs,
				minimum_depth,

				counterparty_forwarding_info,

				channel_transaction_parameters: channel_parameters,
				funding_transaction,
				is_batch_funding,

				counterparty_cur_commitment_point,
				counterparty_prev_commitment_point,
				counterparty_node_id,

				counterparty_shutdown_scriptpubkey,

				commitment_secrets,

				channel_update_status,
				closing_signed_in_flight: false,

				announcement_sigs,

				#[cfg(any(test, fuzzing))]
				next_local_commitment_tx_fee_info_cached: Mutex::new(None),
				#[cfg(any(test, fuzzing))]
				next_remote_commitment_tx_fee_info_cached: Mutex::new(None),

				workaround_lnd_bug_4006: None,
				sent_message_awaiting_response: None,

				latest_inbound_scid_alias,
				// Later in the ChannelManager deserialization phase we scan for channels and assign scid aliases if its missing
				outbound_scid_alias: outbound_scid_alias.unwrap_or(0),

				funding_tx_broadcast_safe_event_emitted: funding_tx_broadcast_safe_event_emitted
					.unwrap_or(false),
				channel_pending_event_emitted: channel_pending_event_emitted.unwrap_or(true),
				channel_ready_event_emitted: channel_ready_event_emitted.unwrap_or(true),

				#[cfg(any(test, fuzzing))]
				historical_inbound_htlc_fulfills,

				channel_type: channel_type.unwrap(),
				channel_keys_id,

				local_initiated_shutdown,

				blocked_monitor_updates: blocked_monitor_updates.unwrap(),
				consignment_endpoint,
				ldk_data_dir,
				is_manual_broadcast: is_manual_broadcast.unwrap_or(false),
			},
			#[cfg(any(dual_funding, splicing))]
			dual_funding_channel_context: None,
		})
	}
}
