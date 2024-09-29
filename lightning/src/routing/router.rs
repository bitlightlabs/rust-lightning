// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The router finds paths within a [`NetworkGraph`] for a payment.

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};
use rgb_lib::ContractId;

use crate::blinded_path::message::{BlindedMessagePath, MessageContext, MessageForwardNode};
use crate::blinded_path::payment::{
	BlindedPaymentPath, ForwardTlvs, PaymentConstraints, PaymentForwardNode, PaymentRelay,
	ReceiveTlvs,
};
use crate::blinded_path::{BlindedHop, Direction, IntroductionNode};
use crate::crypto::chacha20::ChaCha20;
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::{PaymentId, RecipientOnionFields, MIN_FINAL_CLTV_EXPIRY_DELTA};
use crate::ln::features::{
	BlindedHopFeatures, Bolt11InvoiceFeatures, Bolt12InvoiceFeatures, ChannelFeatures, NodeFeatures,
};
use crate::ln::msgs::{DecodeError, ErrorAction, LightningError, MAX_VALUE_MSAT};
use crate::ln::onion_utils;
use crate::ln::{PaymentHash, PaymentPreimage};
use crate::offers::invoice::Bolt12Invoice;
use crate::onion_message::messenger::{
	DefaultMessageRouter, Destination, MessageRouter, OnionMessagePath,
};
use crate::routing::gossip::{
	DirectedChannelInfo, EffectiveCapacity, NetworkGraph, NodeId, ReadOnlyNetworkGraph,
};
use crate::routing::scoring::{ChannelUsage, LockableScore, ScoreLookUp};
use crate::sign::EntropySource;
use crate::util::logger::{Level, Logger};
use crate::util::ser::{Readable, ReadableArgs, Writeable, Writer};

use crate::io;
use crate::prelude::*;
use alloc::collections::BinaryHeap;
use core::ops::Deref;
use core::{cmp, fmt};

use lightning_types::routing::RoutingFees;

pub use lightning_types::routing::{RouteHint, RouteHintHop};

/// A [`Router`] implemented using [`find_route`].
///
/// # Privacy
///
/// Implements [`MessageRouter`] by delegating to [`DefaultMessageRouter`]. See those docs for
/// privacy implications.
pub struct DefaultRouter<
	G: Deref<Target = NetworkGraph<L>>,
	L: Deref,
	ES: Deref,
	S: Deref,
	SP: Sized,
	Sc: ScoreLookUp<ScoreParams = SP>,
> where
	L::Target: Logger,
	S::Target: for<'a> LockableScore<'a, ScoreLookUp = Sc>,
	ES::Target: EntropySource,
{
	network_graph: G,
	logger: L,
	entropy_source: ES,
	scorer: S,
	score_params: SP,
}

impl<
		G: Deref<Target = NetworkGraph<L>>,
		L: Deref,
		ES: Deref,
		S: Deref,
		SP: Sized,
		Sc: ScoreLookUp<ScoreParams = SP>,
	> DefaultRouter<G, L, ES, S, SP, Sc>
where
	L::Target: Logger,
	S::Target: for<'a> LockableScore<'a, ScoreLookUp = Sc>,
	ES::Target: EntropySource,
{
	/// Creates a new router.
	pub fn new(
		network_graph: G, logger: L, entropy_source: ES, scorer: S, score_params: SP,
	) -> Self {
		Self { network_graph, logger, entropy_source, scorer, score_params }
	}
}

impl<
		G: Deref<Target = NetworkGraph<L>>,
		L: Deref,
		ES: Deref,
		S: Deref,
		SP: Sized,
		Sc: ScoreLookUp<ScoreParams = SP>,
	> Router for DefaultRouter<G, L, ES, S, SP, Sc>
where
	L::Target: Logger,
	S::Target: for<'a> LockableScore<'a, ScoreLookUp = Sc>,
	ES::Target: EntropySource,
{
	fn find_route(
		&self, payer: &PublicKey, params: &RouteParameters, first_hops: Option<&[&ChannelDetails]>,
		inflight_htlcs: InFlightHtlcs,
	) -> Result<Route, LightningError> {
		let random_seed_bytes = self.entropy_source.get_secure_random_bytes();
		find_route(
			payer,
			params,
			&self.network_graph,
			first_hops,
			&*self.logger,
			&ScorerAccountingForInFlightHtlcs::new(self.scorer.read_lock(), &inflight_htlcs),
			&self.score_params,
			&random_seed_bytes,
		)
	}

	fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, first_hops: Vec<ChannelDetails>, tlvs: ReceiveTlvs,
		amount_msats: u64, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		// Limit the number of blinded paths that are computed.
		const MAX_PAYMENT_PATHS: usize = 3;

		// Ensure peers have at least three channels so that it is more difficult to infer the
		// recipient's node_id.
		const MIN_PEER_CHANNELS: usize = 3;

		let has_one_peer = first_hops
			.first()
			.map(|details| details.counterparty.node_id)
			.map(|node_id| {
				first_hops.iter().skip(1).all(|details| details.counterparty.node_id == node_id)
			})
			.unwrap_or(false);

		let network_graph = self.network_graph.deref().read_only();
		let is_recipient_announced =
			network_graph.nodes().contains_key(&NodeId::from_pubkey(&recipient));

		let paths = first_hops
			.into_iter()
			.filter(|details| details.counterparty.features.supports_route_blinding())
			.filter(|details| amount_msats <= details.inbound_capacity_msat)
			.filter(|details| amount_msats >= details.inbound_htlc_minimum_msat.unwrap_or(0))
			.filter(|details| amount_msats <= details.inbound_htlc_maximum_msat.unwrap_or(u64::MAX))
			// Limit to peers with announced channels unless the recipient is unannounced.
			.filter(|details| {
				network_graph
					.node(&NodeId::from_pubkey(&details.counterparty.node_id))
					.map(|node| !is_recipient_announced || node.channels.len() >= MIN_PEER_CHANNELS)
					// Allow payments directly with the only peer when unannounced.
					.unwrap_or(!is_recipient_announced && has_one_peer)
			})
			.filter_map(|details| {
				let short_channel_id = match details.get_inbound_payment_scid() {
					Some(short_channel_id) => short_channel_id,
					None => return None,
				};
				let payment_relay: PaymentRelay = match details.counterparty.forwarding_info {
					Some(forwarding_info) => match forwarding_info.try_into() {
						Ok(payment_relay) => payment_relay,
						Err(()) => return None,
					},
					None => return None,
				};

				let cltv_expiry_delta = payment_relay.cltv_expiry_delta as u32;
				let payment_constraints = PaymentConstraints {
					max_cltv_expiry: tlvs.payment_constraints.max_cltv_expiry + cltv_expiry_delta,
					htlc_minimum_msat: details.inbound_htlc_minimum_msat.unwrap_or(0),
				};
				Some(PaymentForwardNode {
					tlvs: ForwardTlvs {
						short_channel_id,
						payment_relay,
						payment_constraints,
						next_blinding_override: None,
						features: BlindedHopFeatures::empty(),
					},
					node_id: details.counterparty.node_id,
					htlc_maximum_msat: details.inbound_htlc_maximum_msat.unwrap_or(u64::MAX),
				})
			})
			.map(|forward_node| {
				BlindedPaymentPath::new(
					&[forward_node],
					recipient,
					tlvs.clone(),
					u64::MAX,
					MIN_FINAL_CLTV_EXPIRY_DELTA,
					&*self.entropy_source,
					secp_ctx,
				)
			})
			.take(MAX_PAYMENT_PATHS)
			.collect::<Result<Vec<_>, _>>();

		match paths {
			Ok(paths) if !paths.is_empty() => Ok(paths),
			_ => {
				if network_graph.nodes().contains_key(&NodeId::from_pubkey(&recipient)) {
					BlindedPaymentPath::new(
						&[],
						recipient,
						tlvs,
						u64::MAX,
						MIN_FINAL_CLTV_EXPIRY_DELTA,
						&*self.entropy_source,
						secp_ctx,
					)
					.map(|path| vec![path])
				} else {
					Err(())
				}
			},
		}
	}
}

impl<
		G: Deref<Target = NetworkGraph<L>>,
		L: Deref,
		ES: Deref,
		S: Deref,
		SP: Sized,
		Sc: ScoreLookUp<ScoreParams = SP>,
	> MessageRouter for DefaultRouter<G, L, ES, S, SP, Sc>
where
	L::Target: Logger,
	S::Target: for<'a> LockableScore<'a, ScoreLookUp = Sc>,
	ES::Target: EntropySource,
{
	fn find_path(
		&self, sender: PublicKey, peers: Vec<PublicKey>, destination: Destination,
	) -> Result<OnionMessagePath, ()> {
		DefaultMessageRouter::<_, _, ES>::find_path(&self.network_graph, sender, peers, destination)
	}

	fn create_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, context: MessageContext, peers: Vec<PublicKey>,
		secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		DefaultMessageRouter::create_blinded_paths(
			&self.network_graph,
			recipient,
			context,
			peers,
			&self.entropy_source,
			secp_ctx,
		)
	}

	fn create_compact_blinded_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, context: MessageContext, peers: Vec<MessageForwardNode>,
		secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		DefaultMessageRouter::create_compact_blinded_paths(
			&self.network_graph,
			recipient,
			context,
			peers,
			&self.entropy_source,
			secp_ctx,
		)
	}
}

/// A trait defining behavior for routing a payment.
pub trait Router: MessageRouter {
	/// Finds a [`Route`] for a payment between the given `payer` and a payee.
	///
	/// The `payee` and the payment's value are given in [`RouteParameters::payment_params`]
	/// and [`RouteParameters::final_value_msat`], respectively.
	fn find_route(
		&self, payer: &PublicKey, route_params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs,
	) -> Result<Route, LightningError>;

	/// Finds a [`Route`] for a payment between the given `payer` and a payee.
	///
	/// The `payee` and the payment's value are given in [`RouteParameters::payment_params`]
	/// and [`RouteParameters::final_value_msat`], respectively.
	///
	/// Includes a [`PaymentHash`] and a [`PaymentId`] to be able to correlate the request with a specific
	/// payment.
	fn find_route_with_id(
		&self, payer: &PublicKey, route_params: &RouteParameters,
		first_hops: Option<&[&ChannelDetails]>, inflight_htlcs: InFlightHtlcs,
		_payment_hash: PaymentHash, _payment_id: PaymentId,
	) -> Result<Route, LightningError> {
		self.find_route(payer, route_params, first_hops, inflight_htlcs)
	}

	/// Creates [`BlindedPaymentPath`]s for payment to the `recipient` node. The channels in `first_hops`
	/// are assumed to be with the `recipient`'s peers. The payment secret and any constraints are
	/// given in `tlvs`.
	fn create_blinded_payment_paths<T: secp256k1::Signing + secp256k1::Verification>(
		&self, recipient: PublicKey, first_hops: Vec<ChannelDetails>, tlvs: ReceiveTlvs,
		amount_msats: u64, secp_ctx: &Secp256k1<T>,
	) -> Result<Vec<BlindedPaymentPath>, ()>;
}

/// [`ScoreLookUp`] implementation that factors in in-flight HTLC liquidity.
///
/// Useful for custom [`Router`] implementations to wrap their [`ScoreLookUp`] on-the-fly when calling
/// [`find_route`].
///
/// [`ScoreLookUp`]: crate::routing::scoring::ScoreLookUp
pub struct ScorerAccountingForInFlightHtlcs<'a, S: Deref>
where
	S::Target: ScoreLookUp,
{
	scorer: S,
	// Maps a channel's short channel id and its direction to the liquidity used up.
	inflight_htlcs: &'a InFlightHtlcs,
}
impl<'a, S: Deref> ScorerAccountingForInFlightHtlcs<'a, S>
where
	S::Target: ScoreLookUp,
{
	/// Initialize a new `ScorerAccountingForInFlightHtlcs`.
	pub fn new(scorer: S, inflight_htlcs: &'a InFlightHtlcs) -> Self {
		ScorerAccountingForInFlightHtlcs { scorer, inflight_htlcs }
	}
}

impl<'a, S: Deref> ScoreLookUp for ScorerAccountingForInFlightHtlcs<'a, S>
where
	S::Target: ScoreLookUp,
{
	type ScoreParams = <S::Target as ScoreLookUp>::ScoreParams;
	fn channel_penalty_msat(
		&self, candidate: &CandidateRouteHop, usage: ChannelUsage, score_params: &Self::ScoreParams,
	) -> u64 {
		let target = match candidate.target() {
			Some(target) => target,
			None => return self.scorer.channel_penalty_msat(candidate, usage, score_params),
		};
		let short_channel_id = match candidate.short_channel_id() {
			Some(short_channel_id) => short_channel_id,
			None => return self.scorer.channel_penalty_msat(candidate, usage, score_params),
		};
		let source = candidate.source();
		if let Some(used_liquidity) =
			self.inflight_htlcs.used_liquidity_msat(&source, &target, short_channel_id)
		{
			let usage = ChannelUsage {
				inflight_htlc_msat: usage.inflight_htlc_msat.saturating_add(used_liquidity),
				..usage
			};

			self.scorer.channel_penalty_msat(candidate, usage, score_params)
		} else {
			self.scorer.channel_penalty_msat(candidate, usage, score_params)
		}
	}
}

/// A data structure for tracking in-flight HTLCs. May be used during pathfinding to account for
/// in-use channel liquidity.
#[derive(Clone)]
pub struct InFlightHtlcs(
	// A map with liquidity value (in msat) keyed by a short channel id and the direction the HTLC
	// is traveling in. The direction boolean is determined by checking if the HTLC source's public
	// key is less than its destination. See `InFlightHtlcs::used_liquidity_msat` for more
	// details.
	HashMap<(u64, bool), u64>,
);

impl InFlightHtlcs {
	/// Constructs an empty `InFlightHtlcs`.
	pub fn new() -> Self {
		InFlightHtlcs(new_hash_map())
	}

	/// Takes in a path with payer's node id and adds the path's details to `InFlightHtlcs`.
	pub fn process_path(&mut self, path: &Path, payer_node_id: PublicKey) {
		if path.hops.is_empty() {
			return;
		};

		let mut cumulative_msat = 0;
		if let Some(tail) = &path.blinded_tail {
			cumulative_msat += tail.final_value_msat;
		}

		// total_inflight_map needs to be direction-sensitive when keeping track of the HTLC value
		// that is held up. However, the `hops` array, which is a path returned by `find_route` in
		// the router excludes the payer node. In the following lines, the payer's information is
		// hardcoded with an inflight value of 0 so that we can correctly represent the first hop
		// in our sliding window of two.
		let reversed_hops_with_payer = path
			.hops
			.iter()
			.rev()
			.skip(1)
			.map(|hop| hop.pubkey)
			.chain(core::iter::once(payer_node_id));

		// Taking the reversed vector from above, we zip it with just the reversed hops list to
		// work "backwards" of the given path, since the last hop's `fee_msat` actually represents
		// the total amount sent.
		for (next_hop, prev_hop) in path.hops.iter().rev().zip(reversed_hops_with_payer) {
			cumulative_msat += next_hop.fee_msat;
			self.0
				.entry((
					next_hop.short_channel_id,
					NodeId::from_pubkey(&prev_hop) < NodeId::from_pubkey(&next_hop.pubkey),
				))
				.and_modify(|used_liquidity_msat| *used_liquidity_msat += cumulative_msat)
				.or_insert(cumulative_msat);
		}
	}

	/// Adds a known HTLC given the public key of the HTLC source, target, and short channel
	/// id.
	pub fn add_inflight_htlc(
		&mut self, source: &NodeId, target: &NodeId, channel_scid: u64, used_msat: u64,
	) {
		self.0
			.entry((channel_scid, source < target))
			.and_modify(|used_liquidity_msat| *used_liquidity_msat += used_msat)
			.or_insert(used_msat);
	}

	/// Returns liquidity in msat given the public key of the HTLC source, target, and short channel
	/// id.
	pub fn used_liquidity_msat(
		&self, source: &NodeId, target: &NodeId, channel_scid: u64,
	) -> Option<u64> {
		self.0.get(&(channel_scid, source < target)).map(|v| *v)
	}
}

impl Writeable for InFlightHtlcs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.0.write(writer)
	}
}

impl Readable for InFlightHtlcs {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let infight_map: HashMap<(u64, bool), u64> = Readable::read(reader)?;
		Ok(Self(infight_map))
	}
}

/// A hop in a route, and additional metadata about it. "Hop" is defined as a node and the channel
/// that leads to it.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RouteHop {
	/// The node_id of the node at this hop.
	pub pubkey: PublicKey,
	/// The node_announcement features of the node at this hop. For the last hop, these may be
	/// amended to match the features present in the invoice this node generated.
	pub node_features: NodeFeatures,
	/// The channel that should be used from the previous hop to reach this node.
	pub short_channel_id: u64,
	/// The channel_announcement features of the channel that should be used from the previous hop
	/// to reach this node.
	pub channel_features: ChannelFeatures,
	/// The fee taken on this hop (for paying for the use of the *next* channel in the path).
	/// If this is the last hop in [`Path::hops`]:
	/// * if we're sending to a [`BlindedPaymentPath`], this is the fee paid for use of the entire
	///   blinded path
	/// * otherwise, this is the full value of this [`Path`]'s part of the payment
	pub fee_msat: u64,
	/// The CLTV delta added for this hop.
	/// If this is the last hop in [`Path::hops`]:
	/// * if we're sending to a [`BlindedPaymentPath`], this is the CLTV delta for the entire blinded
	///   path
	/// * otherwise, this is the CLTV delta expected at the destination
	pub cltv_expiry_delta: u32,
	/// Indicates whether this hop is possibly announced in the public network graph.
	///
	/// Will be `true` if there is a possibility that the channel is publicly known, i.e., if we
	/// either know for sure it's announced in the public graph, or if any public channels exist
	/// for which the given `short_channel_id` could be an alias for. Will be `false` if we believe
	/// the channel to be unannounced.
	///
	/// Will be `true` for objects serialized with LDK version 0.0.116 and before.
	pub maybe_announced_channel: bool,
	/// How much to pay the node.
	pub payment_amount: u64,
	/// RGB amount to send to the following node
	pub rgb_amount: Option<u64>,
}

impl_writeable_tlv_based!(RouteHop, {
	(0, pubkey, required),
	(1, maybe_announced_channel, (default_value, true)),
	(2, node_features, required),
	(4, short_channel_id, required),
	(6, channel_features, required),
	(8, fee_msat, required),
	(10, cltv_expiry_delta, required),(12, rgb_amount, option),
  (14, payment_amount, required),

});

/// The blinded portion of a [`Path`], if we're routing to a recipient who provided blinded paths in
/// their [`Bolt12Invoice`].
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct BlindedTail {
	/// The hops of the [`BlindedPaymentPath`] provided by the recipient.
	pub hops: Vec<BlindedHop>,
	/// The blinding point of the [`BlindedPaymentPath`] provided by the recipient.
	pub blinding_point: PublicKey,
	/// Excess CLTV delta added to the recipient's CLTV expiry to deter intermediate nodes from
	/// inferring the destination. May be 0.
	pub excess_final_cltv_expiry_delta: u32,
	/// The total amount paid on this [`Path`], excluding the fees.
	pub final_value_msat: u64,
}

impl_writeable_tlv_based!(BlindedTail, {
	(0, hops, required_vec),
	(2, blinding_point, required),
	(4, excess_final_cltv_expiry_delta, required),
	(6, final_value_msat, required),
});

/// A path in a [`Route`] to the payment recipient. Must always be at least length one.
/// If no [`Path::blinded_tail`] is present, then [`Path::hops`] length may be up to 19.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Path {
	/// The list of unblinded hops in this [`Path`]. Must be at least length one.
	pub hops: Vec<RouteHop>,
	/// The blinded path at which this path terminates, if we're sending to one, and its metadata.
	pub blinded_tail: Option<BlindedTail>,
}

impl Path {
	/// Gets the fees for a given path, excluding any excess paid to the recipient.
	pub fn fee_msat(&self) -> u64 {
		match &self.blinded_tail {
			Some(_) => self.hops.iter().map(|hop| hop.fee_msat).sum::<u64>(),
			None => {
				// Do not count last hop of each path since that's the full value of the payment
				self.hops
					.split_last()
					.map_or(0, |(_, path_prefix)| path_prefix.iter().map(|hop| hop.fee_msat).sum())
			},
		}
	}

	/// Gets the total amount paid on this [`Path`], excluding the fees.
	pub fn final_value_msat(&self) -> u64 {
		match &self.blinded_tail {
			Some(blinded_tail) => blinded_tail.final_value_msat,
			None => self.hops.last().map_or(0, |hop| hop.fee_msat),
		}
	}

	/// Gets the final hop's CLTV expiry delta.
	pub fn final_cltv_expiry_delta(&self) -> Option<u32> {
		match &self.blinded_tail {
			Some(_) => None,
			None => self.hops.last().map(|hop| hop.cltv_expiry_delta),
		}
	}
}

/// A route directs a payment from the sender (us) to the recipient. If the recipient supports MPP,
/// it can take multiple paths. Each path is composed of one or more hops through the network.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Route {
	/// The list of [`Path`]s taken for a single (potentially-)multi-part payment. If no
	/// [`BlindedTail`]s are present, then the pubkey of the last [`RouteHop`] in each path must be
	/// the same.
	pub paths: Vec<Path>,
	/// The `route_params` parameter passed to [`find_route`].
	///
	/// This is used by `ChannelManager` to track information which may be required for retries.
	///
	/// Will be `None` for objects serialized with LDK versions prior to 0.0.117.
	pub route_params: Option<RouteParameters>,
}

impl Route {
	/// Returns the total amount of fees paid on this [`Route`].
	///
	/// For objects serialized with LDK 0.0.117 and after, this includes any extra payment made to
	/// the recipient, which can happen in excess of the amount passed to [`find_route`] via
	/// [`RouteParameters::final_value_msat`], if we had to reach the [`htlc_minimum_msat`] limits.
	///
	/// [`htlc_minimum_msat`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_update-message
	pub fn get_total_fees(&self) -> u64 {
		let overpaid_value_msat = self
			.route_params
			.as_ref()
			.map_or(0, |p| self.get_total_amount().saturating_sub(p.final_value_msat));
		overpaid_value_msat + self.paths.iter().map(|path| path.fee_msat()).sum::<u64>()
	}

	/// Returns the total amount paid on this [`Route`], excluding the fees.
	///
	/// Might be more than requested as part of the given [`RouteParameters::final_value_msat`] if
	/// we had to reach the [`htlc_minimum_msat`] limits.
	///
	/// [`htlc_minimum_msat`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_update-message
	pub fn get_total_amount(&self) -> u64 {
		self.paths.iter().map(|path| path.final_value_msat()).sum()
	}
}

impl fmt::Display for Route {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		log_route!(self).fmt(f)
	}
}

const SERIALIZATION_VERSION: u8 = 1;
const MIN_SERIALIZATION_VERSION: u8 = 1;

impl Writeable for Route {
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_ver_prefix!(writer, SERIALIZATION_VERSION, MIN_SERIALIZATION_VERSION);
		(self.paths.len() as u64).write(writer)?;
		let mut blinded_tails = Vec::new();
		for (idx, path) in self.paths.iter().enumerate() {
			(path.hops.len() as u8).write(writer)?;
			for hop in path.hops.iter() {
				hop.write(writer)?;
			}
			if let Some(blinded_tail) = &path.blinded_tail {
				if blinded_tails.is_empty() {
					blinded_tails = Vec::with_capacity(path.hops.len());
					for _ in 0..idx {
						blinded_tails.push(None);
					}
				}
				blinded_tails.push(Some(blinded_tail));
			} else if !blinded_tails.is_empty() {
				blinded_tails.push(None);
			}
		}
		write_tlv_fields!(writer, {
			// For compatibility with LDK versions prior to 0.0.117, we take the individual
			// RouteParameters' fields and reconstruct them on read.
			(1, self.route_params.as_ref().map(|p| &p.payment_params), option),
			(2, blinded_tails, optional_vec),
			(3, self.route_params.as_ref().map(|p| p.final_value_msat), option),
			(5, self.route_params.as_ref().and_then(|p| p.max_total_routing_fee_msat), option),
		});
		Ok(())
	}
}

impl Readable for Route {
	fn read<R: io::Read>(reader: &mut R) -> Result<Route, DecodeError> {
		let _ver = read_ver_prefix!(reader, SERIALIZATION_VERSION);
		let path_count: u64 = Readable::read(reader)?;
		if path_count == 0 {
			return Err(DecodeError::InvalidValue);
		}
		let mut paths = Vec::with_capacity(cmp::min(path_count, 128) as usize);
		let mut min_final_cltv_expiry_delta = u32::max_value();
		for _ in 0..path_count {
			let hop_count: u8 = Readable::read(reader)?;
			let mut hops: Vec<RouteHop> = Vec::with_capacity(hop_count as usize);
			for _ in 0..hop_count {
				hops.push(Readable::read(reader)?);
			}
			if hops.is_empty() {
				return Err(DecodeError::InvalidValue);
			}
			min_final_cltv_expiry_delta =
				cmp::min(min_final_cltv_expiry_delta, hops.last().unwrap().cltv_expiry_delta);
			paths.push(Path { hops, blinded_tail: None });
		}
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(1, payment_params, (option: ReadableArgs, min_final_cltv_expiry_delta)),
			(2, blinded_tails, optional_vec),
			(3, final_value_msat, option),
			(5, max_total_routing_fee_msat, option)
			(7, rgb_payment, option)
		});
		let blinded_tails = blinded_tails.unwrap_or(Vec::new());
		if blinded_tails.len() != 0 {
			if blinded_tails.len() != paths.len() {
				return Err(DecodeError::InvalidValue);
			}
			for (path, blinded_tail_opt) in paths.iter_mut().zip(blinded_tails.into_iter()) {
				path.blinded_tail = blinded_tail_opt;
			}
		}

		// If we previously wrote the corresponding fields, reconstruct RouteParameters.
		let route_params = match (payment_params, final_value_msat) {
			(Some(payment_params), Some(final_value_msat)) => Some(RouteParameters {
				payment_params,
				final_value_msat,
				max_total_routing_fee_msat,
				rgb_payment,
			}),
			_ => None,
		};

		Ok(Route { paths, route_params })
	}
}

/// Parameters needed to find a [`Route`].
///
/// Passed to [`find_route`] and [`build_route_from_hops`].
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct RouteParameters {
	/// The parameters of the failed payment path.
	pub payment_params: PaymentParameters,

	/// The amount in msats sent on the failed payment path.
	pub final_value_msat: u64,

	/// The maximum total fees, in millisatoshi, that may accrue during route finding.
	///
	/// This limit also applies to the total fees that may arise while retrying failed payment
	/// paths.
	///
	/// Note that values below a few sats may result in some paths being spuriously ignored.
	pub max_total_routing_fee_msat: Option<u64>,

	/// The contract ID and RGB amount info
	pub rgb_payment: Option<(ContractId, u64)>,
}

impl RouteParameters {
	/// Constructs [`RouteParameters`] from the given [`PaymentParameters`] and a payment amount.
	///
	/// [`Self::max_total_routing_fee_msat`] defaults to 1% of the payment amount + 50 sats
	pub fn from_payment_params_and_value(
		payment_params: PaymentParameters, final_value_msat: u64,
		rgb_payment: Option<(ContractId, u64)>,
	) -> Self {
		Self {
			payment_params,
			final_value_msat,
			max_total_routing_fee_msat: Some(final_value_msat / 100 + 50_000),
			rgb_payment,
		}
	}

	/// Sets the maximum number of hops that can be included in a payment path, based on the provided
	/// [`RecipientOnionFields`] and blinded paths.
	pub fn set_max_path_length(
		&mut self, recipient_onion: &RecipientOnionFields, is_keysend: bool, best_block_height: u32,
	) -> Result<(), ()> {
		let keysend_preimage_opt = is_keysend.then(|| PaymentPreimage([42; 32]));
		onion_utils::set_max_path_length(
			self,
			recipient_onion,
			keysend_preimage_opt,
			best_block_height,
		)
	}
}

impl Writeable for RouteParameters {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		write_tlv_fields!(writer, {
			(0, self.payment_params, required),
			(1, self.max_total_routing_fee_msat, option),
			(2, self.final_value_msat, required),
			// LDK versions prior to 0.0.114 had the `final_cltv_expiry_delta` parameter in
			// `RouteParameters` directly. For compatibility, we write it here.
			(4, self.payment_params.payee.final_cltv_expiry_delta(), option),
			(5, self.rgb_payment, option),
		});
		Ok(())
	}
}

impl Readable for RouteParameters {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, payment_params, (required: ReadableArgs, 0)),
			(1, max_total_routing_fee_msat, option),
			(2, final_value_msat, required),
			(4, final_cltv_delta, option),
						(5, rgb_payment, option),
		});
		let mut payment_params: PaymentParameters = payment_params.0.unwrap();
		if let Payee::Clear { ref mut final_cltv_expiry_delta, .. } = payment_params.payee {
			if final_cltv_expiry_delta == &0 {
				*final_cltv_expiry_delta = final_cltv_delta.ok_or(DecodeError::InvalidValue)?;
			}
		}
		Ok(Self {
			payment_params,
			final_value_msat: final_value_msat.0.unwrap(),
			max_total_routing_fee_msat,
			rgb_payment,
		})
	}
}

/// Maximum total CTLV difference we allow for a full payment path.
pub const DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA: u32 = 1008;

/// Maximum number of paths we allow an (MPP) payment to have.
// The default limit is currently set rather arbitrary - there aren't any real fundamental path-count
// limits, but for now more than 10 paths likely carries too much one-path failure.
pub const DEFAULT_MAX_PATH_COUNT: u8 = 10;

const DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF: u8 = 2;

// The median hop CLTV expiry delta currently seen in the network.
const MEDIAN_HOP_CLTV_EXPIRY_DELTA: u32 = 40;

/// Estimated maximum number of hops that can be included in a payment path. May be inaccurate if
/// payment metadata, custom TLVs, or blinded paths are included in the payment.
// During routing, we only consider paths shorter than our maximum length estimate.
// In the TLV onion format, there is no fixed maximum length, but the `hop_payloads`
// field is always 1300 bytes. As the `tlv_payload` for each hop may vary in length, we have to
// estimate how many hops the route may have so that it actually fits the `hop_payloads` field.
//
// We estimate 3+32 (payload length and HMAC) + 2+8 (amt_to_forward) + 2+4 (outgoing_cltv_value) +
// 2+8 (short_channel_id) = 61 bytes for each intermediate hop and 3+32
// (payload length and HMAC) + 2+8 (amt_to_forward) + 2+4 (outgoing_cltv_value) + 2+32+8
// (payment_secret and total_msat) = 93 bytes for the final hop.
// Since the length of the potentially included `payment_metadata` is unknown to us, we round
// down from (1300-93) / 61 = 19.78... to arrive at a conservative estimate of 19.
pub const MAX_PATH_LENGTH_ESTIMATE: u8 = 19;

/// Information used to route a payment.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PaymentParameters {
	/// Information about the payee, such as their features and route hints for their channels.
	pub payee: Payee,

	/// Expiration of a payment to the payee, in seconds relative to the UNIX epoch.
	pub expiry_time: Option<u64>,

	/// The maximum total CLTV delta we accept for the route.
	/// Defaults to [`DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA`].
	pub max_total_cltv_expiry_delta: u32,

	/// The maximum number of paths that may be used by (MPP) payments.
	/// Defaults to [`DEFAULT_MAX_PATH_COUNT`].
	pub max_path_count: u8,

	/// The maximum number of [`Path::hops`] in any returned path.
	/// Defaults to [`MAX_PATH_LENGTH_ESTIMATE`].
	pub max_path_length: u8,

	/// Selects the maximum share of a channel's total capacity which will be sent over a channel,
	/// as a power of 1/2. A higher value prefers to send the payment using more MPP parts whereas
	/// a lower value prefers to send larger MPP parts, potentially saturating channels and
	/// increasing failure probability for those paths.
	///
	/// Note that this restriction will be relaxed during pathfinding after paths which meet this
	/// restriction have been found. While paths which meet this criteria will be searched for, it
	/// is ultimately up to the scorer to select them over other paths.
	///
	/// A value of 0 will allow payments up to and including a channel's total announced usable
	/// capacity, a value of one will only use up to half its capacity, two 1/4, etc.
	///
	/// Default value: 2
	pub max_channel_saturation_power_of_half: u8,

	/// A list of SCIDs which this payment was previously attempted over and which caused the
	/// payment to fail. Future attempts for the same payment shouldn't be relayed through any of
	/// these SCIDs.
	pub previously_failed_channels: Vec<u64>,

	/// A list of indices corresponding to blinded paths in [`Payee::Blinded::route_hints`] which this
	/// payment was previously attempted over and which caused the payment to fail. Future attempts
	/// for the same payment shouldn't be relayed through any of these blinded paths.
	pub previously_failed_blinded_path_idxs: Vec<u64>,
}

impl Writeable for PaymentParameters {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let mut clear_hints = &vec![];
		let mut blinded_hints = None;
		match &self.payee {
			Payee::Clear { route_hints, .. } => clear_hints = route_hints,
			Payee::Blinded { route_hints, .. } => {
				let hints_iter =
					route_hints.iter().map(|path| (&path.payinfo, path.inner_blinded_path()));
				blinded_hints = Some(crate::util::ser::IterableOwned(hints_iter));
			},
		}
		write_tlv_fields!(writer, {
			(0, self.payee.node_id(), option),
			(1, self.max_total_cltv_expiry_delta, required),
			(2, self.payee.features(), option),
			(3, self.max_path_count, required),
			(4, *clear_hints, required_vec),
			(5, self.max_channel_saturation_power_of_half, required),
			(6, self.expiry_time, option),
			(7, self.previously_failed_channels, required_vec),
			(8, blinded_hints, option),
			(9, self.payee.final_cltv_expiry_delta(), option),
			(11, self.previously_failed_blinded_path_idxs, required_vec),
			(13, self.max_path_length, required),
		});
		Ok(())
	}
}

impl ReadableArgs<u32> for PaymentParameters {
	fn read<R: io::Read>(
		reader: &mut R, default_final_cltv_expiry_delta: u32,
	) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, payee_pubkey, option),
			(1, max_total_cltv_expiry_delta, (default_value, DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA)),
			(2, features, (option: ReadableArgs, payee_pubkey.is_some())),
			(3, max_path_count, (default_value, DEFAULT_MAX_PATH_COUNT)),
			(4, clear_route_hints, required_vec),
			(5, max_channel_saturation_power_of_half, (default_value, DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF)),
			(6, expiry_time, option),
			(7, previously_failed_channels, optional_vec),
			(8, blinded_route_hints, optional_vec),
			(9, final_cltv_expiry_delta, (default_value, default_final_cltv_expiry_delta)),
			(11, previously_failed_blinded_path_idxs, optional_vec),
			(13, max_path_length, (default_value, MAX_PATH_LENGTH_ESTIMATE)),
		});
		let blinded_route_hints = blinded_route_hints.unwrap_or(vec![]);
		let payee = if blinded_route_hints.len() != 0 {
			if clear_route_hints.len() != 0 || payee_pubkey.is_some() {
				return Err(DecodeError::InvalidValue);
			}
			Payee::Blinded {
				route_hints: blinded_route_hints
					.into_iter()
					.map(|(payinfo, path)| BlindedPaymentPath::from_parts(path, payinfo))
					.collect(),
				features: features.and_then(|f: Features| f.bolt12()),
			}
		} else {
			Payee::Clear {
				route_hints: clear_route_hints,
				node_id: payee_pubkey.ok_or(DecodeError::InvalidValue)?,
				features: features.and_then(|f| f.bolt11()),
				final_cltv_expiry_delta: final_cltv_expiry_delta.0.unwrap(),
			}
		};
		Ok(Self {
			max_total_cltv_expiry_delta: _init_tlv_based_struct_field!(
				max_total_cltv_expiry_delta,
				(default_value, unused)
			),
			max_path_count: _init_tlv_based_struct_field!(max_path_count, (default_value, unused)),
			payee,
			max_channel_saturation_power_of_half: _init_tlv_based_struct_field!(
				max_channel_saturation_power_of_half,
				(default_value, unused)
			),
			expiry_time,
			previously_failed_channels: previously_failed_channels.unwrap_or(Vec::new()),
			previously_failed_blinded_path_idxs: previously_failed_blinded_path_idxs
				.unwrap_or(Vec::new()),
			max_path_length: _init_tlv_based_struct_field!(
				max_path_length,
				(default_value, unused)
			),
		})
	}
}

impl PaymentParameters {
	/// Creates a payee with the node id of the given `pubkey`.
	///
	/// The `final_cltv_expiry_delta` should match the expected final CLTV delta the recipient has
	/// provided.
	pub fn from_node_id(payee_pubkey: PublicKey, final_cltv_expiry_delta: u32) -> Self {
		Self {
			payee: Payee::Clear {
				node_id: payee_pubkey,
				route_hints: vec![],
				features: None,
				final_cltv_expiry_delta,
			},
			expiry_time: None,
			max_total_cltv_expiry_delta: DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
			max_path_count: DEFAULT_MAX_PATH_COUNT,
			max_path_length: MAX_PATH_LENGTH_ESTIMATE,
			max_channel_saturation_power_of_half: DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF,
			previously_failed_channels: Vec::new(),
			previously_failed_blinded_path_idxs: Vec::new(),
		}
	}

	/// Creates a payee with the node id of the given `pubkey` to use for keysend payments.
	///
	/// The `final_cltv_expiry_delta` should match the expected final CLTV delta the recipient has
	/// provided.
	///
	/// Note that MPP keysend is not widely supported yet. The `allow_mpp` lets you choose
	/// whether your router will be allowed to find a multi-part route for this payment. If you
	/// set `allow_mpp` to true, you should ensure a payment secret is set on send, likely via
	/// [`RecipientOnionFields::secret_only`].
	///
	/// [`RecipientOnionFields::secret_only`]: crate::ln::channelmanager::RecipientOnionFields::secret_only
	pub fn for_keysend(
		payee_pubkey: PublicKey, final_cltv_expiry_delta: u32, allow_mpp: bool,
	) -> Self {
		Self::from_node_id(payee_pubkey, final_cltv_expiry_delta)
			.with_bolt11_features(Bolt11InvoiceFeatures::for_keysend(allow_mpp))
			.expect(
				"PaymentParameters::from_node_id should always initialize the payee as unblinded",
			)
	}

	/// Creates parameters for paying to a blinded payee from the provided invoice. Sets
	/// [`Payee::Blinded::route_hints`], [`Payee::Blinded::features`], and
	/// [`PaymentParameters::expiry_time`].
	pub fn from_bolt12_invoice(invoice: &Bolt12Invoice) -> Self {
		Self::blinded(invoice.payment_paths().to_vec())
			.with_bolt12_features(invoice.invoice_features().clone())
			.unwrap()
			.with_expiry_time(
				invoice.created_at().as_secs().saturating_add(invoice.relative_expiry().as_secs()),
			)
	}

	/// Creates parameters for paying to a blinded payee from the provided blinded route hints.
	pub fn blinded(blinded_route_hints: Vec<BlindedPaymentPath>) -> Self {
		Self {
			payee: Payee::Blinded { route_hints: blinded_route_hints, features: None },
			expiry_time: None,
			max_total_cltv_expiry_delta: DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA,
			max_path_count: DEFAULT_MAX_PATH_COUNT,
			max_path_length: MAX_PATH_LENGTH_ESTIMATE,
			max_channel_saturation_power_of_half: DEFAULT_MAX_CHANNEL_SATURATION_POW_HALF,
			previously_failed_channels: Vec::new(),
			previously_failed_blinded_path_idxs: Vec::new(),
		}
	}

	/// Includes the payee's features. Errors if the parameters were not initialized with
	/// [`PaymentParameters::from_bolt12_invoice`].
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_bolt12_features(self, features: Bolt12InvoiceFeatures) -> Result<Self, ()> {
		match self.payee {
			Payee::Clear { .. } => Err(()),
			Payee::Blinded { route_hints, .. } => {
				Ok(Self { payee: Payee::Blinded { route_hints, features: Some(features) }, ..self })
			},
		}
	}

	/// Includes the payee's features. Errors if the parameters were initialized with
	/// [`PaymentParameters::from_bolt12_invoice`].
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_bolt11_features(self, features: Bolt11InvoiceFeatures) -> Result<Self, ()> {
		match self.payee {
			Payee::Blinded { .. } => Err(()),
			Payee::Clear { route_hints, node_id, final_cltv_expiry_delta, .. } => Ok(Self {
				payee: Payee::Clear {
					route_hints,
					node_id,
					features: Some(features),
					final_cltv_expiry_delta,
				},
				..self
			}),
		}
	}

	/// Includes hints for routing to the payee. Errors if the parameters were initialized with
	/// [`PaymentParameters::from_bolt12_invoice`].
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_route_hints(self, route_hints: Vec<RouteHint>) -> Result<Self, ()> {
		match self.payee {
			Payee::Blinded { .. } => Err(()),
			Payee::Clear { node_id, features, final_cltv_expiry_delta, .. } => Ok(Self {
				payee: Payee::Clear { route_hints, node_id, features, final_cltv_expiry_delta },
				..self
			}),
		}
	}

	/// Includes a payment expiration in seconds relative to the UNIX epoch.
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_expiry_time(self, expiry_time: u64) -> Self {
		Self { expiry_time: Some(expiry_time), ..self }
	}

	/// Includes a limit for the total CLTV expiry delta which is considered during routing
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_max_total_cltv_expiry_delta(self, max_total_cltv_expiry_delta: u32) -> Self {
		Self { max_total_cltv_expiry_delta, ..self }
	}

	/// Includes a limit for the maximum number of payment paths that may be used.
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_max_path_count(self, max_path_count: u8) -> Self {
		Self { max_path_count, ..self }
	}

	/// Includes a limit for the maximum share of a channel's total capacity that can be sent over, as
	/// a power of 1/2. See [`PaymentParameters::max_channel_saturation_power_of_half`].
	///
	/// This is not exported to bindings users since bindings don't support move semantics
	pub fn with_max_channel_saturation_power_of_half(
		self, max_channel_saturation_power_of_half: u8,
	) -> Self {
		Self { max_channel_saturation_power_of_half, ..self }
	}

	pub(crate) fn insert_previously_failed_blinded_path(
		&mut self, failed_blinded_tail: &BlindedTail,
	) {
		let mut found_blinded_tail = false;
		for (idx, path) in self.payee.blinded_route_hints().iter().enumerate() {
			if &failed_blinded_tail.hops == path.blinded_hops()
				&& failed_blinded_tail.blinding_point == path.blinding_point()
			{
				self.previously_failed_blinded_path_idxs.push(idx as u64);
				found_blinded_tail = true;
			}
		}
		debug_assert!(found_blinded_tail);
	}
}

/// The recipient of a payment, differing based on whether they've hidden their identity with route
/// blinding.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Payee {
	/// The recipient provided blinded paths and payinfo to reach them. The blinded paths themselves
	/// will be included in the final [`Route`].
	Blinded {
		/// Aggregated routing info and blinded paths, for routing to the payee without knowing their
		/// node id.
		route_hints: Vec<BlindedPaymentPath>,
		/// Features supported by the payee.
		///
		/// May be set from the payee's invoice. May be `None` if the invoice does not contain any
		/// features.
		features: Option<Bolt12InvoiceFeatures>,
	},
	/// The recipient included these route hints in their BOLT11 invoice.
	Clear {
		/// The node id of the payee.
		node_id: PublicKey,
		/// Hints for routing to the payee, containing channels connecting the payee to public nodes.
		route_hints: Vec<RouteHint>,
		/// Features supported by the payee.
		///
		/// May be set from the payee's invoice or via [`for_keysend`]. May be `None` if the invoice
		/// does not contain any features.
		///
		/// [`for_keysend`]: PaymentParameters::for_keysend
		features: Option<Bolt11InvoiceFeatures>,
		/// The minimum CLTV delta at the end of the route. This value must not be zero.
		final_cltv_expiry_delta: u32,
	},
}

impl Payee {
	fn node_id(&self) -> Option<PublicKey> {
		match self {
			Self::Clear { node_id, .. } => Some(*node_id),
			_ => None,
		}
	}
	fn node_features(&self) -> Option<NodeFeatures> {
		match self {
			Self::Clear { features, .. } => features.as_ref().map(|f| f.to_context()),
			Self::Blinded { features, .. } => features.as_ref().map(|f| f.to_context()),
		}
	}
	fn supports_basic_mpp(&self) -> bool {
		match self {
			Self::Clear { features, .. } => {
				features.as_ref().map_or(false, |f| f.supports_basic_mpp())
			},
			Self::Blinded { features, .. } => {
				features.as_ref().map_or(false, |f| f.supports_basic_mpp())
			},
		}
	}
	fn features(&self) -> Option<FeaturesRef> {
		match self {
			Self::Clear { features, .. } => features.as_ref().map(|f| FeaturesRef::Bolt11(f)),
			Self::Blinded { features, .. } => features.as_ref().map(|f| FeaturesRef::Bolt12(f)),
		}
	}
	fn final_cltv_expiry_delta(&self) -> Option<u32> {
		match self {
			Self::Clear { final_cltv_expiry_delta, .. } => Some(*final_cltv_expiry_delta),
			_ => None,
		}
	}
	pub(crate) fn blinded_route_hints(&self) -> &[BlindedPaymentPath] {
		match self {
			Self::Blinded { route_hints, .. } => &route_hints[..],
			Self::Clear { .. } => &[],
		}
	}

	pub(crate) fn blinded_route_hints_mut(&mut self) -> &mut [BlindedPaymentPath] {
		match self {
			Self::Blinded { route_hints, .. } => &mut route_hints[..],
			Self::Clear { .. } => &mut [],
		}
	}

	fn unblinded_route_hints(&self) -> &[RouteHint] {
		match self {
			Self::Blinded { .. } => &[],
			Self::Clear { route_hints, .. } => &route_hints[..],
		}
	}
}

enum FeaturesRef<'a> {
	Bolt11(&'a Bolt11InvoiceFeatures),
	Bolt12(&'a Bolt12InvoiceFeatures),
}
enum Features {
	Bolt11(Bolt11InvoiceFeatures),
	Bolt12(Bolt12InvoiceFeatures),
}

impl Features {
	fn bolt12(self) -> Option<Bolt12InvoiceFeatures> {
		match self {
			Self::Bolt12(f) => Some(f),
			_ => None,
		}
	}
	fn bolt11(self) -> Option<Bolt11InvoiceFeatures> {
		match self {
			Self::Bolt11(f) => Some(f),
			_ => None,
		}
	}
}

impl<'a> Writeable for FeaturesRef<'a> {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Bolt11(f) => Ok(f.write(w)?),
			Self::Bolt12(f) => Ok(f.write(w)?),
		}
	}
}

impl ReadableArgs<bool> for Features {
	fn read<R: io::Read>(reader: &mut R, bolt11: bool) -> Result<Self, DecodeError> {
		if bolt11 {
			return Ok(Self::Bolt11(Readable::read(reader)?));
		}
		Ok(Self::Bolt12(Readable::read(reader)?))
	}
}

impl Writeable for RouteHint {
	fn write<W: crate::util::ser::Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		(self.0.len() as u64).write(writer)?;
		for hop in self.0.iter() {
			hop.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for RouteHint {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let hop_count: u64 = Readable::read(reader)?;
		let mut hops = Vec::with_capacity(cmp::min(hop_count, 16) as usize);
		for _ in 0..hop_count {
			hops.push(Readable::read(reader)?);
		}
		Ok(Self(hops))
	}
}

impl_writeable_tlv_based!(RouteHintHop, {
	(0, src_node_id, required),
	(1, htlc_minimum_msat, option),
	(2, short_channel_id, required),
	(3, htlc_maximum_msat, option),
	(4, fees, required),
	(6, cltv_expiry_delta, required),(7, htlc_maximum_rgb, option),

});

#[derive(Eq, PartialEq)]
#[repr(align(64))] // Force the size to 64 bytes
struct RouteGraphNode {
	node_id: NodeId,
	score: u64,
	// The maximum value a yet-to-be-constructed payment path might flow through this node.
	// This value is upper-bounded by us by:
	// - how much is needed for a path being constructed
	// - how much value can channels following this node (up to the destination) can contribute,
	//   considering their capacity and fees
	value_contribution_msat: u64,
	total_cltv_delta: u32,
	/// The number of hops walked up to this node.
	path_length_to_node: u8,
}

impl cmp::Ord for RouteGraphNode {
	fn cmp(&self, other: &RouteGraphNode) -> cmp::Ordering {
		other.score.cmp(&self.score).then_with(|| other.node_id.cmp(&self.node_id))
	}
}

impl cmp::PartialOrd for RouteGraphNode {
	fn partial_cmp(&self, other: &RouteGraphNode) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}

// While RouteGraphNode can be laid out with fewer bytes, performance appears to be improved
// substantially when it is laid out at exactly 64 bytes.
const _GRAPH_NODE_SMALL: usize = 64 - core::mem::size_of::<RouteGraphNode>();
const _GRAPH_NODE_FIXED_SIZE: usize = core::mem::size_of::<RouteGraphNode>() - 64;

/// A [`CandidateRouteHop::FirstHop`] entry.
#[derive(Clone, Debug)]
pub struct FirstHopCandidate<'a> {
	/// Channel details of the first hop
	///
	/// [`ChannelDetails::get_outbound_payment_scid`] MUST be `Some` (indicating the channel
	/// has been funded and is able to pay), and accessor methods may panic otherwise.
	///
	/// [`find_route`] validates this prior to constructing a [`CandidateRouteHop`].
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub details: &'a ChannelDetails,
	/// The node id of the payer, which is also the source side of this candidate route hop.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub payer_node_id: &'a NodeId,
	/// A unique ID which describes the payer.
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but may be equal to one if the
	/// payer is a public node.
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	pub(crate) payer_node_counter: u32,
	/// A unique ID which describes the first hop counterparty.
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but may be equal to one if the
	/// counterparty is a public node.
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	pub(crate) target_node_counter: u32,
}

/// A [`CandidateRouteHop::PublicHop`] entry.
#[derive(Clone, Debug)]
pub struct PublicHopCandidate<'a> {
	/// Information about the channel, including potentially its capacity and
	/// direction-specific information.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub info: DirectedChannelInfo<'a>,
	/// The short channel ID of the channel, i.e. the identifier by which we refer to this
	/// channel.
	pub short_channel_id: u64,
}

/// A [`CandidateRouteHop::PrivateHop`] entry.
#[derive(Clone, Debug)]
pub struct PrivateHopCandidate<'a> {
	/// Information about the private hop communicated via BOLT 11.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub hint: &'a RouteHintHop,
	/// Node id of the next hop in BOLT 11 route hint.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub target_node_id: &'a NodeId,
	/// A unique ID which describes the source node of the hop (further from the payment target).
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but may be equal to one if the
	/// node is a public node.
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	pub(crate) source_node_counter: u32,
	/// A unique ID which describes the destination node of the hop (towards the payment target).
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but may be equal to one if the
	/// node is a public node.
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	pub(crate) target_node_counter: u32,
}

/// A [`CandidateRouteHop::Blinded`] entry.
#[derive(Clone, Debug)]
pub struct BlindedPathCandidate<'a> {
	/// The node id of the introduction node, resolved from either the [`NetworkGraph`] or first
	/// hops.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub source_node_id: &'a NodeId,
	/// Information about the blinded path including the fee, HTLC amount limits, and
	/// cryptographic material required to build an HTLC through the given path.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub hint: &'a BlindedPaymentPath,
	/// Index of the hint in the original list of blinded hints.
	///
	/// This is used to cheaply uniquely identify this blinded path, even though we don't have
	/// a short channel ID for this hop.
	hint_idx: usize,
	/// A unique ID which describes the introduction point of the blinded path.
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but will generally be equal to
	/// one from the public network graph (assuming the introduction point is a public node).
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	source_node_counter: u32,
}

/// A [`CandidateRouteHop::OneHopBlinded`] entry.
#[derive(Clone, Debug)]
pub struct OneHopBlindedPathCandidate<'a> {
	/// The node id of the introduction node, resolved from either the [`NetworkGraph`] or first
	/// hops.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	pub source_node_id: &'a NodeId,
	/// Information about the blinded path including the fee, HTLC amount limits, and
	/// cryptographic material required to build an HTLC terminating with the given path.
	///
	/// Note that the [`BlindedPayInfo`] is ignored here.
	///
	/// This is not exported to bindings users as lifetimes are not expressible in most languages.
	///
	/// [`BlindedPayInfo`]: crate::blinded_path::payment::BlindedPayInfo
	pub hint: &'a BlindedPaymentPath,
	/// Index of the hint in the original list of blinded hints.
	///
	/// This is used to cheaply uniquely identify this blinded path, even though we don't have
	/// a short channel ID for this hop.
	hint_idx: usize,
	/// A unique ID which describes the introduction point of the blinded path.
	///
	/// It will not conflict with any [`NodeInfo::node_counter`]s, but will generally be equal to
	/// one from the public network graph (assuming the introduction point is a public node).
	///
	/// [`NodeInfo::node_counter`]: super::gossip::NodeInfo::node_counter
	source_node_counter: u32,
}

/// A wrapper around the various hop representations.
///
/// Can be used to examine the properties of a hop,
/// potentially to decide whether to include it in a route.
#[derive(Clone, Debug)]
pub enum CandidateRouteHop<'a> {
	/// A hop from the payer, where the outbound liquidity is known.
	FirstHop(FirstHopCandidate<'a>),
	/// A hop found in the [`ReadOnlyNetworkGraph`].
	PublicHop(PublicHopCandidate<'a>),
	/// A private hop communicated by the payee, generally via a BOLT 11 invoice.
	///
	/// Because BOLT 11 route hints can take multiple hops to get to the destination, this may not
	/// terminate at the payee.
	PrivateHop(PrivateHopCandidate<'a>),
	/// A blinded path which starts with an introduction point and ultimately terminates with the
	/// payee.
	///
	/// Because we don't know the payee's identity, [`CandidateRouteHop::target`] will return
	/// `None` in this state.
	///
	/// Because blinded paths are "all or nothing", and we cannot use just one part of a blinded
	/// path, the full path is treated as a single [`CandidateRouteHop`].
	Blinded(BlindedPathCandidate<'a>),
	/// Similar to [`Self::Blinded`], but the path here only has one hop.
	///
	/// While we treat this similarly to [`CandidateRouteHop::Blinded`] in many respects (e.g.
	/// returning `None` from [`CandidateRouteHop::target`]), in this case we do actually know the
	/// payee's identity - it's the introduction point!
	///
	/// [`BlindedPayInfo`] provided for 1-hop blinded paths is ignored because it is meant to apply
	/// to the hops *between* the introduction node and the destination.
	///
	/// This primarily exists to track that we need to included a blinded path at the end of our
	/// [`Route`], even though it doesn't actually add an additional hop in the payment.
	///
	/// [`BlindedPayInfo`]: crate::blinded_path::payment::BlindedPayInfo
	OneHopBlinded(OneHopBlindedPathCandidate<'a>),
}

impl<'a> CandidateRouteHop<'a> {
	/// Returns the short channel ID for this hop, if one is known.
	///
	/// This SCID could be an alias or a globally unique SCID, and thus is only expected to
	/// uniquely identify this channel in conjunction with the [`CandidateRouteHop::source`].
	///
	/// Returns `Some` as long as the candidate is a [`CandidateRouteHop::PublicHop`], a
	/// [`CandidateRouteHop::PrivateHop`] from a BOLT 11 route hint, or a
	/// [`CandidateRouteHop::FirstHop`] with a known [`ChannelDetails::get_outbound_payment_scid`]
	/// (which is always true for channels which are funded and ready for use).
	///
	/// In other words, this should always return `Some` as long as the candidate hop is not a
	/// [`CandidateRouteHop::Blinded`] or a [`CandidateRouteHop::OneHopBlinded`].
	///
	/// Note that this is deliberately not public as it is somewhat of a footgun because it doesn't
	/// define a global namespace.
	#[inline]
	fn short_channel_id(&self) -> Option<u64> {
		match self {
			CandidateRouteHop::FirstHop(hop) => hop.details.get_outbound_payment_scid(),
			CandidateRouteHop::PublicHop(hop) => Some(hop.short_channel_id),
			CandidateRouteHop::PrivateHop(hop) => Some(hop.hint.short_channel_id),
			CandidateRouteHop::Blinded(_) => None,
			CandidateRouteHop::OneHopBlinded(_) => None,
		}
	}

	/// Returns the globally unique short channel ID for this hop, if one is known.
	///
	/// This only returns `Some` if the channel is public (either our own, or one we've learned
	/// from the public network graph), and thus the short channel ID we have for this channel is
	/// globally unique and identifies this channel in a global namespace.
	#[inline]
	pub fn globally_unique_short_channel_id(&self) -> Option<u64> {
		match self {
			CandidateRouteHop::FirstHop(hop) => {
				if hop.details.is_announced {
					hop.details.short_channel_id
				} else {
					None
				}
			},
			CandidateRouteHop::PublicHop(hop) => Some(hop.short_channel_id),
			CandidateRouteHop::PrivateHop(_) => None,
			CandidateRouteHop::Blinded(_) => None,
			CandidateRouteHop::OneHopBlinded(_) => None,
		}
	}

	// NOTE: This may alloc memory so avoid calling it in a hot code path.
	fn features(&self) -> ChannelFeatures {
		match self {
			CandidateRouteHop::FirstHop(hop) => hop.details.counterparty.features.to_context(),
			CandidateRouteHop::PublicHop(hop) => hop.info.channel().features.clone(),
			CandidateRouteHop::PrivateHop(_) => ChannelFeatures::empty(),
			CandidateRouteHop::Blinded(_) => ChannelFeatures::empty(),
			CandidateRouteHop::OneHopBlinded(_) => ChannelFeatures::empty(),
		}
	}

	/// Returns the required difference in HTLC CLTV expiry between the [`Self::source`] and the
	/// next-hop for an HTLC taking this hop.
	///
	/// This is the time that the node(s) in this hop have to claim the HTLC on-chain if the
	/// next-hop goes on chain with a payment preimage.
	#[inline]
	pub fn cltv_expiry_delta(&self) -> u32 {
		match self {
			CandidateRouteHop::FirstHop(_) => 0,
			CandidateRouteHop::PublicHop(hop) => hop.info.direction().cltv_expiry_delta as u32,
			CandidateRouteHop::PrivateHop(hop) => hop.hint.cltv_expiry_delta as u32,
			CandidateRouteHop::Blinded(hop) => hop.hint.payinfo.cltv_expiry_delta as u32,
			CandidateRouteHop::OneHopBlinded(_) => 0,
		}
	}

	/// Returns the minimum amount that can be sent over this hop, in millisatoshis.
	#[inline]
	pub fn htlc_minimum_msat(&self) -> u64 {
		match self {
			CandidateRouteHop::FirstHop(hop) => hop.details.next_outbound_htlc_minimum_msat,
			CandidateRouteHop::PublicHop(hop) => hop.info.direction().htlc_minimum_msat,
			CandidateRouteHop::PrivateHop(hop) => hop.hint.htlc_minimum_msat.unwrap_or(0),
			CandidateRouteHop::Blinded(hop) => hop.hint.payinfo.htlc_minimum_msat,
			CandidateRouteHop::OneHopBlinded { .. } => 0,
		}
	}

	#[inline(always)]
	fn src_node_counter(&self) -> u32 {
		match self {
			CandidateRouteHop::FirstHop(hop) => hop.payer_node_counter,
			CandidateRouteHop::PublicHop(hop) => hop.info.source_counter(),
			CandidateRouteHop::PrivateHop(hop) => hop.source_node_counter,
			CandidateRouteHop::Blinded(hop) => hop.source_node_counter,
			CandidateRouteHop::OneHopBlinded(hop) => hop.source_node_counter,
		}
	}

	#[inline]
	fn target_node_counter(&self) -> Option<u32> {
		match self {
			CandidateRouteHop::FirstHop(hop) => Some(hop.target_node_counter),
			CandidateRouteHop::PublicHop(hop) => Some(hop.info.target_counter()),
			CandidateRouteHop::PrivateHop(hop) => Some(hop.target_node_counter),
			CandidateRouteHop::Blinded(_) => None,
			CandidateRouteHop::OneHopBlinded(_) => None,
		}
	}

	/// Returns the fees that must be paid to route an HTLC over this channel.
	#[inline]
	pub fn fees(&self) -> RoutingFees {
		match self {
			CandidateRouteHop::FirstHop(_) => {
				RoutingFees { base_msat: 0, proportional_millionths: 0 }
			},
			CandidateRouteHop::PublicHop(hop) => hop.info.direction().fees,
			CandidateRouteHop::PrivateHop(hop) => hop.hint.fees,
			CandidateRouteHop::Blinded(hop) => RoutingFees {
				base_msat: hop.hint.payinfo.fee_base_msat,
				proportional_millionths: hop.hint.payinfo.fee_proportional_millionths,
			},
			CandidateRouteHop::OneHopBlinded(_) => {
				RoutingFees { base_msat: 0, proportional_millionths: 0 }
			},
		}
	}

	/// Fetch the effective capacity of this hop.
	///
	/// Note that this may be somewhat expensive, so calls to this should be limited and results
	/// cached!
	fn effective_capacity(&self) -> EffectiveCapacity {
		match self {
			CandidateRouteHop::FirstHop(hop) => EffectiveCapacity::ExactLiquidity {
				liquidity_msat: hop.details.next_outbound_htlc_limit_msat,
			},
			CandidateRouteHop::PublicHop(hop) => hop.info.effective_capacity(),
			CandidateRouteHop::PrivateHop(PrivateHopCandidate {
				hint: RouteHintHop { htlc_maximum_msat: Some(max), .. },
				..
			}) => EffectiveCapacity::HintMaxHTLC { amount_msat: *max },
			CandidateRouteHop::PrivateHop(PrivateHopCandidate {
				hint: RouteHintHop { htlc_maximum_msat: None, .. },
				..
			}) => EffectiveCapacity::Infinite,
			CandidateRouteHop::Blinded(hop) => {
				EffectiveCapacity::HintMaxHTLC { amount_msat: hop.hint.payinfo.htlc_maximum_msat }
			},
			CandidateRouteHop::OneHopBlinded(_) => EffectiveCapacity::Infinite,
		}
	}
	/// Fetch the effective RGB capacity of this hop.
	fn effective_capacity_rgb(&self) -> u64 {
		match self {
			CandidateRouteHop::FirstHop(hop) => hop.details.next_outbound_htlc_limit_rgb,
			CandidateRouteHop::PublicHop(hop) => hop.info.effective_capacity_rgb(),
			CandidateRouteHop::PrivateHop(PrivateHopCandidate {
				hint: RouteHintHop { htlc_maximum_rgb: Some(max), .. },
				..
			}) => *max,
			_ => u64::MAX,
		}
	}

	/// Returns an ID describing the given hop.
	///
	/// See the docs on [`CandidateHopId`] for when this is, or is not, unique.
	#[inline]
	fn id(&self) -> CandidateHopId {
		match self {
			CandidateRouteHop::Blinded(hop) => CandidateHopId::Blinded(hop.hint_idx),
			CandidateRouteHop::OneHopBlinded(hop) => CandidateHopId::Blinded(hop.hint_idx),
			_ => CandidateHopId::Clear((
				self.short_channel_id().unwrap(),
				self.source() < self.target().unwrap(),
			)),
		}
	}
	fn blinded_path(&self) -> Option<&'a BlindedPaymentPath> {
		match self {
			CandidateRouteHop::Blinded(BlindedPathCandidate { hint, .. })
			| CandidateRouteHop::OneHopBlinded(OneHopBlindedPathCandidate { hint, .. }) => Some(&hint),
			_ => None,
		}
	}
	fn blinded_hint_idx(&self) -> Option<usize> {
		match self {
			Self::Blinded(BlindedPathCandidate { hint_idx, .. })
			| Self::OneHopBlinded(OneHopBlindedPathCandidate { hint_idx, .. }) => Some(*hint_idx),
			_ => None,
		}
	}
	/// Returns the source node id of current hop.
	///
	/// Source node id refers to the node forwarding the HTLC through this hop.
	///
	/// For [`Self::FirstHop`] we return payer's node id.
	#[inline]
	pub fn source(&self) -> NodeId {
		match self {
			CandidateRouteHop::FirstHop(hop) => *hop.payer_node_id,
			CandidateRouteHop::PublicHop(hop) => *hop.info.source(),
			CandidateRouteHop::PrivateHop(hop) => hop.hint.src_node_id.into(),
			CandidateRouteHop::Blinded(hop) => *hop.source_node_id,
			CandidateRouteHop::OneHopBlinded(hop) => *hop.source_node_id,
		}
	}
	/// Returns the target node id of this hop, if known.
	///
	/// Target node id refers to the node receiving the HTLC after this hop.
	///
	/// For [`Self::Blinded`] we return `None` because the ultimate destination after the blinded
	/// path is unknown.
	///
	/// For [`Self::OneHopBlinded`] we return `None` because the target is the same as the source,
	/// and such a return value would be somewhat nonsensical.
	#[inline]
	pub fn target(&self) -> Option<NodeId> {
		match self {
			CandidateRouteHop::FirstHop(hop) => Some(hop.details.counterparty.node_id.into()),
			CandidateRouteHop::PublicHop(hop) => Some(*hop.info.target()),
			CandidateRouteHop::PrivateHop(hop) => Some(*hop.target_node_id),
			CandidateRouteHop::Blinded(_) => None,
			CandidateRouteHop::OneHopBlinded(_) => None,
		}
	}
}

/// A unique(ish) identifier for a specific [`CandidateRouteHop`].
///
/// For blinded paths, this ID is unique only within a given [`find_route`] call.
///
/// For other hops, because SCIDs between private channels and public channels can conflict, this
/// isn't guaranteed to be unique at all.
///
/// For our uses, this is generally fine, but it is not public as it is otherwise a rather
/// difficult-to-use API.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialOrd, PartialEq)]
enum CandidateHopId {
	/// Contains (scid, src_node_id < target_node_id)
	Clear((u64, bool)),
	/// Index of the blinded route hint in [`Payee::Blinded::route_hints`].
	Blinded(usize),
}

/// To avoid doing [`PublicKey`] -> [`PathBuildingHop`] hashtable lookups, we assign each
/// [`PublicKey`]/node a `usize` index and simply keep a `Vec` of values.
///
/// While this is easy for gossip-originating nodes (the [`DirectedChannelInfo`] exposes "counters"
/// for us for this purpose) we have to have our own indexes for nodes originating from invoice
/// hints, local channels, or blinded path fake nodes.
///
/// This wrapper handles all this for us, allowing look-up of counters from the various contexts.
///
/// It is first built by passing all [`NodeId`]s that we'll ever care about (which are not in our
/// [`NetworkGraph`], e.g. those from first- and last-hop hints and blinded path introduction
/// points) either though [`NodeCountersBuilder::select_node_counter_for_pubkey`] or
/// [`NodeCountersBuilder::select_node_counter_for_id`], then calling [`NodeCountersBuilder::build`]
/// and using the resulting [`NodeCounters`] to look up any counters.
///
/// [`NodeCounters::private_node_counter_from_pubkey`], specifically, will return `Some` iff
/// [`NodeCountersBuilder::select_node_counter_for_pubkey`] was called on the same key (not
/// [`NodeCountersBuilder::select_node_counter_for_id`]). It will also return a cached copy of the
/// [`PublicKey`] -> [`NodeId`] conversion.
struct NodeCounters<'a> {
	network_graph: &'a ReadOnlyNetworkGraph<'a>,
	private_node_id_to_node_counter: HashMap<NodeId, u32>,
	private_hop_key_cache: HashMap<PublicKey, (NodeId, u32)>,
}

struct NodeCountersBuilder<'a>(NodeCounters<'a>);

impl<'a> NodeCountersBuilder<'a> {
	fn new(network_graph: &'a ReadOnlyNetworkGraph) -> Self {
		Self(NodeCounters {
			network_graph,
			private_node_id_to_node_counter: new_hash_map(),
			private_hop_key_cache: new_hash_map(),
		})
	}

	fn select_node_counter_for_pubkey(&mut self, pubkey: PublicKey) -> u32 {
		let id = NodeId::from_pubkey(&pubkey);
		let counter = self.select_node_counter_for_id(id);
		self.0.private_hop_key_cache.insert(pubkey, (id, counter));
		counter
	}

	fn select_node_counter_for_id(&mut self, node_id: NodeId) -> u32 {
		// For any node_id, we first have to check if its in the existing network graph, and then
		// ensure that we always look up in our internal map first.
		self.0.network_graph.nodes().get(&node_id).map(|node| node.node_counter).unwrap_or_else(
			|| {
				let next_node_counter = self.0.network_graph.max_node_counter()
					+ 1 + self.0.private_node_id_to_node_counter.len() as u32;
				*self.0.private_node_id_to_node_counter.entry(node_id).or_insert(next_node_counter)
			},
		)
	}

	fn build(self) -> NodeCounters<'a> {
		self.0
	}
}

impl<'a> NodeCounters<'a> {
	fn max_counter(&self) -> u32 {
		self.network_graph.max_node_counter() + self.private_node_id_to_node_counter.len() as u32
	}

	fn private_node_counter_from_pubkey(&self, pubkey: &PublicKey) -> Option<&(NodeId, u32)> {
		self.private_hop_key_cache.get(pubkey)
	}

	fn node_counter_from_id(&self, node_id: &NodeId) -> Option<(&NodeId, u32)> {
		self.private_node_id_to_node_counter.get_key_value(node_id).map(|(a, b)| (a, *b)).or_else(
			|| {
				self.network_graph
					.nodes()
					.get_key_value(node_id)
					.map(|(node_id, node)| (node_id, node.node_counter))
			},
		)
	}
}

/// Calculates the introduction point for each blinded path in the given [`PaymentParameters`], if
/// they can be found.
fn calculate_blinded_path_intro_points<'a, L: Deref>(
	payment_params: &PaymentParameters, node_counters: &'a NodeCounters,
	network_graph: &ReadOnlyNetworkGraph, logger: &L, our_node_id: NodeId,
	first_hop_targets: &HashMap<NodeId, (Vec<&ChannelDetails>, u32)>,
) -> Result<Vec<Option<(&'a NodeId, u32)>>, LightningError>
where
	L::Target: Logger,
{
	let introduction_node_id_cache = payment_params
		.payee
		.blinded_route_hints()
		.iter()
		.map(|path| {
			match path.introduction_node() {
				IntroductionNode::NodeId(pubkey) => {
					// Note that this will only return `Some` if the `pubkey` is somehow known to
					// us (i.e. a channel counterparty or in the network graph).
					node_counters.node_counter_from_id(&NodeId::from_pubkey(&pubkey))
				},
				IntroductionNode::DirectedShortChannelId(direction, scid) => path
					.public_introduction_node_id(network_graph)
					.map(|node_id_ref| *node_id_ref)
					.or_else(|| {
						first_hop_targets
							.iter()
							.find(|(_, (channels, _))| {
								channels.iter().any(|details| {
									Some(*scid) == details.get_outbound_payment_scid()
								})
							})
							.map(|(cp, _)| direction.select_node_id(our_node_id, *cp))
					})
					.and_then(|node_id| node_counters.node_counter_from_id(&node_id)),
			}
		})
		.collect::<Vec<_>>();
	match &payment_params.payee {
		Payee::Clear { route_hints, node_id, .. } => {
			for route in route_hints.iter() {
				for hop in &route.0 {
					if hop.src_node_id == *node_id {
						return Err(LightningError {
							err: "Route hint cannot have the payee as the source.".to_owned(),
							action: ErrorAction::IgnoreError,
						});
					}
				}
			}
		},
		Payee::Blinded { route_hints, .. } => {
			if introduction_node_id_cache
				.iter()
				.all(|info_opt| info_opt.map(|(a, _)| a) == Some(&our_node_id))
			{
				return Err(LightningError{err: "Cannot generate a route to blinded paths if we are the introduction node to all of them".to_owned(), action: ErrorAction::IgnoreError});
			}
			for (blinded_path, info_opt) in
				route_hints.iter().zip(introduction_node_id_cache.iter())
			{
				if blinded_path.blinded_hops().len() == 0 {
					return Err(LightningError {
						err: "0-hop blinded path provided".to_owned(),
						action: ErrorAction::IgnoreError,
					});
				}
				let introduction_node_id = match info_opt {
					None => continue,
					Some(info) => info.0,
				};
				if *introduction_node_id == our_node_id {
					log_info!(
						logger,
						"Got blinded path with ourselves as the introduction node, ignoring"
					);
				} else if blinded_path.blinded_hops().len() == 1
					&& route_hints
						.iter()
						.zip(introduction_node_id_cache.iter())
						.filter(|(p, _)| p.blinded_hops().len() == 1)
						.any(|(_, iter_info_opt)| {
							iter_info_opt.is_some() && iter_info_opt != info_opt
						}) {
					return Err(LightningError {
						err: "1-hop blinded paths must all have matching introduction node ids"
							.to_string(),
						action: ErrorAction::IgnoreError,
					});
				}
			}
		},
	}

	Ok(introduction_node_id_cache)
}

#[inline]
fn max_htlc_from_capacity(
	capacity: EffectiveCapacity, max_channel_saturation_power_of_half: u8,
) -> u64 {
	let saturation_shift: u32 = max_channel_saturation_power_of_half as u32;
	match capacity {
		EffectiveCapacity::ExactLiquidity { liquidity_msat } => liquidity_msat,
		EffectiveCapacity::Infinite => u64::max_value(),
		EffectiveCapacity::Unknown => EffectiveCapacity::Unknown.as_msat(),
		EffectiveCapacity::AdvertisedMaxHTLC { amount_msat } => {
			amount_msat.checked_shr(saturation_shift).unwrap_or(0)
		},
		// Treat htlc_maximum_msat from a route hint as an exact liquidity amount, since the invoice is
		// expected to have been generated from up-to-date capacity information.
		EffectiveCapacity::HintMaxHTLC { amount_msat } => amount_msat,
		EffectiveCapacity::Total { capacity_msat, htlc_maximum_msat } => {
			cmp::min(capacity_msat.checked_shr(saturation_shift).unwrap_or(0), htlc_maximum_msat)
		},
	}
}

fn iter_equal<I1: Iterator, I2: Iterator>(mut iter_a: I1, mut iter_b: I2) -> bool
where
	I1::Item: PartialEq<I2::Item>,
{
	loop {
		let a = iter_a.next();
		let b = iter_b.next();
		if a.is_none() && b.is_none() {
			return true;
		}
		if a.is_none() || b.is_none() {
			return false;
		}
		if a.unwrap().ne(&b.unwrap()) {
			return false;
		}
	}
}

/// It's useful to keep track of the hops associated with the fees required to use them,
/// so that we can choose cheaper paths (as per Dijkstra's algorithm).
/// Fee values should be updated only in the context of the whole path, see update_value_and_recompute_fees.
/// These fee values are useful to choose hops as we traverse the graph "payee-to-payer".
#[derive(Clone)]
#[repr(align(128))]
struct PathBuildingHop<'a> {
	candidate: CandidateRouteHop<'a>,
	/// If we've already processed a node as the best node, we shouldn't process it again. Normally
	/// we'd just ignore it if we did as all channels would have a higher new fee, but because we
	/// may decrease the amounts in use as we walk the graph, the actual calculated fee may
	/// decrease as well. Thus, we have to explicitly track which nodes have been processed and
	/// avoid processing them again.
	was_processed: bool,
	/// When processing a node as the next best-score candidate, we want to quickly check if it is
	/// a direct counterparty of ours, using our local channel information immediately if we can.
	///
	/// In order to do so efficiently, we cache whether a node is a direct counterparty here at the
	/// start of a route-finding pass. Unlike all other fields in this struct, this field is never
	/// updated after being initialized - it is set at the start of a route-finding pass and only
	/// read thereafter.
	is_first_hop_target: bool,
	/// Used to compare channels when choosing the for routing.
	/// Includes paying for the use of a hop and the following hops, as well as
	/// an estimated cost of reaching this hop.
	/// Might get stale when fees are recomputed. Primarily for internal use.
	total_fee_msat: u64,
	/// A mirror of the same field in RouteGraphNode. Note that this is only used during the graph
	/// walk and may be invalid thereafter.
	path_htlc_minimum_msat: u64,
	/// All penalties incurred from this channel on the way to the destination, as calculated using
	/// channel scoring.
	path_penalty_msat: u64,

	fee_msat: u64,

	/// All the fees paid *after* this channel on the way to the destination
	next_hops_fee_msat: u64,
	/// Fee paid for the use of the current channel (see candidate.fees()).
	/// The value will be actually deducted from the counterparty balance on the previous link.
	hop_use_fee_msat: u64,

	#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
	// In tests, we apply further sanity checks on cases where we skip nodes we already processed
	// to ensure it is specifically in cases where the fee has gone down because of a decrease in
	// value_contribution_msat, which requires tracking it here. See comments below where it is
	// used for more info.
	value_contribution_msat: u64,
}

const _NODE_MAP_SIZE_TWO_CACHE_LINES: usize = 128 - core::mem::size_of::<Option<PathBuildingHop>>();
const _NODE_MAP_SIZE_EXACTLY_TWO_CACHE_LINES: usize =
	core::mem::size_of::<Option<PathBuildingHop>>() - 128;

impl<'a> core::fmt::Debug for PathBuildingHop<'a> {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		let mut debug_struct = f.debug_struct("PathBuildingHop");
		debug_struct
			.field("source_node_id", &self.candidate.source())
			.field("target_node_id", &self.candidate.target())
			.field("short_channel_id", &self.candidate.short_channel_id())
			.field("is_first_hop_target", &self.is_first_hop_target)
			.field("total_fee_msat", &self.total_fee_msat)
			.field("next_hops_fee_msat", &self.next_hops_fee_msat)
			.field("hop_use_fee_msat", &self.hop_use_fee_msat)
			.field(
				"total_fee_msat - (next_hops_fee_msat + hop_use_fee_msat)",
				&(&self
					.total_fee_msat
					.saturating_sub(self.next_hops_fee_msat)
					.saturating_sub(self.hop_use_fee_msat)),
			)
			.field("path_penalty_msat", &self.path_penalty_msat)
			.field("path_htlc_minimum_msat", &self.path_htlc_minimum_msat)
			.field("cltv_expiry_delta", &self.candidate.cltv_expiry_delta());
		#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
		let debug_struct = debug_struct.field("value_contribution_msat", &self.value_contribution_msat);
		debug_struct.finish()
	}
}

// Instantiated with a list of hops with correct data in them collected during path finding,
// an instance of this struct should be further modified only via given methods.
#[derive(Clone)]
struct PaymentPath<'a> {
	hops: Vec<(PathBuildingHop<'a>, NodeFeatures)>,
}

impl<'a> PaymentPath<'a> {
	// TODO: Add a value_msat field to PaymentPath and use it instead of this function.
	fn get_value_msat(&self) -> u64 {
		self.hops.last().unwrap().0.fee_msat
	}

	fn get_path_penalty_msat(&self) -> u64 {
		self.hops.first().map(|h| h.0.path_penalty_msat).unwrap_or(u64::max_value())
	}

	fn get_total_fee_paid_msat(&self) -> u64 {
		if self.hops.len() < 1 {
			return 0;
		}
		let mut result = 0;
		// Can't use next_hops_fee_msat because it gets outdated.
		for (i, (hop, _)) in self.hops.iter().enumerate() {
			if i != self.hops.len() - 1 {
				result += hop.fee_msat;
			}
		}
		return result;
	}

	fn get_cost_msat(&self) -> u64 {
		self.get_total_fee_paid_msat().saturating_add(self.get_path_penalty_msat())
	}

	// If the amount transferred by the path is updated, the fees should be adjusted. Any other way
	// to change fees may result in an inconsistency.
	//
	// Sometimes we call this function right after constructing a path which is inconsistent in
	// that it the value being transferred has decreased while we were doing path finding, leading
	// to the fees being paid not lining up with the actual limits.
	//
	// Note that this function is not aware of the available_liquidity limit, and thus does not
	// support increasing the value being transferred beyond what was selected during the initial
	// routing passes.
	//
	// Returns the amount that this path contributes to the total payment value, which may be greater
	// than `value_msat` if we had to overpay to meet the final node's `htlc_minimum_msat`.
	fn update_value_and_recompute_fees(&mut self, value_msat: u64) -> u64 {
		let mut extra_contribution_msat = 0;
		let mut total_fee_paid_msat = 0 as u64;
		for i in (0..self.hops.len()).rev() {
			let last_hop = i == self.hops.len() - 1;

			// For non-last-hop, this value will represent the fees paid on the current hop. It
			// will consist of the fees for the use of the next hop, and extra fees to match
			// htlc_minimum_msat of the current channel. Last hop is handled separately.
			let mut cur_hop_fees_msat = 0;
			if !last_hop {
				cur_hop_fees_msat = self.hops.get(i + 1).unwrap().0.hop_use_fee_msat;
			}

			let cur_hop = &mut self.hops.get_mut(i).unwrap().0;
			cur_hop.next_hops_fee_msat = total_fee_paid_msat;
			cur_hop.path_penalty_msat += extra_contribution_msat;
			// Overpay in fees if we can't save these funds due to htlc_minimum_msat.
			// We try to account for htlc_minimum_msat in scoring (add_entry!), so that nodes don't
			// set it too high just to maliciously take more fees by exploiting this
			// match htlc_minimum_msat logic.
			let mut cur_hop_transferred_amount_msat = total_fee_paid_msat + value_msat;
			if let Some(extra_fees_msat) =
				cur_hop.candidate.htlc_minimum_msat().checked_sub(cur_hop_transferred_amount_msat)
			{
				// Note that there is a risk that *previous hops* (those closer to us, as we go
				// payee->our_node here) would exceed their htlc_maximum_msat or available balance.
				//
				// This might make us end up with a broken route, although this should be super-rare
				// in practice, both because of how healthy channels look like, and how we pick
				// channels in add_entry.
				// Also, this can't be exploited more heavily than *announce a free path and fail
				// all payments*.
				cur_hop_transferred_amount_msat += extra_fees_msat;

				// We remember and return the extra fees on the final hop to allow accounting for
				// them in the path's value contribution.
				if last_hop {
					extra_contribution_msat = extra_fees_msat;
				} else {
					total_fee_paid_msat += extra_fees_msat;
					cur_hop_fees_msat += extra_fees_msat;
				}
			}

			if last_hop {
				// Final hop is a special case: it usually has just value_msat (by design), but also
				// it still could overpay for the htlc_minimum_msat.
				cur_hop.fee_msat = cur_hop_transferred_amount_msat;
			} else {
				// Propagate updated fees for the use of the channels to one hop back, where they
				// will be actually paid (fee_msat). The last hop is handled above separately.
				cur_hop.fee_msat = cur_hop_fees_msat;
			}

			// Fee for the use of the current hop which will be deducted on the previous hop.
			// Irrelevant for the first hop, as it doesn't have the previous hop, and the use of
			// this channel is free for us.
			if i != 0 {
				if let Some(new_fee) =
					compute_fees(cur_hop_transferred_amount_msat, cur_hop.candidate.fees())
				{
					cur_hop.hop_use_fee_msat = new_fee;
					total_fee_paid_msat += new_fee;
				} else {
					// It should not be possible because this function is called only to reduce the
					// value. In that case, compute_fee was already called with the same fees for
					// larger amount and there was no overflow.
					unreachable!();
				}
			}
		}
		value_msat + extra_contribution_msat
	}
}

#[inline(always)]
/// Calculate the fees required to route the given amount over a channel with the given fees.
fn compute_fees(amount_msat: u64, channel_fees: RoutingFees) -> Option<u64> {
	amount_msat
		.checked_mul(channel_fees.proportional_millionths as u64)
		.and_then(|part| (channel_fees.base_msat as u64).checked_add(part / 1_000_000))
}

#[inline(always)]
/// Calculate the fees required to route the given amount over a channel with the given fees,
/// saturating to [`u64::max_value`].
fn compute_fees_saturating(amount_msat: u64, channel_fees: RoutingFees) -> u64 {
	amount_msat
		.checked_mul(channel_fees.proportional_millionths as u64)
		.map(|prop| prop / 1_000_000)
		.unwrap_or(u64::max_value())
		.saturating_add(channel_fees.base_msat as u64)
}

/// The default `features` we assume for a node in a route, when no `features` are known about that
/// specific node.
///
/// Default features are:
/// * variable_length_onion_optional
fn default_node_features() -> NodeFeatures {
	let mut features = NodeFeatures::empty();
	features.set_variable_length_onion_optional();
	features
}

struct LoggedPayeePubkey(Option<PublicKey>);
impl fmt::Display for LoggedPayeePubkey {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self.0 {
			Some(pk) => {
				"payee node id ".fmt(f)?;
				pk.fmt(f)
			},
			None => "blinded payee".fmt(f),
		}
	}
}

struct LoggedCandidateHop<'a>(&'a CandidateRouteHop<'a>);
impl<'a> fmt::Display for LoggedCandidateHop<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self.0 {
			CandidateRouteHop::Blinded(BlindedPathCandidate { hint, .. })
			| CandidateRouteHop::OneHopBlinded(OneHopBlindedPathCandidate { hint, .. }) => {
				"blinded route hint with introduction node ".fmt(f)?;
				match hint.introduction_node() {
					IntroductionNode::NodeId(pubkey) => write!(f, "id {}", pubkey)?,
					IntroductionNode::DirectedShortChannelId(direction, scid) => match direction {
						Direction::NodeOne => {
							write!(f, "one on channel with SCID {}", scid)?;
						},
						Direction::NodeTwo => {
							write!(f, "two on channel with SCID {}", scid)?;
						},
					},
				}
				" and blinding point ".fmt(f)?;
				hint.blinding_point().fmt(f)
			},
			CandidateRouteHop::FirstHop(_) => {
				"first hop with SCID ".fmt(f)?;
				self.0.short_channel_id().unwrap().fmt(f)
			},
			CandidateRouteHop::PrivateHop(_) => {
				"route hint with SCID ".fmt(f)?;
				self.0.short_channel_id().unwrap().fmt(f)
			},
			_ => {
				"SCID ".fmt(f)?;
				self.0.short_channel_id().unwrap().fmt(f)
			},
		}
	}
}

#[inline]
fn sort_first_hop_channels(
	channels: &mut Vec<&ChannelDetails>, used_liquidities: &HashMap<CandidateHopId, u64>,
	recommended_value_msat: u64, our_node_pubkey: &PublicKey,
) {
	// Sort the first_hops channels to the same node(s) in priority order of which channel we'd
	// most like to use.
	//
	// First, if channels are below `recommended_value_msat`, sort them in descending order,
	// preferring larger channels to avoid splitting the payment into more MPP parts than is
	// required.
	//
	// Second, because simply always sorting in descending order would always use our largest
	// available outbound capacity, needlessly fragmenting our available channel capacities,
	// sort channels above `recommended_value_msat` in ascending order, preferring channels
	// which have enough, but not too much, capacity for the payment.
	//
	// Available outbound balances factor in liquidity already reserved for previously found paths.
	channels.sort_unstable_by(|chan_a, chan_b| {
		let chan_a_outbound_limit_msat = chan_a.next_outbound_htlc_limit_msat.saturating_sub(
			*used_liquidities
				.get(&CandidateHopId::Clear((
					chan_a.get_outbound_payment_scid().unwrap(),
					our_node_pubkey < &chan_a.counterparty.node_id,
				)))
				.unwrap_or(&0),
		);
		let chan_b_outbound_limit_msat = chan_b.next_outbound_htlc_limit_msat.saturating_sub(
			*used_liquidities
				.get(&CandidateHopId::Clear((
					chan_b.get_outbound_payment_scid().unwrap(),
					our_node_pubkey < &chan_b.counterparty.node_id,
				)))
				.unwrap_or(&0),
		);
		if chan_b_outbound_limit_msat < recommended_value_msat
			|| chan_a_outbound_limit_msat < recommended_value_msat
		{
			// Sort in descending order
			chan_b_outbound_limit_msat.cmp(&chan_a_outbound_limit_msat)
		} else {
			// Sort in ascending order
			chan_a_outbound_limit_msat.cmp(&chan_b_outbound_limit_msat)
		}
	});
}

/// Finds a route from us (payer) to the given target node (payee).
///
/// If the payee provided features in their invoice, they should be provided via the `payee` field
/// in the given [`RouteParameters::payment_params`].
/// Without this, MPP will only be used if the payee's features are available in the network graph.
///
/// Private routing paths between a public node and the target may be included in the `payee` field
/// of [`RouteParameters::payment_params`].
///
/// If some channels aren't announced, it may be useful to fill in `first_hops` with the results
/// from [`ChannelManager::list_usable_channels`]. If it is filled in, the view of these channels
/// from `network_graph` will be ignored, and only those in `first_hops` will be used.
///
/// The fees on channels from us to the next hop are ignored as they are assumed to all be equal.
/// However, the enabled/disabled bit on such channels as well as the `htlc_minimum_msat` /
/// `htlc_maximum_msat` *are* checked as they may change based on the receiving node.
///
/// # Panics
///
/// Panics if first_hops contains channels without `short_channel_id`s;
/// [`ChannelManager::list_usable_channels`] will never include such channels.
///
/// [`ChannelManager::list_usable_channels`]: crate::ln::channelmanager::ChannelManager::list_usable_channels
/// [`Event::PaymentPathFailed`]: crate::events::Event::PaymentPathFailed
/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
pub fn find_route<L: Deref, GL: Deref, S: ScoreLookUp>(
	our_node_pubkey: &PublicKey, route_params: &RouteParameters, network_graph: &NetworkGraph<GL>,
	first_hops: Option<&[&ChannelDetails]>, logger: L, scorer: &S, score_params: &S::ScoreParams,
	random_seed_bytes: &[u8; 32],
) -> Result<Route, LightningError>
where
	L::Target: Logger,
	GL::Target: Logger,
{
	let graph_lock = network_graph.read_only();
	let mut route = get_route(
		our_node_pubkey,
		&route_params,
		&graph_lock,
		first_hops,
		logger,
		scorer,
		score_params,
		random_seed_bytes,
	)?;
	add_random_cltv_offset(
		&mut route,
		&route_params.payment_params,
		&graph_lock,
		random_seed_bytes,
	);
	Ok(route)
}

pub(crate) fn get_route<L: Deref, S: ScoreLookUp>(
	our_node_pubkey: &PublicKey, route_params: &RouteParameters,
	network_graph: &ReadOnlyNetworkGraph, first_hops: Option<&[&ChannelDetails]>, logger: L,
	scorer: &S, score_params: &S::ScoreParams, _random_seed_bytes: &[u8; 32],
) -> Result<Route, LightningError>
where
	L::Target: Logger,
{
	let payment_params = &route_params.payment_params;
	let max_path_length = core::cmp::min(payment_params.max_path_length, MAX_PATH_LENGTH_ESTIMATE);
	let final_value_msat = route_params.final_value_msat;
	// If we're routing to a blinded recipient, we won't have their node id. Therefore, keep the
	// unblinded payee id as an option. We also need a non-optional "payee id" for path construction,
	// so use a dummy id for this in the blinded case.
	let payee_node_id_opt = payment_params.payee.node_id().map(|pk| NodeId::from_pubkey(&pk));
	const DUMMY_BLINDED_PAYEE_ID: [u8; 33] = [2; 33];
	let maybe_dummy_payee_pk = payment_params
		.payee
		.node_id()
		.unwrap_or_else(|| PublicKey::from_slice(&DUMMY_BLINDED_PAYEE_ID).unwrap());
	let maybe_dummy_payee_node_id = NodeId::from_pubkey(&maybe_dummy_payee_pk);
	let our_node_id = NodeId::from_pubkey(&our_node_pubkey);

	if payee_node_id_opt.map_or(false, |payee| payee == our_node_id) {
		return Err(LightningError {
			err: "Cannot generate a route to ourselves".to_owned(),
			action: ErrorAction::IgnoreError,
		});
	}
	if our_node_id == maybe_dummy_payee_node_id {
		return Err(LightningError {
			err: "Invalid origin node id provided, use a different one".to_owned(),
			action: ErrorAction::IgnoreError,
		});
	}

	if final_value_msat > MAX_VALUE_MSAT {
		return Err(LightningError {
			err: "Cannot generate a route of more value than all existing satoshis".to_owned(),
			action: ErrorAction::IgnoreError,
		});
	}

	if final_value_msat == 0 {
		return Err(LightningError {
			err: "Cannot send a payment of 0 msat".to_owned(),
			action: ErrorAction::IgnoreError,
		});
	}

	let final_cltv_expiry_delta = payment_params.payee.final_cltv_expiry_delta().unwrap_or(0);
	if payment_params.max_total_cltv_expiry_delta <= final_cltv_expiry_delta {
		return Err(LightningError{err: "Can't find a route where the maximum total CLTV expiry delta is below the final CLTV expiry.".to_owned(), action: ErrorAction::IgnoreError});
	}

	// The general routing idea is the following:
	// 1. Fill first/last hops communicated by the caller.
	// 2. Attempt to construct a path from payer to payee for transferring
	//    any ~sufficient (described later) value.
	//    If succeed, remember which channels were used and how much liquidity they have available,
	//    so that future paths don't rely on the same liquidity.
	// 3. Proceed to the next step if:
	//    - we hit the recommended target value;
	//    - OR if we could not construct a new path. Any next attempt will fail too.
	//    Otherwise, repeat step 2.
	// 4. See if we managed to collect paths which aggregately are able to transfer target value
	//    (not recommended value).
	// 5. If yes, proceed. If not, fail routing.
	// 6. Select the paths which have the lowest cost (fee plus scorer penalty) per amount
	//    transferred up to the transfer target value.
	// 7. Reduce the value of the last path until we are sending only the target value.
	// 8. If our maximum channel saturation limit caused us to pick two identical paths, combine
	//    them so that we're not sending two HTLCs along the same path.

	// As for the actual search algorithm, we do a payee-to-payer Dijkstra's sorting by each node's
	// distance from the payee
	//
	// We are not a faithful Dijkstra's implementation because we can change values which impact
	// earlier nodes while processing later nodes. Specifically, if we reach a channel with a lower
	// liquidity limit (via htlc_maximum_msat, on-chain capacity or assumed liquidity limits) than
	// the value we are currently attempting to send over a path, we simply reduce the value being
	// sent along the path for any hops after that channel. This may imply that later fees (which
	// we've already tabulated) are lower because a smaller value is passing through the channels
	// (and the proportional fee is thus lower). There isn't a trivial way to recalculate the
	// channels which were selected earlier (and which may still be used for other paths without a
	// lower liquidity limit), so we simply accept that some liquidity-limited paths may be
	// de-preferenced.
	//
	// One potentially problematic case for this algorithm would be if there are many
	// liquidity-limited paths which are liquidity-limited near the destination (ie early in our
	// graph walking), we may never find a path which is not liquidity-limited and has lower
	// proportional fee (and only lower absolute fee when considering the ultimate value sent).
	// Because we only consider paths with at least 5% of the total value being sent, the damage
	// from such a case should be limited, however this could be further reduced in the future by
	// calculating fees on the amount we wish to route over a path, ie ignoring the liquidity
	// limits for the purposes of fee calculation.
	//
	// Alternatively, we could store more detailed path information in the heap (targets, below)
	// and index the best-path map (dist, below) by node *and* HTLC limits, however that would blow
	// up the runtime significantly both algorithmically (as we'd traverse nodes multiple times)
	// and practically (as we would need to store dynamically-allocated path information in heap
	// objects, increasing malloc traffic and indirect memory access significantly). Further, the
	// results of such an algorithm would likely be biased towards lower-value paths.
	//
	// Further, we could return to a faithful Dijkstra's algorithm by rejecting paths with limits
	// outside of our current search value, running a path search more times to gather candidate
	// paths at different values. While this may be acceptable, further path searches may increase
	// runtime for little gain. Specifically, the current algorithm rather efficiently explores the
	// graph for candidate paths, calculating the maximum value which can realistically be sent at
	// the same time, remaining generic across different payment values.

	let network_channels = network_graph.channels();
	let network_nodes = network_graph.nodes();

	if payment_params.max_path_count == 0 {
		return Err(LightningError {
			err: "Can't find a route with no paths allowed.".to_owned(),
			action: ErrorAction::IgnoreError,
		});
	}

	// Allow MPP only if we have a features set from somewhere that indicates the payee supports
	// it. If the payee supports it they're supposed to include it in the invoice, so that should
	// work reliably.
	let allow_mpp = if payment_params.max_path_count == 1 {
		false
	} else if payment_params.payee.supports_basic_mpp() {
		true
	} else if let Some(payee) = payee_node_id_opt {
		network_nodes.get(&payee).map_or(false, |node| {
			node.announcement_info
				.as_ref()
				.map_or(false, |info| info.features().supports_basic_mpp())
		})
	} else {
		false
	};

	let max_total_routing_fee_msat =
		route_params.max_total_routing_fee_msat.unwrap_or(u64::max_value());

	let first_hop_count = first_hops.map(|hops| hops.len()).unwrap_or(0);
	log_trace!(logger, "Searching for a route from payer {} to {} {} MPP and {} first hops {}overriding the network graph of {} nodes and {} channels with a fee limit of {} msat",
		our_node_pubkey, LoggedPayeePubkey(payment_params.payee.node_id()),
		if allow_mpp { "with" } else { "without" },
		first_hop_count, if first_hops.is_some() { "" } else { "not " },
		network_graph.nodes().len(), network_graph.channels().len(),
		max_total_routing_fee_msat);

	if first_hop_count < 10 {
		if let Some(hops) = first_hops {
			for hop in hops {
				log_trace!(
					logger,
					" First hop through {}/{} can send between {}msat and {}msat (inclusive).",
					hop.counterparty.node_id,
					hop.get_outbound_payment_scid().unwrap_or(0),
					hop.next_outbound_htlc_minimum_msat,
					hop.next_outbound_htlc_limit_msat
				);
			}
		}
	}

	let mut node_counter_builder = NodeCountersBuilder::new(&network_graph);

	let payer_node_counter = node_counter_builder.select_node_counter_for_pubkey(*our_node_pubkey);
	let payee_node_counter =
		node_counter_builder.select_node_counter_for_pubkey(maybe_dummy_payee_pk);

	for route in payment_params.payee.unblinded_route_hints().iter() {
		for hop in route.0.iter() {
			node_counter_builder.select_node_counter_for_pubkey(hop.src_node_id);
		}
	}

	// Step (1). Prepare first and last hop targets.
	//
	// First cache all our direct channels so that we can insert them in the heap at startup.
	// Then process any blinded routes, resolving their introduction node and caching it.
	let mut first_hop_targets: HashMap<_, (Vec<&ChannelDetails>, u32)> =
		hash_map_with_capacity(if first_hops.is_some() {
			first_hops.as_ref().unwrap().len()
		} else {
			0
		});
	if let Some(hops) = first_hops {
		for chan in hops {
			if chan.get_outbound_payment_scid().is_none() {
				panic!("first_hops should be filled in with usable channels, not pending ones");
			}
			if chan.counterparty.node_id == *our_node_pubkey {
				return Err(LightningError {
					err: "First hop cannot have our_node_pubkey as a destination.".to_owned(),
					action: ErrorAction::IgnoreError,
				});
			}
			let counterparty_id = NodeId::from_pubkey(&chan.counterparty.node_id);
			first_hop_targets
				.entry(counterparty_id)
				.or_insert_with(|| {
					// Make sure there's a counter assigned for the counterparty
					let node_counter =
						node_counter_builder.select_node_counter_for_id(counterparty_id);
					(Vec::new(), node_counter)
				})
				.0
				.push(chan);
		}
		if first_hop_targets.is_empty() {
			return Err(LightningError {
				err: "Cannot route when there are no outbound routes away from us".to_owned(),
				action: ErrorAction::IgnoreError,
			});
		}
	}

	let node_counters = node_counter_builder.build();

	let introduction_node_id_cache = calculate_blinded_path_intro_points(
		&payment_params,
		&node_counters,
		network_graph,
		&logger,
		our_node_id,
		&first_hop_targets,
	)?;

	// The main heap containing all candidate next-hops sorted by their score (max(fee,
	// htlc_minimum)). Ideally this would be a heap which allowed cheap score reduction instead of
	// adding duplicate entries when we find a better path to a given node.
	let mut targets: BinaryHeap<RouteGraphNode> = BinaryHeap::new();

	// Map from node_id to information about the best current path to that node, including feerate
	// information.
	let dist_len = node_counters.max_counter() + 1;
	let mut dist: Vec<Option<PathBuildingHop>> = vec![None; dist_len as usize];

	// During routing, if we ignore a path due to an htlc_minimum_msat limit, we set this,
	// indicating that we may wish to try again with a higher value, potentially paying to meet an
	// htlc_minimum with extra fees while still finding a cheaper path.
	let mut hit_minimum_limit;

	// When arranging a route, we select multiple paths so that we can make a multi-path payment.
	// We start with a path_value of the exact amount we want, and if that generates a route we may
	// return it immediately. Otherwise, we don't stop searching for paths until we have 3x the
	// amount we want in total across paths, selecting the best subset at the end.
	const ROUTE_CAPACITY_PROVISION_FACTOR: u64 = 3;
	let recommended_value_msat = final_value_msat * ROUTE_CAPACITY_PROVISION_FACTOR as u64;
	let mut path_value_msat = final_value_msat;

	// Routing Fragmentation Mitigation heuristic:
	//
	// Routing fragmentation across many payment paths increases the overall routing
	// fees as you have irreducible routing fees per-link used (`fee_base_msat`).
	// Taking too many smaller paths also increases the chance of payment failure.
	// Thus to avoid this effect, we require from our collected links to provide
	// at least a minimal contribution to the recommended value yet-to-be-fulfilled.
	// This requirement is currently set to be 1/max_path_count of the payment
	// value to ensure we only ever return routes that do not violate this limit.
	let minimal_value_contribution_msat: u64 = if allow_mpp {
		(final_value_msat + (payment_params.max_path_count as u64 - 1))
			/ payment_params.max_path_count as u64
	} else {
		final_value_msat
	};

	// When we start collecting routes we enforce the max_channel_saturation_power_of_half
	// requirement strictly. After we've collected enough (or if we fail to find new routes) we
	// drop the requirement by setting this to 0.
	let mut channel_saturation_pow_half = payment_params.max_channel_saturation_power_of_half;

	// Keep track of how much liquidity has been used in selected channels or blinded paths. Used to
	// determine if the channel can be used by additional MPP paths or to inform path finding
	// decisions. It is aware of direction *only* to ensure that the correct htlc_maximum_msat value
	// is used. Hence, liquidity used in one direction will not offset any used in the opposite
	// direction.
	let mut used_liquidities: HashMap<CandidateHopId, u64> =
		hash_map_with_capacity(network_nodes.len());

	// Keeping track of how much value we already collected across other paths. Helps to decide
	// when we want to stop looking for new paths.
	let mut already_collected_value_msat = 0;

	for (_, (channels, _)) in first_hop_targets.iter_mut() {
		sort_first_hop_channels(
			channels,
			&used_liquidities,
			recommended_value_msat,
			our_node_pubkey,
		);
	}

	log_trace!(
		logger,
		"Building path from {} to payer {} for value {} msat.",
		LoggedPayeePubkey(payment_params.payee.node_id()),
		our_node_pubkey,
		final_value_msat
	);

	// Remember how many candidates we ignored to allow for some logging afterwards.
	let mut num_ignored_value_contribution: u32 = 0;
	let mut num_ignored_path_length_limit: u32 = 0;
	let mut num_ignored_cltv_delta_limit: u32 = 0;
	let mut num_ignored_previously_failed: u32 = 0;
	let mut num_ignored_total_fee_limit: u32 = 0;
	let mut num_ignored_avoid_overpayment: u32 = 0;
	let mut num_ignored_htlc_minimum_msat_limit: u32 = 0;

	macro_rules! add_entry {
		// Adds entry which goes from $candidate.source() to $candidate.target() over the $candidate hop.
		// $next_hops_fee_msat represents the fees paid for using all the channels *after* this one,
		// since that value has to be transferred over this channel.
		// Returns the contribution amount of $candidate if the channel caused an update to `targets`.
		( $candidate: expr, $next_hops_fee_msat: expr,
			$next_hops_value_contribution: expr, $next_hops_path_htlc_minimum_msat: expr,
			$next_hops_path_penalty_msat: expr, $next_hops_cltv_delta: expr, $next_hops_path_length: expr ) => { {
			// We "return" whether we updated the path at the end, and how much we can route via
			// this channel, via this:
			let mut hop_contribution_amt_msat = None;
			// Channels to self should not be used. This is more of belt-and-suspenders, because in
			// practice these cases should be caught earlier:
			// - for regular channels at channel announcement (TODO)
			// - for first and last hops early in get_route
			let src_node_id = $candidate.source();
			if Some(src_node_id) != $candidate.target() {
				let scid_opt = $candidate.short_channel_id();
				let effective_capacity = $candidate.effective_capacity();
				let htlc_maximum_msat = max_htlc_from_capacity(effective_capacity, channel_saturation_pow_half);

				// It is tricky to subtract $next_hops_fee_msat from available liquidity here.
				// It may be misleading because we might later choose to reduce the value transferred
				// over these channels, and the channel which was insufficient might become sufficient.
				// Worst case: we drop a good channel here because it can't cover the high following
				// fees caused by one expensive channel, but then this channel could have been used
				// if the amount being transferred over this path is lower.
				// We do this for now, but this is a subject for removal.
				if let Some(mut available_value_contribution_msat) = htlc_maximum_msat.checked_sub($next_hops_fee_msat) {
					let cltv_expiry_delta = $candidate.cltv_expiry_delta();
					let htlc_minimum_msat = $candidate.htlc_minimum_msat();
					let used_liquidity_msat = used_liquidities
						.get(&$candidate.id())
						.map_or(0, |used_liquidity_msat| {
							available_value_contribution_msat = available_value_contribution_msat
								.saturating_sub(*used_liquidity_msat);
							*used_liquidity_msat
						});

					// Verify the liquidity offered by this channel complies to the minimal contribution.
					let contributes_sufficient_value = available_value_contribution_msat >= minimal_value_contribution_msat;
					// Do not consider candidate hops that would exceed the maximum path length.
					let path_length_to_node = $next_hops_path_length
						+ if $candidate.blinded_hint_idx().is_some() { 0 } else { 1 };
					let exceeds_max_path_length = path_length_to_node > max_path_length;

					// Do not consider candidates that exceed the maximum total cltv expiry limit.
					// In order to already account for some of the privacy enhancing random CLTV
					// expiry delta offset we add on top later, we subtract a rough estimate
					// (2*MEDIAN_HOP_CLTV_EXPIRY_DELTA) here.
					let max_total_cltv_expiry_delta = (payment_params.max_total_cltv_expiry_delta - final_cltv_expiry_delta)
						.checked_sub(2*MEDIAN_HOP_CLTV_EXPIRY_DELTA)
						.unwrap_or(payment_params.max_total_cltv_expiry_delta - final_cltv_expiry_delta);
					let hop_total_cltv_delta = ($next_hops_cltv_delta as u32)
						.saturating_add(cltv_expiry_delta);
					let exceeds_cltv_delta_limit = hop_total_cltv_delta > max_total_cltv_expiry_delta;

					let value_contribution_msat = cmp::min(available_value_contribution_msat, $next_hops_value_contribution);
					// Includes paying fees for the use of the following channels.
					let amount_to_transfer_over_msat: u64 = match value_contribution_msat.checked_add($next_hops_fee_msat) {
						Some(result) => result,
						// Can't overflow due to how the values were computed right above.
						None => unreachable!(),
					};
					#[allow(unused_comparisons)] // $next_hops_path_htlc_minimum_msat is 0 in some calls so rustc complains
					let over_path_minimum_msat = amount_to_transfer_over_msat >= htlc_minimum_msat &&
						amount_to_transfer_over_msat >= $next_hops_path_htlc_minimum_msat;

					#[allow(unused_comparisons)] // $next_hops_path_htlc_minimum_msat is 0 in some calls so rustc complains
					let may_overpay_to_meet_path_minimum_msat =
						(amount_to_transfer_over_msat < htlc_minimum_msat &&
						  recommended_value_msat >= htlc_minimum_msat) ||
						(amount_to_transfer_over_msat < $next_hops_path_htlc_minimum_msat &&
						 recommended_value_msat >= $next_hops_path_htlc_minimum_msat);

					let payment_failed_on_this_channel = match scid_opt {
						Some(scid) => payment_params.previously_failed_channels.contains(&scid),
						None => match $candidate.blinded_hint_idx() {
							Some(idx) => {
								payment_params.previously_failed_blinded_path_idxs.contains(&(idx as u64))
							},
							None => false,
						},
					};

					let (should_log_candidate, first_hop_details) = match $candidate {
						CandidateRouteHop::FirstHop(hop) => (true, Some(hop.details)),
						CandidateRouteHop::PrivateHop(_) => (true, None),
						CandidateRouteHop::Blinded(_) => (true, None),
						CandidateRouteHop::OneHopBlinded(_) => (true, None),
						_ => (false, None),
					}let mut contributes_sufficient_rgb_value = true;
if let Some(rgb_amount) = route_params.rgb_payment.map(|(_, amt)| amt) {
  if $candidate.effective_capacity_rgb() < rgb_amount {
    contributes_sufficient_rgb_value = false;
  }
}
 // If HTLC minimum is larger than the amount we're going to transfer, we shouldn't
// bother considering this channel. If retrying with recommended_value_msat may
// allow us to hit the HTLC minimum limit, set htlc_minimum_limit so that we go
// around again with a higher amount.
if !contributes_sufficient_rgb_value {
  if should_log_candidate {
    log_trace!(logger,
      "Ignoring {} due to its HTLC RGB maximum limit.",
      LoggedCandidateHop(&$candidate));

    if let Some(details) = first_hop_details {
      log_trace!(logger,
        "First hop candidate next_outbound_htlc_limit_rgb: {}",
        details.next_outbound_htlc_limit_rgb,
      );
    }
  }
} else
;

					// If HTLC minimum is larger than the amount we're going to transfer, we shouldn't
					// bother considering this channel. If retrying with recommended_value_msat may
					// allow us to hit the HTLC minimum limit, set htlc_minimum_limit so that we go
					// around again with a higher amount.
					if !contributes_sufficient_value {
						if should_log_candidate {
							log_trace!(logger, "Ignoring {} due to insufficient value contribution (channel max {:?}).",
								LoggedCandidateHop(&$candidate),
								effective_capacity);
						}
						num_ignored_value_contribution += 1;
					} else if exceeds_max_path_length {
						if should_log_candidate {
							log_trace!(logger, "Ignoring {} due to exceeding maximum path length limit.", LoggedCandidateHop(&$candidate));
						}
						num_ignored_path_length_limit += 1;
					} else if exceeds_cltv_delta_limit {
						if should_log_candidate {
							log_trace!(logger, "Ignoring {} due to exceeding CLTV delta limit.", LoggedCandidateHop(&$candidate));

							if let Some(_) = first_hop_details {
								log_trace!(logger,
									"First hop candidate cltv_expiry_delta: {}. Limit: {}",
									hop_total_cltv_delta,
									max_total_cltv_expiry_delta,
								);
							}
						}
						num_ignored_cltv_delta_limit += 1;
					} else if payment_failed_on_this_channel {
						if should_log_candidate {
							log_trace!(logger, "Ignoring {} due to a failed previous payment attempt.", LoggedCandidateHop(&$candidate));
						}
						num_ignored_previously_failed += 1;
					} else if may_overpay_to_meet_path_minimum_msat {
						if should_log_candidate {
							log_trace!(logger,
								"Ignoring {} to avoid overpaying to meet htlc_minimum_msat limit ({}).",
								LoggedCandidateHop(&$candidate), $candidate.htlc_minimum_msat());
						}
						num_ignored_avoid_overpayment += 1;
						hit_minimum_limit = true;
					} else if over_path_minimum_msat {
						// Note that low contribution here (limited by available_liquidity_msat)
						// might violate htlc_minimum_msat on the hops which are next along the
						// payment path (upstream to the payee). To avoid that, we recompute
						// path fees knowing the final path contribution after constructing it.
						let curr_min = cmp::max(
							$next_hops_path_htlc_minimum_msat, htlc_minimum_msat
						);
						let candidate_fees = $candidate.fees();
						let src_node_counter = $candidate.src_node_counter();
						let path_htlc_minimum_msat = compute_fees_saturating(curr_min, candidate_fees)
							.saturating_add(curr_min);

						let dist_entry = &mut dist[src_node_counter as usize];
						let old_entry = if let Some(hop) = dist_entry {
							hop
						} else {
							// If there was previously no known way to access the source node
							// (recall it goes payee-to-payer) of short_channel_id, first add a
							// semi-dummy record just to compute the fees to reach the source node.
							// This will affect our decision on selecting short_channel_id
							// as a way to reach the $candidate.target() node.
							*dist_entry = Some(PathBuildingHop {
								candidate: $candidate.clone(),
								fee_msat: 0,
								next_hops_fee_msat: u64::max_value(),
								hop_use_fee_msat: u64::max_value(),
								total_fee_msat: u64::max_value(),
								path_htlc_minimum_msat,
								path_penalty_msat: u64::max_value(),
								was_processed: false,
								is_first_hop_target: false,
								#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
								value_contribution_msat,
							});
							dist_entry.as_mut().unwrap()
						};

						#[allow(unused_mut)] // We only use the mut in cfg(test)
						let mut should_process = !old_entry.was_processed;
						#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
						{
							// In test/fuzzing builds, we do extra checks to make sure the skipping
							// of already-seen nodes only happens in cases we expect (see below).
							if !should_process { should_process = true; }
						}

						if should_process {
							let mut hop_use_fee_msat = 0;
							let mut total_fee_msat: u64 = $next_hops_fee_msat;

							// Ignore hop_use_fee_msat for channel-from-us as we assume all channels-from-us
							// will have the same effective-fee
							if src_node_id != our_node_id {
								// Note that `u64::max_value` means we'll always fail the
								// `old_entry.total_fee_msat > total_fee_msat` check below
								hop_use_fee_msat = compute_fees_saturating(amount_to_transfer_over_msat, candidate_fees);
								total_fee_msat = total_fee_msat.saturating_add(hop_use_fee_msat);
							}

							// Ignore hops if augmenting the current path to them would put us over `max_total_routing_fee_msat`
							if total_fee_msat > max_total_routing_fee_msat {
								if should_log_candidate {
									log_trace!(logger, "Ignoring {} due to exceeding max total routing fee limit.", LoggedCandidateHop(&$candidate));

									if let Some(_) = first_hop_details {
										log_trace!(logger,
											"First hop candidate routing fee: {}. Limit: {}",
											total_fee_msat,
											max_total_routing_fee_msat,
										);
									}
								}
								num_ignored_total_fee_limit += 1;
							} else {
								let channel_usage = ChannelUsage {
									amount_msat: amount_to_transfer_over_msat,
									inflight_htlc_msat: used_liquidity_msat,
									effective_capacity,
								};
								let channel_penalty_msat =
									scorer.channel_penalty_msat($candidate,
										channel_usage,
										score_params);
								let path_penalty_msat = $next_hops_path_penalty_msat
									.saturating_add(channel_penalty_msat);

								// Update the way of reaching $candidate.source()
								// with the given short_channel_id (from $candidate.target()),
								// if this way is cheaper than the already known
								// (considering the cost to "reach" this channel from the route destination,
								// the cost of using this channel,
								// and the cost of routing to the source node of this channel).
								// Also, consider that htlc_minimum_msat_difference, because we might end up
								// paying it. Consider the following exploit:
								// we use 2 paths to transfer 1.5 BTC. One of them is 0-fee normal 1 BTC path,
								// and for the other one we picked a 1sat-fee path with htlc_minimum_msat of
								// 1 BTC. Now, since the latter is more expensive, we gonna try to cut it
								// by 0.5 BTC, but then match htlc_minimum_msat by paying a fee of 0.5 BTC
								// to this channel.
								// Ideally the scoring could be smarter (e.g. 0.5*htlc_minimum_msat here),
								// but it may require additional tracking - we don't want to double-count
								// the fees included in $next_hops_path_htlc_minimum_msat, but also
								// can't use something that may decrease on future hops.
								let old_cost = cmp::max(old_entry.total_fee_msat, old_entry.path_htlc_minimum_msat)
									.saturating_add(old_entry.path_penalty_msat);
								let new_cost = cmp::max(total_fee_msat, path_htlc_minimum_msat)
									.saturating_add(path_penalty_msat);

								if !old_entry.was_processed && new_cost < old_cost {
									let new_graph_node = RouteGraphNode {
										node_id: src_node_id,
										score: cmp::max(total_fee_msat, path_htlc_minimum_msat).saturating_add(path_penalty_msat),
										total_cltv_delta: hop_total_cltv_delta,
										value_contribution_msat,
										path_length_to_node,
									};
									targets.push(new_graph_node);
									old_entry.next_hops_fee_msat = $next_hops_fee_msat;
									old_entry.hop_use_fee_msat = hop_use_fee_msat;
									old_entry.total_fee_msat = total_fee_msat;
									old_entry.candidate = $candidate.clone();
									old_entry.fee_msat = 0; // This value will be later filled with hop_use_fee_msat of the following channel
									old_entry.path_htlc_minimum_msat = path_htlc_minimum_msat;
									old_entry.path_penalty_msat = path_penalty_msat;
									#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
									{
										old_entry.value_contribution_msat = value_contribution_msat;
									}
									hop_contribution_amt_msat = Some(value_contribution_msat);
								} else if old_entry.was_processed && new_cost < old_cost {
									#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
									{
										// If we're skipping processing a node which was previously
										// processed even though we found another path to it with a
										// cheaper fee, check that it was because the second path we
										// found (which we are processing now) has a lower value
										// contribution due to an HTLC minimum limit.
										//
										// e.g. take a graph with two paths from node 1 to node 2, one
										// through channel A, and one through channel B. Channel A and
										// B are both in the to-process heap, with their scores set by
										// a higher htlc_minimum than fee.
										// Channel A is processed first, and the channels onwards from
										// node 1 are added to the to-process heap. Thereafter, we pop
										// Channel B off of the heap, note that it has a much more
										// restrictive htlc_maximum_msat, and recalculate the fees for
										// all of node 1's channels using the new, reduced, amount.
										//
										// This would be bogus - we'd be selecting a higher-fee path
										// with a lower htlc_maximum_msat instead of the one we'd
										// already decided to use.
										debug_assert!(path_htlc_minimum_msat < old_entry.path_htlc_minimum_msat);
										debug_assert!(
											value_contribution_msat + path_penalty_msat <
											old_entry.value_contribution_msat + old_entry.path_penalty_msat
										);
									}
								}
							}
						}
					} else {
						if should_log_candidate {
							log_trace!(logger,
								"Ignoring {} due to its htlc_minimum_msat limit.",
								LoggedCandidateHop(&$candidate));

							if let Some(details) = first_hop_details {
								log_trace!(logger,
									"First hop candidate next_outbound_htlc_minimum_msat: {}",
									details.next_outbound_htlc_minimum_msat,
								);
							}
						}
						num_ignored_htlc_minimum_msat_limit += 1;
					}
				}
			}
			hop_contribution_amt_msat
		} }
	}

	let default_node_features = default_node_features();

	// Find ways (channels with destination) to reach a given node and store them
	// in the corresponding data structures (routing graph etc).
	// $fee_to_target_msat represents how much it costs to reach to this node from the payee,
	// meaning how much will be paid in fees after this node (to the best of our knowledge).
	// This data can later be helpful to optimize routing (pay lower fees).
	macro_rules! add_entries_to_cheapest_to_target_node {
		( $node: expr, $node_id: expr, $next_hops_value_contribution: expr,
		  $next_hops_cltv_delta: expr, $next_hops_path_length: expr ) => {
			let fee_to_target_msat;
			let next_hops_path_htlc_minimum_msat;
			let next_hops_path_penalty_msat;
			let is_first_hop_target;
			let skip_node = if let Some(elem) = &mut dist[$node.node_counter as usize] {
				let was_processed = elem.was_processed;
				elem.was_processed = true;
				fee_to_target_msat = elem.total_fee_msat;
				next_hops_path_htlc_minimum_msat = elem.path_htlc_minimum_msat;
				next_hops_path_penalty_msat = elem.path_penalty_msat;
				is_first_hop_target = elem.is_first_hop_target;
				was_processed
			} else {
				// Entries are added to dist in add_entry!() when there is a channel from a node.
				// Because there are no channels from payee, it will not have a dist entry at this point.
				// If we're processing any other node, it is always be the result of a channel from it.
				debug_assert_eq!($node_id, maybe_dummy_payee_node_id);

				fee_to_target_msat = 0;
				next_hops_path_htlc_minimum_msat = 0;
				next_hops_path_penalty_msat = 0;
				is_first_hop_target = false;
				false
			};

			if !skip_node {
				if is_first_hop_target {
					if let Some((first_channels, peer_node_counter)) =
						first_hop_targets.get(&$node_id)
					{
						for details in first_channels {
							debug_assert_eq!(*peer_node_counter, $node.node_counter);
							let candidate = CandidateRouteHop::FirstHop(FirstHopCandidate {
								details,
								payer_node_id: &our_node_id,
								payer_node_counter,
								target_node_counter: $node.node_counter,
							});
							add_entry!(
								&candidate,
								fee_to_target_msat,
								$next_hops_value_contribution,
								next_hops_path_htlc_minimum_msat,
								next_hops_path_penalty_msat,
								$next_hops_cltv_delta,
								$next_hops_path_length
							);
						}
					}
				}

				let features = if let Some(node_info) = $node.announcement_info.as_ref() {
					&node_info.features()
				} else {
					&default_node_features
				};

				if !features.requires_unknown_bits() {
					for chan_id in $node.channels.iter() {
						let chan = network_channels.get(chan_id).unwrap();
						if !chan.features.requires_unknown_bits()
							&& chan.contract_id == route_params.rgb_payment.map(|(cid, _)| cid)
						{
							if let Some((directed_channel, source)) = chan.as_directed_to(&$node_id)
							{
								if first_hops.is_none() || *source != our_node_id {
									if directed_channel.direction().enabled {
										let candidate =
											CandidateRouteHop::PublicHop(PublicHopCandidate {
												info: directed_channel,
												short_channel_id: *chan_id,
											});
										add_entry!(
											&candidate,
											fee_to_target_msat,
											$next_hops_value_contribution,
											next_hops_path_htlc_minimum_msat,
											next_hops_path_penalty_msat,
											$next_hops_cltv_delta,
											$next_hops_path_length
										);
									}
								}
							}
						}
					}
				}
			}
		};
	}

	let mut payment_paths = Vec::<PaymentPath>::new();

	// TODO: diversify by nodes (so that all paths aren't doomed if one node is offline).
	'paths_collection: loop {
		// For every new path, start from scratch, except for used_liquidities, which
		// helps to avoid reusing previously selected paths in future iterations.
		targets.clear();
		for e in dist.iter_mut() {
			*e = None;
		}
		for (_, (chans, peer_node_counter)) in first_hop_targets.iter() {
			// In order to avoid looking up whether each node is a first-hop target, we store a
			// dummy entry in dist for each first-hop target, allowing us to do this lookup for
			// free since we're already looking at the `was_processed` flag.
			//
			// Note that all the fields (except `is_first_hop_target`) will be overwritten whenever
			// we find a path to the target, so are left as dummies here.
			dist[*peer_node_counter as usize] = Some(PathBuildingHop {
				candidate: CandidateRouteHop::FirstHop(FirstHopCandidate {
					details: &chans[0],
					payer_node_id: &our_node_id,
					target_node_counter: u32::max_value(),
					payer_node_counter: u32::max_value(),
				}),
				fee_msat: 0,
				next_hops_fee_msat: u64::max_value(),
				hop_use_fee_msat: u64::max_value(),
				total_fee_msat: u64::max_value(),
				path_htlc_minimum_msat: u64::max_value(),
				path_penalty_msat: u64::max_value(),
				was_processed: false,
				is_first_hop_target: true,
				#[cfg(all(not(ldk_bench), any(test, fuzzing)))]
				value_contribution_msat: 0,
			});
		}
		hit_minimum_limit = false;

		// If first hop is a private channel and the only way to reach the payee, this is the only
		// place where it could be added.
		payee_node_id_opt.map(|payee| {
			first_hop_targets.get(&payee).map(|(first_channels, peer_node_counter)| {
				debug_assert_eq!(*peer_node_counter, payee_node_counter);
				for details in first_channels {
					let candidate = CandidateRouteHop::FirstHop(FirstHopCandidate {
						details,
						payer_node_id: &our_node_id,
						payer_node_counter,
						target_node_counter: payee_node_counter,
					});
					let added = add_entry!(&candidate, 0, path_value_msat, 0, 0u64, 0, 0).is_some();
					log_trace!(
						logger,
						"{} direct route to payee via {}",
						if added { "Added" } else { "Skipped" },
						LoggedCandidateHop(&candidate)
					);
				}
			})
		});

		// Add the payee as a target, so that the payee-to-payer
		// search algorithm knows what to start with.
		payee_node_id_opt.map(|payee| match network_nodes.get(&payee) {
			// The payee is not in our network graph, so nothing to add here.
			// There is still a chance of reaching them via last_hops though,
			// so don't yet fail the payment here.
			// If not, targets.pop() will not even let us enter the loop in step 2.
			None => {},
			Some(node) => {
				add_entries_to_cheapest_to_target_node!(node, payee, path_value_msat, 0, 0);
			},
		});

		// Step (2).
		// If a caller provided us with last hops, add them to routing targets. Since this happens
		// earlier than general path finding, they will be somewhat prioritized, although currently
		// it matters only if the fees are exactly the same.
		debug_assert_eq!(
			payment_params.payee.blinded_route_hints().len(),
			introduction_node_id_cache.len(),
			"introduction_node_id_cache was built by iterating the blinded_route_hints, so they should be the same len"
		);
		for (hint_idx, hint) in payment_params.payee.blinded_route_hints().iter().enumerate() {
			// Only add the hops in this route to our candidate set if either
			// we have a direct channel to the first hop or the first hop is
			// in the regular network graph.
			let source_node_opt = introduction_node_id_cache[hint_idx];
			let (source_node_id, source_node_counter) =
				if let Some(v) = source_node_opt { v } else { continue };
			if our_node_id == *source_node_id {
				continue;
			}
			let candidate = if hint.blinded_hops().len() == 1 {
				CandidateRouteHop::OneHopBlinded(OneHopBlindedPathCandidate {
					source_node_counter,
					source_node_id,
					hint,
					hint_idx,
				})
			} else {
				CandidateRouteHop::Blinded(BlindedPathCandidate {
					source_node_counter,
					source_node_id,
					hint,
					hint_idx,
				})
			};
			let mut path_contribution_msat = path_value_msat;
			if let Some(hop_used_msat) =
				add_entry!(&candidate, 0, path_contribution_msat, 0, 0_u64, 0, 0)
			{
				path_contribution_msat = hop_used_msat;
			} else {
				continue;
			}
			if let Some((first_channels, peer_node_counter)) =
				first_hop_targets.get_mut(source_node_id)
			{
				sort_first_hop_channels(
					first_channels,
					&used_liquidities,
					recommended_value_msat,
					our_node_pubkey,
				);
				for details in first_channels {
					let first_hop_candidate = CandidateRouteHop::FirstHop(FirstHopCandidate {
						details,
						payer_node_id: &our_node_id,
						payer_node_counter,
						target_node_counter: *peer_node_counter,
					});
					let blinded_path_fee =
						match compute_fees(path_contribution_msat, candidate.fees()) {
							Some(fee) => fee,
							None => continue,
						};
					let path_min = candidate.htlc_minimum_msat().saturating_add(
						compute_fees_saturating(candidate.htlc_minimum_msat(), candidate.fees()),
					);
					add_entry!(
						&first_hop_candidate,
						blinded_path_fee,
						path_contribution_msat,
						path_min,
						0_u64,
						candidate.cltv_expiry_delta(),
						0
					);
				}
			}
		}
		for route in
			payment_params.payee.unblinded_route_hints().iter().filter(|route| !route.0.is_empty())
		{
			let first_hop_src_id = NodeId::from_pubkey(&route.0.first().unwrap().src_node_id);
			let first_hop_src_is_reachable =
				// Only add the hops in this route to our candidate set if either we are part of
				// the first hop, we have a direct channel to the first hop, or the first hop is in
				// the regular network graph.
				our_node_id == first_hop_src_id ||
				first_hop_targets.get(&first_hop_src_id).is_some() ||
				network_nodes.get(&first_hop_src_id).is_some();
			if first_hop_src_is_reachable {
				// We start building the path from reverse, i.e., from payee
				// to the first RouteHintHop in the path.
				let hop_iter = route.0.iter().rev();
				let prev_hop_iter = core::iter::once(&maybe_dummy_payee_pk)
					.chain(route.0.iter().skip(1).rev().map(|hop| &hop.src_node_id));
				let mut hop_used = true;
				let mut aggregate_next_hops_fee_msat: u64 = 0;
				let mut aggregate_next_hops_path_htlc_minimum_msat: u64 = 0;
				let mut aggregate_next_hops_path_penalty_msat: u64 = 0;
				let mut aggregate_next_hops_cltv_delta: u32 = 0;
				let mut aggregate_next_hops_path_length: u8 = 0;
				let mut aggregate_path_contribution_msat = path_value_msat;

				for (idx, (hop, prev_hop_id)) in hop_iter.zip(prev_hop_iter).enumerate() {
					let (target, private_target_node_counter) =
						node_counters.private_node_counter_from_pubkey(&prev_hop_id)
    						.expect("node_counter_from_pubkey is called on all unblinded_route_hints keys during setup, so is always Some here");
					let (_src_id, private_source_node_counter) =
						node_counters.private_node_counter_from_pubkey(&hop.src_node_id)
							.expect("node_counter_from_pubkey is called on all unblinded_route_hints keys during setup, so is always Some here");

					if let Some((first_channels, _)) = first_hop_targets.get(target) {
						if first_channels
							.iter()
							.any(|d| d.outbound_scid_alias == Some(hop.short_channel_id))
						{
							log_trace!(logger, "Ignoring route hint with SCID {} (and any previous) due to it being a direct channel of ours.",
								hop.short_channel_id);
							break;
						}
					}

					let candidate = network_channels
						.get(&hop.short_channel_id)
						.and_then(|channel| channel.as_directed_to(target))
						.map(|(info, _)| {
							CandidateRouteHop::PublicHop(PublicHopCandidate {
								info,
								short_channel_id: hop.short_channel_id,
							})
						})
						.unwrap_or_else(|| {
							CandidateRouteHop::PrivateHop(PrivateHopCandidate {
								hint: hop,
								target_node_id: target,
								source_node_counter: *private_source_node_counter,
								target_node_counter: *private_target_node_counter,
							})
						});

					if let Some(hop_used_msat) = add_entry!(
						&candidate,
						aggregate_next_hops_fee_msat,
						aggregate_path_contribution_msat,
						aggregate_next_hops_path_htlc_minimum_msat,
						aggregate_next_hops_path_penalty_msat,
						aggregate_next_hops_cltv_delta,
						aggregate_next_hops_path_length
					) {
						aggregate_path_contribution_msat = hop_used_msat;
					} else {
						// If this hop was not used then there is no use checking the preceding
						// hops in the RouteHint. We can break by just searching for a direct
						// channel between last checked hop and first_hop_targets.
						hop_used = false;
					}

					let used_liquidity_msat =
						used_liquidities.get(&candidate.id()).copied().unwrap_or(0);
					let channel_usage = ChannelUsage {
						amount_msat: final_value_msat + aggregate_next_hops_fee_msat,
						inflight_htlc_msat: used_liquidity_msat,
						effective_capacity: candidate.effective_capacity(),
					};
					let channel_penalty_msat =
						scorer.channel_penalty_msat(&candidate, channel_usage, score_params);
					aggregate_next_hops_path_penalty_msat =
						aggregate_next_hops_path_penalty_msat.saturating_add(channel_penalty_msat);

					aggregate_next_hops_cltv_delta =
						aggregate_next_hops_cltv_delta.saturating_add(hop.cltv_expiry_delta as u32);

					aggregate_next_hops_path_length =
						aggregate_next_hops_path_length.saturating_add(1);

					// Searching for a direct channel between last checked hop and first_hop_targets
					if let Some((first_channels, peer_node_counter)) =
						first_hop_targets.get_mut(target)
					{
						sort_first_hop_channels(
							first_channels,
							&used_liquidities,
							recommended_value_msat,
							our_node_pubkey,
						);
						for details in first_channels {
							let first_hop_candidate =
								CandidateRouteHop::FirstHop(FirstHopCandidate {
									details,
									payer_node_id: &our_node_id,
									payer_node_counter,
									target_node_counter: *peer_node_counter,
								});
							add_entry!(
								&first_hop_candidate,
								aggregate_next_hops_fee_msat,
								aggregate_path_contribution_msat,
								aggregate_next_hops_path_htlc_minimum_msat,
								aggregate_next_hops_path_penalty_msat,
								aggregate_next_hops_cltv_delta,
								aggregate_next_hops_path_length
							);
						}
					}

					if !hop_used {
						break;
					}

					// In the next values of the iterator, the aggregate fees already reflects
					// the sum of value sent from payer (final_value_msat) and routing fees
					// for the last node in the RouteHint. We need to just add the fees to
					// route through the current node so that the preceding node (next iteration)
					// can use it.
					let hops_fee =
						compute_fees(aggregate_next_hops_fee_msat + final_value_msat, hop.fees)
							.map_or(None, |inc| inc.checked_add(aggregate_next_hops_fee_msat));
					aggregate_next_hops_fee_msat = if let Some(val) = hops_fee {
						val
					} else {
						break;
					};

					// The next channel will need to relay this channel's min_htlc *plus* the fees taken by
					// this route hint's source node to forward said min over this channel.
					aggregate_next_hops_path_htlc_minimum_msat = {
						let curr_htlc_min = cmp::max(
							candidate.htlc_minimum_msat(),
							aggregate_next_hops_path_htlc_minimum_msat,
						);
						let curr_htlc_min_fee =
							if let Some(val) = compute_fees(curr_htlc_min, hop.fees) {
								val
							} else {
								break;
							};
						if let Some(min) = curr_htlc_min.checked_add(curr_htlc_min_fee) {
							min
						} else {
							break;
						}
					};

					if idx == route.0.len() - 1 {
						// The last hop in this iterator is the first hop in
						// overall RouteHint.
						// If this hop connects to a node with which we have a direct channel,
						// ignore the network graph and, if the last hop was added, add our
						// direct channel to the candidate set.
						//
						// Note that we *must* check if the last hop was added as `add_entry`
						// always assumes that the third argument is a node to which we have a
						// path.
						if let Some((first_channels, peer_node_counter)) =
							first_hop_targets.get_mut(&NodeId::from_pubkey(&hop.src_node_id))
						{
							sort_first_hop_channels(
								first_channels,
								&used_liquidities,
								recommended_value_msat,
								our_node_pubkey,
							);
							for details in first_channels {
								let first_hop_candidate =
									CandidateRouteHop::FirstHop(FirstHopCandidate {
										details,
										payer_node_id: &our_node_id,
										payer_node_counter,
										target_node_counter: *peer_node_counter,
									});
								add_entry!(
									&first_hop_candidate,
									aggregate_next_hops_fee_msat,
									aggregate_path_contribution_msat,
									aggregate_next_hops_path_htlc_minimum_msat,
									aggregate_next_hops_path_penalty_msat,
									aggregate_next_hops_cltv_delta,
									aggregate_next_hops_path_length
								);
							}
						}
					}
				}
			}
		}

		log_trace!(
			logger,
			"Starting main path collection loop with {} nodes pre-filled from first/last hops.",
			targets.len()
		);

		// At this point, targets are filled with the data from first and
		// last hops communicated by the caller, and the payment receiver.
		let mut found_new_path = false;

		// Step (3).
		// If this loop terminates due the exhaustion of targets, two situations are possible:
		// - not enough outgoing liquidity:
		//   0 < already_collected_value_msat < final_value_msat
		// - enough outgoing liquidity:
		//   final_value_msat <= already_collected_value_msat < recommended_value_msat
		// Both these cases (and other cases except reaching recommended_value_msat) mean that
		// paths_collection will be stopped because found_new_path==false.
		// This is not necessarily a routing failure.
		'path_construction: while let Some(RouteGraphNode {
			node_id,
			total_cltv_delta,
			mut value_contribution_msat,
			path_length_to_node,
			..
		}) = targets.pop()
		{
			// Since we're going payee-to-payer, hitting our node as a target means we should stop
			// traversing the graph and arrange the path out of what we found.
			if node_id == our_node_id {
				let mut new_entry = dist[payer_node_counter as usize].take().unwrap();
				let mut ordered_hops: Vec<(PathBuildingHop, NodeFeatures)> =
					vec![(new_entry.clone(), default_node_features.clone())];

				'path_walk: loop {
					let mut features_set = false;
					let candidate = &ordered_hops.last().unwrap().0.candidate;
					let target = candidate.target().unwrap_or(maybe_dummy_payee_node_id);
					let target_node_counter = candidate.target_node_counter();
					if let Some((first_channels, _)) = first_hop_targets.get(&target) {
						for details in first_channels {
							if let CandidateRouteHop::FirstHop(FirstHopCandidate {
								details: last_hop_details,
								..
							}) = candidate
							{
								if details.get_outbound_payment_scid()
									== last_hop_details.get_outbound_payment_scid()
								{
									ordered_hops.last_mut().unwrap().1 =
										details.counterparty.features.to_context();
									features_set = true;
									break;
								}
							}
						}
					}
					if !features_set {
						if let Some(node) = network_nodes.get(&target) {
							if let Some(node_info) = node.announcement_info.as_ref() {
								ordered_hops.last_mut().unwrap().1 = node_info.features().clone();
							} else {
								ordered_hops.last_mut().unwrap().1 = default_node_features.clone();
							}
						} else {
							// We can fill in features for everything except hops which were
							// provided via the invoice we're paying. We could guess based on the
							// recipient's features but for now we simply avoid guessing at all.
						}
					}

					// Means we successfully traversed from the payer to the payee, now
					// save this path for the payment route. Also, update the liquidity
					// remaining on the used hops, so that we take them into account
					// while looking for more paths.
					if target_node_counter.is_none() {
						break 'path_walk;
					}
					if target_node_counter == Some(payee_node_counter) {
						break 'path_walk;
					}

					new_entry = match dist[target_node_counter.unwrap() as usize].take() {
						Some(payment_hop) => payment_hop,
						// We can't arrive at None because, if we ever add an entry to targets,
						// we also fill in the entry in dist (see add_entry!).
						None => unreachable!(),
					};
					// We "propagate" the fees one hop backward (topologically) here,
					// so that fees paid for a HTLC forwarding on the current channel are
					// associated with the previous channel (where they will be subtracted).
					ordered_hops.last_mut().unwrap().0.fee_msat = new_entry.hop_use_fee_msat;
					ordered_hops.push((new_entry.clone(), default_node_features.clone()));
				}
				ordered_hops.last_mut().unwrap().0.fee_msat = value_contribution_msat;
				ordered_hops.last_mut().unwrap().0.hop_use_fee_msat = 0;

				log_trace!(logger, "Found a path back to us from the target with {} hops contributing up to {} msat: \n {:#?}",
					ordered_hops.len(), value_contribution_msat, ordered_hops.iter().map(|h| &(h.0)).collect::<Vec<&PathBuildingHop>>());

				let mut payment_path = PaymentPath { hops: ordered_hops };

				// We could have possibly constructed a slightly inconsistent path: since we reduce
				// value being transferred along the way, we could have violated htlc_minimum_msat
				// on some channels we already passed (assuming dest->source direction). Here, we
				// recompute the fees again, so that if that's the case, we match the currently
				// underpaid htlc_minimum_msat with fees.
				debug_assert_eq!(payment_path.get_value_msat(), value_contribution_msat);
				let desired_value_contribution =
					cmp::min(value_contribution_msat, final_value_msat);
				value_contribution_msat =
					payment_path.update_value_and_recompute_fees(desired_value_contribution);

				// Since a path allows to transfer as much value as
				// the smallest channel it has ("bottleneck"), we should recompute
				// the fees so sender HTLC don't overpay fees when traversing
				// larger channels than the bottleneck. This may happen because
				// when we were selecting those channels we were not aware how much value
				// this path will transfer, and the relative fee for them
				// might have been computed considering a larger value.
				// Remember that we used these channels so that we don't rely
				// on the same liquidity in future paths.
				let mut prevented_redundant_path_selection = false;
				for (hop, _) in payment_path.hops.iter() {
					let spent_on_hop_msat = value_contribution_msat + hop.next_hops_fee_msat;
					let used_liquidity_msat = used_liquidities
						.entry(hop.candidate.id())
						.and_modify(|used_liquidity_msat| *used_liquidity_msat += spent_on_hop_msat)
						.or_insert(spent_on_hop_msat);
					let hop_capacity = hop.candidate.effective_capacity();
					let hop_max_msat =
						max_htlc_from_capacity(hop_capacity, channel_saturation_pow_half);
					if *used_liquidity_msat == hop_max_msat {
						// If this path used all of this channel's available liquidity, we know
						// this path will not be selected again in the next loop iteration.
						prevented_redundant_path_selection = true;
					}
					debug_assert!(*used_liquidity_msat <= hop_max_msat);
				}
				if !prevented_redundant_path_selection {
					// If we weren't capped by hitting a liquidity limit on a channel in the path,
					// we'll probably end up picking the same path again on the next iteration.
					// Decrease the available liquidity of a hop in the middle of the path.
					let victim_candidate =
						&payment_path.hops[(payment_path.hops.len()) / 2].0.candidate;
					let exhausted = u64::max_value();
					log_trace!(logger,
						"Disabling route candidate {} for future path building iterations to avoid duplicates.",
						LoggedCandidateHop(victim_candidate));
					if let Some(scid) = victim_candidate.short_channel_id() {
						*used_liquidities
							.entry(CandidateHopId::Clear((scid, false)))
							.or_default() = exhausted;
						*used_liquidities.entry(CandidateHopId::Clear((scid, true))).or_default() =
							exhausted;
					}
				}

				// Track the total amount all our collected paths allow to send so that we know
				// when to stop looking for more paths
				already_collected_value_msat += value_contribution_msat;

				payment_paths.push(payment_path);
				found_new_path = true;
				break 'path_construction;
			}

			// If we found a path back to the payee, we shouldn't try to process it again. This is
			// the equivalent of the `elem.was_processed` check in
			// add_entries_to_cheapest_to_target_node!() (see comment there for more info).
			if node_id == maybe_dummy_payee_node_id {
				continue 'path_construction;
			}

			// Otherwise, since the current target node is not us,
			// keep "unrolling" the payment graph from payee to payer by
			// finding a way to reach the current target from the payer side.
			match network_nodes.get(&node_id) {
				None => {},
				Some(node) => {
					add_entries_to_cheapest_to_target_node!(
						node,
						node_id,
						value_contribution_msat,
						total_cltv_delta,
						path_length_to_node
					);
				},
			}
		}

		if !allow_mpp {
			if !found_new_path && channel_saturation_pow_half != 0 {
				channel_saturation_pow_half = 0;
				continue 'paths_collection;
			}
			// If we don't support MPP, no use trying to gather more value ever.
			break 'paths_collection;
		}

		// Step (4).
		// Stop either when the recommended value is reached or if no new path was found in this
		// iteration.
		// In the latter case, making another path finding attempt won't help,
		// because we deterministically terminated the search due to low liquidity.
		if !found_new_path && channel_saturation_pow_half != 0 {
			channel_saturation_pow_half = 0;
		} else if !found_new_path
			&& hit_minimum_limit
			&& already_collected_value_msat < final_value_msat
			&& path_value_msat != recommended_value_msat
		{
			log_trace!(logger, "Failed to collect enough value, but running again to collect extra paths with a potentially higher limit.");
			path_value_msat = recommended_value_msat;
		} else if already_collected_value_msat >= recommended_value_msat || !found_new_path {
			log_trace!(logger, "Have now collected {} msat (seeking {} msat) in paths. Last path loop {} a new path.",
				already_collected_value_msat, recommended_value_msat, if found_new_path { "found" } else { "did not find" });
			break 'paths_collection;
		} else if found_new_path
			&& already_collected_value_msat == final_value_msat
			&& payment_paths.len() == 1
		{
			// Further, if this was our first walk of the graph, and we weren't limited by an
			// htlc_minimum_msat, return immediately because this path should suffice. If we were
			// limited by an htlc_minimum_msat value, find another path with a higher value,
			// potentially allowing us to pay fees to meet the htlc_minimum on the new path while
			// still keeping a lower total fee than this path.
			if !hit_minimum_limit {
				log_trace!(logger, "Collected exactly our payment amount on the first pass, without hitting an htlc_minimum_msat limit, exiting.");
				break 'paths_collection;
			}
			log_trace!(logger, "Collected our payment amount on the first pass, but running again to collect extra paths with a potentially higher value to meet htlc_minimum_msat limit.");
			path_value_msat = recommended_value_msat;
		}
	}

	let num_ignored_total = num_ignored_value_contribution
		+ num_ignored_path_length_limit
		+ num_ignored_cltv_delta_limit
		+ num_ignored_previously_failed
		+ num_ignored_avoid_overpayment
		+ num_ignored_htlc_minimum_msat_limit
		+ num_ignored_total_fee_limit;
	if num_ignored_total > 0 {
		log_trace!(logger,
			"Ignored {} candidate hops due to insufficient value contribution, {} due to path length limit, {} due to CLTV delta limit, {} due to previous payment failure, {} due to htlc_minimum_msat limit, {} to avoid overpaying, {} due to maximum total fee limit. Total: {} ignored candidates.",
			num_ignored_value_contribution, num_ignored_path_length_limit,
			num_ignored_cltv_delta_limit, num_ignored_previously_failed,
			num_ignored_htlc_minimum_msat_limit, num_ignored_avoid_overpayment,
			num_ignored_total_fee_limit, num_ignored_total);
	}

	// Step (5).
	if payment_paths.len() == 0 {
		return Err(LightningError {
			err: "Failed to find a path to the given destination".to_owned(),
			action: ErrorAction::IgnoreError,
		});
	}

	if already_collected_value_msat < final_value_msat {
		return Err(LightningError {
			err: "Failed to find a sufficient route to the given destination".to_owned(),
			action: ErrorAction::IgnoreError,
		});
	}

	// Step (6).
	let mut selected_route = payment_paths;

	debug_assert_eq!(
		selected_route.iter().map(|p| p.get_value_msat()).sum::<u64>(),
		already_collected_value_msat
	);
	let mut overpaid_value_msat = already_collected_value_msat - final_value_msat;

	// First, sort by the cost-per-value of the path, dropping the paths that cost the most for
	// the value they contribute towards the payment amount.
	// We sort in descending order as we will remove from the front in `retain`, next.
	selected_route.sort_unstable_by(|a, b| {
		(((b.get_cost_msat() as u128) << 64) / (b.get_value_msat() as u128))
			.cmp(&(((a.get_cost_msat() as u128) << 64) / (a.get_value_msat() as u128)))
	});

	// We should make sure that at least 1 path left.
	let mut paths_left = selected_route.len();
	selected_route.retain(|path| {
		if paths_left == 1 {
			return true;
		}
		let path_value_msat = path.get_value_msat();
		if path_value_msat <= overpaid_value_msat {
			overpaid_value_msat -= path_value_msat;
			paths_left -= 1;
			return false;
		}
		true
	});
	debug_assert!(selected_route.len() > 0);

	if overpaid_value_msat != 0 {
		// Step (7).
		// Now, subtract the remaining overpaid value from the most-expensive path.
		// TODO: this could also be optimized by also sorting by feerate_per_sat_routed,
		// so that the sender pays less fees overall. And also htlc_minimum_msat.
		selected_route.sort_unstable_by(|a, b| {
			let a_f = a
				.hops
				.iter()
				.map(|hop| hop.0.candidate.fees().proportional_millionths as u64)
				.sum::<u64>();
			let b_f = b
				.hops
				.iter()
				.map(|hop| hop.0.candidate.fees().proportional_millionths as u64)
				.sum::<u64>();
			a_f.cmp(&b_f).then_with(|| b.get_cost_msat().cmp(&a.get_cost_msat()))
		});
		let expensive_payment_path = selected_route.first_mut().unwrap();

		// We already dropped all the paths with value below `overpaid_value_msat` above, thus this
		// can't go negative.
		let expensive_path_new_value_msat =
			expensive_payment_path.get_value_msat() - overpaid_value_msat;
		expensive_payment_path.update_value_and_recompute_fees(expensive_path_new_value_msat);
	}

	// Step (8).
	// Sort by the path itself and combine redundant paths.
	// Note that we sort by SCIDs alone as its simpler but when combining we have to ensure we
	// compare both SCIDs and NodeIds as individual nodes may use random aliases causing collisions
	// across nodes.
	selected_route.sort_unstable_by_key(|path| {
		let mut key = [CandidateHopId::Clear((42, true)); MAX_PATH_LENGTH_ESTIMATE as usize];
		debug_assert!(path.hops.len() <= key.len());
		for (scid, key) in path.hops.iter().map(|h| h.0.candidate.id()).zip(key.iter_mut()) {
			*key = scid;
		}
		key
	});
	for idx in 0..(selected_route.len() - 1) {
		if idx + 1 >= selected_route.len() {
			break;
		}
		if iter_equal(
			selected_route[idx].hops.iter().map(|h| (h.0.candidate.id(), h.0.candidate.target())),
			selected_route[idx + 1]
				.hops
				.iter()
				.map(|h| (h.0.candidate.id(), h.0.candidate.target())),
		) {
			let new_value =
				selected_route[idx].get_value_msat() + selected_route[idx + 1].get_value_msat();
			selected_route[idx].update_value_and_recompute_fees(new_value);
			selected_route.remove(idx + 1);
		}
	}

	let mut paths = Vec::new();
	for payment_path in selected_route {
		let mut hops = Vec::with_capacity(payment_path.hops.len());
		for (hop, node_features) in
			payment_path.hops.iter().filter(|(h, _)| h.candidate.short_channel_id().is_some())
		{
			let target =
				hop.candidate.target().expect("target is defined when short_channel_id is defined");
			let maybe_announced_channel = if let CandidateRouteHop::PublicHop(_) = hop.candidate {
				// If we sourced the hop from the graph we're sure the target node is announced.
				true
			} else if let CandidateRouteHop::FirstHop(first_hop) = &hop.candidate {
				// If this is a first hop we also know if it's announced.
				first_hop.details.is_announced
			} else {
				// If we sourced it any other way, we double-check the network graph to see if
				// there are announced channels between the endpoints. If so, the hop might be
				// referring to any of the announced channels, as its `short_channel_id` might be
				// an alias, in which case we don't take any chances here.
				network_graph.node(&target).map_or(false, |hop_node| {
					hop_node.channels.iter().any(|scid| {
						network_graph.channel(*scid).map_or(false, |c| {
							c.as_directed_from(&hop.candidate.source()).is_some()
						})
					})
				})
			};

			hops.push(RouteHop {
				pubkey: PublicKey::from_slice(target.as_slice()).map_err(|_| LightningError {
					err: format!("Public key {:?} is invalid", &target),
					action: ErrorAction::IgnoreAndLog(Level::Trace),
				})?,
				node_features: node_features.clone(),
				short_channel_id: hop.candidate.short_channel_id().unwrap(),
				channel_features: hop.candidate.features(),
				fee_msat: hop.fee_msat,
				cltv_expiry_delta: hop.candidate.cltv_expiry_delta(),
				maybe_announced_channel,
				payment_amount: final_value_msat,
				rgb_amount: None,
			});
		}
		let mut final_cltv_delta = final_cltv_expiry_delta;
		let blinded_tail = payment_path.hops.last().and_then(|(h, _)| {
			if let Some(blinded_path) = h.candidate.blinded_path() {
				final_cltv_delta = h.candidate.cltv_expiry_delta();
				Some(BlindedTail {
					hops: blinded_path.blinded_hops().to_vec(),
					blinding_point: blinded_path.blinding_point(),
					excess_final_cltv_expiry_delta: 0,
					final_value_msat: h.fee_msat,
				})
			} else {
				None
			}
		});
		// Propagate the cltv_expiry_delta one hop backwards since the delta from the current hop is
		// applicable for the previous hop.
		hops.iter_mut().rev().fold(final_cltv_delta, |prev_cltv_expiry_delta, hop| {
			core::mem::replace(&mut hop.cltv_expiry_delta, prev_cltv_expiry_delta)
		});

		paths.push(Path { hops, blinded_tail });
	}
	// Make sure we would never create a route with more paths than we allow.
	debug_assert!(paths.len() <= payment_params.max_path_count.into());

	if let Some(node_features) = payment_params.payee.node_features() {
		for path in paths.iter_mut() {
			path.hops.last_mut().unwrap().node_features = node_features.clone();
		}
	}

	let route = Route { paths, route_params: Some(route_params.clone()) };

	// Make sure we would never create a route whose total fees exceed max_total_routing_fee_msat.
	if let Some(max_total_routing_fee_msat) = route_params.max_total_routing_fee_msat {
		if route.get_total_fees() > max_total_routing_fee_msat {
			return Err(LightningError {
				err: format!(
					"Failed to find route that adheres to the maximum total fee limit of {}msat",
					max_total_routing_fee_msat
				),
				action: ErrorAction::IgnoreError,
			});
		}
	}

	log_info!(logger, "Got route: {}", log_route!(route));
	Ok(route)
}

// When an adversarial intermediary node observes a payment, it may be able to infer its
// destination, if the remaining CLTV expiry delta exactly matches a feasible path in the network
// graph. In order to improve privacy, this method obfuscates the CLTV expiry deltas along the
// payment path by adding a randomized 'shadow route' offset to the final hop.
fn add_random_cltv_offset(
	route: &mut Route, payment_params: &PaymentParameters, network_graph: &ReadOnlyNetworkGraph,
	random_seed_bytes: &[u8; 32],
) {
	let network_channels = network_graph.channels();
	let network_nodes = network_graph.nodes();

	for path in route.paths.iter_mut() {
		let mut shadow_ctlv_expiry_delta_offset: u32 = 0;

		// Remember the last three nodes of the random walk and avoid looping back on them.
		// Init with the last three nodes from the actual path, if possible.
		let mut nodes_to_avoid: [NodeId; 3] = [
			NodeId::from_pubkey(&path.hops.last().unwrap().pubkey),
			NodeId::from_pubkey(&path.hops.get(path.hops.len().saturating_sub(2)).unwrap().pubkey),
			NodeId::from_pubkey(&path.hops.get(path.hops.len().saturating_sub(3)).unwrap().pubkey),
		];

		// Choose the last publicly known node as the starting point for the random walk.
		let mut cur_hop: Option<NodeId> = None;
		let mut path_nonce = [0u8; 12];
		if let Some(starting_hop) = path
			.hops
			.iter()
			.rev()
			.find(|h| network_nodes.contains_key(&NodeId::from_pubkey(&h.pubkey)))
		{
			cur_hop = Some(NodeId::from_pubkey(&starting_hop.pubkey));
			path_nonce.copy_from_slice(&cur_hop.unwrap().as_slice()[..12]);
		}

		// Init PRNG with the path-dependant nonce, which is static for private paths.
		let mut prng = ChaCha20::new(random_seed_bytes, &path_nonce);
		let mut random_path_bytes = [0u8; ::core::mem::size_of::<usize>()];

		// Pick a random path length in [1 .. 3]
		prng.process_in_place(&mut random_path_bytes);
		let random_walk_length =
			usize::from_be_bytes(random_path_bytes).wrapping_rem(3).wrapping_add(1);

		for random_hop in 0..random_walk_length {
			// If we don't find a suitable offset in the public network graph, we default to
			// MEDIAN_HOP_CLTV_EXPIRY_DELTA.
			let mut random_hop_offset = MEDIAN_HOP_CLTV_EXPIRY_DELTA;

			if let Some(cur_node_id) = cur_hop {
				if let Some(cur_node) = network_nodes.get(&cur_node_id) {
					// Randomly choose the next unvisited hop.
					prng.process_in_place(&mut random_path_bytes);
					if let Some(random_channel) = usize::from_be_bytes(random_path_bytes)
						.checked_rem(cur_node.channels.len())
						.and_then(|index| cur_node.channels.get(index))
						.and_then(|id| network_channels.get(id))
					{
						random_channel.as_directed_from(&cur_node_id).map(|(dir_info, next_id)| {
							if !nodes_to_avoid.iter().any(|x| x == next_id) {
								nodes_to_avoid[random_hop] = *next_id;
								random_hop_offset = dir_info.direction().cltv_expiry_delta.into();
								cur_hop = Some(*next_id);
							}
						});
					}
				}
			}

			shadow_ctlv_expiry_delta_offset = shadow_ctlv_expiry_delta_offset
				.checked_add(random_hop_offset)
				.unwrap_or(shadow_ctlv_expiry_delta_offset);
		}

		// Limit the total offset to reduce the worst-case locked liquidity timevalue
		const MAX_SHADOW_CLTV_EXPIRY_DELTA_OFFSET: u32 = 3 * 144;
		shadow_ctlv_expiry_delta_offset =
			cmp::min(shadow_ctlv_expiry_delta_offset, MAX_SHADOW_CLTV_EXPIRY_DELTA_OFFSET);

		// Limit the offset so we never exceed the max_total_cltv_expiry_delta. To improve plausibility,
		// we choose the limit to be the largest possible multiple of MEDIAN_HOP_CLTV_EXPIRY_DELTA.
		let path_total_cltv_expiry_delta: u32 = path.hops.iter().map(|h| h.cltv_expiry_delta).sum();
		let mut max_path_offset =
			payment_params.max_total_cltv_expiry_delta - path_total_cltv_expiry_delta;
		max_path_offset = cmp::max(
			max_path_offset - (max_path_offset % MEDIAN_HOP_CLTV_EXPIRY_DELTA),
			max_path_offset % MEDIAN_HOP_CLTV_EXPIRY_DELTA,
		);
		shadow_ctlv_expiry_delta_offset =
			cmp::min(shadow_ctlv_expiry_delta_offset, max_path_offset);

		// Add 'shadow' CLTV offset to the final hop
		if let Some(tail) = path.blinded_tail.as_mut() {
			tail.excess_final_cltv_expiry_delta = tail
				.excess_final_cltv_expiry_delta
				.checked_add(shadow_ctlv_expiry_delta_offset)
				.unwrap_or(tail.excess_final_cltv_expiry_delta);
		}
		if let Some(last_hop) = path.hops.last_mut() {
			last_hop.cltv_expiry_delta = last_hop
				.cltv_expiry_delta
				.checked_add(shadow_ctlv_expiry_delta_offset)
				.unwrap_or(last_hop.cltv_expiry_delta);
		}
	}
}

/// Construct a route from us (payer) to the target node (payee) via the given hops (which should
/// exclude the payer, but include the payee). This may be useful, e.g., for probing the chosen path.
///
/// Re-uses logic from `find_route`, so the restrictions described there also apply here.
pub fn build_route_from_hops<L: Deref, GL: Deref>(
	our_node_pubkey: &PublicKey, hops: &[PublicKey], route_params: &RouteParameters,
	network_graph: &NetworkGraph<GL>, logger: L, random_seed_bytes: &[u8; 32],
) -> Result<Route, LightningError>
where
	L::Target: Logger,
	GL::Target: Logger,
{
	let graph_lock = network_graph.read_only();
	let mut route = build_route_from_hops_internal(
		our_node_pubkey,
		hops,
		&route_params,
		&graph_lock,
		logger,
		random_seed_bytes,
	)?;
	add_random_cltv_offset(
		&mut route,
		&route_params.payment_params,
		&graph_lock,
		random_seed_bytes,
	);
	Ok(route)
}

fn build_route_from_hops_internal<L: Deref>(
	our_node_pubkey: &PublicKey, hops: &[PublicKey], route_params: &RouteParameters,
	network_graph: &ReadOnlyNetworkGraph, logger: L, random_seed_bytes: &[u8; 32],
) -> Result<Route, LightningError>
where
	L::Target: Logger,
{
	struct HopScorer {
		our_node_id: NodeId,
		hop_ids: [Option<NodeId>; MAX_PATH_LENGTH_ESTIMATE as usize],
	}

	impl ScoreLookUp for HopScorer {
		type ScoreParams = ();
		fn channel_penalty_msat(
			&self, candidate: &CandidateRouteHop, _usage: ChannelUsage,
			_score_params: &Self::ScoreParams,
		) -> u64 {
			let mut cur_id = self.our_node_id;
			for i in 0..self.hop_ids.len() {
				if let Some(next_id) = self.hop_ids[i] {
					if cur_id == candidate.source() && Some(next_id) == candidate.target() {
						return 0;
					}
					cur_id = next_id;
				} else {
					break;
				}
			}
			u64::max_value()
		}
	}

	impl<'a> Writeable for HopScorer {
		#[inline]
		fn write<W: Writer>(&self, _w: &mut W) -> Result<(), io::Error> {
			unreachable!();
		}
	}

	if hops.len() > MAX_PATH_LENGTH_ESTIMATE.into() {
		return Err(LightningError {
			err: "Cannot build a route exceeding the maximum path length.".to_owned(),
			action: ErrorAction::IgnoreError,
		});
	}

	let our_node_id = NodeId::from_pubkey(our_node_pubkey);
	let mut hop_ids = [None; MAX_PATH_LENGTH_ESTIMATE as usize];
	for i in 0..hops.len() {
		hop_ids[i] = Some(NodeId::from_pubkey(&hops[i]));
	}

	let scorer = HopScorer { our_node_id, hop_ids };

	get_route(
		our_node_pubkey,
		route_params,
		network_graph,
		None,
		logger,
		&scorer,
		&Default::default(),
		random_seed_bytes,
	)
}

/*
#[cfg(any(test, ldk_bench))]
pub(crate) mod bench_utils {
	use super::*;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::SecretKey;
	use std::fs::File;
	use std::io::Read;

	use crate::chain::transaction::OutPoint;
	use crate::ln::channel_state::{ChannelCounterparty, ChannelShutdownState};
	use crate::ln::channelmanager;
	use crate::ln::types::ChannelId;
	use crate::routing::scoring::{ProbabilisticScorer, ScoreUpdate};
	use crate::sync::Arc;
	use crate::util::config::UserConfig;
	use crate::util::test_utils::TestLogger;

	/// Tries to open a network graph file, or panics with a URL to fetch it.
	pub(crate) fn get_graph_scorer_file() -> Result<(std::fs::File, std::fs::File), &'static str> {
		let load_file = |fname, err_str| {
			File::open(fname) // By default we're run in RL/lightning
				.or_else(|_| File::open(&format!("lightning/{}", fname))) // We may be run manually in RL/
				.or_else(|_| {
					// Fall back to guessing based on the binary location
					// path is likely something like .../rust-lightning/target/debug/deps/lightning-...
					let mut path = std::env::current_exe().unwrap();
					path.pop(); // lightning-...
					path.pop(); // deps
					path.pop(); // debug
					path.pop(); // target
					path.push("lightning");
					path.push(fname);
					File::open(path)
				})
				.or_else(|_| {
					// Fall back to guessing based on the binary location for a subcrate
					// path is likely something like .../rust-lightning/bench/target/debug/deps/bench..
					let mut path = std::env::current_exe().unwrap();
					path.pop(); // bench...
					path.pop(); // deps
					path.pop(); // debug
					path.pop(); // target
					path.pop(); // bench
					path.push("lightning");
					path.push(fname);
					File::open(path)
				})
				.map_err(|_| err_str)
		};
		let graph_res = load_file(
			"net_graph-2023-12-10.bin",
			"Please fetch https://bitcoin.ninja/ldk-net_graph-v0.0.118-2023-12-10.bin and place it at lightning/net_graph-2023-12-10.bin"
		);
		let scorer_res = load_file(
			"scorer-2023-12-10.bin",
			"Please fetch https://bitcoin.ninja/ldk-scorer-v0.0.118-2023-12-10.bin and place it at lightning/scorer-2023-12-10.bin"
		);
		#[cfg(require_route_graph_test)]
		return Ok((graph_res.unwrap(), scorer_res.unwrap()));
		#[cfg(not(require_route_graph_test))]
		return Ok((graph_res?, scorer_res?));
	}

	pub(crate) fn read_graph_scorer(
		logger: &TestLogger,
	) -> Result<
		(
			Arc<NetworkGraph<&TestLogger>>,
			ProbabilisticScorer<Arc<NetworkGraph<&TestLogger>>, &TestLogger>,
		),
		&'static str,
	> {
		let (mut graph_file, mut scorer_file) = get_graph_scorer_file()?;
		let mut graph_buffer = Vec::new();
		let mut scorer_buffer = Vec::new();
		graph_file.read_to_end(&mut graph_buffer).unwrap();
		scorer_file.read_to_end(&mut scorer_buffer).unwrap();
		let graph = Arc::new(NetworkGraph::read(&mut &graph_buffer[..], logger).unwrap());
		let scorer_args = (Default::default(), Arc::clone(&graph), logger);
		let scorer = ProbabilisticScorer::read(&mut &scorer_buffer[..], scorer_args).unwrap();
		Ok((graph, scorer))
	}

	pub(crate) fn payer_pubkey() -> PublicKey {
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap())
	}

	#[inline]
	pub(crate) fn first_hop(node_id: PublicKey) -> ChannelDetails {
		#[allow(deprecated)] // TODO: Remove once balance_msat is removed.
		ChannelDetails {
			channel_id: ChannelId::new_zero(),
			counterparty: ChannelCounterparty {
				features: channelmanager::provided_init_features(&UserConfig::default()),
				node_id,
				unspendable_punishment_reserve: 0,
				forwarding_info: None,
				outbound_htlc_minimum_msat: None,
				outbound_htlc_maximum_msat: None,
			},
			funding_txo: Some(OutPoint {
				txid: bitcoin::Txid::from_slice(&[0; 32]).unwrap(),
				index: 0,
			}),
			channel_type: None,
			short_channel_id: Some(1),
			inbound_scid_alias: None,
			outbound_scid_alias: None,
			channel_value_satoshis: 10_000_000_000,
			user_channel_id: 0,
			balance_msat: 10_000_000_000,
			outbound_capacity_msat: 10_000_000_000,
			next_outbound_htlc_minimum_msat: 0,
			next_outbound_htlc_limit_msat: 10_000_000_000,
			inbound_capacity_msat: 0,
			unspendable_punishment_reserve: None,
			confirmations_required: None,
			confirmations: None,
			force_close_spend_delay: None,
			is_outbound: true,
			is_channel_ready: true,
			is_usable: true,
			is_announced: true,
			inbound_htlc_minimum_msat: None,
			inbound_htlc_maximum_msat: None,
			config: None,
			feerate_sat_per_1000_weight: None,
			channel_shutdown_state: Some(ChannelShutdownState::NotShuttingDown),
			pending_inbound_htlcs: Vec::new(),
			pending_outbound_htlcs: Vec::new(),
		}
	}

	pub(crate) fn generate_test_routes<S: ScoreLookUp + ScoreUpdate>(
		graph: &NetworkGraph<&TestLogger>, scorer: &mut S, score_params: &S::ScoreParams,
		features: Bolt11InvoiceFeatures, mut seed: u64, starting_amount: u64, route_count: usize,
	) -> Vec<(ChannelDetails, PaymentParameters, u64)> {
		let payer = payer_pubkey();
		let random_seed_bytes = [42; 32];

		let nodes = graph.read_only().nodes().clone();
		let mut route_endpoints = Vec::new();
		for _ in 0..route_count {
			loop {
				seed = seed.overflowing_mul(6364136223846793005).0.overflowing_add(1).0;
				let src = PublicKey::from_slice(
					nodes
						.unordered_keys()
						.skip((seed as usize) % nodes.len())
						.next()
						.unwrap()
						.as_slice(),
				)
				.unwrap();
				seed = seed.overflowing_mul(6364136223846793005).0.overflowing_add(1).0;
				let dst = PublicKey::from_slice(
					nodes
						.unordered_keys()
						.skip((seed as usize) % nodes.len())
						.next()
						.unwrap()
						.as_slice(),
				)
				.unwrap();
				let params = PaymentParameters::from_node_id(dst, 42)
					.with_bolt11_features(features.clone())
					.unwrap();
				let first_hop = first_hop(src);
				let amt_msat = starting_amount + seed % 1_000_000;
				let route_params =
					RouteParameters::from_payment_params_and_value(params.clone(), amt_msat);
				let path_exists = get_route(
					&payer,
					&route_params,
					&graph.read_only(),
					Some(&[&first_hop]),
					&TestLogger::new(),
					scorer,
					score_params,
					&random_seed_bytes,
				)
				.is_ok();
				if path_exists {
					route_endpoints.push((first_hop, params, amt_msat));
					break;
				}
			}
		}

		route_endpoints
	}
}

#[cfg(ldk_bench)]
pub mod benches {
	use super::*;
	use crate::ln::channelmanager;
	use crate::ln::features::Bolt11InvoiceFeatures;
	use crate::routing::gossip::NetworkGraph;
	use crate::routing::scoring::{FixedPenaltyScorer, ProbabilisticScoringFeeParameters};
	use crate::routing::scoring::{ScoreLookUp, ScoreUpdate};
	use crate::util::config::UserConfig;
	use crate::util::logger::{Logger, Record};
	use crate::util::test_utils::TestLogger;

	use criterion::Criterion;

	struct DummyLogger {}
	impl Logger for DummyLogger {
		fn log(&self, _record: Record) {}
	}

	pub fn generate_routes_with_zero_penalty_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, _) = bench_utils::read_graph_scorer(&logger).unwrap();
		let scorer = FixedPenaltyScorer::with_penalty(0);
		generate_routes(
			bench,
			&network_graph,
			scorer,
			&Default::default(),
			Bolt11InvoiceFeatures::empty(),
			0,
			"generate_routes_with_zero_penalty_scorer",
		);
	}

	pub fn generate_mpp_routes_with_zero_penalty_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, _) = bench_utils::read_graph_scorer(&logger).unwrap();
		let scorer = FixedPenaltyScorer::with_penalty(0);
		generate_routes(
			bench,
			&network_graph,
			scorer,
			&Default::default(),
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()),
			0,
			"generate_mpp_routes_with_zero_penalty_scorer",
		);
	}

	pub fn generate_routes_with_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let params = ProbabilisticScoringFeeParameters::default();
		generate_routes(
			bench,
			&network_graph,
			scorer,
			&params,
			Bolt11InvoiceFeatures::empty(),
			0,
			"generate_routes_with_probabilistic_scorer",
		);
	}

	pub fn generate_mpp_routes_with_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let params = ProbabilisticScoringFeeParameters::default();
		generate_routes(
			bench,
			&network_graph,
			scorer,
			&params,
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()),
			0,
			"generate_mpp_routes_with_probabilistic_scorer",
		);
	}

	pub fn generate_large_mpp_routes_with_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let params = ProbabilisticScoringFeeParameters::default();
		generate_routes(
			bench,
			&network_graph,
			scorer,
			&params,
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()),
			100_000_000,
			"generate_large_mpp_routes_with_probabilistic_scorer",
		);
	}

	pub fn generate_routes_with_nonlinear_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let mut params = ProbabilisticScoringFeeParameters::default();
		params.linear_success_probability = false;
		generate_routes(
			bench,
			&network_graph,
			scorer,
			&params,
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()),
			0,
			"generate_routes_with_nonlinear_probabilistic_scorer",
		);
	}

	pub fn generate_mpp_routes_with_nonlinear_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let mut params = ProbabilisticScoringFeeParameters::default();
		params.linear_success_probability = false;
		generate_routes(
			bench,
			&network_graph,
			scorer,
			&params,
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()),
			0,
			"generate_mpp_routes_with_nonlinear_probabilistic_scorer",
		);
	}

	pub fn generate_large_mpp_routes_with_nonlinear_probabilistic_scorer(bench: &mut Criterion) {
		let logger = TestLogger::new();
		let (network_graph, scorer) = bench_utils::read_graph_scorer(&logger).unwrap();
		let mut params = ProbabilisticScoringFeeParameters::default();
		params.linear_success_probability = false;
		generate_routes(
			bench,
			&network_graph,
			scorer,
			&params,
			channelmanager::provided_bolt11_invoice_features(&UserConfig::default()),
			100_000_000,
			"generate_large_mpp_routes_with_nonlinear_probabilistic_scorer",
		);
	}

	fn generate_routes<S: ScoreLookUp + ScoreUpdate>(
		bench: &mut Criterion, graph: &NetworkGraph<&TestLogger>, mut scorer: S,
		score_params: &S::ScoreParams, features: Bolt11InvoiceFeatures, starting_amount: u64,
		bench_name: &'static str,
	) {
		// First, get 100 (source, destination) pairs for which route-getting actually succeeds...
		let route_endpoints = bench_utils::generate_test_routes(
			graph,
			&mut scorer,
			score_params,
			features,
			0xdeadbeef,
			starting_amount,
			50,
		);

		// ...then benchmark finding paths between the nodes we learned.
		do_route_bench(bench, graph, scorer, score_params, bench_name, route_endpoints);
	}

	#[inline(never)]
	fn do_route_bench<S: ScoreLookUp + ScoreUpdate>(
		bench: &mut Criterion, graph: &NetworkGraph<&TestLogger>, scorer: S,
		score_params: &S::ScoreParams, bench_name: &'static str,
		route_endpoints: Vec<(ChannelDetails, PaymentParameters, u64)>,
	) {
		let payer = bench_utils::payer_pubkey();
		let random_seed_bytes = [42; 32];

		let mut idx = 0;
		bench.bench_function(bench_name, |b| {
			b.iter(|| {
				let (first_hop, params, amt) = &route_endpoints[idx % route_endpoints.len()];
				let route_params =
					RouteParameters::from_payment_params_and_value(params.clone(), *amt);
				assert!(get_route(
					&payer,
					&route_params,
					&graph.read_only(),
					Some(&[first_hop]),
					&DummyLogger {},
					&scorer,
					score_params,
					&random_seed_bytes
				)
				.is_ok());
				idx += 1;
			})
		});
	}
}
*/
