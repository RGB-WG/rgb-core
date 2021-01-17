// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use amplify::DumbDefault;
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::io;

use bitcoin::hashes::{sha256, Hmac};
use bitcoin::secp256k1::{PublicKey, Signature};
use bitcoin::{Script, Txid};

use super::payment::{ChannelId, TempChannelId};
use super::Features;
use crate::bp::chain::AssetId;
use crate::bp::{HashLock, HashPreimage};
use crate::lightning_encoding::{self, LightningDecode, LightningEncode};
use crate::lnp::{CreateUnmarshaller, Payload, Unmarshall, Unmarshaller};
use crate::SECP256K1_PUBKEY_DUMB;

#[cfg(feature = "rgb")]
use crate::rgb::Consignment;

lazy_static! {
    pub static ref LNPWP_UNMARSHALLER: Unmarshaller<Messages> =
        Messages::create_unmarshaller();
}

#[derive(Clone, Debug, Display, LnpApi)]
#[lnp_api(encoding = "lightning")]
#[lnpbp_crate(crate)]
#[non_exhaustive]
pub enum Messages {
    // Part I: Generic messages outside of channel operations
    // ======================================================
    /// Once authentication is complete, the first message reveals the features
    /// supported or required by this node, even if this is a reconnection.
    #[lnp_api(type = 16)]
    #[display("init(...)")]
    Init(Init),

    /// For simplicity of diagnosis, it's often useful to tell a peer that
    /// something is incorrect.
    #[lnp_api(type = 17)]
    #[display("error(...)")]
    Error(Error),

    /// In order to allow for the existence of long-lived TCP connections, at
    /// times it may be required that both ends keep alive the TCP connection
    /// at the application level. Such messages also allow obfuscation of
    /// traffic patterns.
    #[lnp_api(type = 18)]
    #[display("ping(...)")]
    Ping(Ping),

    /// The pong message is to be sent whenever a ping message is received. It
    /// serves as a reply and also serves to keep the connection alive, while
    /// explicitly notifying the other end that the receiver is still active.
    /// Within the received ping message, the sender will specify the number of
    /// bytes to be included within the data payload of the pong message.
    #[lnp_api(type = 19)]
    #[display("pong(...)")]
    Pong(Vec<u8>),

    // Part II: Channel management protocol
    // ====================================
    //
    // 1. Channel establishment
    // ------------------------
    #[lnp_api(type = 32)]
    #[display("open_channel(...)")]
    OpenChannel(OpenChannel),

    #[lnp_api(type = 33)]
    #[display("accept_channel(...)")]
    AcceptChannel(AcceptChannel),

    #[lnp_api(type = 34)]
    #[display("funding_created(...)")]
    FundingCreated(FundingCreated),

    #[lnp_api(type = 35)]
    #[display("funding_signed(...)")]
    FundingSigned(FundingSigned),

    #[lnp_api(type = 36)]
    #[display("funding_locked(...)")]
    FundingLocked(FundingLocked),

    #[lnp_api(type = 38)]
    #[display("shutdown(...)")]
    Shutdown(Shutdown),

    #[lnp_api(type = 39)]
    #[display("closing_signed(...)")]
    ClosingSigned(ClosingSigned),

    // 2. Normal operations
    // --------------------
    #[lnp_api(type = 128)]
    #[display("update_add_htlc(...)")]
    UpdateAddHtlc(UpdateAddHtlc),

    #[lnp_api(type = 130)]
    #[display("update_fulfill_htlc(...)")]
    UpdateFulfillHtlc(UpdateFulfillHtlc),

    #[lnp_api(type = 131)]
    #[display("update_fail_htlc(...)")]
    UpdateFailHtlc(UpdateFailHtlc),

    #[lnp_api(type = 135)]
    #[display("update_fail_malformed_htlc(...)")]
    UpdateFailMalformedHtlc(UpdateFailMalformedHtlc),

    #[lnp_api(type = 132)]
    #[display("commitment_signed(...)")]
    CommitmentSigned(CommitmentSigned),

    #[lnp_api(type = 133)]
    #[display("revoke_and_ack(...)")]
    RevokeAndAck(RevokeAndAck),

    #[lnp_api(type = 134)]
    #[display("update_fee(...)")]
    UpdateFee(UpdateFee),

    #[lnp_api(type = 136)]
    #[display("channel_reestablish(...)")]
    ChannelReestablish(ChannelReestablish),

    // 3. RGB
    // ------
    #[cfg(feature = "rgb")]
    #[lnp_api(type = 57156)]
    #[display("assign_funds(...)")]
    AssignFunds(AssignFunds),
}

/// Once authentication is complete, the first message reveals the features
/// supported or required by this node, even if this is a reconnection.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-init-message>
#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display("init({global_features}, {local_features}, {assets:#?})")]
pub struct Init {
    pub global_features: Features,
    pub local_features: Features,
    #[tlv(type = 1)]
    pub assets: HashSet<AssetId>,
    /* #[tlv(unknown)]
     * pub unknown_tlvs: BTreeMap<tlv::Type, tlv::RawRecord>, */
}

/// In order to allow for the existence of long-lived TCP connections, at
/// times it may be required that both ends keep alive the TCP connection
/// at the application level. Such messages also allow obfuscation of
/// traffic patterns.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-ping-and-pong-messages>
#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct Ping {
    pub ignored: Vec<u8>,
    pub pong_size: u16,
}

/// For simplicity of diagnosis, it's often useful to tell a peer that something
/// is incorrect.
///
/// # Specification
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#the-error-message>
#[derive(Clone, PartialEq, Debug, Error, LightningEncode, LightningDecode)]
#[lnpbp_crate(crate)]
pub struct Error {
    /// The channel is referred to by channel_id, unless channel_id is 0 (i.e.
    /// all bytes are 0), in which case it refers to all channels.
    pub channel_id: Option<ChannelId>,

    /// Any specific error details, either as string or binary data
    pub data: Vec<u8>,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Error")?;
        if let Some(channel_id) = self.channel_id {
            write!(f, " on channel {}", channel_id)?;
        } else {
            f.write_str(" on all channels")?;
        }
        // NB: if data is not composed solely of printable ASCII characters (For
        // reference: the printable character set includes byte values 32
        // through 126, inclusive) SHOULD NOT print out data verbatim.
        if let Ok(msg) = String::from_utf8(self.data.clone()) {
            write!(f, ": {}", msg)?;
        }
        Ok(())
    }
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct OpenChannel {
    /// The genesis hash of the blockchain where the channel is to be opened
    pub chain_hash: AssetId,

    /// A temporary channel ID, until the funding outpoint is announced
    pub temporary_channel_id: TempChannelId,

    /// The channel value
    pub funding_satoshis: u64,

    /// The amount to push to the counterparty as part of the open, in
    /// milli-satoshi
    pub push_msat: u64,

    /// The threshold below which outputs on transactions broadcast by sender
    /// will be omitted
    pub dust_limit_satoshis: u64,

    /// The maximum inbound HTLC value in flight towards sender, in
    /// milli-satoshi
    pub max_htlc_value_in_flight_msat: u64,

    /// The minimum value unencumbered by HTLCs for the counterparty to keep
    /// in the channel
    pub channel_reserve_satoshis: u64,

    /// The minimum HTLC size incoming to sender, in milli-satoshi
    pub htlc_minimum_msat: u64,

    /// The fee rate per 1000-weight of sender generated transactions, until
    /// updated by update_fee
    pub feerate_per_kw: u32,

    /// The number of blocks which the counterparty will have to wait to claim
    /// on-chain funds if they broadcast a commitment transaction
    pub to_self_delay: u16,

    /// The maximum number of inbound HTLCs towards sender
    pub max_accepted_htlcs: u16,

    /// The sender's key controlling the funding transaction
    pub funding_pubkey: PublicKey,

    /// Used to derive a revocation key for transactions broadcast by
    /// counterparty
    pub revocation_basepoint: PublicKey,

    /// A payment key to sender for transactions broadcast by counterparty
    pub payment_point: PublicKey,

    /// Used to derive a payment key to sender for transactions broadcast by
    /// sender
    pub delayed_payment_basepoint: PublicKey,

    /// Used to derive an HTLC payment key to sender
    pub htlc_basepoint: PublicKey,

    /// The first to-be-broadcast-by-sender transaction's per commitment point
    pub first_per_commitment_point: PublicKey,

    /// Channel flags
    pub channel_flags: u8,
    /* TODO: Uncomment once TLVs derivation will be implemented
     * /// Optionally, a request to pre-set the to-sender output's
     * scriptPubkey /// for when we collaboratively close
     * #[lnpwp(tlv=0)]
     * pub shutdown_scriptpubkey: Option<Script>, */

    /* #[lpwpw(unknown_tlvs)]
     * pub unknown_tlvs: BTreeMap<u64, Vec<u8>>, */
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct AcceptChannel {
    /// A temporary channel ID, until the funding outpoint is announced
    pub temporary_channel_id: TempChannelId,

    /// The threshold below which outputs on transactions broadcast by sender
    /// will be omitted
    pub dust_limit_satoshis: u64,

    /// The maximum inbound HTLC value in flight towards sender, in
    /// milli-satoshi
    pub max_htlc_value_in_flight_msat: u64,

    /// The minimum value unencumbered by HTLCs for the counterparty to keep in
    /// the channel
    pub channel_reserve_satoshis: u64,

    /// The minimum HTLC size incoming to sender, in milli-satoshi
    pub htlc_minimum_msat: u64,

    /// Minimum depth of the funding transaction before the channel is
    /// considered open
    pub minimum_depth: u32,

    /// The number of blocks which the counterparty will have to wait to claim
    /// on-chain funds if they broadcast a commitment transaction
    pub to_self_delay: u16,

    /// The maximum number of inbound HTLCs towards sender
    pub max_accepted_htlcs: u16,

    /// The sender's key controlling the funding transaction
    pub funding_pubkey: PublicKey,

    /// Used to derive a revocation key for transactions broadcast by
    /// counterparty
    pub revocation_basepoint: PublicKey,

    /// A payment key to sender for transactions broadcast by counterparty
    pub payment_point: PublicKey,

    /// Used to derive a payment key to sender for transactions broadcast by
    /// sender
    pub delayed_payment_basepoint: PublicKey,

    /// Used to derive an HTLC payment key to sender for transactions broadcast
    /// by counterparty
    pub htlc_basepoint: PublicKey,

    /// The first to-be-broadcast-by-sender transaction's per commitment point
    pub first_per_commitment_point: PublicKey,
    /* TODO: Uncomment once TLVs derivation will be implemented
     * /// Optionally, a request to pre-set the to-sender output's
     * scriptPubkey /// for when we collaboratively close
     * #[lnpwp(tlv=0)]
     * pub shutdown_scriptpubkey: Option<Script>,
     * #[lpwpw(unknown_tlvs)]
     * pub unknown_tlvs: BTreeMap<u64, Vec<u8>>, */
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct FundingCreated {
    /// A temporary channel ID, until the funding is established
    pub temporary_channel_id: TempChannelId,

    /// The funding transaction ID
    pub funding_txid: Txid,

    /// The specific output index funding this channel
    pub funding_output_index: u16,

    /// The signature of the channel initiator (funder) on the funding
    /// transaction
    pub signature: Signature,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct FundingSigned {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The signature of the channel acceptor on the funding transaction
    pub signature: Signature,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct FundingLocked {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The per-commitment point of the second commitment transaction
    pub next_per_commitment_point: PublicKey,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct Shutdown {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The destination of this peer's funds on closing.
    /// Must be in one of these forms: p2pkh, p2sh, p2wpkh, p2wsh.
    pub scriptpubkey: Script,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct ClosingSigned {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The proposed total fee for the closing transaction
    pub fee_satoshis: u64,

    /// A signature on the closing transaction
    pub signature: Signature,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct UpdateAddHtlc {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The HTLC ID
    pub htlc_id: u64,

    /// The HTLC value in milli-satoshi
    pub amount_msat: u64,

    /// The payment hash, the pre-image of which controls HTLC redemption
    pub payment_hash: HashLock,

    /// The expiry height of the HTLC
    pub cltv_expiry: u32,

    /// An obfuscated list of hops and instructions for each hop along the
    /// path. It commits to the HTLC by setting the payment_hash as associated
    /// data, i.e. includes the payment_hash in the computation of HMACs. This
    /// prevents replay attacks that would reuse a previous
    /// onion_routing_packet with a different payment_hash.
    pub onion_routing_packet: OnionPacket,

    /// RGB Extension: TLV
    #[cfg(feature = "rgb")]
    pub asset_id: Option<AssetId>,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct UpdateFulfillHtlc {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The HTLC ID
    pub htlc_id: u64,

    /// The pre-image of the payment hash, allowing HTLC redemption
    pub payment_preimage: HashPreimage,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct UpdateFailHtlc {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The HTLC ID
    pub htlc_id: u64,

    /// The reason field is an opaque encrypted blob for the benefit of the
    /// original HTLC initiator, as defined in BOLT #4; however, there's a
    /// special malformed failure variant for the case where the peer couldn't
    /// parse it: in this case the current node instead takes action,
    /// encrypting it into a update_fail_htlc for relaying.
    pub reason: Vec<u8>,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct UpdateFailMalformedHtlc {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The HTLC ID
    pub htlc_id: u64,

    /// SHA256 hash of onion data
    pub sha256_of_onion: sha256::Hash,

    /// The failure code
    pub failure_code: u16,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct CommitmentSigned {
    /// The channel ID
    pub channel_id: ChannelId,

    /// A signature on the commitment transaction
    pub signature: Signature,

    /// Signatures on the HTLC transactions
    pub htlc_signatures: Vec<Signature>,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct RevokeAndAck {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The secret corresponding to the per-commitment point
    pub per_commitment_secret: [u8; 32],

    /// The next sender-broadcast commitment transaction's per-commitment point
    pub next_per_commitment_point: PublicKey,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct UpdateFee {
    /// The channel ID
    pub channel_id: ChannelId,

    /// Fee rate per 1000-weight of the transaction
    pub feerate_per_kw: u32,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct ChannelReestablish {
    /// The channel ID
    pub channel_id: ChannelId,

    /// The next commitment number for the sender
    pub next_commitment_number: u64,

    /// The next commitment number for the recipient
    pub next_revocation_number: u64,

    /// Proof that the sender knows the per-commitment secret of a specific
    /// commitment transaction belonging to the recipient
    pub your_last_per_commitment_secret: [u8; 32],

    /// The sender's per-commitment point for their current commitment
    /// transaction
    pub my_current_per_commitment_point: PublicKey,
}

#[cfg(feature = "rgb")]
#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct AssignFunds {
    /// The channel ID
    pub channel_id: ChannelId,

    /// Consignment
    pub consignment: Consignment,

    /// Outpoint containing assignments
    pub outpoint: OutPoint,

    /// Blinding factor to decode concealed outpoint
    pub blinding: u64,
}

impl LightningEncode for Messages {
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, io::Error> {
        Payload::from(self.clone()).lightning_encode(e)
    }
}

impl LightningDecode for Messages {
    fn lightning_decode<D: io::Read>(
        d: D,
    ) -> Result<Self, lightning_encoding::Error> {
        Ok((&*LNPWP_UNMARSHALLER
            .unmarshall(&Vec::<u8>::lightning_decode(d)?)
            .map_err(|err| {
                lightning_encoding::Error::DataIntegrityError(s!(
                    "can't unmarshall LMP message"
                ))
            })?)
            .clone())
    }
}

impl DumbDefault for OpenChannel {
    fn dumb_default() -> Self {
        OpenChannel {
            chain_hash: none!(),
            temporary_channel_id: TempChannelId::dumb_default(),
            funding_satoshis: 0,
            push_msat: 0,
            dust_limit_satoshis: 0,
            max_htlc_value_in_flight_msat: 0,
            channel_reserve_satoshis: 0,
            htlc_minimum_msat: 0,
            feerate_per_kw: 0,
            to_self_delay: 0,
            max_accepted_htlcs: 0,
            funding_pubkey: *SECP256K1_PUBKEY_DUMB,
            revocation_basepoint: *SECP256K1_PUBKEY_DUMB,
            payment_point: *SECP256K1_PUBKEY_DUMB,
            delayed_payment_basepoint: *SECP256K1_PUBKEY_DUMB,
            htlc_basepoint: *SECP256K1_PUBKEY_DUMB,
            first_per_commitment_point: *SECP256K1_PUBKEY_DUMB,
            channel_flags: 0,
            /* shutdown_scriptpubkey: None,
             * unknown_tlvs: none!(), */
        }
    }
}

#[derive(
    Clone, PartialEq, Eq, Debug, Display, LightningEncode, LightningDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct OnionPacket {
    pub version: u8,
    pub public_key: bitcoin::secp256k1::PublicKey,
    pub hop_data: Vec<u8>, //[u8; 20 * 65],
    pub hmac: Hmac<sha256::Hash>,
}

impl DumbDefault for OnionPacket {
    fn dumb_default() -> Self {
        OnionPacket {
            version: 0,
            public_key: *SECP256K1_PUBKEY_DUMB,
            hop_data: empty!(),
            hmac: zero!(),
        }
    }
}
