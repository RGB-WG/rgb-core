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

//! Disclosure is the way to make certain confidential information about the
//! stash public.

use std::collections::BTreeMap;
use std::io;
use std::str::FromStr;

use bitcoin::hashes::{sha256, sha256t};
use bitcoin::secp256k1::{PublicKey, Signature};
use lnpbp::bech32::{self, FromBech32Str, ToBech32String};
use lnpbp::client_side_validation::{
    commit_strategy, CommitEncode, CommitEncodeWithStrategy, ConsensusCommit,
};
use lnpbp::commit_verify::CommitVerify;
use lnpbp::TaggedHash;

use crate::contract::seal::Confidential;
use crate::contract::ConcealSeals;
use crate::{
    Anchor, AnchorId, ConcealState, ContractId, Extension, Transition,
};

pub const RGB_DISCLOSURE_VERSION: u16 = 0;

// TODO: Change the value
static MIDSTATE_DISCLOSURE_ID: [u8; 32] = [
    8, 36, 37, 167, 51, 70, 76, 241, 171, 132, 169, 56, 76, 108, 174, 226, 197,
    98, 75, 254, 29, 125, 170, 233, 184, 121, 13, 183, 90, 51, 134, 6,
];

/// Tag used for [`DisclosureId`] hash types
pub struct DisclosureIdTag;

impl sha256t::Tag for DisclosureIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_DISCLOSURE_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Unique disclosure identifier equivalent to the commitment hash
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Wrapper,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[wrapper(Debug, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[display(DisclosureId::to_bech32_string)]
pub struct DisclosureId(sha256t::Hash<DisclosureIdTag>);

impl<MSG> CommitVerify<MSG> for DisclosureId
where
    MSG: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &MSG) -> DisclosureId {
        DisclosureId::hash(msg)
    }
}

impl CommitEncodeWithStrategy for DisclosureId {
    type Strategy = commit_strategy::UsingStrict;
}

impl bech32::Strategy for DisclosureId {
    const HRP: &'static str = "id";
    type Strategy = bech32::strategies::UsingStrictEncoding;
}

impl FromStr for DisclosureId {
    type Err = bech32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DisclosureId::from_bech32_str(s)
    }
}

// TODO: Change the value
static MIDSTATE_SIG_HASH: [u8; 32] = [
    8, 36, 37, 167, 51, 70, 76, 241, 171, 132, 169, 56, 76, 108, 174, 226, 197,
    98, 75, 254, 29, 125, 170, 233, 184, 121, 13, 183, 90, 51, 134, 6,
];

/// Tag used for [`SigHash`] hash types
pub struct SigHashTag;

impl sha256t::Tag for SigHashTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_SIG_HASH);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Disclosure sig hash
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Wrapper,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[wrapper(Debug, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[display(LowerHex)]
pub struct SigHash(sha256t::Hash<SigHashTag>);

// We are limited by 16-bit integer size for the number of anchors and
// extensions to disclose, but this is fine since we can produce multiple
// disclosures when needed
#[derive(
    Getters, Clone, PartialEq, Debug, Default, StrictEncode, StrictDecode,
)]
pub struct Disclosure {
    version: u16,
    transitions: BTreeMap<Anchor, BTreeMap<ContractId, Transition>>,
    extensions: BTreeMap<ContractId, Extension>,
    comment: Option<String>,
    signature: Option<Signature>,
    sig_source: Option<AnchorId>,
}

impl CommitEncode for Disclosure {
    fn commit_encode<E: io::Write>(&self, e: E) -> usize {
        // 1. Do not conceal data: two disclosures exposing different data
        //    from the same sources MUST have different disclosure ids
        // 2. Do not include comment
        // 3. Do not include signature (since the signature signs commitment id
        //    + comment commitment)
        unimplemented!()
    }
}

impl ConsensusCommit for Disclosure {
    type Commitment = DisclosureId;
}

impl ConcealSeals for Disclosure {
    fn conceal_seals(&mut self, seals: &Vec<Confidential>) -> usize {
        unimplemented!()
    }
}

impl ConcealState for Disclosure {
    fn conceal_state_except(&mut self, seals: &Vec<Confidential>) -> usize {
        unimplemented!()
    }
}

// TODO: Create trait and add it to Consignment as well
pub trait ConcealAnchors {}
impl ConcealAnchors for Disclosure {}

impl Disclosure {
    pub fn insert_anchored_transitions(&mut self) -> usize {
        unimplemented!()
    }

    pub fn insert_extensions(&mut self) -> usize {
        unimplemented!()
    }

    pub fn change_comment(&mut self, comment: &str) -> bool {
        unimplemented!()
    }

    pub fn sig_hash(&self) -> SigHash {
        // Do a disclosure::SigHash type, which should be a tagged hash
        // combining comment and disclosure commitment id
        unimplemented!()
    }

    pub fn set_signature(
        &mut self,
        pubkey: PublicKey,
        signature: Signature,
        sig_source: Option<AnchorId>,
    ) -> bool {
        unimplemented!()
    }
}
