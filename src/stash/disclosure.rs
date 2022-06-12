// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Disclosure is the way to make certain confidential information about the
//! stash public.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io;
use std::str::FromStr;

use amplify::Wrapper;
use bitcoin::hashes::{self, sha256, sha256t, Hash, HashEngine};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::PublicKey;
use bp::dbc::{Anchor, AnchorId};
use commit_verify::{
    commit_encode, lnpbp4, CommitEncode, CommitVerify, ConsensusCommit, PrehashedProtocol,
    TaggedHash,
};
use lnpbp::bech32::{self, FromBech32Str, ToBech32String};
use strict_encoding::StrictEncode;

use crate::contract::seal::Confidential;
use crate::{ConcealAnchors, ConcealSeals, ConcealState, ContractId, Extension, Transition};

pub const RGB_DISCLOSURE_VERSION: u16 = 0;

// TODO #62: Change the value
static MIDSTATE_DISCLOSURE_ID: [u8; 32] = [
    8, 36, 37, 167, 51, 70, 76, 241, 171, 132, 169, 56, 76, 108, 174, 226, 197, 98, 75, 254, 29,
    125, 170, 233, 184, 121, 13, 183, 90, 51, 134, 6,
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
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
    StrictDecode
)]
#[wrapper(Debug, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[display(DisclosureId::to_bech32_string)]
pub struct DisclosureId(sha256t::Hash<DisclosureIdTag>);

// TODO: Use tagged protocol
impl<Msg> CommitVerify<Msg, PrehashedProtocol> for DisclosureId
where Msg: AsRef<[u8]>
{
    #[inline]
    fn commit(msg: &Msg) -> DisclosureId { DisclosureId::hash(msg) }
}

impl commit_encode::Strategy for DisclosureId {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl bech32::Strategy for DisclosureId {
    const HRP: &'static str = "id";
    type Strategy = bech32::strategies::UsingStrictEncoding;
}

impl FromStr for DisclosureId {
    type Err = bech32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> { DisclosureId::from_bech32_str(s) }
}

// TODO #62: Change the value
static MIDSTATE_SIG_HASH: [u8; 32] = [
    8, 36, 37, 167, 51, 70, 76, 241, 171, 132, 169, 56, 76, 108, 174, 226, 197, 98, 75, 254, 29,
    125, 170, 233, 184, 121, 13, 183, 90, 51, 134, 6,
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
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
    StrictDecode
)]
#[wrapper(Debug, LowerHex, BorrowSlice, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[display(LowerHex)]
pub struct SigHash(sha256t::Hash<SigHashTag>);

impl Hash for SigHash {
    type Engine = <sha256t::Hash<SigHashTag> as Hash>::Engine;
    type Inner = <sha256t::Hash<SigHashTag> as Hash>::Inner;
    const LEN: usize = sha256t::Hash::<SigHashTag>::LEN;

    fn from_engine(e: Self::Engine) -> Self { <Self as Wrapper>::Inner::from_engine(e).into() }

    fn from_slice(sl: &[u8]) -> Result<Self, hashes::Error> {
        <Self as Wrapper>::Inner::from_slice(sl).map(Wrapper::from_inner)
    }

    fn into_inner(self) -> Self::Inner { Wrapper::into_inner(self).into_inner() }

    fn as_inner(&self) -> &Self::Inner { Wrapper::as_inner(self).as_inner() }

    fn from_inner(inner: Self::Inner) -> Self { <Self as Wrapper>::Inner::from_inner(inner).into() }
}

/// Disclosure purpose is to expose a set of stash data related to number of
/// RGB contracts to some external entity – or store them outside of the stash
/// to be merged lately upon a certain event (for instance, withness transaction
/// being mined or receiving a signature for the updated channel state from an
/// LN channel counterparty).
///
/// MB: We are limited by 16-bit integer size for the number of anchors and
/// extensions to disclose, but this is fine since we can produce multiple
/// disclosures when needed
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[derive(Getters, Clone, PartialEq, Debug, Default, StrictEncode, StrictDecode)]
pub struct Disclosure {
    /// Since these are not consensus-critical data structure (we never commit
    /// to it) we can use encoding versioning here
    version: u8,

    /// State transitions organized by anchor and then RGB contract
    transitions: BTreeMap<
        AnchorId,
        (
            Anchor<lnpbp4::MerkleBlock>,
            BTreeMap<ContractId, Transition>,
        ),
    >,

    /// State extensions organized by RGB contract
    extensions: BTreeMap<ContractId, Vec<Extension>>,

    /// Optional human-readable comment on the nature of the disclosed data
    comment: Option<String>,

    /// Signatures over all fields (apart from the signature itself) which may
    /// be used for proving the source of the disclosure and for attributing
    /// client-validated data which are the part of the disclosure
    ///
    /// Map also provides the source of the key used for the signature.
    /// The key may be the same key which is used inside one of the
    /// anchors within the disclosure, which perfectly attributes signer
    /// with one of the previous owners of the disclosure data. Otherwise
    /// the attribution is external to the disclosure.
    ///
    /// NB: For Schnorr keys ECDSA signature still has to be used here.
    signatures: BTreeMap<PublicKey, Signature>,
}

impl CommitEncode for Disclosure {
    fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
        // 1. Do not conceal data: two disclosures exposing different data
        //    from the same sources MUST have different disclosure ids
        // 2. Do not include comment
        // 3. Do not include signature (since the signature signs commitment id
        //    + comment commitment)
        (|| -> Result<usize, strict_encoding::Error> {
            Ok(strict_encode_list!(e; self.version, self.transitions, self.extensions))
        })()
        .expect("Commit encoding is in-memory encoding and must not fail")
    }
}

impl ConsensusCommit for Disclosure {
    type Commitment = DisclosureId;
}

impl ConcealSeals for Disclosure {
    fn conceal_seals(&mut self, seals: &[Confidential]) -> usize {
        self.transitions
            .iter_mut()
            .fold(0usize, |count, (_, (_, map))| {
                map.iter_mut().fold(count, |count, (_, transition)| {
                    count + transition.conceal_seals(seals)
                })
            })
    }
}

impl ConcealState for Disclosure {
    fn conceal_state_except(&mut self, seals: &[Confidential]) -> usize {
        self.transitions
            .iter_mut()
            .fold(0usize, |count, (_, (_, map))| {
                map.iter_mut().fold(count, |count, (_, transition)| {
                    count + transition.conceal_state_except(seals)
                })
            })
    }
}

impl ConcealAnchors for Disclosure {
    fn conceal_anchors_except(
        &mut self,
        contracts: impl AsRef<[ContractId]>,
    ) -> Result<usize, lnpbp4::LeafNotKnown> {
        let mut count = 0usize;
        for (_, (anchor, _)) in &mut self.transitions {
            count += anchor.conceal_anchors_except(contracts.as_ref())?;
        }
        Ok(count)
    }
}

impl Disclosure {
    pub fn insert_anchored_transitions(
        &mut self,
        anchor: Anchor<lnpbp4::MerkleBlock>,
        transitions: BTreeMap<ContractId, Transition>,
    ) {
        self.signatures = empty!();
        match self.transitions.entry(anchor.anchor_id()) {
            Entry::Vacant(entry) => {
                entry.insert((anchor, transitions));
            }
            Entry::Occupied(mut entry) => {
                let (a, t) = entry.get_mut();
                *a = anchor.merge_reveal(a.clone()).expect(
                    "Anchor into_revealed procedure is broken for anchors with the same id",
                );
                t.extend(transitions);
            }
        }
    }

    pub fn insert_extensions(&mut self, contract_id: ContractId, extensions: Vec<Extension>) {
        self.signatures = empty!();
        self.extensions
            .entry(contract_id)
            .or_insert(empty!())
            .extend(extensions);
    }

    pub fn change_comment(&mut self, comment: String) -> bool {
        self.signatures = empty!();
        let had_comment = self.comment.is_some();
        self.comment = Some(comment);
        had_comment
    }

    pub fn remove_comment(&mut self) -> bool {
        self.signatures = empty!();
        let had_comment = self.comment.is_some();
        self.comment = None;
        had_comment
    }

    pub fn sig_hash(&self) -> SigHash {
        let mut engine = SigHash::engine();
        self.commit_encode(&mut engine);
        if let Some(ref comment) = self.comment {
            engine.input(&sha256::Hash::hash(comment.as_bytes()))
        }
        SigHash::from_engine(engine)
    }

    pub fn add_signature(&mut self, pubkey: PublicKey, signature: Signature) -> Option<Signature> {
        self.signatures.insert(pubkey, signature)
    }

    pub fn remove_signature(&mut self, pubkey: PublicKey) -> Option<Signature> {
        self.signatures.remove(&pubkey)
    }

    #[inline]
    pub fn empty_signatures(&mut self) -> usize {
        let count = self.signatures.len();
        self.signatures = empty!();
        count
    }
}

// TODO #63: Validate disclosures
