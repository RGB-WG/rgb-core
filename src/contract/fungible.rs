// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2023 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This mod represents **atomic rational values** (or, simply just **value**),
//! it a value representing a portion of something whole with a certain fixed
//! level of precision (atomicity). Such values are commonly used to represent
//! some coins of fungible tokens, where each coin or token consists of an
//! integer number of atomic subdivisions of the total supply (like satoshis in
//! bitcoin represent just a portion, i.e. fixed-percision rational number, of
//! the total possible bitcoin supply). Such numbers demonstrate constant
//! properties regarding their total sum and, thus, can be made confidential
//! using elliptic curve homomorphic cryptography such as Pedesen commitments.

use core::cmp::Ordering;
use core::fmt::Debug;
use core::num::ParseIntError;
use core::ops::Deref;
use core::str::FromStr;
use std::io;
use std::io::Write;

use amplify::hex::ToHex;
// We do not import particular modules to keep aware with namespace prefixes
// that we do not use the standard secp256k1zkp library
use amplify::{hex, Array, Bytes32, Wrapper};
use bp::secp256k1::rand::thread_rng;
use commit_verify::{CommitEncode, CommitVerify, CommitmentProtocol, Conceal, UntaggedProtocol};
use secp256k1_zkp::rand::{Rng, RngCore};
use secp256k1_zkp::SECP256K1;
use strict_encoding::{
    DecodeError, ReadTuple, StrictDecode, StrictDumb, StrictEncode, TypedRead, TypedWrite,
    WriteTuple,
};

use super::{ConfidentialState, ExposedState};
use crate::{schema, StateCommitment, StateData, StateType, LIB_NAME_RGB};

/// An atom of an additive state, which thus can be monomorphically encrypted.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum FungibleState {
    /// 64-bit value.
    #[from]
    #[strict_type(tag = 8)] // Matches strict types U64 primitive value
    Bits64(u64),
    // When/if adding more variants do not forget to re-write FromStr impl
}

impl Default for FungibleState {
    fn default() -> Self { FungibleState::Bits64(0) }
}

impl From<RevealedValue> for FungibleState {
    fn from(revealed: RevealedValue) -> Self { revealed.value }
}

impl FromStr for FungibleState {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { s.parse().map(FungibleState::Bits64) }
}

impl From<FungibleState> for u64 {
    fn from(value: FungibleState) -> Self {
        match value {
            FungibleState::Bits64(val) => val,
        }
    }
}

impl FungibleState {
    pub fn fungible_type(&self) -> schema::FungibleType {
        match self {
            FungibleState::Bits64(_) => schema::FungibleType::Unsigned64Bit,
        }
    }

    pub fn as_u64(&self) -> u64 { (*self).into() }
}

/// value provided for a blinding factor overflows prime field order for
/// Secp256k1 curve.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
#[from(secp256k1_zkp::UpstreamError)]
pub struct InvalidFieldElement;

/// Errors parsing string representation of a blinding factor.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum BlindingParseError {
    /// invalid blinding factor hex representation - {0}
    #[from]
    Hex(hex::Error),

    /// blinding factor value is invalid and does not belongs to the Secp256k1
    /// curve field.
    #[from(InvalidFieldElement)]
    InvalidFieldElement,
}

/// Blinding factor used in creating Pedersen commitment to an [`AtomicValue`].
///
/// Knowledge of the blinding factor is important to reproduce the commitment
/// process if the original value is kept.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(Self::to_hex)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", try_from = "secp256k1_zkp::SecretKey")
)]
pub struct BlindingFactor(Bytes32);

impl Deref for BlindingFactor {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target { self.0.as_inner() }
}

impl ToHex for BlindingFactor {
    fn to_hex(&self) -> String { self.0.to_hex() }
}

impl FromStr for BlindingFactor {
    type Err = BlindingParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Bytes32::from_str(s)?;
        Self::try_from(bytes).map_err(BlindingParseError::from)
    }
}

impl From<secp256k1_zkp::SecretKey> for BlindingFactor {
    fn from(key: secp256k1_zkp::SecretKey) -> Self { Self(Bytes32::from_inner(*key.as_ref())) }
}

impl From<BlindingFactor> for secp256k1_zkp::SecretKey {
    fn from(bf: BlindingFactor) -> Self { bf.to_secret_key() }
}

impl BlindingFactor {
    /// Creates a random blinding factor.
    #[inline]
    pub fn random() -> Self { Self::random_custom(&mut thread_rng()) }

    /// Generates a random blinding factor using custom random number generator.
    #[inline]
    pub fn random_custom<R: Rng + RngCore>(rng: &mut R) -> Self {
        secp256k1_zkp::SecretKey::new(rng).into()
    }

    /// Generates new blinding factor which balances a given set of negatives
    /// and positives into zero.
    ///
    /// # Errors
    ///
    /// If any subset of the negatives or positives are inverses of other
    /// negatives or positives, or if the balancing factor is zero (sum of
    /// negatives already equal to the sum of positives).
    pub fn zero_balanced(
        negative: impl IntoIterator<Item = BlindingFactor>,
        positive: impl IntoIterator<Item = BlindingFactor>,
    ) -> Result<Self, InvalidFieldElement> {
        let mut blinding_neg_sum = secp256k1_zkp::Scalar::ZERO;
        let mut blinding_pos_sum = secp256k1_zkp::Scalar::ZERO;
        for neg in negative {
            blinding_neg_sum = neg.to_secret_key().add_tweak(&blinding_neg_sum)?.into();
        }
        let blinding_neg_sum =
            secp256k1_zkp::SecretKey::from_slice(&blinding_neg_sum.to_be_bytes())?.negate();
        for pos in positive {
            blinding_pos_sum = pos.to_secret_key().add_tweak(&blinding_pos_sum)?.into();
        }
        let blinding_correction = blinding_neg_sum.add_tweak(&blinding_pos_sum)?.negate();
        Ok(blinding_correction.into())
    }

    fn to_secret_key(self) -> secp256k1_zkp::SecretKey {
        secp256k1_zkp::SecretKey::from_slice(self.0.as_slice())
            .expect("blinding factor is an invalid secret key")
    }
}

impl TryFrom<[u8; 32]> for BlindingFactor {
    type Error = InvalidFieldElement;

    fn try_from(array: [u8; 32]) -> Result<Self, Self::Error> {
        secp256k1_zkp::SecretKey::from_slice(&array)
            .map_err(|_| InvalidFieldElement)
            .map(Self::from)
    }
}

impl TryFrom<Bytes32> for BlindingFactor {
    type Error = InvalidFieldElement;

    fn try_from(bytes: Bytes32) -> Result<Self, Self::Error> {
        Self::try_from(bytes.to_byte_array())
    }
}

/// State item for a homomorphically-encryptable state.
///
/// Consists of the 64-bit value and
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, rename = "RevealedFungible")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct RevealedValue {
    /// Original value in smallest indivisible units
    pub value: FungibleState,

    /// Blinding factor used in Pedersen commitment
    pub blinding: BlindingFactor,

    /// Asset-specific tag preventing mixing assets of different type.
    pub asset_tag: Bytes32,
}

impl RevealedValue {
    /// Constructs new state using the provided value using random blinding
    /// factor.
    pub fn new_random_blinding(value: impl Into<FungibleState>, asset_tag: Bytes32) -> Self {
        Self::with_blinding(value, BlindingFactor::random(), asset_tag)
    }

    /// Constructs new state using the provided value and random generator for
    /// creating blinding factor.
    pub fn with_random_blinding<R: Rng + RngCore>(
        value: impl Into<FungibleState>,
        rng: &mut R,
        asset_tag: Bytes32,
    ) -> Self {
        Self {
            value: value.into(),
            blinding: BlindingFactor::random_custom(rng),
            asset_tag,
        }
    }

    /// Convenience constructor.
    pub fn with_blinding(
        value: impl Into<FungibleState>,
        blinding: BlindingFactor,
        asset_tag: Bytes32,
    ) -> Self {
        Self {
            value: value.into(),
            blinding,
            asset_tag,
        }
    }
}

impl ExposedState for RevealedValue {
    type Confidential = ConcealedValue;
    fn state_type(&self) -> StateType { StateType::Fungible }
    fn state_data(&self) -> StateData { StateData::Fungible(*self) }
}

impl Conceal for RevealedValue {
    type Concealed = ConcealedValue;

    fn conceal(&self) -> Self::Concealed { ConcealedValue::commit(self) }
}

// We need this manual implementation while conceal procedure is inaccessible
// w/o bulletproofs operational
impl CommitEncode for RevealedValue {
    fn commit_encode(&self, e: &mut impl Write) {
        let commitment = PedersenCommitment::commit(self);
        commitment.commit_encode(e);
    }
}

impl PartialOrd for RevealedValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for RevealedValue {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.value.cmp(&other.value) {
            Ordering::Equal => self.blinding.0.cmp(&other.blinding.0),
            other => other,
        }
    }
}

/// Opaque type holding pedersen commitment for an [`FungibleState`].
#[derive(Wrapper, Copy, Clone, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, FromStr, Display, LowerHex)]
#[derive(StrictType)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct PedersenCommitment(secp256k1_zkp::PedersenCommitment);

impl StrictDumb for PedersenCommitment {
    fn strict_dumb() -> Self {
        secp256k1_zkp::PedersenCommitment::from_slice(&[0x08; 33])
            .expect("hardcoded pedersen commitment value")
            .into()
    }
}

impl StrictEncode for PedersenCommitment {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        writer.write_tuple::<Self>(|w| Ok(w.write_field(&self.0.serialize())?.complete()))
    }
}

impl StrictDecode for PedersenCommitment {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let commitment = r.read_field::<[u8; 33]>()?;
            secp256k1_zkp::PedersenCommitment::from_slice(&commitment)
                .map_err(|_| {
                    DecodeError::DataIntegrityError(s!("invalid pedersen commitment data"))
                })
                .map(PedersenCommitment::from_inner)
        })
    }
}

impl CommitVerify<RevealedValue, UntaggedProtocol> for PedersenCommitment {
    fn commit(revealed: &RevealedValue) -> Self {
        use secp256k1_zkp::{Generator, Tag, Tweak};

        let blinding = Tweak::from_inner(revealed.blinding.0.into_inner())
            .expect("type guarantees of BlindingFactor are broken");
        let FungibleState::Bits64(value) = revealed.value;

        let tag = Tag::from(revealed.asset_tag.to_byte_array());
        let generator = Generator::new_unblinded(SECP256K1, tag);

        secp256k1_zkp::PedersenCommitment::new(SECP256K1, value, blinding, generator).into()
    }
}

/// A dumb placeholder for a future bulletproofs.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct NoiseDumb(Array<u8, 512>);

impl Default for NoiseDumb {
    fn default() -> Self {
        let mut dumb = [0u8; 512];
        thread_rng().fill(&mut dumb);
        NoiseDumb(dumb.into())
    }
}

/// Range proof value.
///
/// Range proofs must be used alongside [`PedersenCommitment`]s to ensure that
/// the value do not overflow on arithmetic operations with the commitments.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum RangeProof {
    /// Value used when bulletproofs library is not available.
    ///
    /// Always fails validation if no source value is given.
    #[strict_type(tag = 0xFF)]
    Placeholder(NoiseDumb),
}

impl Default for RangeProof {
    fn default() -> Self { RangeProof::Placeholder(default!()) }
}

pub struct PedersenProtocol;

impl CommitmentProtocol for PedersenProtocol {}

/// Confidential version of the additive state.
///
/// See also revealed version [`RevealedValue`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, rename = "ConcealedFungible")]
#[derive(CommitEncode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ConcealedValue {
    /// Pedersen commitment to the original [`FungibleState`].
    pub commitment: PedersenCommitment,
    /// Range proof for the [`FungibleState`] not exceeding type boundaries.
    #[commit_encode(skip)]
    pub range_proof: RangeProof,
}

impl ConfidentialState for ConcealedValue {
    fn state_type(&self) -> StateType { StateType::Fungible }
    fn state_commitment(&self) -> StateCommitment { StateCommitment::Fungible(*self) }
}

impl CommitVerify<RevealedValue, PedersenProtocol> for ConcealedValue {
    #[allow(dead_code, unreachable_code, unused_variables)]
    fn commit(revealed: &RevealedValue) -> Self {
        panic!(
            "Error: current version of RGB Core doesn't support production of bulletproofs; thus, \
             fungible state must be never concealed"
        );
        let commitment = PedersenCommitment::commit(revealed);
        // TODO: Do actual conceal upon integration of bulletproofs library
        let range_proof = RangeProof::default();
        ConcealedValue {
            commitment,
            range_proof,
        }
    }
}

impl ConcealedValue {
    /// Verifies bulletproof against the commitment.
    pub fn verify(&self) -> bool {
        match self.range_proof {
            RangeProof::Placeholder(_) => false,
        }
    }
}

/// Errors verifying range proofs.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum RangeProofError {
    /// invalid blinding factor {0}.
    InvalidBlinding(BlindingFactor),

    /// bulletproofs verification is not implemented in RGB Core v0.10. Please
    /// update your software and try again, or ask your software producer to use
    /// latest RGB release.
    BulletproofsAbsent,
}

impl ConcealedValue {
    /// Verifies validity of the range proof.
    pub fn verify_range_proof(&self) -> Result<bool, RangeProofError> {
        Err(RangeProofError::BulletproofsAbsent)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn commitments_determinism() {
        let value = RevealedValue::with_random_blinding(15, &mut thread_rng(), Bytes32::zero());

        let generators = (0..10)
            .map(|_| {
                let mut val = vec![];
                value.commit_encode(&mut val);
                val
            })
            .collect::<HashSet<_>>();
        assert_eq!(generators.len(), 1);
    }

    #[test]
    #[should_panic]
    fn pedersen_blinding_mismatch() {
        let mut r = thread_rng();
        let tag = Bytes32::zero();

        let a = PedersenCommitment::commit(&RevealedValue::with_random_blinding(15, &mut r, tag))
            .into_inner();
        let b = PedersenCommitment::commit(&RevealedValue::with_random_blinding(7, &mut r, tag))
            .into_inner();

        let c = PedersenCommitment::commit(&RevealedValue::with_random_blinding(13, &mut r, tag))
            .into_inner();
        let d = PedersenCommitment::commit(&RevealedValue::with_random_blinding(9, &mut r, tag))
            .into_inner();

        assert!(secp256k1_zkp::verify_commitments_sum_to_equal(SECP256K1, &[a, b], &[c, d]))
    }

    #[test]
    fn pedersen_blinding_same() {
        let blinding =
            BlindingFactor::from(secp256k1_zkp::SecretKey::from_slice(&[1u8; 32]).unwrap());
        let tag = Bytes32::zero();

        let a = PedersenCommitment::commit(&RevealedValue::with_blinding(15, blinding, tag))
            .into_inner();
        let b = PedersenCommitment::commit(&RevealedValue::with_blinding(7, blinding, tag))
            .into_inner();

        let c = PedersenCommitment::commit(&RevealedValue::with_blinding(13, blinding, tag))
            .into_inner();
        let d = PedersenCommitment::commit(&RevealedValue::with_blinding(9, blinding, tag))
            .into_inner();

        assert!(secp256k1_zkp::verify_commitments_sum_to_equal(SECP256K1, &[a, b], &[c, d]))
    }

    #[test]
    #[should_panic]
    fn pedersen_blinding_same_tag_differ() {
        let blinding =
            BlindingFactor::from(secp256k1_zkp::SecretKey::from_slice(&[1u8; 32]).unwrap());
        let tag1 = Bytes32::zero();
        let tag2 = Bytes32::from_array([1; 32]);

        let a = PedersenCommitment::commit(&RevealedValue::with_blinding(15, blinding, tag2))
            .into_inner();
        let b = PedersenCommitment::commit(&RevealedValue::with_blinding(7, blinding, tag1))
            .into_inner();

        let c = PedersenCommitment::commit(&RevealedValue::with_blinding(13, blinding, tag2))
            .into_inner();
        let d = PedersenCommitment::commit(&RevealedValue::with_blinding(9, blinding, tag1))
            .into_inner();

        assert!(secp256k1_zkp::verify_commitments_sum_to_equal(SECP256K1, &[a, b], &[c, d]))
    }

    #[test]
    fn pedersen_two_tags() {
        let blinding =
            BlindingFactor::from(secp256k1_zkp::SecretKey::from_slice(&[1u8; 32]).unwrap());
        let tag1 = Bytes32::zero();
        let tag2 = Bytes32::from_array([1; 32]);

        let a = PedersenCommitment::commit(&RevealedValue::with_blinding(15, blinding, tag2))
            .into_inner();
        let b = PedersenCommitment::commit(&RevealedValue::with_blinding(7, blinding, tag2))
            .into_inner();
        let c = PedersenCommitment::commit(&RevealedValue::with_blinding(2, blinding, tag1))
            .into_inner();
        let d = PedersenCommitment::commit(&RevealedValue::with_blinding(4, blinding, tag1))
            .into_inner();

        let e = PedersenCommitment::commit(&RevealedValue::with_blinding(13, blinding, tag2))
            .into_inner();
        let f = PedersenCommitment::commit(&RevealedValue::with_blinding(9, blinding, tag2))
            .into_inner();
        let g = PedersenCommitment::commit(&RevealedValue::with_blinding(1, blinding, tag1))
            .into_inner();
        let h = PedersenCommitment::commit(&RevealedValue::with_blinding(5, blinding, tag1))
            .into_inner();

        assert!(secp256k1_zkp::verify_commitments_sum_to_equal(SECP256K1, &[a, b, c, d], &[
            e, f, g, h
        ]))
    }

    #[test]
    fn pedersen_blinding_balance() {
        let tag = Bytes32::from_array([1; 32]);

        let blinding1 = BlindingFactor::random();
        let blinding2 = BlindingFactor::random();
        let blinding3 = BlindingFactor::random();
        let blinding4 = BlindingFactor::zero_balanced([blinding1, blinding2], [blinding3]).unwrap();

        let a = PedersenCommitment::commit(&RevealedValue::with_blinding(15, blinding1, tag))
            .into_inner();
        let b = PedersenCommitment::commit(&RevealedValue::with_blinding(7, blinding2, tag))
            .into_inner();

        let c = PedersenCommitment::commit(&RevealedValue::with_blinding(13, blinding3, tag))
            .into_inner();
        let d = PedersenCommitment::commit(&RevealedValue::with_blinding(9, blinding4, tag))
            .into_inner();

        assert!(secp256k1_zkp::verify_commitments_sum_to_equal(SECP256K1, &[a, b], &[c, d]))
    }
}
