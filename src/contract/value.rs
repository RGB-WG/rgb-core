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
use core::str::FromStr;
use std::io;
use std::io::Write;
use std::num::ParseIntError;
use std::ops::Deref;

use amplify::hex::{Error, FromHex, ToHex};
// We do not import particular modules to keep aware with namespace prefixes
// that we do not use the standard secp256k1zkp library
use amplify::{hex, Array, AsAny, Bytes32, Wrapper};
use bp::secp256k1::rand::thread_rng;
use commit_verify::{
    CommitEncode, CommitStrategy, CommitVerify, Conceal, Sha256, UntaggedProtocol,
};
use secp256k1_zkp::rand::{Rng, RngCore};
use secp256k1_zkp::SECP256K1;
use strict_encoding::{
    DecodeError, ReadTuple, StrictDecode, StrictDumb, StrictEncode, TypedRead, TypedWrite,
    WriteTuple,
};

use super::{ConfidentialState, RevealedState};
use crate::LIB_NAME_RGB;

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
pub enum ValueAtom {
    /// 64-bit value.
    #[from]
    #[strict_type(tag = 8)] // Matches strict types U64 primitive value
    Bits64(u64),
    // When/if adding more variants do not forget to re-write FromStr impl
}

impl Default for ValueAtom {
    fn default() -> Self { ValueAtom::Bits64(0) }
}

impl From<Revealed> for ValueAtom {
    fn from(revealed: Revealed) -> Self { revealed.value }
}

impl FromStr for ValueAtom {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { s.parse().map(ValueAtom::Bits64) }
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
    serde(crate = "serde_crate", from = "secp256k1_zkp::SecretKey")
)]
pub struct BlindingFactor(Bytes32);

impl Deref for BlindingFactor {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target { self.0.as_inner() }
}

impl ToHex for BlindingFactor {
    fn to_hex(&self) -> String { self.0.to_hex() }
}

impl FromHex for BlindingFactor {
    fn from_hex(s: &str) -> Result<Self, Error> { Bytes32::from_hex(s).map(Self) }
    fn from_byte_iter<I>(_: I) -> Result<Self, Error>
    where I: Iterator<Item = Result<u8, Error>> + ExactSizeIterator + DoubleEndedIterator {
        unreachable!()
    }
}

impl FromStr for BlindingFactor {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_hex(s) }
}

impl From<secp256k1_zkp::SecretKey> for BlindingFactor {
    fn from(key: secp256k1_zkp::SecretKey) -> Self { Self(Bytes32::from_inner(*key.as_ref())) }
}

impl From<BlindingFactor> for secp256k1_zkp::SecretKey {
    fn from(bf: BlindingFactor) -> Self {
        secp256k1_zkp::SecretKey::from_slice(bf.0.as_inner())
            .expect("blinding factor is an invalid secret key")
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// value provided for a blinding factor overflows prime field order for
/// Secp256k1 curve.
pub struct FieldOrderOverflow;

impl TryFrom<[u8; 32]> for BlindingFactor {
    type Error = FieldOrderOverflow;

    fn try_from(array: [u8; 32]) -> Result<Self, Self::Error> {
        secp256k1_zkp::SecretKey::from_slice(&array)
            .map_err(|_| FieldOrderOverflow)
            .map(Self::from)
    }
}

/// State item for a homomorphically-encryptable state.
///
/// Consists of the 64-bit value and
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Revealed {
    /// Original value in smallest indivisible units
    pub value: ValueAtom,

    /// Blinding factor used in Pedersen commitment
    pub blinding: BlindingFactor,
}

impl Revealed {
    /// Constructs new state using the provided value and random generator for
    /// creating blinding factor.
    pub fn new<R: Rng + RngCore>(value: ValueAtom, rng: &mut R) -> Self {
        Self {
            value,
            blinding: BlindingFactor::from(secp256k1_zkp::SecretKey::new(rng)),
        }
    }

    /// Convenience constructor.
    pub fn with(value: ValueAtom, blinding: impl Into<BlindingFactor>) -> Self {
        Self {
            value,
            blinding: blinding.into(),
        }
    }
}

impl RevealedState for Revealed {}

impl Conceal for Revealed {
    type Concealed = Confidential;

    fn conceal(&self) -> Self::Concealed {
        // TODO: Remove panic upon integration of bulletproofs library
        panic!(
            "current version of RGB Core doesn't support production of bulletproofs. The method \
             leading to this panic must not be used for now."
        );
        // Confidential::commit(self)
    }
}
impl CommitStrategy for Revealed {
    type Strategy = commit_verify::strategies::ConcealStrict;
}

impl PartialOrd for Revealed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.value.partial_cmp(&other.value) {
            None => None,
            Some(Ordering::Equal) => self.blinding.0.partial_cmp(&other.blinding.0),
            other => other,
        }
    }
}

impl Ord for Revealed {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.value.cmp(&other.value) {
            Ordering::Equal => self.blinding.0.cmp(&other.blinding.0),
            other => other,
        }
    }
}

/// Opaque type holding pedersen commitment for an [`ValueAtom`].
#[derive(Wrapper, Copy, Clone, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, FromStr, Display, LowerHex)]
#[derive(StrictType)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct PedersenCommitment(secp256k1_zkp::PedersenCommitment);

impl StrictDumb for PedersenCommitment {
    fn strict_dumb() -> Self {
        secp256k1_zkp::PedersenCommitment::from_slice(&[1u8; 32])
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

impl CommitStrategy for PedersenCommitment {
    type Strategy = commit_verify::strategies::Strict;
}

impl CommitVerify<Revealed, UntaggedProtocol> for PedersenCommitment {
    fn commit(revealed: &Revealed) -> Self {
        use secp256k1_zkp::{Generator, Tag, Tweak};

        let blinding = Tweak::from_inner(revealed.blinding.0.into_inner())
            .expect("type guarantees of BlindingFactor are broken");
        let value = match revealed.value {
            ValueAtom::Bits64(value) => value,
        };

        // TODO: Check that we create correct generator value.
        let g = secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &secp256k1_zkp::ONE_KEY);
        let h = Sha256::digest(&g.serialize_uncompressed());
        let tag = Tag::from(h);
        let generator = Generator::new_unblinded(SECP256K1, tag);

        secp256k1_zkp::PedersenCommitment::new(&SECP256K1, value, blinding, generator).into()
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
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

/// Confidential version of the additive state.
///
/// See also revealed version [`Revealed`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Confidential {
    /// Pedersen commitment to the original [`ValueAtom`].
    pub commitment: PedersenCommitment,
    /// Range proof for the [`ValueAtom`] not exceeding type boundaries.
    pub range_proof: RangeProof,
}

impl ConfidentialState for Confidential {}

impl Confidential {
    /// Verifies bulletproof against the commitment.
    pub fn verify(&self) -> bool {
        match self.range_proof {
            RangeProof::Placeholder(_) => false,
        }
    }
}

impl CommitEncode for Confidential {
    fn commit_encode(&self, e: &mut impl Write) {
        // We do not commit to the range proofs!
        self.commitment.commit_encode(e)
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

impl Confidential {
    /// Verifies validity of the range proof.
    pub fn verify_range_proof(&self) -> Result<bool, RangeProofError> {
        Err(RangeProofError::BulletproofsAbsent)
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    pub fn verify_commit_sum<C: Into<secp256k1_zkp::PedersenCommitment>>(
        positive: impl IntoIterator<Item = C>,
        negative: impl IntoIterator<Item = C>,
    ) -> bool {
        let positive = positive.into_iter().map(C::into).collect::<Vec<_>>();
        let negative = negative.into_iter().map(C::into).collect::<Vec<_>>();
        secp256k1_zkp::verify_commitments_sum_to_equal(SECP256K1, &positive, &negative)
    }
}

#[cfg(test)]
mod test {
    use secp256k1_zkp::{rand, Scalar, SecretKey};
    use strict_encoding::{StrictDecode, StrictEncode};
    use strict_encoding_test::test_vec_decoding_roundtrip;

    use super::super::test::test_confidential;
    use super::*;

    static AMOUNT_65: [u8; 40] = [
        0x3, 0x41, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa6, 0x2b, 0x27, 0xae, 0x5a, 0xf, 0x8c,
        0x59, 0x5a, 0xfc, 0x8b, 0x55, 0xe5, 0x5f, 0x72, 0xd7, 0x29, 0x1, 0x55, 0xfa, 0x68, 0x25,
        0xe6, 0x3f, 0x62, 0x73, 0x54, 0xab, 0xfd, 0x11, 0x2e,
    ];
    static CONFIDENTIAL_COMMITMENT: [u8; 33] = [
        9, 28, 151, 197, 83, 49, 80, 112, 118, 251, 95, 172, 13, 248, 153, 215, 36, 80, 132, 186,
        165, 230, 100, 123, 89, 195, 155, 50, 186, 47, 189, 101, 5,
    ];
    static CONFIDENTIAL_AMOUNT: [u8; 35] = [
        9, 28, 151, 197, 83, 49, 80, 112, 118, 251, 95, 172, 13, 248, 153, 215, 36, 80, 132, 186,
        165, 230, 100, 123, 89, 195, 155, 50, 186, 47, 189, 101, 5, 0, 0,
    ];

    static AMOUNT_64: [u8; 40] = [
        0x3, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xab, 0xe8, 0x9d, 0x73, 0xbd, 0x1c, 0x25,
        0x6d, 0x3c, 0x94, 0x94, 0xda, 0x5, 0xcc, 0x29, 0x7e, 0x34, 0xc3, 0xed, 0xfb, 0x6, 0xdb,
        0x6f, 0xe4, 0xdf, 0x6f, 0x28, 0x6e, 0x5d, 0xf6, 0xce,
    ];

    #[allow(dead_code)]
    static COMMIT_SUM: [u8; 33] = [
        0x08, 0x60, 0x23, 0x9f, 0xaa, 0x01, 0x4d, 0x24, 0x69, 0x22, 0x7f, 0x84, 0x17, 0x81, 0xe6,
        0x0a, 0x08, 0xa1, 0x42, 0xa9, 0x69, 0x89, 0x05, 0xba, 0x0e, 0x50, 0xae, 0x80, 0x88, 0x21,
        0xbf, 0xed, 0xc4,
    ];

    #[test]
    #[ignore]
    // We ignore the test since we do not have the correct test vectors.
    // These ones are coming from the grin library and they are not compatible
    // with elements project.
    fn test_amount() {
        // Test encoding decoding
        let _: Revealed = test_vec_decoding_roundtrip(AMOUNT_65).unwrap();
        let _: Revealed = test_vec_decoding_roundtrip(AMOUNT_64).unwrap();
        let _: Confidential = test_vec_decoding_roundtrip(CONFIDENTIAL_AMOUNT).unwrap();

        // Test commitment
        test_confidential::<Revealed>(&AMOUNT_65, &CONFIDENTIAL_AMOUNT, &CONFIDENTIAL_COMMITMENT);

        // Test comparison
        let revealed_64 = Revealed::strict_decode(&AMOUNT_64[..]).unwrap();
        let old_revealed = Revealed::strict_decode(&AMOUNT_65[..]).unwrap();
        assert_eq!(revealed_64.cmp(&old_revealed), Ordering::Less);
        assert_eq!(revealed_64.partial_cmp(&old_revealed).unwrap(), Ordering::Less);
        let coded_conf = Confidential::strict_decode(&CONFIDENTIAL_AMOUNT[..]).unwrap();
        let old_conf = old_revealed.commit_conceal();
        let new_conf = revealed_64.commit_conceal();
        assert_eq!(coded_conf, old_conf);
        assert_ne!(old_conf, new_conf);

        // Test confidential addition
        assert!(coded_conf.verify_range_proof().is_ok());
    }

    #[test]
    #[ignore]
    // We ignore the test since we do not have the correct test vectors.
    // These ones are coming from the grin library and they are not compatible
    // with elements project.
    fn test_commit_sum() {
        let positive = [1u64, 2u64, 3u64, 4u64, 5u64];
        let negative = [7u64, 8u64];

        // Generate random blinding factors
        let mut rng = rand::thread_rng();
        // We do not need the last one since it is auto-generated to
        // zero-balance the rest
        let count = positive.len() + negative.len() - 1;
        let mut sum = Scalar::ZERO;
        let mut blinding_factors = Vec::<_>::with_capacity(count + 1);
        for _ in 0..count {
            let bf = secp256k1::SecretKey::new(&mut rng);
            sum = bf.add_tweak(&sum).unwrap().into();
            blinding_factors.push(bf);
        }

        // let positive_factors = blinding_factors[..positive.len()].to_vec();
        // let negative_factors = blinding_factors[positive.len()..].to_vec();

        let correction = SecretKey::from_slice(&sum.to_le_bytes()).unwrap().negate();
        blinding_factors.push(correction);

        // Create Revealed amounts with corrected blinding factors
        let mut amounts = positive.to_vec();
        amounts.extend(negative.iter());

        let commitments: Vec<PedersenCommitment> = amounts
            .into_iter()
            .zip(blinding_factors.iter())
            .map(|(amount, blinding_factor)| {
                Revealed {
                    value: amount,
                    blinding: blinding_factor.clone().into(),
                }
                .commit_conceal()
                .commitment
            })
            .collect();

        assert!(Confidential::verify_commit_sum(
            commitments[..positive.len()],
            commitments[positive.len()..]
        ));

        // Create Revealed amounts with wrong positive values
        let wrong_positive = [1u64, 5u64, 3u64, 4u64, 5u64];
        let mut amounts = wrong_positive.to_vec();
        amounts.extend(negative.iter());

        // Create commitments with wrong positive values
        let wrong_commitments: Vec<PedersenCommitment> = amounts
            .into_iter()
            .zip(blinding_factors.iter())
            .map(|(amount, blinding_factor)| {
                Revealed {
                    value: amount,
                    blinding: blinding_factor.clone().into(),
                }
                .commit_conceal()
                .commitment
            })
            .collect();

        // Ensure commit sum verification fails for wrong positive values
        assert!(!Confidential::verify_commit_sum(
            wrong_commitments[..positive.len()],
            wrong_commitments[positive.len()..]
        ));
    }

    // We ignore this test for now since we are not checking blinding factor to
    // be a correct scalar on Secp on read operations - for performance reason.
    // It's validity will be checked during Pedersen commitment validation
    // anyway
    #[test]
    #[ignore]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_blinding() {
        let blind = Revealed::strict_decode(&AMOUNT_64[..]).unwrap().blinding;

        let mut buff = vec![];
        blind.strict_encode(&mut buff).unwrap();

        buff[0] = 0x10u8;

        BlindingFactor::strict_decode(&buff[..]).unwrap();
    }

    // TODO: Enable when bulletproofs will be back
    /*
    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_rangeproof() {
        let proof = Confidential::strict_decode(&CONFIDENTIAL_AMOUNT[..])
            .unwrap()
            .bulletproof;

        let mut buff = vec![];
        proof.strict_encode(&mut buff).unwrap();

        let mut pad = vec![0u8; 4465];
        buff.append(&mut pad);
        buff[0] = 0x14u8;
        buff[1] = 0x14u8;

        secp256k1zkp::pedersen::RangeProof::strict_decode(&buff[..]).unwrap();
    }
     */
}
