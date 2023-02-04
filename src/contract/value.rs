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
use std::io;
use std::str::FromStr;

// We do not import particular modules to keep aware with namespace prefixes
// that we do not use the standard secp256k1zkp library
use amplify::hex::{Error, FromHex};
use amplify::{Slice32, Wrapper};
use bitcoin_hashes::sha256::Midstate;
use bitcoin_hashes::{sha256, Hash};
use commit_verify::{commit_encode, CommitConceal, CommitEncode, CommitVerify, CommitmentProtocol};
use secp256k1_zkp::rand::{Rng, RngCore};
use secp256k1_zkp::{PedersenCommitment, SECP256K1};

use super::{ConfidentialState, RevealedState};

pub type AtomicValue = u64;

impl From<Revealed> for AtomicValue {
    fn from(revealed: Revealed) -> Self { revealed.value }
}

/// Proof for Pedersen commitment: a blinding key
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex, BorrowSlice)]
pub struct BlindingFactor(Slice32);

impl AsRef<[u8]> for BlindingFactor {
    #[inline]
    fn as_ref(&self) -> &[u8] { &self.0[..] }
}

impl From<secp256k1_zkp::SecretKey> for BlindingFactor {
    fn from(key: secp256k1_zkp::SecretKey) -> Self {
        Self::from_inner(Slice32::from_inner(*key.as_ref()))
    }
}

impl From<BlindingFactor> for secp256k1_zkp::SecretKey {
    fn from(bf: BlindingFactor) -> Self {
        secp256k1_zkp::SecretKey::from_slice(bf.into_inner().as_inner())
            .expect("blinding factor is an invalid secret key")
    }
}

impl FromHex for BlindingFactor {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where I: Iterator<Item = Result<u8, Error>> + ExactSizeIterator + DoubleEndedIterator {
        Slice32::from_byte_iter(iter).map(BlindingFactor::from_inner)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, AsAny)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display("{value}#{blinding}")]
pub struct Revealed {
    /// Original value in smallest indivisible units
    pub value: AtomicValue,

    /// Blinding factor used in Pedersen commitment
    pub blinding: BlindingFactor,
}

impl Revealed {
    /// Convenience constructor.
    pub fn with(value: AtomicValue, blinding: impl Into<BlindingFactor>) -> Self {
        Self {
            value,
            blinding: blinding.into(),
        }
    }
}

/// Error parsing RGB revealed value from string. The string must has form of
/// `<value>#<hex_blinding_factor>`
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum RevealedParseError {
    /// No `#` separator between value and blinding factor found while
    /// parsing RGB revealed value
    NoSeparator,

    /// No blinding factor is present within RGB revealed value string
    /// representation
    NoBlindingFactor,

    /// Extra component within RGB revealed value string representation
    /// following value and blinding factor
    ExtraComponent,

    /// Error parsing atomic value representation of RGB revealed value, which
    /// has to be an integer
    #[from(std::num::ParseIntError)]
    AtomicInt,

    /// Error parsing Pedersen commitment inside RGB revealed value string
    /// representation. The commitment must be a hex-encoded
    #[from(amplify::hex::Error)]
    PedersenHex,
}

impl FromStr for Revealed {
    type Err = RevealedParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('#');
        match (split.next(), split.next(), split.next()) {
            (Some(v), Some(b), None) => Ok(Revealed {
                value: v.parse()?,
                blinding: BlindingFactor::from_hex(b)?,
            }),
            (None, ..) => Err(RevealedParseError::NoSeparator),
            (Some(_), None, _) => Err(RevealedParseError::NoBlindingFactor),
            (_, _, Some(_)) => Err(RevealedParseError::ExtraComponent),
        }
    }
}

impl Revealed {
    pub fn with_amount<R: Rng + RngCore>(amount: AtomicValue, rng: &mut R) -> Self {
        Self {
            value: amount,
            blinding: BlindingFactor::from(secp256k1_zkp::SecretKey::new(rng)),
        }
    }
}

impl RevealedState for Revealed {}

impl CommitConceal for Revealed {
    type ConcealedCommitment = Confidential;

    fn commit_conceal(&self) -> Self::ConcealedCommitment { Confidential::commit(self) }
}
impl commit_encode::Strategy for Revealed {
    type Strategy = commit_encode::strategies::UsingConceal;
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

#[derive(Clone, Debug, Eq, PartialEq, Hash, AsAny)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Confidential {
    // TODO: make fields private to provide type guarantees on the data validity
    pub commitment: PedersenCommitment,
    pub bulletproof: Box<[u8]>,
}

impl ConfidentialState for Confidential {}

/*
impl StrictEncode for Confidential {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        let len = self.bulletproof.len() as u16;
        self.commitment.serialize().strict_encode(&mut e)?;
        self.bulletproof.strict_encode(e)?;
        Ok(len as usize + 33 + 2)
    }
}

impl StrictDecode for Confidential {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        let commitment = <[u8; 33]>::strict_decode(&mut d)?;
        let commitment = PedersenCommitment::from_slice(&commitment).map_err(|_| {
            strict_encoding::Error::DataIntegrityError(s!("invalid pedersen commitment data"))
        })?;
        let bulletproof = Box::<[u8]>::strict_decode(d)?;
        Ok(Self {
            commitment,
            bulletproof,
        })
    }
}
 */

impl CommitEncode for Confidential {
    fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
        // We do not commit to the bulletproof!
        self.commitment.serialize().as_ref().commit_encode(&mut e)
    }
}

/// Commitment protocol
pub enum Bulletproofs {}

impl CommitmentProtocol for Bulletproofs {
    const HASH_TAG_MIDSTATE: Option<Midstate> = None;
}

impl CommitVerify<Revealed, Bulletproofs> for Confidential {
    fn commit(revealed: &Revealed) -> Self {
        use secp256k1_zkp::{Generator, Tag, Tweak};

        // TODO: provide type-level guarantees on Revealed that the blinding
        //       factor is valid by making fields private and checking the value
        //       on deserialization
        let blinding = Tweak::from_inner(revealed.blinding.0.into_inner())
            .map_err(|_| BulletproofsError::InvalidBlinding(revealed.blinding))
            .expect("the provided blinding factor is faked");
        let value = revealed.value;

        // TODO: Check that we create a correct generator value.
        let g = secp256k1_zkp::PublicKey::from_secret_key(SECP256K1, &secp256k1_zkp::ONE_KEY);
        let h = sha256::Hash::hash(&g.serialize_uncompressed());
        let tag = Tag::from(h.into_inner());
        let generator = Generator::new_unblinded(SECP256K1, tag);

        let commitment = PedersenCommitment::new(&SECP256K1, value, blinding, generator);
        Confidential {
            commitment,
            // TODO: We can't produce valid bulletproofs today
            bulletproof: Box::default(),
        }
    }
}

#[derive(Copy, Clone, Debug, Display, Error)]
#[display(doc_comments)]
pub enum BulletproofsError {
    /// invalid blinding factor {0}.
    InvalidBlinding(BlindingFactor),

    /// bulletproofs verification is not implemented in RGB Core v0.10. Please
    /// update your software and try again, or ask your software producer to use
    /// latest RGB release.
    Unimplemented,
}

impl Confidential {
    pub fn verify_bullet_proof(&self) -> Result<bool, BulletproofsError> {
        Err(BulletproofsError::Unimplemented)
    }

    pub fn verify_commit_sum(
        positive: Vec<PedersenCommitment>,
        negative: Vec<PedersenCommitment>,
    ) -> bool {
        secp256k1_zkp::verify_commitments_sum_to_equal(
            secp256k1_zkp::SECP256K1,
            &positive,
            &negative,
        )
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
        assert_eq!(
            revealed_64.partial_cmp(&old_revealed).unwrap(),
            Ordering::Less
        );
        let coded_conf = Confidential::strict_decode(&CONFIDENTIAL_AMOUNT[..]).unwrap();
        let old_conf = old_revealed.commit_conceal();
        let new_conf = revealed_64.commit_conceal();
        assert_eq!(coded_conf, old_conf);
        assert_ne!(old_conf, new_conf);

        // Test confidential addition
        assert!(coded_conf.verify_bullet_proof().is_ok());
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
            commitments[..positive.len()].to_vec(),
            commitments[positive.len()..].to_vec()
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
            wrong_commitments[..positive.len()].to_vec(),
            wrong_commitments[positive.len()..].to_vec()
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
