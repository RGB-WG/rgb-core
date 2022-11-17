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
use core::ops::Add;
use std::hash::Hasher;
use std::io;
use std::str::FromStr;

// We do not import particular modules to keep aware with namespace prefixes
// that we do not use the standard secp256k1zkp library
use amplify::hex::{Error, FromHex};
use amplify::{Slice32, Wrapper};
use bitcoin::hashes::sha256::Midstate;
use commit_verify::{commit_encode, CommitConceal, CommitEncode, CommitVerify, CommitmentProtocol};
use secp256k1zkp;
pub use secp256k1zkp::pedersen;
use secp256k1zkp::rand::{Rng, RngCore};
use secp256k1zkp::SecretKey;

use super::{ConfidentialState, RevealedState, SECP256K1_ZKP};

pub type AtomicValue = u64;

impl From<Revealed> for AtomicValue {
    fn from(revealed: Revealed) -> Self { revealed.value }
}

/// Proof for Pedersen commitment: a blinding key
#[derive(
    Wrapper,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    Display,
    From,
    ConfinedEncode,
    ConfinedDecode
)]
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

impl From<secp256k1zkp::SecretKey> for BlindingFactor {
    fn from(key: SecretKey) -> Self { Self::from_inner(Slice32::from_inner(key.0)) }
}

impl From<BlindingFactor> for secp256k1zkp::SecretKey {
    fn from(bf: BlindingFactor) -> Self { SecretKey(bf.into_inner().into_inner()) }
}

impl FromHex for BlindingFactor {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where I: Iterator<Item = Result<u8, Error>> + ExactSizeIterator + DoubleEndedIterator {
        Slice32::from_byte_iter(iter).map(BlindingFactor::from_inner)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, AsAny)]
#[derive(ConfinedEncode, ConfinedDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display("{value}#{blinding}")]
pub struct Revealed {
    /// Original value in smallest indivisible units
    pub value: AtomicValue,

    /// Blinding factor used in Pedersen commitment
    pub blinding: BlindingFactor,
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
            blinding: BlindingFactor::from(secp256k1zkp::SecretKey::new(&SECP256K1_ZKP, rng)),
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

#[derive(Clone, Debug, AsAny, ConfinedEncode, ConfinedDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Confidential {
    pub commitment: pedersen::Commitment,
    pub bulletproof: pedersen::RangeProof,
}

impl ConfidentialState for Confidential {}

impl CommitEncode for Confidential {
    fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
        // We do not commit to the bulletproof!
        self.commitment.commit_encode(&mut e)
    }
}

impl PartialOrd for Confidential {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (&self.commitment.0[..]).partial_cmp(&other.commitment.0[..]) {
            None => None,
            Some(Ordering::Equal) => self.bulletproof.proof[0..self.bulletproof.plen]
                .partial_cmp(&other.bulletproof.proof[0..other.bulletproof.plen]),
            other => other,
        }
    }
}

impl Ord for Confidential {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.commitment.0.cmp(&other.commitment.0) {
            Ordering::Equal => self.bulletproof.proof[0..self.bulletproof.plen]
                .cmp(&other.bulletproof.proof[0..other.bulletproof.plen]),
            other => other,
        }
    }
}

impl std::hash::Hash for Confidential {
    fn hash<H: Hasher>(&self, state: &mut H) { state.write(&self.commitment.0) }
}

// The normal notion of the equivalence operator is to compare the _value_
// behind any data structure. However, here we compare not the value we
// are committing to, but the commitment itself. This is different to the
// design of the original Bulletproof designers, but is appropriate for the
// goals of RGB project and client-side validation paradigm
impl PartialEq for Confidential {
    fn eq(&self, other: &Self) -> bool {
        let plen = self.bulletproof.plen;
        self.commitment.0.to_vec() == other.commitment.0.to_vec()
            && self.bulletproof.proof[..plen] == other.bulletproof.proof[..plen]
    }
}

pub enum HomomorphicBulletproofGrin {}

impl CommitmentProtocol for HomomorphicBulletproofGrin {
    const HASH_TAG_MIDSTATE: Option<Midstate> = None;
}

impl CommitVerify<Revealed, HomomorphicBulletproofGrin> for Confidential {
    fn commit(revealed: &Revealed) -> Self {
        let blinding = revealed.blinding;
        let value = revealed.value;

        let commitment = SECP256K1_ZKP
            .commit(value, blinding.into())
            .expect("Internal inconsistency in Grin secp256k1zkp library Pedersen commitments");
        let bulletproof = SECP256K1_ZKP.bullet_proof(
            value,
            blinding.into(),
            blinding.into(),
            blinding.into(),
            None,
            None,
        );
        Confidential {
            commitment,
            bulletproof,
        }
    }
}

impl Eq for Confidential {}

impl Add<pedersen::Commitment> for Confidential {
    type Output = pedersen::Commitment;

    fn add(self, other: pedersen::Commitment) -> Self::Output {
        SECP256K1_ZKP
            .commit_sum(vec![self.commitment, other], vec![])
            .expect("Failed to add Pedersen commitments")
    }
}

impl Confidential {
    pub fn zero_pedersen_commitment() -> pedersen::Commitment {
        SECP256K1_ZKP
            .commit_value(0)
            .expect("Internal inconsistency in Grin secp256k1zkp library Pedersen commitments")
    }

    pub fn verify_bullet_proof(&self) -> Result<pedersen::ProofRange, secp256k1zkp::Error> {
        SECP256K1_ZKP.verify_bullet_proof(self.commitment, self.bulletproof, None)
    }

    pub fn verify_commit_sum(
        positive: Vec<pedersen::Commitment>,
        negative: Vec<pedersen::Commitment>,
    ) -> bool {
        SECP256K1_ZKP.verify_commit_sum(positive, negative)
    }
}

#[cfg(test)]
mod test {
    use confined_encoding::{confined_deserialize, ConfinedDecode, ConfinedEncode};
    use confined_encoding_test::test_vec_decoding_roundtrip;

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
    static CONFIDENTIAL_AMOUNT: [u8; 710] = [
        9, 28, 151, 197, 83, 49, 80, 112, 118, 251, 95, 172, 13, 248, 153, 215, 36, 80, 132, 186,
        165, 230, 100, 123, 89, 195, 155, 50, 186, 47, 189, 101, 5, 163, 2, 114, 162, 252, 251, 44,
        98, 42, 164, 34, 212, 235, 97, 123, 222, 196, 164, 124, 8, 122, 98, 37, 8, 159, 65, 234,
        58, 191, 245, 162, 158, 68, 182, 103, 98, 130, 199, 125, 161, 189, 120, 101, 236, 80, 120,
        98, 199, 227, 254, 73, 234, 171, 248, 94, 167, 58, 66, 73, 13, 147, 128, 54, 193, 157, 241,
        11, 53, 130, 243, 155, 164, 124, 192, 31, 145, 20, 116, 107, 79, 72, 128, 66, 222, 85, 68,
        232, 226, 239, 130, 32, 183, 64, 207, 10, 209, 21, 17, 128, 224, 110, 255, 73, 222, 124,
        165, 140, 130, 82, 107, 252, 212, 112, 20, 240, 165, 35, 151, 179, 101, 133, 217, 28, 144,
        199, 85, 67, 15, 65, 240, 93, 151, 253, 212, 223, 152, 51, 37, 19, 8, 158, 183, 124, 99,
        219, 50, 88, 206, 132, 146, 143, 173, 118, 249, 88, 209, 111, 56, 106, 251, 192, 47, 69,
        243, 147, 34, 254, 114, 75, 139, 231, 61, 54, 90, 72, 194, 47, 241, 67, 103, 226, 49, 202,
        146, 95, 37, 183, 236, 114, 156, 40, 50, 87, 105, 98, 65, 6, 142, 160, 41, 127, 159, 124,
        37, 211, 221, 77, 113, 94, 46, 213, 34, 195, 162, 62, 158, 103, 179, 43, 84, 241, 103, 128,
        9, 233, 143, 203, 244, 134, 43, 122, 182, 202, 108, 34, 118, 188, 234, 213, 205, 1, 176,
        249, 251, 213, 61, 1, 67, 37, 154, 230, 107, 250, 193, 132, 186, 6, 155, 189, 165, 212,
        198, 65, 122, 24, 93, 247, 40, 213, 97, 211, 151, 232, 66, 50, 175, 45, 193, 160, 215, 119,
        139, 51, 114, 64, 176, 202, 244, 219, 222, 84, 37, 80, 84, 36, 126, 85, 157, 242, 222, 46,
        118, 82, 73, 15, 229, 205, 253, 158, 168, 220, 232, 233, 206, 60, 177, 11, 171, 75, 220,
        33, 27, 43, 23, 235, 197, 154, 163, 87, 31, 123, 242, 80, 81, 30, 6, 163, 253, 10, 162, 45,
        191, 174, 244, 36, 158, 91, 1, 172, 180, 9, 60, 243, 90, 129, 40, 0, 10, 109, 62, 241, 121,
        249, 237, 241, 58, 184, 42, 246, 37, 38, 164, 64, 194, 166, 215, 146, 233, 222, 162, 63,
        15, 248, 191, 16, 100, 240, 213, 107, 6, 84, 248, 254, 102, 107, 90, 228, 206, 151, 8, 202,
        0, 203, 130, 165, 208, 216, 10, 75, 123, 13, 217, 12, 168, 56, 135, 89, 139, 175, 153, 166,
        157, 238, 45, 235, 116, 209, 58, 129, 39, 39, 150, 178, 235, 100, 58, 94, 197, 234, 27,
        231, 44, 140, 226, 96, 35, 219, 47, 247, 162, 204, 123, 211, 197, 133, 153, 45, 234, 91,
        69, 204, 231, 188, 154, 227, 15, 226, 87, 51, 255, 167, 109, 156, 29, 151, 103, 156, 128,
        137, 12, 67, 186, 247, 24, 140, 254, 47, 45, 6, 178, 157, 26, 235, 209, 246, 167, 139, 56,
        214, 111, 49, 220, 35, 88, 27, 54, 68, 109, 173, 63, 13, 64, 34, 74, 103, 20, 143, 203, 22,
        242, 84, 60, 21, 91, 60, 111, 167, 93, 35, 45, 19, 43, 203, 1, 238, 131, 11, 254, 89, 15,
        211, 0, 201, 81, 101, 174, 223, 91, 199, 148, 24, 170, 221, 51, 2, 57, 17, 202, 210, 22,
        38, 118, 124, 82, 244, 117, 112, 16, 125, 118, 117, 245, 105, 24, 194, 24, 251, 209, 251,
        70, 206, 84, 159, 133, 223, 1, 79, 185, 51, 128, 26, 131, 233, 184, 195, 189, 141, 58, 138,
        51, 179, 13, 204, 50, 51, 206, 58, 161, 37, 122, 214, 33, 154, 214, 73, 35, 150, 220, 117,
        71, 233, 86, 133, 17, 128, 134, 61, 38, 140, 241, 186, 151, 39, 106, 226, 231, 44, 129, 10,
        211, 10, 7, 161, 111, 115, 117, 180, 160, 74, 193, 169, 11, 238, 76, 89, 214, 190, 94, 135,
        57, 18, 61, 212, 45, 122, 3, 225, 63, 10, 222, 73, 80, 61, 216, 4, 238, 181,
    ];

    static AMOUNT_64: [u8; 40] = [
        0x3, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xab, 0xe8, 0x9d, 0x73, 0xbd, 0x1c, 0x25,
        0x6d, 0x3c, 0x94, 0x94, 0xda, 0x5, 0xcc, 0x29, 0x7e, 0x34, 0xc3, 0xed, 0xfb, 0x6, 0xdb,
        0x6f, 0xe4, 0xdf, 0x6f, 0x28, 0x6e, 0x5d, 0xf6, 0xce,
    ];

    static COMMIT_SUM: [u8; 33] = [
        0x08, 0x60, 0x23, 0x9f, 0xaa, 0x01, 0x4d, 0x24, 0x69, 0x22, 0x7f, 0x84, 0x17, 0x81, 0xe6,
        0x0a, 0x08, 0xa1, 0x42, 0xa9, 0x69, 0x89, 0x05, 0xba, 0x0e, 0x50, 0xae, 0x80, 0x88, 0x21,
        0xbf, 0xed, 0xc4,
    ];

    #[test]
    fn test_amount() {
        // Test encoding decoding
        let _: Revealed = test_vec_decoding_roundtrip(AMOUNT_65).unwrap();
        let _: Revealed = test_vec_decoding_roundtrip(AMOUNT_64).unwrap();
        let _: Confidential = test_vec_decoding_roundtrip(CONFIDENTIAL_AMOUNT).unwrap();

        // Test commitment
        test_confidential::<Revealed>(&AMOUNT_65, &CONFIDENTIAL_AMOUNT, &CONFIDENTIAL_COMMITMENT);

        // Test comparison
        let revealed_64 = Revealed::confined_decode(&AMOUNT_64[..]).unwrap();
        let old_revealed = Revealed::confined_decode(&AMOUNT_65[..]).unwrap();
        assert_eq!(revealed_64.cmp(&old_revealed), Ordering::Less);
        assert_eq!(
            revealed_64.partial_cmp(&old_revealed).unwrap(),
            Ordering::Less
        );
        let coded_conf = Confidential::confined_decode(&CONFIDENTIAL_AMOUNT[..]).unwrap();
        let old_conf = old_revealed.commit_conceal();
        let new_conf = revealed_64.commit_conceal();
        assert_eq!(coded_conf, old_conf);
        assert_ne!(old_conf, new_conf);
        assert_eq!(old_conf.cmp(&new_conf), Ordering::Greater);
        assert_eq!(old_conf.partial_cmp(&new_conf).unwrap(), Ordering::Greater);

        // Test confidential addition
        assert!(coded_conf.verify_bullet_proof().is_ok());
        let new_commit = new_conf.commitment;
        let sum = old_conf.add(new_commit);
        let commit_sum =
            secp256k1zkp::pedersen::Commitment::confined_decode(&COMMIT_SUM[..]).unwrap();
        assert_eq!(sum, commit_sum);
    }

    #[test]
    fn test_commit_sum() {
        let positive = [1u64, 2u64, 3u64, 4u64, 5u64];
        let negative = [7u64, 8u64];

        // Generate random blinding factors
        let mut rng = secp256k1zkp::rand::thread_rng();
        // We do not need the last one since it is auto-generated to
        // zero-balance the rest
        let count = positive.len() + negative.len() - 1;
        let mut blinding_factors = Vec::<_>::with_capacity(count + 1);
        for _ in 0..count {
            blinding_factors.push(secp256k1zkp::SecretKey::new(&SECP256K1_ZKP, &mut rng));
        }

        let positive_factors = blinding_factors[..positive.len()].to_vec();
        let negative_factors = blinding_factors[positive.len()..].to_vec();

        let correction = SECP256K1_ZKP
            .blind_sum(positive_factors, negative_factors)
            .unwrap();

        blinding_factors.push(correction);

        // Create Revealed amounts with corrected blinding factors
        let mut amounts = positive.to_vec();
        amounts.extend(negative.iter());

        let commitments: Vec<secp256k1zkp::pedersen::Commitment> = amounts
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
        let wrong_commitments: Vec<secp256k1zkp::pedersen::Commitment> = amounts
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

    #[test]
    fn test_zero_commmit() {
        let zero_commit = Confidential::zero_pedersen_commitment();

        let mut handmade_bytes = vec![0x08u8];
        handmade_bytes.extend(&[0x0u8; 32]);
        let handmade_commit =
            secp256k1zkp::pedersen::Commitment::confined_decode(&handmade_bytes[..]).unwrap();

        assert_eq!(handmade_commit, zero_commit);
    }

    #[test]
    #[should_panic(expected = "DataNotEntirelyConsumed")]
    fn test_pederson() {
        let mut bytes = COMMIT_SUM.clone().to_vec();
        bytes.append(&mut [0u8, 0u8].to_vec());
        let _: secp256k1zkp::pedersen::Commitment = confined_deserialize(&bytes).unwrap();
    }

    // We ignore this test for now since we are not checking blinding factor to
    // be a correct scalar on Secp on read operations - for performance reason.
    // It's validity will be checked during Pedersen commitment validation
    // anyway
    #[test]
    #[ignore]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_blinding() {
        let blind = Revealed::confined_decode(&AMOUNT_64[..]).unwrap().blinding;

        let mut buff = vec![];
        blind.confined_encode(&mut buff).unwrap();

        buff[0] = 0x10u8;

        BlindingFactor::confined_decode(&buff[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_rangeproof() {
        let proof = Confidential::confined_decode(&CONFIDENTIAL_AMOUNT[..])
            .unwrap()
            .bulletproof;

        let mut buff = vec![];
        proof.confined_encode(&mut buff).unwrap();

        let mut pad = vec![0u8; 4465];
        buff.append(&mut pad);
        buff[0] = 0x14u8;
        buff[1] = 0x14u8;

        secp256k1zkp::pedersen::RangeProof::confined_decode(&buff[..]).unwrap();
    }
}
