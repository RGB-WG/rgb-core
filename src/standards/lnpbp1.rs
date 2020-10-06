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

use std::collections::BTreeSet;

use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1;

use crate::SECP256K1;

lazy_static! {
    /// Single SHA256 hash of "LNPBP1" string according to LNPBP-1 acting as a
    /// prefix to the message in computing tweaking factor
    pub static ref LNPBP1_HASHED_TAG: [u8; 32] = {
        sha256::Hash::hash(b"LNPBP1").into_inner()
    };
}

type Keyset = BTreeSet<secp256k1::PublicKey>;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// Keyset must include target public key, but no target key found it
    /// the provided set.
    NotKeysetMember,

    /// Elliptic curve point addition resulted in point in infinity; you
    /// must select different source public keys
    SumInfiniteResult,

    /// LNPBP-1 commitment either is outside of Secp256k1 order `n` (this event
    /// has negligible probability <~2^-64), or, when added to the provided
    /// keyset, results in point at infinity. You may try with a different
    /// source message or public keys.
    InvalidTweak,
}

/// Function implements commitment procedure according to LNPBP-1.
///
/// # Parameters
///
/// - A set of public keys for committing during the LNPBP-1 procedure
/// - Target public key for tweaking. Must be a part of the keyset, otherwise
///   function will fail with [`Error::NotKeysetMember`]
/// - Protocol-specific tag in form of 32-byte hash
/// - Message to commit, which must be representable as a byte slice using
///   [`AsRef::as_ref()`]
/// NB: According to LNPBP-1 the message supplied here must be already
/// prefixed with 32-byte SHA256 hash of the protocol-specific prefix
///
/// # Returns
///
/// Tuple, consisting of
/// 1) modified target pubkey from `target_pubkey` parameter, tweaked with
/// 2) tweaking factor, as a 32-byte array
/// 3) modified keyset in which the original target public key is replaced with
///    a tweaked version
///
/// # Protocol:
///
/// This is an extract from LNPBP-1 standard. Please refer to the original
/// document for the verification:
/// <https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0001.md>
///
/// For a given message `msg` and original public key `P` the **commit
/// procedure** is defined as follows:
///
/// 1. Construct a byte string `lnbp1_msg`, composed of the original message
///    prefixed with a single SHA256 hash of `LNPBP1`
///    string and a single SHA256 hash of protocol-specific tag:
///    `lnbp1_msg = SHA256("LNPBP1")||SHA256(<protocol-specific-tag>)||msg`
/// 2. Compute HMAC-SHA256 of the `lnbp1_msg` and `P`, named **tweaking
///    factor**: `f = HMAC_SHA256(lnbp1_msg, P)`
/// 3. Make sure that the tweaking factor is less than order `p` of Zp prime
///    number set used in Secp256k1 curve; otherwise fail the protocol.
/// 4. Multiply the tweaking factor on Secp256k1 generator point
///    `G`: `F = G * f` ignoring the possible overflow of the resulting
///    elliptic curve point `F` over the order `n` of `G`. Check that the
///    result not equal to the point-at-infinity; otherwise fail the
///    protocol, indicating the reason of failure, such that the protocol
///    may be run with another initial public key `P'` value.
/// 5. Add two elliptic curve points, the original public key `P` and
///    tweaking-factor based point `F`, obtaining the resulting tweaked
///    public key `T`: `T = P + F`. Check that the result not equal to the
///    point-at-infinity; otherwise fail the protocol, indicating the reason
///    of failure, such that the protocol may be run with another initial
///    public key `P'` value.
///
/// The final formula for the commitment is:
/// `T = P + G * HMAC_SHA256(SHA256("LNPBP1") ||
/// SHA256(<protocol-specific-tag>) || msg, P)`
// #[consensus_critical("RGB")]
// #[standard_critical("LNPBP-1")]
pub fn commit(
    keyset: &mut Keyset,
    target_pubkey: &mut secp256k1::PublicKey,
    protocol_tag: &sha256::Hash,
    message: impl AsRef<[u8]>,
) -> Result<[u8; 32], Error> {
    if !keyset.remove(target_pubkey) {
        return Err(Error::NotKeysetMember);
    }

    // ! [CONSENSUS-CRITICAL]:
    // ! [STANDARD-CRITICAL]: We commit to the sum of all public keys,
    //                        not a single pubkey. For single key the set
    //                        is represented by itself
    let pubkey_sum = keyset
        .iter()
        .try_fold(target_pubkey.clone(), |sum, pubkey| sum.combine(pubkey))
        .map_err(|_| Error::SumInfiniteResult)?;

    // ! [CONSENSUS-CRITICAL]:
    // ! [STANDARD-CRITICAL]: HMAC engine is based on sha256 hash
    let mut hmac_engine =
        HmacEngine::<sha256::Hash>::new(&pubkey_sum.serialize());

    // ! [CONSENSUS-CRITICAL]:
    // ! [STANDARD-CRITICAL]: Hash process started with consuming first
    //                        protocol prefix: single SHA256 hash of
    //                        ASCII "LNPBP-1" string.
    // NB: We use the same hash as in LNPBP-1 so when there is no other
    //     keys involved the commitment would not differ.
    hmac_engine.input(&LNPBP1_HASHED_TAG[..]);

    // ! [CONSENSUS-CRITICAL]:
    // ! [STANDARD-CRITICAL]: The second prefix comes from the upstream
    //                        protocol as a part of the container
    hmac_engine.input(&protocol_tag[..]);

    // ! [CONSENSUS-CRITICAL]:
    // ! [STANDARD-CRITICAL]: Next we hash the message. The message must be
    //                        prefixed with the protocol-specific prefix:
    //                        another single SHA256 hash of protocol name.
    //                        However this is not the part of this function,
    //                        the function expect that the `msg` is already
    //                        properly prefixed
    hmac_engine.input(message.as_ref());

    // Producing and storing tweaking factor in container
    let hmac = Hmac::from_engine(hmac_engine);
    let tweaking_factor = *hmac.as_inner();

    // Applying tweaking factor to public key
    target_pubkey
        .add_exp_assign(&SECP256K1, &tweaking_factor[..])
        .map_err(|_| Error::InvalidTweak)?;

    keyset.insert(target_pubkey.clone());

    // Returning tweaked public key
    Ok(tweaking_factor)
}

/// Convenience LNPBP-1 verification function
pub fn verify(
    verified_pubkey: secp256k1::PublicKey,
    original_keyset: &Keyset,
    target_pubkey: secp256k1::PublicKey,
    protocol_tag: &sha256::Hash,
    message: impl AsRef<[u8]>,
) -> bool {
    match commit(
        &mut original_keyset.clone(),
        &mut target_pubkey.clone(),
        protocol_tag,
        message,
    ) {
        // If the commitment function fails, it means that it was not able to
        // commit with the provided data, meaning that the commitment was not
        // created. Thus, we return that verification have not passed, and not
        // a error.
        Err(_) => return false,

        // Verification succeeds if the commitment procedure produces public key
        // equivalent to the verified one
        Ok(_) => target_pubkey == verified_pubkey,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_lnpbp1_tag() {
        assert_eq!(
            sha256::Hash::hash(b"LNPBP1").into_inner(),
            *LNPBP1_HASHED_TAG
        );
        assert_ne!(
            sha256::Hash::hash(b"LNPBP2").into_inner(),
            *LNPBP1_HASHED_TAG
        );
        assert_ne!(
            sha256::Hash::hash(b"LNPBP-1").into_inner(),
            *LNPBP1_HASHED_TAG
        );
        assert_ne!(
            sha256::Hash::hash(b"LNPBP_1").into_inner(),
            *LNPBP1_HASHED_TAG
        );
        assert_ne!(
            sha256::Hash::hash(b"lnpbp1").into_inner(),
            *LNPBP1_HASHED_TAG
        );
        assert_ne!(
            sha256::Hash::hash(b"lnpbp-1").into_inner(),
            *LNPBP1_HASHED_TAG
        );
        assert_ne!(
            sha256::Hash::hash(b"lnpbp_1").into_inner(),
            *LNPBP1_HASHED_TAG
        );
    }
}
