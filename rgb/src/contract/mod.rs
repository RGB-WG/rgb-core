// LNP/BP Rust Library
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

mod assignments;
#[macro_use]
pub mod data;
mod conceal;
mod metadata;
pub mod nodes;
pub mod seal;
pub mod value;

pub use assignments::{
    Assignments, ConfidentialState, DeclarativeStrategy, HashStrategy,
    OwnedRights, OwnedState, ParentOwnedRights, ParentPublicRights,
    PedersenStrategy, RevealedState, StateTypes,
};
pub use conceal::AutoConceal;
pub use metadata::Metadata;
pub use nodes::{ContractId, Extension, Genesis, Node, NodeId, Transition};
pub use seal::SealDefinition;
pub use value::AtomicValue;

use lnpbp::secp256k1zkp::Secp256k1 as Secp256k1zkp;
lazy_static! {
    /// Secp256k1zpk context object
    pub(crate) static ref SECP256K1_ZKP: Secp256k1zkp =
        Secp256k1zkp::with_caps(lnpbp::secp256k1zkp::ContextFlag::Commit);
}

/// Error returned when the requested data does not exist
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display(Debug)]
pub struct NoDataError;

#[cfg(test)]
pub(crate) mod test {
    use lnpbp::client_side_validation::{CommitEncode, Conceal};
    use lnpbp::strict_encoding::{StrictDecode, StrictEncode};

    pub fn test_confidential<T>(data: &[u8], encoded: &[u8], commitment: &[u8])
    where
        T: Conceal + StrictDecode + StrictEncode + Clone + CommitEncode,
        <T as Conceal>::Confidential: StrictDecode + StrictEncode + Eq,
    {
        // Create the Revealed Structure from data bytes
        let revealed = T::strict_decode(data).unwrap();

        // Conceal the Revealed structure into Confidential
        let confidential = revealed.conceal();

        // Strict_encode Confidential data
        let mut confidential_encoded = vec![];
        confidential
            .strict_encode(&mut confidential_encoded)
            .unwrap();

        // strict_encode Revealed data
        let mut revealed_encoded: Vec<u8> = vec![];
        revealed.strict_encode(&mut revealed_encoded).unwrap();

        // Assert encoded Confidential matches precomputed vector
        assert_eq!(encoded, &confidential_encoded[..]);

        // Assert encoded Confidential and Revealed are not equal
        assert_ne!(confidential_encoded.to_vec(), revealed_encoded);

        // commit_encode Revealed structure
        let mut commit_encoded_revealed = vec![];
        revealed.clone().commit_encode(&mut commit_encoded_revealed);

        if encoded == commitment {
            // Assert commit_encode and encoded Confidential matches
            assert_eq!(commit_encoded_revealed, confidential_encoded);
        } else {
            // Assert commit_encode and encoded Confidential does not match
            assert_ne!(commit_encoded_revealed, confidential_encoded);
        }

        // Assert commit_encode and precomputed Confidential matches
        assert_eq!(commit_encoded_revealed, commitment);
    }
}
