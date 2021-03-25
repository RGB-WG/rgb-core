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
pub mod reveal;
pub mod seal;
pub mod value;

pub use assignments::{
    Assignments, ConfidentialState, DeclarativeStrategy, HashStrategy,
    NodeOutput, OwnedRights, OwnedState, ParentOwnedRights, ParentPublicRights,
    PedersenStrategy, PublicRights, RevealedState, StateTypes,
};
pub(self) use assignments::{
    OwnedRightsInner, ParentOwnedRightsInner, ParentPublicRightsInner,
    PublicRightsInner,
};
pub use conceal::{ConcealSeals, ConcealState};
pub use metadata::Metadata;
pub use nodes::{ContractId, Extension, Genesis, Node, NodeId, Transition};
pub use reveal::IntoRevealed;
pub use seal::{SealDefinition, SealEndpoint, ToSealDefinition};
pub use value::AtomicValue;

use secp256k1zkp::Secp256k1 as Secp256k1zkp;
lazy_static! {
    /// Secp256k1zpk context object
    pub(crate) static ref SECP256K1_ZKP: Secp256k1zkp =
        Secp256k1zkp::with_caps(secp256k1zkp::ContextFlag::Commit);
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    Error,
    From,
)]
#[display(doc_comments)]
pub enum StateRetrievalError {
    /// The requested state has a mismatched data type
    StateTypeMismatch,

    /// Some of the requested data are confidential, when they must be present
    /// in revealed form
    #[from(ConfidentialDataError)]
    ConfidentialData,
}

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
/// The requested data are not present
pub struct NoDataError;

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
/// Some of the requested data are confidential, when they must be present in
/// revealed form
pub struct ConfidentialDataError;

#[cfg(test)]
pub(crate) mod test {
    use lnpbp::client_side_validation::{CommitConceal, CommitEncode};
    use lnpbp::strict_encoding::{StrictDecode, StrictEncode};

    pub fn test_confidential<T>(data: &[u8], encoded: &[u8], commitment: &[u8])
    where
        T: CommitConceal + StrictDecode + StrictEncode + Clone + CommitEncode,
        <T as CommitConceal>::ConcealedCommitment:
            StrictDecode + StrictEncode + Eq,
    {
        // Create the Revealed Structure from data bytes
        let revealed = T::strict_decode(data).unwrap();

        // CommitConceal the Revealed structure into Confidential
        let confidential = revealed.commit_conceal();

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
