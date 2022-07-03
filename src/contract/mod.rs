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

mod assignments;
#[macro_use]
pub mod data;
mod conceal;
mod metadata;
pub mod nodes;
pub mod reveal;
mod rights;
pub mod seal;
pub mod value;
pub mod attachment;

pub(self) use assignments::EMPTY_ASSIGNMENTS;
pub use assignments::{
    Assignment, AttachmentStrategy, ConfidentialState, DeclarativeStrategy, EndpointValueMap,
    HashStrategy, PedersenStrategy, RevealedState, SealValueMap, State, StateType,
    TypedAssignments,
};
pub use attachment::AttachmentId;
pub use conceal::{ConcealSeals, ConcealState};
pub use metadata::Metadata;
pub use nodes::{ContractId, Extension, Genesis, Node, NodeId, NodeOutpoint, Transition};
use once_cell::sync::Lazy;
pub use reveal::{MergeReveal, RevealSeals};
pub use rights::{OwnedRights, ParentOwnedRights, ParentPublicRights, PublicRights};
pub(crate) use rights::{OwnedRightsInner, PublicRightsInner};
pub use seal::{IntoRevealedSeal, SealEndpoint};
use secp256k1zkp::Secp256k1 as Secp256k1zkp;
pub use value::{AtomicValue, HomomorphicBulletproofGrin};

/// Secp256k1zpk context object
pub(crate) static SECP256K1_ZKP: Lazy<Secp256k1zkp> =
    Lazy::new(|| Secp256k1zkp::with_caps(secp256k1zkp::ContextFlag::Commit));

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StateRetrievalError {
    /// The requested state has a mismatched data type
    StateTypeMismatch,

    /// Some of the requested data are confidential, when they must be present
    /// in revealed form
    #[from(ConfidentialDataError)]
    ConfidentialData,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// The requested data are not present
pub struct NoDataError;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// Some of the requested data are confidential, when they must be present in
/// revealed form
pub struct ConfidentialDataError;

#[cfg(test)]
pub(crate) mod test {
    use commit_verify::{CommitConceal, CommitEncode};
    use strict_encoding::{StrictDecode, StrictEncode};

    pub fn test_confidential<T>(data: &[u8], encoded: &[u8], commitment: &[u8])
    where
        T: CommitConceal + StrictDecode + StrictEncode + Clone + CommitEncode,
        <T as CommitConceal>::ConcealedCommitment: StrictDecode + StrictEncode + Eq,
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
