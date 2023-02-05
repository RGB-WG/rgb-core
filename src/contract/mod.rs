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

pub mod seal;

mod conceal;
// pub mod reveal;

pub mod value;
pub mod attachment;
pub mod data;
// mod assignments;
// mod metadata;
// pub mod nodes;
// mod rights;

pub use attachment::AttachId;
pub use conceal::{ConcealSeals, ConcealState};
// pub use reveal::{MergeReveal, RevealSeals};
pub use value::{
    BlindingFactor, FieldOrderOverflow, NoiseDumb, PedersenCommitment, RangeProof, RangeProofError,
    ValueAtom,
};

/*pub(self) use assignments::EMPTY_ASSIGNMENTS;
pub use assignments::{
    Assignment, AttachmentStrategy, ConfidentialState, DeclarativeStrategy, EndpointValueMap,
    HashStrategy, PedersenStrategy, RevealedState, SealValueMap, State, StateType,
    TypedAssignments,
};
pub use metadata::Metadata;
pub use nodes::{ContractId, Extension, Genesis, Node, NodeId, NodeOutpoint, Transition};
pub use rights::{OwnedRights, ParentOwnedRights, ParentPublicRights, PublicRights};
pub(crate) use rights::{OwnedRightsInner, PublicRightsInner};
pub use seal::{IntoRevealedSeal, SealEndpoint};
*/

/// Marker trait for types of state which are just a commitment to the actual
/// state data.
pub trait ConfidentialState: core::fmt::Debug + Clone + amplify::AsAny {}

/// Marker trait for types of state holding explicit state data.
pub trait RevealedState:
    core::fmt::Debug + commit_verify::Conceal + Clone + amplify::AsAny
{
}

/// Errors retrieving state data.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StateRetrievalError {
    /// the requested state has a mismatched data type.
    StateTypeMismatch,

    /// some of the requested data are confidential, when they must be present
    /// in revealed form.
    #[from(ConfidentialDataError)]
    ConfidentialData,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// the requested data are not present.
pub struct NoDataError;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// some of the requested data are confidential, when they must be present in
/// revealed form.
pub struct ConfidentialDataError;

#[cfg(test)]
pub(crate) mod test {
    use commit_verify::{CommitConceal, CommitEncode};
    use strict_encoding::{StrictDecode, StrictEncode};

    pub use super::value::test_helpers::*;

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
