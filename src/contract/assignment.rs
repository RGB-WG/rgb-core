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

use core::cmp::Ordering;
use core::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::{io, vec};

use amplify::confinement::SmallVec;
use commit_verify::merkle::{MerkleLeaves, MerkleNode};
use commit_verify::{CommitEncode, CommitStrategy, CommitmentId, Conceal};
use strict_encoding::{StrictDumb, StrictEncode, StrictWriter};

use super::{attachment, data, fungible, seal, RevealedState};
use crate::data::VoidState;
use crate::LIB_NAME_RGB;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// the requested data are not present.
pub struct UnknownDataError;

/// Categories of the state
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum StateType {
    /// No state data
    Void,

    /// Value-based state, i.e. which can be committed to with a Pedersen
    /// commitment
    Fungible,

    /// State defined with custom data
    Structured,

    /// Attached data container
    Attachment,
}

/// State data are assigned to a seal definition, which means that they are
/// owned by a person controlling spending of the seal UTXO, unless the seal
/// is closed, indicating that a transfer of ownership had taken place
#[derive(Clone, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(
    lib = LIB_NAME_RGB,
    tags = custom,
    dumb = { Self::Confidential { seal: strict_dumb!(), state: strict_dumb!() } }
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum Assign<State: RevealedState> {
    #[strict_type(tag = 0x00)]
    Confidential {
        seal: seal::Confidential,
        state: State::Confidential,
    },
    #[strict_type(tag = 0x03)]
    Revealed { seal: seal::Revealed, state: State },
    #[strict_type(tag = 0x02)]
    ConfidentialSeal {
        seal: seal::Confidential,
        state: State,
    },
    #[strict_type(tag = 0x01)]
    ConfidentialState {
        seal: seal::Revealed,
        state: State::Confidential,
    },
}

// Consensus-critical!
// Assignment indexes are part of the transition ancestor's commitment, so
// here we use deterministic ordering based on hash values of the concealed
// seal data contained within the assignment
impl<State: RevealedState> PartialOrd for Assign<State> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.to_confidential_seal()
            .partial_cmp(&other.to_confidential_seal())
    }
}

impl<State: RevealedState> Ord for Assign<State> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_confidential_seal()
            .cmp(&other.to_confidential_seal())
    }
}

impl<State: RevealedState> PartialEq for Assign<State> {
    fn eq(&self, other: &Self) -> bool {
        self.to_confidential_seal() == other.to_confidential_seal() &&
            self.to_confidential_state() == other.to_confidential_state()
    }
}

impl<State: RevealedState> Eq for Assign<State> {}

impl<State: RevealedState> Hash for Assign<State> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_confidential_seal().hash(state);
        self.to_confidential_state().hash(state);
    }
}

impl<State: RevealedState> Assign<State> {
    pub fn revealed(seal: seal::Revealed, state: State) -> Self { Assign::Revealed { seal, state } }

    pub fn with_seal_replaced(assignment: &Self, seal: seal::Revealed) -> Self {
        match assignment {
            Assign::Confidential { seal: _, state } |
            Assign::ConfidentialState { seal: _, state } => Assign::ConfidentialState {
                seal,
                state: state.clone(),
            },
            Assign::ConfidentialSeal { seal: _, state } | Assign::Revealed { seal: _, state } => {
                Assign::Revealed {
                    seal,
                    state: state.clone(),
                }
            }
        }
    }

    pub fn to_confidential_seal(&self) -> seal::Confidential {
        match self {
            Assign::Revealed { seal, .. } | Assign::ConfidentialState { seal, .. } => {
                seal.conceal()
            }
            Assign::Confidential { seal, .. } | Assign::ConfidentialSeal { seal, .. } => *seal,
        }
    }

    pub fn revealed_seal(&self) -> Option<seal::Revealed> {
        match self {
            Assign::Revealed { seal, .. } | Assign::ConfidentialState { seal, .. } => Some(*seal),
            Assign::Confidential { .. } | Assign::ConfidentialSeal { .. } => None,
        }
    }

    pub fn to_confidential_state(&self) -> State::Confidential {
        match self {
            Assign::Revealed { state, .. } | Assign::ConfidentialSeal { state, .. } => {
                state.conceal()
            }
            Assign::Confidential { state, .. } | Assign::ConfidentialState { state, .. } => {
                state.clone()
            }
        }
    }

    pub fn as_revealed_state(&self) -> Option<&State> {
        match self {
            Assign::Revealed { state, .. } | Assign::ConfidentialSeal { state, .. } => Some(state),
            Assign::Confidential { .. } | Assign::ConfidentialState { .. } => None,
        }
    }

    pub fn as_revealed(&self) -> Option<(&seal::Revealed, &State)> {
        match self {
            Assign::Revealed { seal, state } => Some((seal, state)),
            _ => None,
        }
    }

    pub fn to_revealed(&self) -> Option<(seal::Revealed, State)> {
        match self {
            Assign::Revealed { seal, state } => Some((*seal, state.clone())),
            _ => None,
        }
    }

    pub fn into_revealed(self) -> Option<(seal::Revealed, State)> {
        match self {
            Assign::Revealed { seal, state } => Some((seal, state)),
            _ => None,
        }
    }
}

impl<State: RevealedState> Conceal for Assign<State>
where Self: Clone
{
    type Concealed = Self;

    fn conceal(&self) -> Self::Concealed {
        match self {
            Assign::Confidential { .. } => self.clone(),
            Assign::ConfidentialState { seal, state } => Self::Confidential {
                seal: seal.conceal(),
                state: state.clone(),
            },
            Assign::Revealed { seal, state } => Self::Confidential {
                seal: seal.conceal(),
                state: state.conceal(),
            },
            Assign::ConfidentialSeal { seal, state } => Self::Confidential {
                seal: *seal,
                state: state.conceal(),
            },
        }
    }
}

// We can't use `UsingConceal` strategy here since it relies on the
// `commit_encode` of the concealed type, and here the concealed type is again
// `OwnedState`, leading to a recurrency. So we use `strict_encode` of the
// concealed data.
impl<State: RevealedState> CommitEncode for Assign<State>
where Self: Clone
{
    fn commit_encode(&self, e: &mut impl io::Write) {
        let w = StrictWriter::with(u32::MAX as usize, e);
        self.conceal().strict_encode(w).ok();
    }
}

impl<State: RevealedState> CommitmentId for Assign<State>
where Self: Clone
{
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:owned-state:v1#23A";
    type Id = MerkleNode;
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Declarative(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum TypedAssigns {
    // TODO: Consider using non-empty variants
    #[strict_type(tag = 0x00)]
    Declarative(SmallVec<Assign<VoidState>>),
    #[strict_type(tag = 0x01)]
    Fungible(SmallVec<Assign<fungible::Revealed>>),
    #[strict_type(tag = 0x02)]
    Structured(SmallVec<Assign<data::Revealed>>),
    #[strict_type(tag = 0xFF)]
    Attachment(SmallVec<Assign<attachment::Revealed>>),
}

impl TypedAssigns {
    pub fn is_empty(&self) -> bool {
        match self {
            TypedAssigns::Declarative(set) => set.is_empty(),
            TypedAssigns::Fungible(set) => set.is_empty(),
            TypedAssigns::Structured(set) => set.is_empty(),
            TypedAssigns::Attachment(set) => set.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            TypedAssigns::Declarative(set) => set.len(),
            TypedAssigns::Fungible(set) => set.len(),
            TypedAssigns::Structured(set) => set.len(),
            TypedAssigns::Attachment(set) => set.len(),
        }
    }

    #[inline]
    pub fn state_type(&self) -> StateType {
        match self {
            TypedAssigns::Declarative(_) => StateType::Void,
            TypedAssigns::Fungible(_) => StateType::Fungible,
            TypedAssigns::Structured(_) => StateType::Structured,
            TypedAssigns::Attachment(_) => StateType::Attachment,
        }
    }

    #[inline]
    pub fn is_declarative(&self) -> bool { matches!(self, TypedAssigns::Declarative(_)) }

    #[inline]
    pub fn is_fungible(&self) -> bool { matches!(self, TypedAssigns::Fungible(_)) }

    #[inline]
    pub fn is_structured(&self) -> bool { matches!(self, TypedAssigns::Structured(_)) }

    #[inline]
    pub fn is_attachment(&self) -> bool { matches!(self, TypedAssigns::Attachment(_)) }

    #[inline]
    pub fn as_declarative(&self) -> &[Assign<VoidState>] {
        match self {
            TypedAssigns::Declarative(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_fungible(&self) -> &[Assign<fungible::Revealed>] {
        match self {
            TypedAssigns::Fungible(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_structured(&self) -> &[Assign<data::Revealed>] {
        match self {
            TypedAssigns::Structured(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_attachment(&self) -> &[Assign<attachment::Revealed>] {
        match self {
            TypedAssigns::Attachment(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_declarative_mut(&mut self) -> Option<&mut SmallVec<Assign<VoidState>>> {
        match self {
            TypedAssigns::Declarative(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_fungible_mut(&mut self) -> Option<&mut SmallVec<Assign<fungible::Revealed>>> {
        match self {
            TypedAssigns::Fungible(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_structured_mut(&mut self) -> Option<&mut SmallVec<Assign<data::Revealed>>> {
        match self {
            TypedAssigns::Structured(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_attachment_mut(&mut self) -> Option<&mut SmallVec<Assign<attachment::Revealed>>> {
        match self {
            TypedAssigns::Attachment(set) => Some(set),
            _ => None,
        }
    }

    /// If seal definition does not exist, returns [`UnknownDataError`]. If the
    /// seal is confidential, returns `Ok(None)`; otherwise returns revealed
    /// seal data packed as `Ok(Some(`[`seal::Revealed`]`))`
    pub fn revealed_seal_at(&self, index: u16) -> Result<Option<seal::Revealed>, UnknownDataError> {
        Ok(match self {
            TypedAssigns::Declarative(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
            TypedAssigns::Fungible(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
            TypedAssigns::Structured(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
            TypedAssigns::Attachment(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
        })
    }

    pub fn to_confidential_seals(&self) -> Vec<seal::Confidential> {
        match self {
            TypedAssigns::Declarative(s) => {
                s.iter().map(Assign::<_>::to_confidential_seal).collect()
            }
            TypedAssigns::Fungible(s) => s.iter().map(Assign::<_>::to_confidential_seal).collect(),
            TypedAssigns::Structured(s) => {
                s.iter().map(Assign::<_>::to_confidential_seal).collect()
            }
            TypedAssigns::Attachment(s) => {
                s.iter().map(Assign::<_>::to_confidential_seal).collect()
            }
        }
    }

    pub fn as_structured_state_at(
        &self,
        index: u16,
    ) -> Result<Option<&data::Revealed>, UnknownDataError> {
        match self {
            TypedAssigns::Structured(vec) => Ok(vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .as_revealed_state()),
            _ => Err(UnknownDataError),
        }
    }

    pub fn as_fungible_state_at(
        &self,
        index: u16,
    ) -> Result<Option<&fungible::Revealed>, UnknownDataError> {
        match self {
            TypedAssigns::Fungible(vec) => Ok(vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .as_revealed_state()),
            _ => Err(UnknownDataError),
        }
    }
}

impl CommitStrategy for TypedAssigns {
    type Strategy =
        commit_verify::strategies::Merklize<{ u128::from_be_bytes(*b"rgb:state:owned*") }>;
}

impl MerkleLeaves for TypedAssigns {
    type Leaf = MerkleNode;
    type LeafIter = vec::IntoIter<MerkleNode>;

    fn merkle_leaves(&self) -> Self::LeafIter {
        match self {
            TypedAssigns::Declarative(vec) => vec
                .iter()
                .map(Assign::<VoidState>::commitment_id)
                .collect::<Vec<_>>(),
            TypedAssigns::Fungible(vec) => vec
                .iter()
                .map(Assign::<fungible::Revealed>::commitment_id)
                .collect::<Vec<_>>(),
            TypedAssigns::Structured(vec) => vec
                .iter()
                .map(Assign::<data::Revealed>::commitment_id)
                .collect::<Vec<_>>(),
            TypedAssigns::Attachment(vec) => vec
                .iter()
                .map(Assign::<attachment::Revealed>::commitment_id)
                .collect::<Vec<_>>(),
        }
        .into_iter()
    }
}
