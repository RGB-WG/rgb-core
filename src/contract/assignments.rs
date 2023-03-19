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
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::{io, vec};

use amplify::confinement::{Confined, SmallVec, TinyOrdMap};
use commit_verify::merkle::{MerkleLeaves, MerkleNode};
use commit_verify::{CommitEncode, CommitStrategy, CommitmentId, Conceal};
use strict_encoding::{StrictDumb, StrictEncode, StrictWriter};

use super::{attachment, data, fungible, ExposedState};
use crate::contract::seal::GenesisSeal;
use crate::data::VoidState;
use crate::{AssignmentsType, ExposedSeal, GraphSeal, SecretSeal, StateType, LIB_NAME_RGB};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// the requested data are not present.
pub struct UnknownDataError;

pub type AssignRights<Seal> = Assign<VoidState, Seal>;
pub type AssignFungible<Seal> = Assign<fungible::Revealed, Seal>;
pub type AssignData<Seal> = Assign<data::Revealed, Seal>;
pub type AssignAttach<Seal> = Assign<attachment::Revealed, Seal>;

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
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        bound = "State::Confidential: serde::Serialize + serde::de::DeserializeOwned, State: \
                 serde::Serialize + serde::de::DeserializeOwned, Seal: serde::Serialize + \
                 serde::de::DeserializeOwned"
    )
)]
pub enum Assign<State: ExposedState, Seal: ExposedSeal> {
    #[strict_type(tag = 0x00)]
    Confidential {
        seal: SecretSeal,
        state: State::Confidential,
    },
    #[strict_type(tag = 0x03)]
    Revealed { seal: Seal, state: State },
    #[strict_type(tag = 0x02)]
    ConfidentialSeal { seal: SecretSeal, state: State },
    #[strict_type(tag = 0x01)]
    ConfidentialState {
        seal: Seal,
        state: State::Confidential,
    },
}

// Consensus-critical!
// Assignment indexes are part of the transition ancestor's commitment, so
// here we use deterministic ordering based on hash values of the concealed
// seal data contained within the assignment
impl<State: ExposedState, Seal: ExposedSeal> PartialOrd for Assign<State, Seal> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.to_confidential_seal()
            .partial_cmp(&other.to_confidential_seal())
    }
}

impl<State: ExposedState, Seal: ExposedSeal> Ord for Assign<State, Seal> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_confidential_seal()
            .cmp(&other.to_confidential_seal())
    }
}

impl<State: ExposedState, Seal: ExposedSeal> PartialEq for Assign<State, Seal> {
    fn eq(&self, other: &Self) -> bool {
        self.to_confidential_seal() == other.to_confidential_seal() &&
            self.to_confidential_state() == other.to_confidential_state()
    }
}

impl<State: ExposedState, Seal: ExposedSeal> Eq for Assign<State, Seal> {}

impl<State: ExposedState, Seal: ExposedSeal> Hash for Assign<State, Seal> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_confidential_seal().hash(state);
        self.to_confidential_state().hash(state);
    }
}

impl<State: ExposedState, Seal: ExposedSeal> Assign<State, Seal> {
    pub fn revealed(seal: Seal, state: State) -> Self { Assign::Revealed { seal, state } }

    pub fn with_seal_replaced(assignment: &Self, seal: Seal) -> Self {
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

    pub fn to_confidential_seal(&self) -> SecretSeal {
        match self {
            Assign::Revealed { seal, .. } | Assign::ConfidentialState { seal, .. } => {
                seal.conceal()
            }
            Assign::Confidential { seal, .. } | Assign::ConfidentialSeal { seal, .. } => *seal,
        }
    }

    pub fn revealed_seal(&self) -> Option<Seal> {
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

    pub fn into_revealed_state(self) -> Option<State> {
        match self {
            Assign::Revealed { state, .. } | Assign::ConfidentialSeal { state, .. } => Some(state),
            Assign::Confidential { .. } | Assign::ConfidentialState { .. } => None,
        }
    }

    pub fn as_revealed(&self) -> Option<(&Seal, &State)> {
        match self {
            Assign::Revealed { seal, state } => Some((seal, state)),
            _ => None,
        }
    }

    pub fn to_revealed(&self) -> Option<(Seal, State)> {
        match self {
            Assign::Revealed { seal, state } => Some((*seal, state.clone())),
            _ => None,
        }
    }

    pub fn into_revealed(self) -> Option<(Seal, State)> {
        match self {
            Assign::Revealed { seal, state } => Some((seal, state)),
            _ => None,
        }
    }
}

impl<State: ExposedState, Seal: ExposedSeal> Conceal for Assign<State, Seal>
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
impl<State: ExposedState, Seal: ExposedSeal> CommitEncode for Assign<State, Seal>
where Self: Clone
{
    fn commit_encode(&self, e: &mut impl io::Write) {
        let w = StrictWriter::with(u32::MAX as usize, e);
        self.conceal().strict_encode(w).ok();
    }
}

impl<State: ExposedState, Seal: ExposedSeal> CommitmentId for Assign<State, Seal>
where Self: Clone
{
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:owned-state:v1#23A";
    type Id = MerkleNode;
}

impl<State: ExposedState> Assign<State, GenesisSeal> {
    pub fn transmutate_seals(&self) -> Assign<State, GraphSeal> {
        match self {
            Assign::Confidential { seal, state } => Assign::Confidential {
                seal: *seal,
                state: state.clone(),
            },
            Assign::ConfidentialSeal { seal, state } => Assign::ConfidentialSeal {
                seal: *seal,
                state: state.clone(),
            },
            Assign::Revealed { seal, state } => Assign::Revealed {
                seal: seal.transmutate(),
                state: state.clone(),
            },
            Assign::ConfidentialState { seal, state } => Assign::ConfidentialState {
                seal: seal.transmutate(),
                state: state.clone(),
            },
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Declarative(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        bound = "Seal: serde::Serialize + serde::de::DeserializeOwned"
    )
)]
pub enum TypedAssigns<Seal: ExposedSeal> {
    // TODO: Consider using non-empty variants
    #[strict_type(tag = 0x00)]
    Declarative(SmallVec<AssignRights<Seal>>),
    #[strict_type(tag = 0x01)]
    Fungible(SmallVec<AssignFungible<Seal>>),
    #[strict_type(tag = 0x02)]
    Structured(SmallVec<AssignData<Seal>>),
    #[strict_type(tag = 0xFF)]
    Attachment(SmallVec<AssignAttach<Seal>>),
}

impl<Seal: ExposedSeal> TypedAssigns<Seal> {
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
    pub fn as_declarative(&self) -> &[AssignRights<Seal>] {
        match self {
            TypedAssigns::Declarative(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_fungible(&self) -> &[AssignFungible<Seal>] {
        match self {
            TypedAssigns::Fungible(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_structured(&self) -> &[AssignData<Seal>] {
        match self {
            TypedAssigns::Structured(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_attachment(&self) -> &[AssignAttach<Seal>] {
        match self {
            TypedAssigns::Attachment(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_declarative_mut(&mut self) -> Option<&mut SmallVec<AssignRights<Seal>>> {
        match self {
            TypedAssigns::Declarative(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_fungible_mut(&mut self) -> Option<&mut SmallVec<AssignFungible<Seal>>> {
        match self {
            TypedAssigns::Fungible(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_structured_mut(&mut self) -> Option<&mut SmallVec<AssignData<Seal>>> {
        match self {
            TypedAssigns::Structured(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_attachment_mut(&mut self) -> Option<&mut SmallVec<AssignAttach<Seal>>> {
        match self {
            TypedAssigns::Attachment(set) => Some(set),
            _ => None,
        }
    }

    /// If seal definition does not exist, returns [`UnknownDataError`]. If the
    /// seal is confidential, returns `Ok(None)`; otherwise returns revealed
    /// seal data packed as `Ok(Some(`[`Seal`]`))`
    pub fn revealed_seal_at(&self, index: u16) -> Result<Option<Seal>, UnknownDataError> {
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

    pub fn to_confidential_seals(&self) -> Vec<SecretSeal> {
        match self {
            TypedAssigns::Declarative(s) => s
                .iter()
                .map(AssignRights::<Seal>::to_confidential_seal)
                .collect(),
            TypedAssigns::Fungible(s) => s
                .iter()
                .map(AssignFungible::<Seal>::to_confidential_seal)
                .collect(),
            TypedAssigns::Structured(s) => s
                .iter()
                .map(AssignData::<Seal>::to_confidential_seal)
                .collect(),
            TypedAssigns::Attachment(s) => s
                .iter()
                .map(AssignAttach::<Seal>::to_confidential_seal)
                .collect(),
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

    pub fn into_structured_state_at(
        self,
        index: u16,
    ) -> Result<Option<data::Revealed>, UnknownDataError> {
        match self {
            TypedAssigns::Structured(vec) => {
                if index as usize >= vec.len() {
                    return Err(UnknownDataError);
                }
                Ok(vec
                    .into_inner()
                    .remove(index as usize)
                    .into_revealed_state())
            }
            _ => Err(UnknownDataError),
        }
    }

    pub fn into_fungible_state_at(
        self,
        index: u16,
    ) -> Result<Option<fungible::Revealed>, UnknownDataError> {
        match self {
            TypedAssigns::Fungible(vec) => {
                if index as usize >= vec.len() {
                    return Err(UnknownDataError);
                }
                Ok(vec
                    .into_inner()
                    .remove(index as usize)
                    .into_revealed_state())
            }
            _ => Err(UnknownDataError),
        }
    }
}

impl<Seal: ExposedSeal> CommitStrategy for TypedAssigns<Seal> {
    type Strategy =
        commit_verify::strategies::Merklize<{ u128::from_be_bytes(*b"rgb:state:owned*") }>;
}

impl<Seal: ExposedSeal> MerkleLeaves for TypedAssigns<Seal> {
    type Leaf = MerkleNode;
    type LeafIter = vec::IntoIter<MerkleNode>;

    fn merkle_leaves(&self) -> Self::LeafIter {
        match self {
            TypedAssigns::Declarative(vec) => vec
                .iter()
                .map(AssignRights::commitment_id)
                .collect::<Vec<_>>(),
            TypedAssigns::Fungible(vec) => vec
                .iter()
                .map(AssignFungible::commitment_id)
                .collect::<Vec<_>>(),
            TypedAssigns::Structured(vec) => vec
                .iter()
                .map(AssignData::commitment_id)
                .collect::<Vec<_>>(),
            TypedAssigns::Attachment(vec) => vec
                .iter()
                .map(AssignAttach::commitment_id)
                .collect::<Vec<_>>(),
        }
        .into_iter()
    }
}

impl TypedAssigns<GenesisSeal> {
    pub fn transmutate_seals(&self) -> TypedAssigns<GraphSeal> {
        match self {
            TypedAssigns::Declarative(a) => TypedAssigns::Declarative(
                Confined::try_from_iter(a.iter().map(|a| a.transmutate_seals()))
                    .expect("same size"),
            ),
            TypedAssigns::Fungible(a) => TypedAssigns::Fungible(
                Confined::try_from_iter(a.iter().map(|a| a.transmutate_seals()))
                    .expect("same size"),
            ),
            TypedAssigns::Structured(a) => TypedAssigns::Structured(
                Confined::try_from_iter(a.iter().map(|a| a.transmutate_seals()))
                    .expect("same size"),
            ),
            TypedAssigns::Attachment(a) => TypedAssigns::Attachment(
                Confined::try_from_iter(a.iter().map(|a| a.transmutate_seals()))
                    .expect("same size"),
            ),
        }
    }
}

#[derive(Wrapper, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        transparent,
        bound = "Seal: serde::Serialize + serde::de::DeserializeOwned"
    )
)]
pub struct Assignments<Seal>(TinyOrdMap<AssignmentsType, TypedAssigns<Seal>>)
where Seal: ExposedSeal;

impl<Seal: ExposedSeal> Default for Assignments<Seal> {
    fn default() -> Self { Self(empty!()) }
}

impl<Seal: ExposedSeal> CommitEncode for Assignments<Seal> {
    fn commit_encode(&self, mut e: &mut impl io::Write) {
        let w = StrictWriter::with(u32::MAX as usize, &mut e);
        self.0.len_u8().strict_encode(w).ok();
        for (ty, state) in &self.0 {
            let w = StrictWriter::with(u32::MAX as usize, &mut e);
            ty.strict_encode(w).ok();
            state.commit_encode(e);
        }
    }
}

impl Assignments<GenesisSeal> {
    pub fn transmutate_seals(&self) -> Assignments<GraphSeal> {
        Assignments(
            Confined::try_from_iter(self.iter().map(|(t, a)| (*t, a.transmutate_seals())))
                .expect("same size"),
        )
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, From)]
pub enum AssignmentsRef<'op> {
    #[from]
    Genesis(&'op Assignments<GenesisSeal>),

    #[from]
    Graph(&'op Assignments<GraphSeal>),
}

impl AssignmentsRef<'_> {
    pub fn len(&self) -> usize {
        match self {
            AssignmentsRef::Genesis(a) => a.len(),
            AssignmentsRef::Graph(a) => a.len(),
        }
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn types(&self) -> BTreeSet<AssignmentsType> {
        match self {
            AssignmentsRef::Genesis(a) => a.keys().copied().collect(),
            AssignmentsRef::Graph(a) => a.keys().copied().collect(),
        }
    }

    pub fn has_type(&self, t: AssignmentsType) -> bool {
        match self {
            AssignmentsRef::Genesis(a) => a.contains_key(&t),
            AssignmentsRef::Graph(a) => a.contains_key(&t),
        }
    }

    pub fn get(&self, t: AssignmentsType) -> Option<TypedAssigns<GraphSeal>> {
        match self {
            AssignmentsRef::Genesis(a) => a.get(&t).map(TypedAssigns::transmutate_seals),
            AssignmentsRef::Graph(a) => a.get(&t).cloned(),
        }
    }
}
