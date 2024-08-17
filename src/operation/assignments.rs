// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.
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
use std::collections::{btree_map, BTreeSet};
use std::hash::Hash;

use amplify::confinement::{Confined, SmallVec, TinyOrdMap};
use commit_verify::{Conceal, ReservedBytes};
use strict_encoding::{StrictDumb, StrictEncode};

use super::ExposedState;
use crate::operation::seal::GenesisSeal;
use crate::{
    AssignmentType, ExposedSeal, GraphSeal, RevealedAttach, RevealedData, RevealedValue,
    SecretSeal, StateType, VoidState, XChain, LIB_NAME_RGB_COMMIT,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// the requested data are not present.
pub struct UnknownDataError;

pub type AssignRights<Seal> = Assign<VoidState, Seal>;
pub type AssignFungible<Seal> = Assign<RevealedValue, Seal>;
pub type AssignData<Seal> = Assign<RevealedData, Seal>;
pub type AssignAttach<Seal> = Assign<RevealedAttach, Seal>;

/// State data are assigned to a seal definition, which means that they are
/// owned by a person controlling spending of the seal UTXO, unless the seal
/// is closed, indicating that a transfer of ownership had taken place
#[derive(Clone, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(
    lib = LIB_NAME_RGB_COMMIT,
    tags = custom,
    dumb = { Self::Confidential { seal: strict_dumb!(), state: strict_dumb!(), lock: default!() } }
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        untagged,
        bound = "State::Confidential: serde::Serialize + serde::de::DeserializeOwned, State: \
                 serde::Serialize + serde::de::DeserializeOwned, Seal: serde::Serialize + \
                 serde::de::DeserializeOwned"
    )
)]
pub enum Assign<State: ExposedState, Seal: ExposedSeal> {
    #[strict_type(tag = 0x00)]
    Confidential {
        seal: XChain<SecretSeal>,
        state: State::Confidential,
        lock: ReservedBytes<2, 0>,
    },
    #[strict_type(tag = 0x03)]
    Revealed {
        seal: XChain<Seal>,
        state: State,
        lock: ReservedBytes<2, 0>,
    },
    #[strict_type(tag = 0x02)]
    ConfidentialSeal {
        seal: XChain<SecretSeal>,
        state: State,
        lock: ReservedBytes<2, 0>,
    },
    #[strict_type(tag = 0x01)]
    ConfidentialState {
        seal: XChain<Seal>,
        state: State::Confidential,
        lock: ReservedBytes<2, 0>,
    },
}

// Consensus-critical!
// Assignment indexes are part of the transition ancestor's commitment, so
// here we use deterministic ordering based on hash values of the concealed
// seal data contained within the assignment
impl<State: ExposedState, Seal: ExposedSeal> PartialOrd for Assign<State, Seal> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<State: ExposedState, Seal: ExposedSeal> Ord for Assign<State, Seal> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_confidential_seal()
            .cmp(&other.to_confidential_seal())
    }
}

impl<State: ExposedState, Seal: ExposedSeal> PartialEq for Assign<State, Seal> {
    fn eq(&self, other: &Self) -> bool {
        self.to_confidential_seal() == other.to_confidential_seal()
            && self.to_confidential_state() == other.to_confidential_state()
    }
}

impl<State: ExposedState, Seal: ExposedSeal> Eq for Assign<State, Seal> {}

impl<State: ExposedState, Seal: ExposedSeal> Assign<State, Seal> {
    pub fn revealed(seal: XChain<Seal>, state: State) -> Self {
        Assign::Revealed {
            seal,
            state,
            lock: default!(),
        }
    }

    pub fn with_seal_replaced(assignment: &Self, seal: XChain<Seal>) -> Self {
        match assignment {
            Assign::Confidential {
                seal: _,
                state,
                lock,
            }
            | Assign::ConfidentialState {
                seal: _,
                state,
                lock,
            } => Assign::ConfidentialState {
                seal,
                state: *state,
                lock: *lock,
            },
            Assign::ConfidentialSeal {
                seal: _,
                state,
                lock,
            }
            | Assign::Revealed {
                seal: _,
                state,
                lock,
            } => Assign::Revealed {
                seal,
                state: state.clone(),
                lock: *lock,
            },
        }
    }

    pub fn to_confidential_seal(&self) -> XChain<SecretSeal> {
        match self {
            Assign::Revealed { seal, .. } | Assign::ConfidentialState { seal, .. } => {
                seal.conceal()
            }
            Assign::Confidential { seal, .. } | Assign::ConfidentialSeal { seal, .. } => *seal,
        }
    }

    pub fn revealed_seal(&self) -> Option<XChain<Seal>> {
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
            Assign::Confidential { state, .. } | Assign::ConfidentialState { state, .. } => *state,
        }
    }

    pub fn as_revealed_state(&self) -> Option<&State> {
        match self {
            Assign::Revealed { state, .. } | Assign::ConfidentialSeal { state, .. } => Some(state),
            Assign::Confidential { .. } | Assign::ConfidentialState { .. } => None,
        }
    }

    pub fn as_revealed_state_mut(&mut self) -> Option<&mut State> {
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

    pub fn as_revealed(&self) -> Option<(&XChain<Seal>, &State)> {
        match self {
            Assign::Revealed { seal, state, .. } => Some((seal, state)),
            _ => None,
        }
    }

    pub fn to_revealed(&self) -> Option<(XChain<Seal>, State)> {
        match self {
            Assign::Revealed { seal, state, .. } => Some((*seal, state.clone())),
            _ => None,
        }
    }

    pub fn into_revealed(self) -> Option<(XChain<Seal>, State)> {
        match self {
            Assign::Revealed { seal, state, .. } => Some((seal, state)),
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
            Assign::ConfidentialState { seal, state, lock } => Self::Confidential {
                seal: seal.conceal(),
                state: *state,
                lock: *lock,
            },
            Assign::Revealed { seal, state, lock } => Self::Confidential {
                seal: seal.conceal(),
                state: state.conceal(),
                lock: *lock,
            },
            Assign::ConfidentialSeal { seal, state, lock } => Self::Confidential {
                seal: *seal,
                state: state.conceal(),
                lock: *lock,
            },
        }
    }
}

impl<State: ExposedState> Assign<State, GenesisSeal> {
    pub fn transmutate_seals(&self) -> Assign<State, GraphSeal> {
        match self {
            Assign::Confidential { seal, state, lock } => Assign::Confidential {
                seal: *seal,
                state: *state,
                lock: *lock,
            },
            Assign::ConfidentialSeal { seal, state, lock } => Assign::ConfidentialSeal {
                seal: *seal,
                state: state.clone(),
                lock: *lock,
            },
            Assign::Revealed { seal, state, lock } => Assign::Revealed {
                seal: seal.transmutate(),
                state: state.clone(),
                lock: *lock,
            },
            Assign::ConfidentialState { seal, state, lock } => Assign::ConfidentialState {
                seal: seal.transmutate(),
                state: *state,
                lock: *lock,
            },
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = custom, dumb = Self::Declarative(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        tag = "type",
        content = "items",
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

impl<Seal: ExposedSeal> Conceal for TypedAssigns<Seal> {
    type Concealed = Self;
    fn conceal(&self) -> Self::Concealed {
        match self {
            TypedAssigns::Declarative(s) => {
                let concealed_iter = s.iter().map(AssignRights::<Seal>::conceal);
                let inner = SmallVec::try_from_iter(concealed_iter).expect("same size");
                TypedAssigns::Declarative(inner)
            }
            TypedAssigns::Fungible(s) => {
                let concealed_iter = s.iter().map(AssignFungible::<Seal>::conceal);
                let inner = SmallVec::try_from_iter(concealed_iter).expect("same size");
                TypedAssigns::Fungible(inner)
            }
            TypedAssigns::Structured(s) => {
                let concealed_iter = s.iter().map(AssignData::<Seal>::conceal);
                let inner = SmallVec::try_from_iter(concealed_iter).expect("same size");
                TypedAssigns::Structured(inner)
            }
            TypedAssigns::Attachment(s) => {
                let concealed_iter = s.iter().map(AssignAttach::<Seal>::conceal);
                let inner = SmallVec::try_from_iter(concealed_iter).expect("same size");
                TypedAssigns::Attachment(inner)
            }
        }
    }
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

    pub fn len_u16(&self) -> u16 {
        match self {
            TypedAssigns::Declarative(set) => set.len_u16(),
            TypedAssigns::Fungible(set) => set.len_u16(),
            TypedAssigns::Structured(set) => set.len_u16(),
            TypedAssigns::Attachment(set) => set.len_u16(),
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
    pub fn revealed_seal_at(&self, index: u16) -> Result<Option<XChain<Seal>>, UnknownDataError> {
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

    pub fn to_confidential_seals(&self) -> Vec<XChain<SecretSeal>> {
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
    ) -> Result<Option<&RevealedData>, UnknownDataError> {
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
    ) -> Result<Option<&RevealedValue>, UnknownDataError> {
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
    ) -> Result<Option<RevealedData>, UnknownDataError> {
        match self {
            TypedAssigns::Structured(vec) => {
                if index as usize >= vec.len() {
                    return Err(UnknownDataError);
                }
                Ok(vec.release().remove(index as usize).into_revealed_state())
            }
            _ => Err(UnknownDataError),
        }
    }

    pub fn into_fungible_state_at(
        self,
        index: u16,
    ) -> Result<Option<RevealedValue>, UnknownDataError> {
        match self {
            TypedAssigns::Fungible(vec) => {
                if index as usize >= vec.len() {
                    return Err(UnknownDataError);
                }
                Ok(vec.release().remove(index as usize).into_revealed_state())
            }
            _ => Err(UnknownDataError),
        }
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

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        crate = "serde_crate",
        transparent,
        bound = "Seal: serde::Serialize + serde::de::DeserializeOwned"
    )
)]
pub struct Assignments<Seal>(TinyOrdMap<AssignmentType, TypedAssigns<Seal>>)
where Seal: ExposedSeal;

impl<Seal: ExposedSeal> Default for Assignments<Seal> {
    fn default() -> Self { Self(empty!()) }
}

impl Assignments<GenesisSeal> {
    pub fn transmutate_seals(&self) -> Assignments<GraphSeal> {
        Assignments(
            Confined::try_from_iter(self.iter().map(|(t, a)| (*t, a.transmutate_seals())))
                .expect("same size"),
        )
    }
}

impl<Seal: ExposedSeal> IntoIterator for Assignments<Seal> {
    type Item = (AssignmentType, TypedAssigns<Seal>);
    type IntoIter = btree_map::IntoIter<AssignmentType, TypedAssigns<Seal>>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
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

    pub fn flat(&self) -> Assignments<GraphSeal> {
        match *self {
            AssignmentsRef::Genesis(a) => a.transmutate_seals(),
            AssignmentsRef::Graph(a) => a.clone(),
        }
    }

    pub fn types(&self) -> BTreeSet<AssignmentType> {
        match self {
            AssignmentsRef::Genesis(a) => a.keys().copied().collect(),
            AssignmentsRef::Graph(a) => a.keys().copied().collect(),
        }
    }

    pub fn has_type(&self, t: AssignmentType) -> bool {
        match self {
            AssignmentsRef::Genesis(a) => a.contains_key(&t),
            AssignmentsRef::Graph(a) => a.contains_key(&t),
        }
    }

    pub fn get(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        match self {
            AssignmentsRef::Genesis(a) => a.get(&t).map(TypedAssigns::transmutate_seals),
            AssignmentsRef::Graph(a) => a.get(&t).cloned(),
        }
    }
}
