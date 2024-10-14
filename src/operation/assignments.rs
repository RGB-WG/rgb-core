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

use std::cmp::Ordering;
use std::collections::{btree_map, BTreeSet};
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::{Deref, DerefMut};

use amplify::confinement::{Confined, NonEmptyVec, TinyOrdMap, U16 as U16MAX};
use commit_verify::{Conceal, ReservedBytes};
use strict_encoding::{StrictDumb, StrictEncode};

use crate::{
    AssignmentType, ExposedSeal, GenesisSeal, GraphSeal, SecretSeal, State, XChain,
    LIB_NAME_RGB_COMMIT,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// the requested data are not present.
pub struct ItemAbsent;

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
        bound = "Seal: serde::Serialize + serde::de::DeserializeOwned"
    )
)]
pub enum Assign<Seal: ExposedSeal> {
    #[strict_type(tag = 0x00)]
    Confidential {
        seal: XChain<SecretSeal>,
        state: State,
        lock: ReservedBytes<2, 0>,
    },
    #[strict_type(tag = 0x01)]
    Revealed {
        seal: XChain<Seal>,
        state: State,
        lock: ReservedBytes<2, 0>,
    },
}

// Consensus-critical!
// Assignment indexes are part of the transition ancestor's commitment, so
// here we use deterministic ordering based on hash values of the concealed
// seal data contained within the assignment
impl<Seal: ExposedSeal> PartialOrd for Assign<Seal> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<Seal: ExposedSeal> Ord for Assign<Seal> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_confidential_seal()
            .cmp(&other.to_confidential_seal())
    }
}

impl<Seal: ExposedSeal> PartialEq for Assign<Seal> {
    fn eq(&self, other: &Self) -> bool {
        self.to_confidential_seal() == other.to_confidential_seal()
            && self.as_state() == other.as_state()
    }
}

impl<Seal: ExposedSeal> Eq for Assign<Seal> {}

impl<Seal: ExposedSeal> Assign<Seal> {
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
            } => Assign::Confidential {
                seal: seal.conceal(),
                state: state.clone(),
                lock: *lock,
            },
            Assign::Revealed {
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

    pub fn as_state(&self) -> &State {
        match self {
            Assign::Confidential { state, .. } | Assign::Revealed { state, .. } => state,
        }
    }

    pub fn to_state(&self) -> State {
        match self {
            Assign::Confidential { state, .. } | Assign::Revealed { state, .. } => state.clone(),
        }
    }

    pub fn into_state(self) -> State {
        match self {
            Assign::Confidential { state, .. } | Assign::Revealed { state, .. } => state,
        }
    }

    pub fn to_confidential_seal(&self) -> XChain<SecretSeal> {
        match self {
            Assign::Revealed { seal, .. } => seal.conceal(),
            Assign::Confidential { seal, .. } => *seal,
        }
    }

    pub fn revealed_seal(&self) -> Option<XChain<Seal>> {
        match self {
            Assign::Revealed { seal, .. } => Some(*seal),
            Assign::Confidential { .. } => None,
        }
    }
}

impl<Seal: ExposedSeal> Conceal for Assign<Seal>
where Self: Clone
{
    type Concealed = Self;

    fn conceal(&self) -> Self::Concealed {
        match self {
            Assign::Confidential { .. } => self.clone(),
            Assign::Revealed { seal, state, lock } => Self::Confidential {
                seal: seal.conceal(),
                state: state.clone(),
                lock: *lock,
            },
        }
    }
}

impl Assign<GenesisSeal> {
    pub fn transmute_seals(&self) -> Assign<GraphSeal> {
        match self {
            Assign::Confidential { seal, state, lock } => Assign::Confidential {
                seal: *seal,
                state: state.clone(),
                lock: *lock,
            },
            Assign::Revealed { seal, state, lock } => Assign::Revealed {
                seal: seal.transmutate(),
                state: state.clone(),
                lock: *lock,
            },
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, From)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", bound = "Seal: serde::Serialize + serde::de::DeserializeOwned")
)]
pub struct TypedAssigns<Seal: ExposedSeal>(NonEmptyVec<Assign<Seal>, U16MAX>);

impl<Seal: ExposedSeal> Deref for TypedAssigns<Seal> {
    type Target = NonEmptyVec<Assign<Seal>, U16MAX>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl<Seal: ExposedSeal> DerefMut for TypedAssigns<Seal> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl<Seal: ExposedSeal> StrictDumb for TypedAssigns<Seal> {
    fn strict_dumb() -> Self { Self(NonEmptyVec::with(strict_dumb!())) }
}

impl<Seal: ExposedSeal> Conceal for TypedAssigns<Seal> {
    type Concealed = Self;
    fn conceal(&self) -> Self::Concealed {
        let concealed_iter = self.0.iter().map(Assign::<Seal>::conceal);
        let inner = NonEmptyVec::from_iter_checked(concealed_iter);
        TypedAssigns(inner)
    }
}

impl<Seal: ExposedSeal> TypedAssigns<Seal> {
    pub fn with(item: Assign<Seal>) -> Self { Self(NonEmptyVec::with(item)) }

    /// If seal definition does not exist, returns [`ItemAbsent`]. If the
    /// seal is confidential, returns `Ok(None)`; otherwise returns revealed
    /// seal data packed as `Ok(Some(`[`Seal`]`))`
    pub fn revealed_seal_at(&self, index: u16) -> Result<Option<XChain<Seal>>, ItemAbsent> {
        Ok(self
            .0
            .get(index as usize)
            .ok_or(ItemAbsent)?
            .revealed_seal())
    }

    pub fn as_state_at(&self, index: u16) -> Result<&State, ItemAbsent> {
        Ok(self.0.get(index as usize).ok_or(ItemAbsent)?.as_state())
    }

    pub fn into_state_at(self, index: u16) -> Result<State, ItemAbsent> {
        if index >= self.0.len_u16() {
            return Err(ItemAbsent);
        }
        Ok(self.0.release().remove(index as usize).into_state())
    }

    pub fn confidential_seals(&self) -> Vec<XChain<SecretSeal>> {
        self.0
            .iter()
            .map(Assign::<Seal>::to_confidential_seal)
            .collect()
    }
}

impl TypedAssigns<GenesisSeal> {
    pub fn transmute_seals(&self) -> TypedAssigns<GraphSeal> {
        TypedAssigns(NonEmptyVec::from_iter_checked(self.0.iter().map(Assign::transmute_seals)))
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
    pub fn transmute_seals(&self) -> Assignments<GraphSeal> {
        Assignments(
            Confined::try_from_iter(self.iter().map(|(t, a)| (*t, a.transmute_seals())))
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

    pub fn to_graph_seals(&self) -> Assignments<GraphSeal> {
        match *self {
            AssignmentsRef::Genesis(a) => a.transmute_seals(),
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
            AssignmentsRef::Genesis(a) => a.get(&t).map(TypedAssigns::transmute_seals),
            AssignmentsRef::Graph(a) => a.get(&t).cloned(),
        }
    }
}
