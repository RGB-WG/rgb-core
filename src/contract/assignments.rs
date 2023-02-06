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

use amplify::confinement::MediumVec;
use commit_verify::merkle::MerkleNode;
use commit_verify::CommitmentId;

use super::state::{AttachmentPair, DeclarativePair, FungiblePair, StructuredPair};
use super::{
    attachment, data, seal, value, AssignedState, ConfidentialDataError, StateRetrievalError,
    StateType, UnknownDataError,
};
use crate::LIB_NAME_RGB;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Declarative(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
pub enum TypedState {
    // TODO: Consider using non-empty variants
    #[strict_type(tag = 0x00)]
    Declarative(MediumVec<AssignedState<DeclarativePair>>),
    #[strict_type(tag = 0x01)]
    Fungible(MediumVec<AssignedState<FungiblePair>>),
    #[strict_type(tag = 0x02)]
    Structured(MediumVec<AssignedState<StructuredPair>>),
    #[strict_type(tag = 0xFF)]
    Attachment(MediumVec<AssignedState<AttachmentPair>>),
}

impl TypedState {
    #[inline]
    pub fn state_type(&self) -> StateType {
        match self {
            TypedState::Declarative(_) => StateType::Void,
            TypedState::Fungible(_) => StateType::Fungible,
            TypedState::Structured(_) => StateType::Structured,
            TypedState::Attachment(_) => StateType::Attachment,
        }
    }

    #[inline]
    pub fn is_declarative(&self) -> bool { matches!(self, TypedState::Declarative(_)) }

    #[inline]
    pub fn is_fungible(&self) -> bool { matches!(self, TypedState::Fungible(_)) }

    #[inline]
    pub fn is_structured(&self) -> bool { matches!(self, TypedState::Structured(_)) }

    #[inline]
    pub fn is_attachment(&self) -> bool { matches!(self, TypedState::Attachment(_)) }

    #[inline]
    pub fn as_declarative(&self) -> &[AssignedState<DeclarativePair>] {
        match self {
            TypedState::Declarative(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_fungible(&self) -> &[AssignedState<FungiblePair>] {
        match self {
            TypedState::Fungible(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_structured(&self) -> &[AssignedState<StructuredPair>] {
        match self {
            TypedState::Structured(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_attachment(&self) -> &[AssignedState<AttachmentPair>] {
        match self {
            TypedState::Attachment(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_declarative_mut(&mut self) -> Option<&mut MediumVec<AssignedState<DeclarativePair>>> {
        match self {
            TypedState::Declarative(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_fungible_mut(&mut self) -> Option<&mut MediumVec<AssignedState<FungiblePair>>> {
        match self {
            TypedState::Fungible(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_structured_mut(&mut self) -> Option<&mut MediumVec<AssignedState<StructuredPair>>> {
        match self {
            TypedState::Structured(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_attachment_mut(&mut self) -> Option<&mut MediumVec<AssignedState<AttachmentPair>>> {
        match self {
            TypedState::Attachment(set) => Some(set),
            _ => None,
        }
    }

    pub fn revealed_seal_outputs(&self) -> Vec<(seal::Revealed, u16)> {
        match self {
            TypedState::Declarative(s) => s
                .iter()
                .map(AssignedState::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
            TypedState::Fungible(s) => s
                .iter()
                .map(AssignedState::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
            TypedState::Structured(s) => s
                .iter()
                .map(AssignedState::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
            TypedState::Attachment(s) => s
                .iter()
                .map(AssignedState::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
        }
    }

    /// If seal definition does not exist, returns [`UnknownDataError`]. If the
    /// seal is confidential, returns `Ok(None)`; otherwise returns revealed
    /// seal data packed as `Ok(Some(`[`seal::Revealed`]`))`
    pub fn revealed_seal_at(&self, index: u16) -> Result<Option<seal::Revealed>, UnknownDataError> {
        Ok(match self {
            TypedState::Declarative(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
            TypedState::Fungible(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
            TypedState::Structured(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
            TypedState::Attachment(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
        })
    }

    pub fn revealed_seals(&self) -> Result<Vec<seal::Revealed>, ConfidentialDataError> {
        let list: Vec<_> = match self {
            TypedState::Declarative(s) => s.iter().map(AssignedState::<_>::revealed_seal).collect(),
            TypedState::Fungible(s) => s.iter().map(AssignedState::<_>::revealed_seal).collect(),
            TypedState::Structured(s) => s.iter().map(AssignedState::<_>::revealed_seal).collect(),
            TypedState::Attachment(s) => s.iter().map(AssignedState::<_>::revealed_seal).collect(),
        };
        let len = list.len();
        let filtered: Vec<seal::Revealed> = list.into_iter().flatten().collect();
        if len != filtered.len() {
            return Err(ConfidentialDataError);
        }
        Ok(filtered)
    }

    pub fn filter_revealed_seals(&self) -> Vec<seal::Revealed> {
        match self {
            TypedState::Declarative(s) => s
                .iter()
                .filter_map(AssignedState::<_>::revealed_seal)
                .collect(),
            TypedState::Fungible(s) => s
                .iter()
                .filter_map(AssignedState::<_>::revealed_seal)
                .collect(),
            TypedState::Structured(s) => s
                .iter()
                .filter_map(AssignedState::<_>::revealed_seal)
                .collect(),
            TypedState::Attachment(s) => s
                .iter()
                .filter_map(AssignedState::<_>::revealed_seal)
                .collect(),
        }
    }

    pub fn to_confidential_seals(&self) -> Vec<seal::Confidential> {
        match self {
            TypedState::Declarative(s) => s
                .iter()
                .map(AssignedState::<_>::to_confidential_seal)
                .collect(),
            TypedState::Fungible(s) => s
                .iter()
                .map(AssignedState::<_>::to_confidential_seal)
                .collect(),
            TypedState::Structured(s) => s
                .iter()
                .map(AssignedState::<_>::to_confidential_seal)
                .collect(),
            TypedState::Attachment(s) => s
                .iter()
                .map(AssignedState::<_>::to_confidential_seal)
                .collect(),
        }
    }

    // --------------------

    pub fn revealed_fungible_state(&self) -> Result<Vec<&value::Revealed>, StateRetrievalError> {
        let list = match self {
            TypedState::Fungible(s) => s.iter().map(AssignedState::<_>::as_revealed_state),
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&value::Revealed> = list.flatten().collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        Ok(filtered)
    }

    pub fn revealed_structured_state(&self) -> Result<Vec<&data::Revealed>, StateRetrievalError> {
        let list = match self {
            TypedState::Structured(s) => s.iter().map(AssignedState::<_>::as_revealed_state),
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&data::Revealed> = list.flatten().collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        Ok(filtered)
    }

    pub fn revealed_attachments(&self) -> Result<Vec<&attachment::Revealed>, StateRetrievalError> {
        let list = match self {
            TypedState::Attachment(s) => s.iter().map(AssignedState::<_>::as_revealed_state),
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&attachment::Revealed> = list.flatten().collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        Ok(filtered)
    }

    pub fn filter_revealed_fungible_state(&self) -> Vec<&value::Revealed> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(s) => s
                .iter()
                .filter_map(AssignedState::<_>::as_revealed_state)
                .collect(),
            TypedState::Structured(_) => vec![],
            TypedState::Attachment(_) => vec![],
        }
    }

    pub fn filter_revealed_structured_state(&self) -> Vec<&data::Revealed> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(_) => vec![],
            TypedState::Structured(s) => s
                .iter()
                .filter_map(AssignedState::<_>::as_revealed_state)
                .collect(),
            TypedState::Attachment(_) => vec![],
        }
    }

    pub fn filter_revealed_attachments(&self) -> Vec<&attachment::Revealed> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(_) => vec![],
            TypedState::Structured(_) => vec![],
            TypedState::Attachment(s) => s
                .iter()
                .filter_map(AssignedState::<_>::as_revealed_state)
                .collect(),
        }
    }

    pub fn to_confidential_fungible_state(&self) -> Vec<value::Confidential> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(s) => s
                .iter()
                .map(AssignedState::<_>::to_confidential_state)
                .collect(),
            TypedState::Structured(_) => vec![],
            TypedState::Attachment(_) => vec![],
        }
    }

    pub fn to_confidential_structured_state(&self) -> Vec<data::Confidential> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(_) => vec![],
            TypedState::Structured(s) => s
                .iter()
                .map(AssignedState::<_>::to_confidential_state)
                .collect(),
            TypedState::Attachment(_) => vec![],
        }
    }

    pub fn to_confidential_attachments(&self) -> Vec<attachment::Confidential> {
        match self {
            TypedState::Declarative(_) => vec![],
            TypedState::Fungible(_) => vec![],
            TypedState::Structured(_) => vec![],
            TypedState::Attachment(s) => s
                .iter()
                .map(AssignedState::<_>::to_confidential_state)
                .collect(),
        }
    }

    #[inline]
    pub fn revealed_fungible_assignments(
        &self,
    ) -> Result<Vec<(seal::Revealed, &value::Revealed)>, StateRetrievalError> {
        match self {
            TypedState::Fungible(vec) => {
                let unfiltered: Vec<_> = vec
                    .iter()
                    .filter_map(|assignment| {
                        assignment.revealed_seal().and_then(|seal| {
                            assignment.as_revealed_state().map(|state| (seal, state))
                        })
                    })
                    .collect();
                if unfiltered.len() != vec.len() {
                    Err(StateRetrievalError::ConfidentialData)
                } else {
                    Ok(unfiltered)
                }
            }
            _ => Err(StateRetrievalError::StateTypeMismatch),
        }
    }

    #[inline]
    pub fn revealed_structured_assignments(
        &self,
    ) -> Result<Vec<(seal::Revealed, &data::Revealed)>, StateRetrievalError> {
        match self {
            TypedState::Structured(vec) => {
                let unfiltered: Vec<_> = vec
                    .iter()
                    .filter_map(|assignment| {
                        assignment.revealed_seal().and_then(|seal| {
                            assignment.as_revealed_state().map(|state| (seal, state))
                        })
                    })
                    .collect();
                if unfiltered.len() != vec.len() {
                    Err(StateRetrievalError::ConfidentialData)
                } else {
                    Ok(unfiltered)
                }
            }
            _ => Err(StateRetrievalError::StateTypeMismatch),
        }
    }

    #[inline]
    pub fn revealed_attachment_assignments(
        &self,
    ) -> Result<Vec<(seal::Revealed, &attachment::Revealed)>, StateRetrievalError> {
        match self {
            TypedState::Attachment(vec) => {
                let unfiltered: Vec<_> = vec
                    .iter()
                    .filter_map(|assignment| {
                        assignment.revealed_seal().and_then(|seal| {
                            assignment.as_revealed_state().map(|state| (seal, state))
                        })
                    })
                    .collect();
                if unfiltered.len() != vec.len() {
                    Err(StateRetrievalError::ConfidentialData)
                } else {
                    Ok(unfiltered)
                }
            }
            _ => Err(StateRetrievalError::StateTypeMismatch),
        }
    }

    // ---------------

    pub fn is_empty(&self) -> bool {
        match self {
            TypedState::Declarative(set) => set.is_empty(),
            TypedState::Fungible(set) => set.is_empty(),
            TypedState::Structured(set) => set.is_empty(),
            TypedState::Attachment(set) => set.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            TypedState::Declarative(set) => set.len(),
            TypedState::Fungible(set) => set.len(),
            TypedState::Structured(set) => set.len(),
            TypedState::Attachment(set) => set.len(),
        }
    }

    pub fn commitment_leaves(&self) -> Vec<MerkleNode> {
        match self {
            TypedState::Declarative(vec) => vec
                .iter()
                .map(AssignedState::<DeclarativePair>::commitment_id)
                .collect(),
            TypedState::Fungible(vec) => vec
                .iter()
                .map(AssignedState::<FungiblePair>::commitment_id)
                .collect(),
            TypedState::Structured(vec) => vec
                .iter()
                .map(AssignedState::<StructuredPair>::commitment_id)
                .collect(),
            TypedState::Attachment(vec) => vec
                .iter()
                .map(AssignedState::<AttachmentPair>::commitment_id)
                .collect(),
        }
    }
}
