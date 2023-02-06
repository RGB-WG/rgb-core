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

use super::owned_state::{AttachmentStrategy, DeclarativeStrategy, HashStrategy, PedersenStrategy};
use super::{
    attachment, data, seal, value, Assignment, ConfidentialDataError, StateRetrievalError,
    StateType, UnknownDataError,
};
use crate::LIB_NAME_RGB;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Void(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
pub enum TypedAssignments {
    // TODO: Consider using non-empty variants
    #[strict_type(tag = 0x00)]
    Void(MediumVec<Assignment<DeclarativeStrategy>>),
    #[strict_type(tag = 0x01)]
    Value(MediumVec<Assignment<PedersenStrategy>>),
    #[strict_type(tag = 0x02)]
    Data(MediumVec<Assignment<HashStrategy>>),
    #[strict_type(tag = 0xFF)]
    Attachment(MediumVec<Assignment<AttachmentStrategy>>),
}

impl TypedAssignments {
    #[inline]
    pub fn state_type(&self) -> StateType {
        match self {
            TypedAssignments::Void(_) => StateType::Void,
            TypedAssignments::Value(_) => StateType::Value,
            TypedAssignments::Data(_) => StateType::Data,
            TypedAssignments::Attachment(_) => StateType::Attachment,
        }
    }

    #[inline]
    pub fn is_declarative(&self) -> bool { matches!(self, TypedAssignments::Void(_)) }

    #[inline]
    pub fn has_value(&self) -> bool { matches!(self, TypedAssignments::Value(_)) }

    #[inline]
    pub fn has_data(&self) -> bool { matches!(self, TypedAssignments::Data(_)) }

    #[inline]
    pub fn is_attachment(&self) -> bool { matches!(self, TypedAssignments::Attachment(_)) }

    #[inline]
    pub fn as_declarative_assignments(&self) -> &[Assignment<DeclarativeStrategy>] {
        match self {
            TypedAssignments::Void(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_value_assignments(&self) -> &[Assignment<PedersenStrategy>] {
        match self {
            TypedAssignments::Value(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_data_assignments(&self) -> &[Assignment<HashStrategy>] {
        match self {
            TypedAssignments::Data(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_attachment_assignments(&self) -> &[Assignment<AttachmentStrategy>] {
        match self {
            TypedAssignments::Attachment(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn as_declarative_assignments_mut(
        &mut self,
    ) -> Option<&mut MediumVec<Assignment<DeclarativeStrategy>>> {
        match self {
            TypedAssignments::Void(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_value_assignments_mut(
        &mut self,
    ) -> Option<&mut MediumVec<Assignment<PedersenStrategy>>> {
        match self {
            TypedAssignments::Value(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_data_assignments_mut(&mut self) -> Option<&mut MediumVec<Assignment<HashStrategy>>> {
        match self {
            TypedAssignments::Data(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn as_attachment_assignments_mut(
        &mut self,
    ) -> Option<&mut MediumVec<Assignment<AttachmentStrategy>>> {
        match self {
            TypedAssignments::Attachment(set) => Some(set),
            _ => None,
        }
    }

    pub fn revealed_seal_outputs(&self) -> Vec<(seal::Revealed, u16)> {
        match self {
            TypedAssignments::Void(s) => s
                .iter()
                .map(Assignment::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
            TypedAssignments::Value(s) => s
                .iter()
                .map(Assignment::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
            TypedAssignments::Data(s) => s
                .iter()
                .map(Assignment::<_>::revealed_seal)
                .enumerate()
                .filter_map(|(no, seal)| seal.map(|s| (s, no as u16)))
                .collect(),
            TypedAssignments::Attachment(s) => s
                .iter()
                .map(Assignment::<_>::revealed_seal)
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
            TypedAssignments::Void(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
            TypedAssignments::Value(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
            TypedAssignments::Data(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
            TypedAssignments::Attachment(vec) => vec
                .get(index as usize)
                .ok_or(UnknownDataError)?
                .revealed_seal(),
        })
    }

    pub fn revealed_seals(&self) -> Result<Vec<seal::Revealed>, ConfidentialDataError> {
        let list: Vec<_> = match self {
            TypedAssignments::Void(s) => s.iter().map(Assignment::<_>::revealed_seal).collect(),
            TypedAssignments::Value(s) => s.iter().map(Assignment::<_>::revealed_seal).collect(),
            TypedAssignments::Data(s) => s.iter().map(Assignment::<_>::revealed_seal).collect(),
            TypedAssignments::Attachment(s) => {
                s.iter().map(Assignment::<_>::revealed_seal).collect()
            }
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
            TypedAssignments::Void(s) => s
                .iter()
                .filter_map(Assignment::<_>::revealed_seal)
                .collect(),
            TypedAssignments::Value(s) => s
                .iter()
                .filter_map(Assignment::<_>::revealed_seal)
                .collect(),
            TypedAssignments::Data(s) => s
                .iter()
                .filter_map(Assignment::<_>::revealed_seal)
                .collect(),
            TypedAssignments::Attachment(s) => s
                .iter()
                .filter_map(Assignment::<_>::revealed_seal)
                .collect(),
        }
    }

    pub fn to_confidential_seals(&self) -> Vec<seal::Confidential> {
        match self {
            TypedAssignments::Void(s) => s
                .iter()
                .map(Assignment::<_>::to_confidential_seal)
                .collect(),
            TypedAssignments::Value(s) => s
                .iter()
                .map(Assignment::<_>::to_confidential_seal)
                .collect(),
            TypedAssignments::Data(s) => s
                .iter()
                .map(Assignment::<_>::to_confidential_seal)
                .collect(),
            TypedAssignments::Attachment(s) => s
                .iter()
                .map(Assignment::<_>::to_confidential_seal)
                .collect(),
        }
    }

    pub fn as_revealed_state_values(&self) -> Result<Vec<&value::Revealed>, StateRetrievalError> {
        let list = match self {
            TypedAssignments::Value(s) => s.iter().map(Assignment::<_>::as_revealed_state),
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&value::Revealed> = list.flatten().collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        Ok(filtered)
    }

    pub fn as_revealed_state_data(&self) -> Result<Vec<&data::Revealed>, StateRetrievalError> {
        let list = match self {
            TypedAssignments::Data(s) => s.iter().map(Assignment::<_>::as_revealed_state),
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&data::Revealed> = list.flatten().collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        Ok(filtered)
    }

    pub fn as_revealed_state_attachments(
        &self,
    ) -> Result<Vec<&attachment::Revealed>, StateRetrievalError> {
        let list = match self {
            TypedAssignments::Attachment(s) => s.iter().map(Assignment::<_>::as_revealed_state),
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&attachment::Revealed> = list.flatten().collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        Ok(filtered)
    }

    pub fn filter_revealed_state_values(&self) -> Vec<&value::Revealed> {
        match self {
            TypedAssignments::Void(_) => vec![],
            TypedAssignments::Value(s) => s
                .iter()
                .filter_map(Assignment::<_>::as_revealed_state)
                .collect(),
            TypedAssignments::Data(_) => vec![],
            TypedAssignments::Attachment(_) => vec![],
        }
    }

    pub fn filter_revealed_state_data(&self) -> Vec<&data::Revealed> {
        match self {
            TypedAssignments::Void(_) => vec![],
            TypedAssignments::Value(_) => vec![],
            TypedAssignments::Data(s) => s
                .iter()
                .filter_map(Assignment::<_>::as_revealed_state)
                .collect(),
            TypedAssignments::Attachment(_) => vec![],
        }
    }

    pub fn filter_revealed_state_attachments(&self) -> Vec<&attachment::Revealed> {
        match self {
            TypedAssignments::Void(_) => vec![],
            TypedAssignments::Value(_) => vec![],
            TypedAssignments::Data(_) => vec![],
            TypedAssignments::Attachment(s) => s
                .iter()
                .filter_map(Assignment::<_>::as_revealed_state)
                .collect(),
        }
    }

    pub fn to_confidential_state_pedersen(&self) -> Vec<value::Confidential> {
        match self {
            TypedAssignments::Void(_) => vec![],
            TypedAssignments::Value(s) => s
                .iter()
                .map(Assignment::<_>::to_confidential_state)
                .collect(),
            TypedAssignments::Data(_) => vec![],
            TypedAssignments::Attachment(_) => vec![],
        }
    }

    pub fn to_confidential_state_hashed(&self) -> Vec<data::Confidential> {
        match self {
            TypedAssignments::Void(_) => vec![],
            TypedAssignments::Value(_) => vec![],
            TypedAssignments::Data(s) => s
                .iter()
                .map(Assignment::<_>::to_confidential_state)
                .collect(),
            TypedAssignments::Attachment(_) => vec![],
        }
    }

    pub fn to_confidential_state_attachments(&self) -> Vec<attachment::Confidential> {
        match self {
            TypedAssignments::Void(_) => vec![],
            TypedAssignments::Value(_) => vec![],
            TypedAssignments::Data(_) => vec![],
            TypedAssignments::Attachment(s) => s
                .iter()
                .map(Assignment::<_>::to_confidential_state)
                .collect(),
        }
    }

    #[inline]
    pub fn as_revealed_owned_value(
        &self,
    ) -> Result<Vec<(seal::Revealed, &value::Revealed)>, StateRetrievalError> {
        match self {
            TypedAssignments::Value(vec) => {
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
    pub fn as_revealed_owned_data(
        &self,
    ) -> Result<Vec<(seal::Revealed, &data::Revealed)>, StateRetrievalError> {
        match self {
            TypedAssignments::Data(vec) => {
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
    pub fn as_revealed_owned_attachments(
        &self,
    ) -> Result<Vec<(seal::Revealed, &attachment::Revealed)>, StateRetrievalError> {
        match self {
            TypedAssignments::Attachment(vec) => {
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

    pub fn is_empty(&self) -> bool {
        match self {
            TypedAssignments::Void(set) => set.is_empty(),
            TypedAssignments::Value(set) => set.is_empty(),
            TypedAssignments::Data(set) => set.is_empty(),
            TypedAssignments::Attachment(set) => set.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            TypedAssignments::Void(set) => set.len(),
            TypedAssignments::Value(set) => set.len(),
            TypedAssignments::Data(set) => set.len(),
            TypedAssignments::Attachment(set) => set.len(),
        }
    }

    pub fn commitment_leaves(&self) -> Vec<MerkleNode> {
        match self {
            TypedAssignments::Void(vec) => vec
                .iter()
                .map(Assignment::<DeclarativeStrategy>::commitment_id)
                .collect(),
            TypedAssignments::Value(vec) => vec
                .iter()
                .map(Assignment::<PedersenStrategy>::commitment_id)
                .collect(),
            TypedAssignments::Data(vec) => vec
                .iter()
                .map(Assignment::<HashStrategy>::commitment_id)
                .collect(),
            TypedAssignments::Attachment(vec) => vec
                .iter()
                .map(Assignment::<AttachmentStrategy>::commitment_id)
                .collect(),
        }
    }
}
