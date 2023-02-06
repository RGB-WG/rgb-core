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
use std::io;

use commit_verify::merkle::MerkleNode;
use commit_verify::{CommitEncode, CommitmentId, Conceal};
use strict_encoding::{StrictEncode, StrictWriter};

use super::{attachment, data, seal, value, ConfidentialState, RevealedState};
use crate::LIB_NAME_RGB;

/// Categories of the state
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum StateType {
    /// No state data
    Void,

    /// Value-based state, i.e. which can be committed to with a Pedersen
    /// commitment
    Value,

    /// State defined with custom data
    Data,

    /// Attached data container
    Attachment,
}
pub trait State: Debug {
    type Confidential: ConfidentialState;
    type Revealed: RevealedState;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct DeclarativeStrategy;
impl State for DeclarativeStrategy {
    type Confidential = data::Void;
    type Revealed = data::Void;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct PedersenStrategy;
impl State for PedersenStrategy {
    type Confidential = value::Confidential;
    type Revealed = value::Revealed;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct HashStrategy;
impl State for HashStrategy {
    type Confidential = data::Confidential;
    type Revealed = data::Revealed;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct AttachmentStrategy;
impl State for AttachmentStrategy {
    type Confidential = attachment::Confidential;
    type Revealed = attachment::Revealed;
}

/// State data are assigned to a seal definition, which means that they are
/// owned by a person controlling spending of the seal UTXO, unless the seal
/// is closed, indicating that a transfer of ownership had taken place
#[derive(Clone, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(
    lib = LIB_NAME_RGB,
    tags = custom,
    dumb = { Self::Confidential { seal: strict_dumb!(), state: strict_dumb!() } }
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
pub enum Assignment<StateType>
where
    StateType: State,
    // Deterministic ordering requires Eq operation, so the confidential
    // state must have it
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    #[strict_type(tag = 0x00)]
    Confidential {
        seal: seal::Confidential,
        state: StateType::Confidential,
    },
    #[strict_type(tag = 0x04)]
    Revealed {
        seal: seal::Revealed,
        state: StateType::Revealed,
    },
    #[strict_type(tag = 0x02)]
    ConfidentialSeal {
        seal: seal::Confidential,
        state: StateType::Revealed,
    },
    #[strict_type(tag = 0x01)]
    ConfidentialState {
        seal: seal::Revealed,
        state: StateType::Confidential,
    },
}

// Consensus-critical!
// Assignment indexes are part of the transition ancestor's commitment, so
// here we use deterministic ordering based on hash values of the concealed
// seal data contained within the assignment
impl<StateType> PartialOrd for Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.to_confidential_seal()
            .partial_cmp(&other.to_confidential_seal())
    }
}

impl<StateType> Ord for Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_confidential_seal()
            .cmp(&other.to_confidential_seal())
    }
}

impl<StateType> PartialEq for Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn eq(&self, other: &Self) -> bool {
        self.to_confidential_seal() == other.to_confidential_seal() &&
            self.to_confidential_state() == other.to_confidential_state()
    }
}

impl<StateType> Eq for Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
}

impl<StateType> Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    pub fn revealed(seal: seal::Revealed, state: StateType::Revealed) -> Self {
        Assignment::Revealed { seal, state }
    }

    pub fn with_seal_replaced(assignment: &Self, seal: seal::Revealed) -> Self {
        match assignment {
            Assignment::Confidential { seal: _, state } |
            Assignment::ConfidentialState { seal: _, state } => Assignment::ConfidentialState {
                seal,
                state: state.clone(),
            },
            Assignment::ConfidentialSeal { seal: _, state } |
            Assignment::Revealed { seal: _, state } => Assignment::Revealed {
                seal,
                state: state.clone(),
            },
        }
    }

    pub fn to_confidential_seal(&self) -> seal::Confidential {
        match self {
            Assignment::Revealed { seal, .. } | Assignment::ConfidentialState { seal, .. } => {
                seal.conceal()
            }
            Assignment::Confidential { seal, .. } | Assignment::ConfidentialSeal { seal, .. } => {
                *seal
            }
        }
    }

    pub fn revealed_seal(&self) -> Option<seal::Revealed> {
        match self {
            Assignment::Revealed { seal, .. } | Assignment::ConfidentialState { seal, .. } => {
                Some(*seal)
            }
            Assignment::Confidential { .. } | Assignment::ConfidentialSeal { .. } => None,
        }
    }

    pub fn to_confidential_state(&self) -> StateType::Confidential {
        match self {
            Assignment::Revealed { state, .. } | Assignment::ConfidentialSeal { state, .. } => {
                state.conceal().into()
            }
            Assignment::Confidential { state, .. } |
            Assignment::ConfidentialState { state, .. } => state.clone(),
        }
    }

    pub fn as_revealed_state(&self) -> Option<&StateType::Revealed> {
        match self {
            Assignment::Revealed { state, .. } | Assignment::ConfidentialSeal { state, .. } => {
                Some(state)
            }
            Assignment::Confidential { .. } | Assignment::ConfidentialState { .. } => None,
        }
    }

    pub fn as_revealed(&self) -> Option<(&seal::Revealed, &StateType::Revealed)> {
        match self {
            Assignment::Revealed { seal, state } => Some((seal, state)),
            _ => None,
        }
    }

    pub fn to_revealed(&self) -> Option<(seal::Revealed, StateType::Revealed)> {
        match self {
            Assignment::Revealed { seal, state } => Some((*seal, state.clone())),
            _ => None,
        }
    }

    pub fn into_revealed(self) -> Option<(seal::Revealed, StateType::Revealed)> {
        match self {
            Assignment::Revealed { seal, state } => Some((seal, state)),
            _ => None,
        }
    }
}

impl<StateType> Conceal for Assignment<StateType>
where
    Self: Clone,
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    type Concealed = Self;

    fn conceal(&self) -> Self::Concealed {
        match self {
            Assignment::Confidential { .. } => self.clone(),
            Assignment::ConfidentialState { seal, state } => Self::Confidential {
                seal: seal.conceal(),
                state: state.clone(),
            },
            Assignment::Revealed { seal, state } => Self::Confidential {
                seal: seal.conceal(),
                state: state.conceal().into(),
            },
            Assignment::ConfidentialSeal { seal, state } => Self::Confidential {
                seal: *seal,
                state: state.conceal().into(),
            },
        }
    }
}

// We can't use `UsingConceal` strategy here since it relies on the
// `commit_encode` of the concealed type, and here the concealed type is again
// `OwnedState`, leading to a recurrency. So we use `strict_encode` of the
// concealed data.
impl<StateType> CommitEncode for Assignment<StateType>
where
    Self: Clone,
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn commit_encode(&self, e: &mut impl io::Write) {
        let w = StrictWriter::with(u32::MAX as usize, e);
        self.conceal().strict_encode(w).ok();
    }
}

impl<StateType> CommitmentId for Assignment<StateType>
where
    Self: Clone,
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:owned-state:v1#23A";
    type Id = MerkleNode;
}
