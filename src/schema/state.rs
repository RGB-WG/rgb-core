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

use amplify::num::{u24, u3};
use commit_verify::ReservedBytes;
use strict_types::SemId;

use crate::LIB_NAME_RGB_COMMIT;

/// Number of field elements, from 1 to 8. Can't be zero.
// TODO: Use NonZeroU3 when available.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct FielCount(u3);

/// NB: Schema can't check presence of structured state data and attachments for the owned state,
/// since this state is omitted from the history after compression, and the check can't be
/// arithmetized. Thus, while owned state may have a structured data and an attachment, they are
/// opaque for the RGB consensus validation.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct OwnedStateSchema {
    /// Reserved for the future versions
    pub reserved: ReservedBytes<1>,

    /// Presence and number of field elements.
    pub fiel_count: Option<FielCount>,
}

/// Indicates whether a state should be included into the contract history.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
pub enum PublicationSchema {
    /// The state is local to the operation subgraph between owned state and genesis.
    #[strict_type(tag = 0x00, dumb)]
    Local,

    /// The state structured data and attachment must be always included in the contract history
    /// even when are not part of the ancestor operations; and they must persist even when the
    /// history is compressed.
    #[strict_type(tag = 0x01)]
    Published {
        /// Maximal number of elements of this global state which are kept as a part of the
        /// contract state.
        depth: u24,
    },
}

impl PublicationSchema {
    pub fn is_published(self) -> bool { matches!(self, Self::Published { .. }) }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalStateSchema {
    /// Reserved for the future versions
    pub reserved: ReservedBytes<1>,

    /// Presence and number of field elements.
    pub fiel_count: Option<FielCount>,

    /// Semantic type id for the structured unverifiable part of the state, if such is present.
    pub sem_id: Option<SemId>,

    /// Indicates whether the state should - or must include an attachment.
    pub attach: Option<bool>,

    /// Indicates whether a state should be included into the contract history.
    pub publication: PublicationSchema,
}

impl GlobalStateSchema {
    pub fn is_published(&self) -> bool { self.publication.is_published() }

    /// All global state which is either public, or contains unverifiable data (structured state or
    /// attachments) can't be ommitted from the history on compression, and thus preserved in its
    /// explicit form.
    pub fn is_preserved(&self) -> bool {
        self.publication.is_published() || self.sem_id.is_some() || self.attach.is_some()
    }
}
