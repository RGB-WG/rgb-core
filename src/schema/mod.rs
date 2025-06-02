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

mod operations;
#[allow(clippy::module_inception)]
mod schema;
mod state;
mod occurrences;

pub use occurrences::{Occurrences, OccurrencesMismatch};
pub use operations::{
    AssignmentType, AssignmentsSchema, GenesisSchema, GlobalSchema, MetaSchema, OpFullType,
    OpSchema, TransitionSchema, Verifier,
};
pub use schema::{
    AssignmentDetails, GlobalDetails, GlobalStateType, MetaDetails, MetaType, Schema, SchemaId,
    TransitionDetails, TransitionType,
};
pub use state::{GlobalStateSchema, OwnedStateSchema};
