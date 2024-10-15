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

//! Common API for accessing RGB contract operation graph, including individual
//! state transitions, extensions, genesis, outputs, assignments &
//! single-use-seal data.

use std::collections::BTreeMap;

use aluvm::library::{Lib, LibId};
use amplify::confinement::{Confined, ConfinedOrdMap};
use strict_types::TypeSystem;

use super::EAnchor;
use crate::vm::XWitnessId;
use crate::{
    AssignmentType, AssignmentsRef, BundleId, ContractId, Extension, ExtensionType, Genesis,
    GlobalState, GraphSeal, Inputs, Metadata, OpFullType, OpId, OpType, Operation, Schema,
    Transition, TransitionBundle, TransitionType, TypedAssigns, Valencies,
};

pub const CONSIGNMENT_MAX_LIBS: usize = 1024;

pub type Scripts = ConfinedOrdMap<LibId, Lib, 0, CONSIGNMENT_MAX_LIBS>;

#[derive(Copy, Clone, PartialEq, Eq, Debug, From)]
pub enum OpRef<'op> {
    #[from]
    Genesis(&'op Genesis),
    #[from]
    Transition(&'op Transition),
    #[from]
    Extension(&'op Extension),
}

impl<'op> Operation for OpRef<'op> {
    fn op_type(&self) -> OpType {
        match self {
            Self::Genesis(op) => op.op_type(),
            Self::Transition(op) => op.op_type(),
            Self::Extension(op) => op.op_type(),
        }
    }

    fn full_type(&self) -> OpFullType {
        match self {
            Self::Genesis(op) => op.full_type(),
            Self::Transition(op) => op.full_type(),
            Self::Extension(op) => op.full_type(),
        }
    }

    fn id(&self) -> OpId {
        match self {
            Self::Genesis(op) => op.id(),
            Self::Transition(op) => op.id(),
            Self::Extension(op) => op.id(),
        }
    }

    fn contract_id(&self) -> ContractId {
        match self {
            Self::Genesis(op) => op.contract_id(),
            Self::Transition(op) => op.contract_id(),
            Self::Extension(op) => op.contract_id(),
        }
    }

    fn nonce(&self) -> u64 {
        match self {
            Self::Genesis(op) => op.nonce(),
            Self::Transition(op) => op.nonce(),
            Self::Extension(op) => op.nonce(),
        }
    }

    fn transition_type(&self) -> Option<TransitionType> {
        match self {
            Self::Genesis(op) => op.transition_type(),
            Self::Transition(op) => op.transition_type(),
            Self::Extension(op) => op.transition_type(),
        }
    }

    fn extension_type(&self) -> Option<ExtensionType> {
        match self {
            Self::Genesis(op) => op.extension_type(),
            Self::Transition(op) => op.extension_type(),
            Self::Extension(op) => op.extension_type(),
        }
    }

    fn metadata(&self) -> &Metadata {
        match self {
            Self::Genesis(op) => op.metadata(),
            Self::Transition(op) => op.metadata(),
            Self::Extension(op) => op.metadata(),
        }
    }

    fn globals(&self) -> &GlobalState {
        match self {
            Self::Genesis(op) => op.globals(),
            Self::Transition(op) => op.globals(),
            Self::Extension(op) => op.globals(),
        }
    }

    fn valencies(&self) -> &Valencies {
        match self {
            Self::Genesis(op) => op.valencies(),
            Self::Transition(op) => op.valencies(),
            Self::Extension(op) => op.valencies(),
        }
    }

    fn assignments(&self) -> AssignmentsRef<'op> {
        match self {
            Self::Genesis(op) => (&op.assignments).into(),
            Self::Transition(op) => (&op.assignments).into(),
            Self::Extension(op) => (&op.assignments).into(),
        }
    }

    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        match self {
            Self::Genesis(op) => op.assignments_by_type(t),
            Self::Transition(op) => op.assignments_by_type(t),
            Self::Extension(op) => op.assignments_by_type(t),
        }
    }

    fn inputs(&self) -> Inputs {
        match self {
            Self::Genesis(op) => op.inputs(),
            Self::Transition(op) => op.inputs(),
            Self::Extension(op) => op.inputs(),
        }
    }
}

pub struct CheckedConsignment<'consignment, C: ConsignmentApi>(&'consignment C);

impl<'consignment, C: ConsignmentApi> CheckedConsignment<'consignment, C> {
    pub fn new(consignment: &'consignment C) -> Self { Self(consignment) }
}

impl<'consignment, C: ConsignmentApi> ConsignmentApi for CheckedConsignment<'consignment, C> {
    fn schema(&self) -> &Schema { self.0.schema() }

    fn types(&self) -> &TypeSystem { self.0.types() }

    fn scripts(&self) -> &Scripts { self.0.scripts() }

    fn operation(&self, opid: OpId) -> Option<OpRef> {
        self.0.operation(opid).filter(|op| op.id() == opid)
    }

    fn genesis(&self) -> &Genesis { self.0.genesis() }

    fn bundle_ids<'iter>(&self) -> impl Iterator<Item = BundleId> + 'iter { self.0.bundle_ids() }

    fn bundle(&self, bundle_id: BundleId) -> Option<&TransitionBundle> {
        self.0
            .bundle(bundle_id)
            .filter(|b| b.bundle_id() == bundle_id)
    }

    fn anchor(&self, bundle_id: BundleId) -> Option<(XWitnessId, &EAnchor)> {
        self.0.anchor(bundle_id)
    }

    fn op_witness_id(&self, opid: OpId) -> Option<XWitnessId> { self.0.op_witness_id(opid) }
}

/// Trait defining common data access API for all storage-related RGB structures
///
/// The API provided for the consignment should not verify the internal
/// consistency, schema conformance or validation status of the RGB contract
/// data within the storage or container. If the methods are called on an
/// invalid or absent data, the API must always return [`None`] or empty
/// collections/iterators.
pub trait ConsignmentApi {
    /// Returns reference to the schema object used by the consignment.
    fn schema(&self) -> &Schema;

    /// Returns reference to the type system.
    fn types(&self) -> &TypeSystem;

    /// Returns reference to a collection of AluVM libraries used for the
    /// validation.
    fn scripts(&self) -> &Scripts;

    /// Retrieves reference to an operation (genesis, state transition or state
    /// extension) matching the provided id, or `None` otherwise
    fn operation(&self, opid: OpId) -> Option<OpRef>;

    /// Contract genesis.
    fn genesis(&self) -> &Genesis;

    /// Returns iterator over all bundle ids present in the consignment.
    fn bundle_ids<'iter>(&self) -> impl Iterator<Item = BundleId> + 'iter;

    /// Returns reference to a bundle given a bundle id.
    fn bundle(&self, bundle_id: BundleId) -> Option<&TransitionBundle>;

    /// Returns a grip given a bundle id.
    fn anchor(&self, bundle_id: BundleId) -> Option<(XWitnessId, &EAnchor)>;

    /// Returns witness id for a given operation.
    fn op_witness_id(&self, opid: OpId) -> Option<XWitnessId>;
}
