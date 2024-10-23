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

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use aluvm::data::Number;
use aluvm::isa::Instr;
use aluvm::reg::{Reg32, RegA};
use aluvm::Vm;
use amplify::confinement::Confined;
use amplify::Wrapper;

use crate::validation::{CheckedApi, ContractApi};
use crate::vm::{ContractStateAccess, ContractStateEvolve, OpInfo, OrdOpRef, RgbIsa, VmContext};
use crate::{
    validation, AssignmentType, Assignments, Extension, GraphSeal, Inputs, OpId, Operation, Opout,
    Schema, Transition, TypedAssigns, Valencies,
};

impl Schema {
    pub fn validate_state<
        'validator,
        C: ContractApi,
        S: ContractStateAccess + ContractStateEvolve,
    >(
        &'validator self,
        consignment: &'validator CheckedApi<'_, C>,
        op: OrdOpRef,
        contract_state: Rc<RefCell<S>>,
    ) -> validation::Status {
        let opid = op.id();
        let mut status = validation::Status::new();

        let (validator, ty) = match op {
            OrdOpRef::Genesis(_) => (self.genesis_validator, None::<u16>),
            OrdOpRef::Transition(
                Transition {
                    transition_type, ..
                },
                ..,
            ) => {
                let transition_schema = *self
                    .transition_validators
                    .get(transition_type)
                    .unwrap_or(&self.default_transition_validator);
                (transition_schema, Some(transition_type.into_inner()))
            }
            OrdOpRef::Extension(Extension { extension_type, .. }, ..) => {
                let extension_schema = *self
                    .extension_validators
                    .get(extension_type)
                    .unwrap_or(&self.default_extension_validator);
                (extension_schema, Some(extension_type.into_inner()))
            }
        };

        let prev_state = if let OrdOpRef::Transition(transition, ..) = op {
            extract_prev_state(consignment, opid, &transition.inputs, &mut status)
        } else {
            Assignments::default()
        };
        let mut redeemed = Valencies::default();
        if let OrdOpRef::Extension(extension, ..) = op {
            for valency in extension.redeemed.keys() {
                redeemed.push(*valency).expect("same size");
            }
        }

        let genesis = consignment.genesis();
        let op_info = OpInfo::with(opid, &op, &prev_state, &redeemed);
        let context = VmContext {
            contract_id: genesis.contract_id(),
            op_info,
            contract_state,
        };

        // We need to run scripts as the very last step, since before that
        // we need to make sure that the operation data match the schema, so
        // scripts are not required to validate the structure of the state
        let scripts = consignment.scripts();
        let mut vm = Vm::<Instr<RgbIsa<S>>>::new();
        if let Some(ty) = ty {
            vm.registers.set_n(RegA::A16, Reg32::Reg0, ty);
        }
        if !vm.exec(validator, |id| scripts.get(&id), &context) {
            let error_code: Option<Number> = vm.registers.get_n(RegA::A8, Reg32::Reg0).into();
            status.add_failure(validation::Failure::ScriptFailure(
                opid,
                error_code.map(u8::from),
                None,
            ));
            // We return here since all other validations will have no valid state to access
            return status;
        }
        let contract_state = context.contract_state;
        if contract_state.borrow_mut().evolve_state(op).is_err() {
            status.add_failure(validation::Failure::ContractStateFilled(opid));
            // We return here since all other validations will have no valid state to access
            return status;
        }

        status
    }
}

fn extract_prev_state<C: ContractApi>(
    consignment: &C,
    opid: OpId,
    inputs: &Inputs,
    status: &mut validation::Status,
) -> Assignments<GraphSeal> {
    let mut assignments = BTreeMap::<AssignmentType, TypedAssigns<GraphSeal>>::new();
    for input in inputs {
        let Opout { op, ty, no } = input.prev_out;

        let prev_op = match consignment.operation(op) {
            None => {
                status.add_failure(validation::Failure::OperationAbsent(op));
                continue;
            }
            Some(op) => op,
        };

        let no = no as usize;
        if let Some(prev_assignments) = prev_op.assignments_by_type(ty) {
            if let Some(prev_assign) = prev_assignments.get(no).cloned() {
                if let Some(typed_assigns) = assignments.get_mut(&ty) {
                    typed_assigns.push(prev_assign).expect("same size");
                } else {
                    assignments
                        .insert(ty, TypedAssigns::with(prev_assign))
                        .expect("same size");
                }
            } else {
                status.add_failure(validation::Failure::NoPrevOut(opid, input.prev_out));
            }
        } else {
            // Presence of the required owned rights type in the
            // parent operation was already validated; we have nothing
            // to report here
        }
    }
    Confined::try_from(assignments)
        .expect("collections is assembled from another collection with the same size requirements")
        .into()
}
