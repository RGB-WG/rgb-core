// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use aluvm::isa::{Instr, InstructionSet};
use aluvm::regs::IdxA;
use aluvm::{CoreConfig, IsaId, Lib, LibId};
use amplify::confinement::{NonEmptyOrdMap, SmallDeque, SmallVec, TinyOrdMap, TinyOrdSet};
use amplify::num::u5;

use crate::{
    AssignmentType, Assignments, ExtensionType, GlobalRef, GlobalState, GlobalStateType, Metadata, RgbInstr, RgbSeal,
    TransitionType, Validators, VerifiableState, SCHEMA_LIBS_MAX_COUNT,
};

pub type RgbIsa = Instr<LibId, RgbInstr>;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum VmError {
    /// invalid instruction set architecture `{0}`.
    Isa(String),

    /// provided schema requires RGB VM instruction set architectures which are not supported by the
    /// current version of RGB consensus (`{0}`).
    IsaExt(String),

    /// validation script has failed with a code {0:#4x}.
    Failed(u16),
}

/// Context for executing RGB VM instructions used to provide VM with the contract and operation
/// information and state data.
pub struct VmContext<'ctx> {
    pub op_ty: Option<u8>,
    pub contract_global: &'ctx TinyOrdMap<GlobalStateType, SmallDeque<GlobalRef>>,
    pub metadata: &'ctx Metadata,
    pub operation_input: TinyOrdMap<AssignmentType, SmallVec<VerifiableState>>,
    pub operation_global: &'ctx GlobalState,
    pub operation_owned: TinyOrdMap<AssignmentType, SmallVec<VerifiableState>>,
}

pub struct RgbVm {
    vm: aluvm::Vm<RgbIsa>,
    validators: Validators,
    libs: NonEmptyOrdMap<LibId, Lib, SCHEMA_LIBS_MAX_COUNT>,

    empty_globals: TinyOrdMap<GlobalStateType, SmallDeque<GlobalRef>>,
}

impl RgbVm {
    pub(crate) fn with(
        isa: &IsaId,
        isae: &TinyOrdSet<IsaId>,
        config: CoreConfig,
        validators: &Validators,
        libs: &NonEmptyOrdMap<LibId, Lib, SCHEMA_LIBS_MAX_COUNT>,
    ) -> Result<Self, VmError> {
        if &RgbInstr::isa_id() != isa {
            return Err(VmError::Isa(isa.to_string()));
        }
        let diff = isae
            .difference(&RgbInstr::isa_ext())
            .map(IsaId::to_string)
            .collect::<Vec<_>>();
        if !diff.is_empty() {
            return Err(VmError::IsaExt(diff.join(", ")));
        }
        let vm = aluvm::Vm::with(config);
        Ok(Self {
            vm,
            validators: validators.clone(),
            libs: libs.clone(),
            empty_globals: empty!(),
        })
    }

    pub fn validate_genesis<Seal: RgbSeal>(
        &mut self,
        metadata: &Metadata,
        globals: &GlobalState,
        assignments: &Assignments<Seal>,
    ) -> Result<(), VmError> {
        self.vm.reset();

        let operation_owned = map_assignments(assignments);
        let context = VmContext {
            op_ty: None,
            contract_global: &self.empty_globals,
            metadata,
            operation_global: globals,
            operation_input: empty!(),
            operation_owned,
        };

        self.vm
            .exec(self.validators.genesis_validator, |id| self.libs.get(&id), &context);
        self.result()
    }

    pub fn validate_extension<Seal: RgbSeal>(
        &mut self,
        ty: ExtensionType,
        contract_global: &TinyOrdMap<GlobalStateType, SmallDeque<GlobalRef>>,
        metadata: &Metadata,
        globals: &GlobalState,
        assignments: &Assignments<Seal>,
    ) -> Result<(), VmError> {
        self.vm.reset();

        let operation_owned = map_assignments(assignments);
        let context = VmContext {
            op_ty: Some(ty.to_u8()),
            contract_global,
            metadata,
            operation_global: globals,
            operation_input: empty!(),
            operation_owned,
        };

        let validator = self
            .validators
            .extension_validators
            .get(&ty)
            .unwrap_or(&self.validators.default_extension_validator);

        self.vm.exec(*validator, |id| self.libs.get(&id), &context);
        self.result()
    }

    pub fn validate_transition<Seal: RgbSeal>(
        &mut self,
        ty: TransitionType,
        contract_global: &TinyOrdMap<GlobalStateType, SmallDeque<GlobalRef>>,
        metadata: &Metadata,
        operation_global: &GlobalState,
        operation_input: TinyOrdMap<AssignmentType, SmallVec<VerifiableState>>,
        assignments: &Assignments<Seal>,
    ) -> Result<(), VmError> {
        self.vm.reset();

        let operation_owned = map_assignments(assignments);
        let context = VmContext {
            op_ty: Some(ty.to_u8()),
            contract_global,
            metadata,
            operation_input,
            operation_global,
            operation_owned,
        };

        let validator = self
            .validators
            .transition_validators
            .get(&ty)
            .unwrap_or(&self.validators.default_transition_validator);

        self.vm.exec(*validator, |id| self.libs.get(&id), &context);
        self.result()
    }

    fn result(&self) -> Result<(), VmError> {
        if self.vm.core.has_failed() {
            Err(VmError::Failed(
                self.vm
                    .core
                    .a16(IdxA::from(u5::with(15)))
                    .unwrap_or_default(),
            ))
        } else {
            Ok(())
        }
    }
}

fn map_assignments<Seal: RgbSeal>(
    assignments: &Assignments<Seal>,
) -> TinyOrdMap<AssignmentType, SmallVec<VerifiableState>> {
    let outputs = assignments.into_iter().map(|(ty, ta)| {
        let ta = SmallVec::from_iter_checked(ta.into_iter().map(|a| a.state));
        (*ty, ta)
    });
    TinyOrdMap::from_iter_checked(outputs)
}
