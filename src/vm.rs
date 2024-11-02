// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use aluvm::{CoreConfig, IsaId, Lib};
use amplify::confinement::{MediumOrdMap, SmallDeque, TinyOrdMap, TinyOrdSet};

use crate::{
    Assign, Assignments, ExtensionType, GlobalRef, GlobalState, GlobalStateType, Metadata, Opout, RgbSeal,
    TransitionType, Validators,
};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("todo!")]
pub struct VmError {}

pub struct RgbVm {}

impl RgbVm {
    pub(crate) fn with(
        isa: &TinyOrdSet<IsaId>,
        config: CoreConfig,
        validators: Validators,
        libs: &TinyOrdSet<Lib>,
    ) -> Self {
        todo!()
    }

    pub fn validate_genesis<Seal: RgbSeal>(
        &mut self,
        metadata: &Metadata,
        globals: &GlobalState,
        assignments: &Assignments<Seal>,
    ) -> Result<(), VmError> {
        todo!()
    }

    pub fn validate_extension<Seal: RgbSeal>(
        &mut self,
        ty: ExtensionType,
        contract_global: &TinyOrdMap<GlobalStateType, SmallDeque<GlobalRef>>,
        metadata: &Metadata,
        globals: &GlobalState,
        assignments: &Assignments<Seal>,
    ) -> Result<(), VmError> {
        todo!()
    }

    pub fn validate_transition<Seal: RgbSeal>(
        &mut self,
        ty: TransitionType,
        contract_global: &TinyOrdMap<GlobalStateType, SmallDeque<GlobalRef>>,
        unspent: &MediumOrdMap<Opout, Assign<Seal>>,
        metadata: &Metadata,
        globals: &GlobalState,
        assignments: &Assignments<Seal>,
    ) -> Result<(), VmError> {
        todo!()
    }
}
