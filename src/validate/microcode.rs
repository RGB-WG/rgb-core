// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use aluvm::regs::{IdxA, RegA, A};
use aluvm::{ExecStep, LibId, Site};
use amplify::confinement::{SmallDeque, SmallVec};

use crate::{AssignmentType, GlobalStateType, MetaType, VerifiableState, VmContext};

impl<'ctx> VmContext<'ctx> {
    #[must_use]
    pub(super) fn cnc(&self, ty: GlobalStateType) -> u16 {
        self.contract_global
            .get(&ty)
            .map(SmallDeque::len_u16)
            .unwrap_or_default()
    }
    #[must_use]
    pub(super) fn cng(&self, ty: GlobalStateType) -> Option<u16> {
        self.operation_global.get(&ty).map(|list| list.len_u16())
    }
    #[must_use]
    pub(super) fn cni(&self, ty: AssignmentType) -> Option<u16> { self.operation_input.get(&ty).map(SmallVec::len_u16) }
    #[must_use]
    pub(super) fn cno(&self, ty: AssignmentType) -> Option<u16> { self.operation_owned.get(&ty).map(SmallVec::len_u16) }

    #[must_use]
    pub(super) fn rdc(&self, ty: GlobalStateType, pos: u16) -> Option<VerifiableState> {
        let stack = self.contract_global.get(&ty)?;
        let glob = stack.iter().nth_back(pos as usize)?;
        Some(glob.state)
    }

    #[must_use]
    pub(super) fn rdg(&self, ty: GlobalStateType, pos: u16) -> Option<VerifiableState> {
        let list = self.operation_global.get(&ty)?;
        let state = list.get(pos as usize)?;
        Some(state.verifiable)
    }

    #[must_use]
    pub(super) fn rdi(&self, ty: AssignmentType, pos: u16) -> Option<VerifiableState> {
        let list = self.operation_input.get(&ty)?;
        list.get(pos as usize).cloned()
    }

    #[must_use]
    pub(super) fn rdo(&self, ty: AssignmentType, pos: u16) -> Option<VerifiableState> {
        let list = self.operation_owned.get(&ty)?;
        list.get(pos as usize).cloned()
    }

    #[must_use]
    pub(super) fn rdm(&self, ty: MetaType) -> Option<VerifiableState> { self.metadata.get(&ty).cloned() }
}

/// Core-based microcode for RGB1 ISAE.
pub(super) trait Microcode {
    fn cnt<C>(&mut self, counting_circuit: C, dst: IdxA) -> ExecStep<Site<LibId>>
    where C: FnOnce() -> u16;

    fn cn<C>(&mut self, counting_circuit: C, dst: IdxA) -> ExecStep<Site<LibId>>
    where C: FnOnce() -> Option<u16>;

    /// Read [`VerifiableState`] using `read_circuit` provided with an index from `pos` `A16`
    /// register; then load `el` element of it to the `dst` register by running [`Self::ldfe`].
    ///
    /// If `read_circuit`, or [`Self::ldfe`] fails, sets `dst` to `None` and `CK` to a failed state,
    /// returning [`ExecStep::FailContinue`]. Otherwise, returns [`ExecStep::Next`].
    #[must_use]
    fn rdild<C>(&mut self, reading_circuit: C, dst: RegA, pos: IdxA, el: u8) -> ExecStep<Site<LibId>>
    where C: FnOnce(u16) -> Option<VerifiableState>;

    /// Read [`VerifiableState`] using `read_circuit` and then load `el` element of it to the `dst`
    /// register by running [`Self::ldfe`].
    ///
    /// If `read_circuit`, or [`Self::ldfe`] fails, sets `dst` to `None` and `CK` to a failed state,
    /// returning [`ExecStep::FailContinue`]. Otherwise, returns [`ExecStep::Next`].
    #[must_use]
    fn rdld<C>(&mut self, reading_circuit: C, dst: RegA, el: u8) -> ExecStep<Site<LibId>>
    where C: FnOnce() -> Option<VerifiableState>;

    /// Load a field element to a destination `A` register.
    ///
    /// If the bit dimensions of the `dst` and field element do not match, or if the verifiable
    /// state doesn't have a field element with index `el`, returns `false`. Otherwise, returns
    /// `true`.
    #[must_use]
    fn ldfe(&mut self, state: VerifiableState, dst: RegA, el: u8) -> bool;
}

impl Microcode for aluvm::Core<LibId> {
    fn cnt<C>(&mut self, counting_circuit: C, dst: IdxA) -> ExecStep<Site<LibId>>
    where C: FnOnce() -> u16 {
        let count = counting_circuit();
        self.set_a16(dst, count);
        ExecStep::Next
    }

    fn cn<C>(&mut self, counting_circuit: C, dst: IdxA) -> ExecStep<Site<LibId>>
    where C: FnOnce() -> Option<u16> {
        if let Some(count) = counting_circuit() {
            self.set_a16(dst, count);
            ExecStep::Next
        } else {
            self.clr_a16(dst);
            ExecStep::FailContinue
        }
    }

    fn rdild<C>(&mut self, reading_circuit: C, dst: RegA, pos: IdxA, el: u8) -> ExecStep<Site<LibId>>
    where C: FnOnce(u16) -> Option<VerifiableState> {
        let pos = self.a16(pos);
        let writing_circuit = |state: VerifiableState| self.ldfe(state, dst, el).then_some(());
        if pos
            .and_then(reading_circuit)
            .and_then(writing_circuit)
            .is_some()
        {
            ExecStep::Next
        } else {
            self.clr_a(dst);
            ExecStep::FailContinue
        }
    }

    fn rdld<C>(&mut self, reading_circuit: C, dst: RegA, el: u8) -> ExecStep<Site<LibId>>
    where C: FnOnce() -> Option<VerifiableState> {
        let writing_circuit = |state: VerifiableState| self.ldfe(state, dst, el).then_some(());

        if reading_circuit().and_then(writing_circuit).is_some() {
            ExecStep::Next
        } else {
            self.clr_a(dst);
            ExecStep::FailContinue
        }
    }

    fn ldfe(&mut self, state: VerifiableState, dst: RegA, el: u8) -> bool {
        match (state, dst.a()) {
            (VerifiableState::Le32bit(arr), A::A32) => {
                let Some(fiel) = arr.get(el) else { return false };
                self.set_a32(dst.idx(), fiel);
                true
            }
            (VerifiableState::Le64bit(arr), A::A64) => {
                let Some(fiel) = arr.get(el) else { return false };
                self.set_a64(dst.idx(), fiel);
                true
            }
            (VerifiableState::Le128Bit(arr), A::A128) => {
                let Some(fiel) = arr.get(el) else { return false };
                self.set_a128(dst.idx(), fiel);
                true
            }
            _ => false,
        }
    }
}
