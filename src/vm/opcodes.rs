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

use std::marker::PhantomData;

use aluvm::reg::{Reg16, Reg32, RegS};
use amplify::num::{u2, u3};

use super::ContractStateAccess;

/// Operations defined under RGB ISA extension (`RGB`).
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum ContractOp<S: ContractStateAccess> {
    /// Counts number of global items elements defined by the current operation of the type,
    /// provided by the second argument, and puts the number to the destination `a32`
    /// register from the first argument.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// only if the `ty` index is unset. In this case, the value of the destination register
    /// remains unchanged.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("cn.c    a32{dst},a16{ty}")]
    CnC {
        /// Index of an `a32` register receiving count of global state items of the type provided
        /// in `ty`, contained in the contract global state.
        dst: Reg32,
        /// Index of `a16` register containing global state type.
        ty: Reg32,
    },

    /// Counts number of global items elements defined by the current operation of the type,
    /// provided by the second argument, and puts the number to the destination `a16`
    /// register from the first argument.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// only if the `ty` index is unset. In this case, the value of the destination register
    /// remains unchanged.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("cn.g    a16{dst},a16{ty}")]
    CnG {
        /// Index of an `a16` register receiving count of global state items of the type provided
        /// in `ty`, contained in the current operation.
        dst: Reg32,
        /// Index of `a16` register containing global state type.
        ty: Reg32,
    },

    /// Counts number of inputs (closed assignment seals) of the type provided by the second
    /// argument and puts the number to the destination `a16` register from the first argument.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// only if the `ty` index is unset. In this case, the value of the destination register
    /// remains unchanged.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("cn.i    a16{dst},a16{ty}")]
    CnI {
        /// Index of an `a16` register receiving count of the assignments which seals were closed
        /// by the current operation.
        dst: Reg32,
        /// Index of `a16` register containing assignment type.
        ty: Reg32,
    },

    /// Counts number of outputs (owned state assignments) of the type provided by the second
    /// argument and puts the number to the destination `a16` register from the first argument.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// only if the `ty` index is unset. In this case, the value of the destination register
    /// remains unchanged.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("cn.o    a16{dst},a16{ty}")]
    CnO {
        /// Index of an `a16` register receiving assignments count of the type provided in `ty`.
        dst: Reg32,
        /// Index of `a16` register containing assignment type.
        ty: Reg32,
    },

    #[doc(hidden)]
    /// Reserved command inside the counting operations sub-block.
    ///
    /// Currently, always set `st0` to failed state and terminate the program.
    #[display("cn.{instr}    a16{dst},a16{ty}")]
    CnReserved {
        instr: u2,
        dst: Reg32,
        ty: Reg32,
        _phantom: PhantomData<S>,
    },

    // TODO: implement ct.* operations
    #[doc(hidden)]
    /// Reserved for counting type ids.
    ///
    /// Currently, always set `st0` to failed state and terminate the program.
    #[display("ct.{instr}    a16{dst}")]
    CtReserved { instr: u3, dst: Reg32 },

    /// Loads contract global state.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// in the following cases:
    /// - `ty` index is unset;
    /// - `pos` index is unset;
    /// - the contract doesn't have the provided global state type;
    /// - the contract global state of the provided type has less than `pos` items.
    ///
    /// The value of the destination register in all these cases is not changed.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("ld.c    {dst},a16{ty},a32{pos}")]
    LdC {
        /// Index of string register receiving the loaded state data.
        dst: RegS,
        /// Index of `a16` register containing global state type.
        ty: Reg32,
        /// Index of `a32` register containing position inside the list of all global state by the
        /// given `ty` type.
        pos: Reg32,
    },

    /// Loads global state from the current operation.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// in the following cases:
    /// - `ty` index is unset;
    /// - `pos` index is unset;
    /// - the operation doesn't have the provided global state type;
    /// - the operation global state of the provided type has less than `pos` items.
    ///
    /// The value of the destination register in all these cases is not changed.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("ld.g    {dst},a16{ty},a16{pos}")]
    LdG {
        /// Index of string register receiving the loaded state data.
        dst: RegS,
        /// Index of `a16` register containing global state type.
        ty: Reg32,
        /// Index of `a16` register containing position inside the list of all global state by the
        /// given `ty` type.
        pos: Reg32,
    },

    /// Loads owned state from an assignment which seal was closed with the current operation
    /// ("input").
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// in the following cases:
    /// - `ty` index is unset;
    /// - `pos` index is unset;
    /// - none of the operation's inputs has the provided assignment type;
    /// - there is less than `pos` assignments in operation inputs of the provided type.
    ///
    /// The value of the destination register in all these cases is not changed.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("ld.i    {dst},a16{ty},a16{pos}")]
    LdI {
        /// Index of string register receiving the loaded state data.
        dst: RegS,
        /// Index of `a16` register containing assignment type.
        ty: Reg32,
        /// Index of `a16` register containing position inside the list of all assignments of the
        /// `ty` type.
        pos: Reg32,
    },

    /// Loads owned state assigned by the current operation.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// in the following cases:
    /// - `ty` index is unset;
    /// - `pos` index is unset;
    /// - the operation doesn't have assignments of the provided type;
    /// - the operation assignments of the provided type has less than `pos` items.
    ///
    /// The value of the destination register in all these cases is not changed.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("ld.o    {dst},a16{ty},a16{pos}")]
    LdO {
        /// Index of string register receiving the loaded state data.
        dst: RegS,
        /// Index of `a16` register containing assignment type.
        ty: Reg32,
        /// Index of `a16` register containing position inside the list of all assignments of the
        /// `ty` type.
        pos: Reg32,
    },

    /// Loads operation metadata.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// in the following cases:
    /// - `ty` index is unset;
    /// - the operation doesn't metadata of the provided type.
    ///
    /// The value of the destination register in all these cases is not changed.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("ldm     {dst},a16{ty}")]
    LdM {
        /// Index of string register receiving the loaded state data.
        dst: RegS,
        /// Index of `a16` register containing global state type.
        ty: Reg16,
    },
}
