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

/// Transforms a block of RGB assembly code into a program, which can be assembled into a
/// binary form with [`Lib::assemble`].
///
/// The resulting program has `Vec::<`[`Instr`]`<`[`RgbIsa`]`>``>` type.
///
/// # Example
///
/// ```
/// use rgbcore::{assemble, rgbasm};
///
/// let asm = rgbasm! {
///         ld.g    s16[0],a16[0],a16[1];
///         ret;
/// };
/// /// Compiled library which can be used by an RGB schema for validation.
/// let lib = assemble(asm);
/// println!("{lib}");
/// ```
///
/// [`Lib::assemble`]: aluvm::library::Lib::assemble
/// [`Instr`]: aluvm::isa::Instr
/// [`RgbIsa`]: crate::vm::RgbIsa
#[macro_export]
macro_rules! rgbasm {
    ($( $tt:tt )+) => {{ {
        use $crate::isa_instr;
        use aluvm::{_reg_idx, _reg_idx16};
        $crate::vm::aluasm_isa! { $crate::vm::RgbIsa<_> => $( $tt )+ }
    } }};
}

#[doc(hidden)]
/// An RGB assembly instruction (a variant of [`crate::vm::RgbIsa`] enum).
#[macro_export]
macro_rules! isa_instr {
    (cn.c a32[$dst:literal],a16[$ty:literal]) => {{
        $crate::vm::RgbIsa::Contract($crate::vm::ContractOp::CnC {
            dst: RegS::from($dst),
            ty: _reg_idx![$ty],
        })
    }};
    (cn.g a16[$dst:literal],a16[$ty:literal]) => {{
        $crate::vm::RgbIsa::Contract($crate::vm::ContractOp::CnG {
            dst: RegS::from($dst),
            ty: _reg_idx![$ty],
        })
    }};
    (cn.i a16[$dst:literal],a16[$ty:literal]) => {{
        $crate::vm::RgbIsa::Contract($crate::vm::ContractOp::CnI {
            dst: RegS::from($dst),
            ty: _reg_idx![$ty],
        })
    }};
    (cn.o a16[$dst:literal],a16[$ty:literal]) => {{
        $crate::vm::RgbIsa::Contract($crate::vm::ContractOp::CnO {
            dst: RegS::from($dst),
            ty: _reg_idx![$ty],
        })
    }};

    (cn $_:ident $($tt:tt)+) => {{
        compile_error!(
            "`cn` mnemonic must be followed by a suffix specifying state type: `.i` for inputs, \
             `.o` for output assignments, `.g` for operation global state or `.c` for contract \
             global state."
        )
    }};
    (cn.c $($tt:tt)+) => {{
        compile_error!("invalid arguments for `cn.c` mnemonic.")
    }};
    (cn.g $($tt:tt)+) => {{
        compile_error!("invalid arguments for `cn.g` mnemonic.")
    }};
    (cn.i $($tt:tt)+) => {{
        compile_error!("invalid arguments for `cn.i` mnemonic.")
    }};
    (cn.o $($tt:tt)+) => {{
        compile_error!("invalid arguments for `cn.o` mnemonic.")
    }};
    (cn. $sfx:ident $($tt:tt)+) => {{
        compile_error!(
            "invalid suffix for `cn` mnemonic. Allowed suffixes `.i` for inputs, `.o` for output \
             assignments, `.g` for operation global state or `.c` for contract global state."
        )
    }};

    (ld.c s16[$dst:literal],a16[$ty:literal],a32[$pos:literal]) => {{
        $crate::vm::RgbIsa::Contract($crate::vm::ContractOp::LdC {
            dst: RegS::from($dst),
            ty: _reg_idx![$ty],
            pos: _reg_idx16![$pos],
        })
    }};
    (ld.g s16[$dst:literal],a16[$ty:literal],a16[$pos:literal]) => {{
        $crate::vm::RgbIsa::Contract($crate::vm::ContractOp::LdG {
            dst: RegS::from($dst),
            ty: _reg_idx![$ty],
            pos: _reg_idx![$pos],
        })
    }};
    (ld.i s16[$dst:literal],a16[$ty:literal],a16[$pos:literal]) => {{
        $crate::vm::RgbIsa::Contract($crate::vm::ContractOp::LdI {
            dst: RegS::from($dst),
            ty: _reg_idx![$ty],
            pos: _reg_idx![$pos],
        })
    }};
    (ld.o s16[$dst:literal],a16[$ty:literal],a16[$pos:literal]) => {{
        $crate::vm::RgbIsa::Contract($crate::vm::ContractOp::LdO {
            dst: RegS::from($dst),
            ty: _reg_idx![$ty],
            pos: _reg_idx![$pos],
        })
    }};

    (ld.m s16[$dst:literal],a16[$ty:literal]) => {{
        $crate::vm::RgbIsa::Contract($crate::vm::ContractOp::LdC {
            dst: RegS::from($dst),
            ty: _reg_idx![$ty],
        })
    }};

    (ld $_:ident $($tt:tt)+) => {{
        compile_error!(
            "`ld` mnemonic must be followed by a suffix specifying state type: `.i` for inputs, \
             `.o` for output assignments, `.g` for operation global state, `.c` for contract \
             global state, or `m` for metadata."
        )
    }};
    (ld.c $($tt:tt)+) => {{
        compile_error!("invalid arguments for `ld.c` mnemonic.")
    }};
    (ld.g $($tt:tt)+) => {{
        compile_error!("invalid arguments for `ld.g` mnemonic.")
    }};
    (ld.i $($tt:tt)+) => {{
        compile_error!("invalid arguments for `ld.i` mnemonic.")
    }};
    (ld.o $($tt:tt)+) => {{
        compile_error!("invalid arguments for `ld.o` mnemonic.")
    }};
    (ld.m $($tt:tt)+) => {{
        compile_error!("invalid arguments for `ld.m` mnemonic.")
    }};
    (ld. $sfx:ident $($tt:tt)+) => {{
        compile_error!(
            "invalid suffix for `ld` mnemonic. Allowed suffixes `.i` for inputs, `.o` for output \
             assignments, `.g` for operation global state, `.c` for contract global state or `.m` \
             for metadata."
        )
    }};

    ($op:ident $($tt:tt)+) => {{
        compile_error!(concat!("unrecognized assembly mnemonic `", stringify!($op), "`"))
    }};
}

// TODO: Move to aluvm

#[macro_export]
macro_rules! a16 {
    ($var:ident) => {
        Reg::A(RegA::A16, ($var).into()).into()
    };
}

#[macro_export]
macro_rules! a32 {
    ($var:ident) => {
        Reg::A(RegA::A32, ($var).into()).into()
    };
}
