// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use std::convert::Infallible;

pub use aluvm::stl::aluvm_stl;
use amplify::{Bytes, Bytes32};
use commit_verify::stl::commit_verify_stl;
use commit_verify::StrictHash;
use single_use_seals::SealWitness;
use strict_encoding::{StrictProduct, StrictTuple, StrictType, TypeName};
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::LibBuilder;
use strict_types::{CompileError, TypeLib};

use crate::{
    ContractId, Extension, Genesis, OpId, RgbSeal, RgbWitness, Transition, ValidationError, VerifiedContractState,
    LIB_NAME_RGB_COMMIT, LIB_NAME_RGB_LOGIC,
};

/// Strict types id for the library providing data types for RGB consensus.
pub const LIB_ID_RGB_COMMIT: &str = "stl:e34bLx8U-iXAiLoF-Uvz.lun-EMEGotf-uzLJwMs-EVsilEU#annual-factor-object";
/// Strict types id for the library providing data types for RGB consensus.
pub const LIB_ID_RGB_LOGIC: &str = "stl:SCtqOrUy-niXJlxu-9gqayQs-r5KKXwA-TI2mus.-e3rhnYI#marco-charter-dominic";

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(AsSlice, Display, FromStr, Hex)]
#[derive(StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
pub struct Seal(Bytes32);
impl RgbSeal for Seal {
    type Params = Bytes<8>;

    fn params() -> Self::Params { zero!() }
}
impl StrictType for Seal {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_RGB_COMMIT;
    fn strict_name() -> Option<TypeName> { None }
}
impl StrictProduct for Seal {}
impl StrictTuple for Seal {
    const FIELD_COUNT: u8 = 1;
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Witness(ContractId, OpId);
impl SealWitness<Seal> for Witness {
    type Message = (ContractId, OpId);
    type Error = ValidationError<Infallible>;
    fn verify_seal(&self, _seal: &Seal, _msg: &Self::Message) -> Result<(), Self::Error> { Ok(()) }
}
impl RgbWitness<Seal> for Witness {
    fn order(&self) -> impl Ord { 0 }
}

fn _rgb_commit_stl<Seal: RgbSeal>() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_COMMIT), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        aluvm_stl().to_dependency()
    })
    .transpile::<Genesis<Seal>>()
    .transpile::<Extension<Seal>>()
    .transpile::<Transition<Seal>>()
    .compile()
}

fn _rgb_logic_stl<Seal: RgbSeal, W: RgbWitness<Seal>>() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_LOGIC), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        aluvm_stl().to_dependency(),
        _rgb_commit_stl::<Seal>().unwrap().to_dependency()
    })
        .transpile::<VerifiedContractState<Seal, W>>()
        // TODO: Commit to the RGB ISA once AluVM will support strict types
        // .transpile::<RgbIsa>()
        .compile()
}

/// Generates strict type library providing data types for RGB consensus.
pub fn rgb_commit_stl() -> TypeLib {
    _rgb_commit_stl::<Seal>().expect("invalid strict type RGB consensus commitments library")
}

/// Generates strict type library providing data types for RGB consensus.
pub fn rgb_logic_stl() -> TypeLib {
    _rgb_logic_stl::<Seal, Witness>().expect("invalid strict type RGB consensus logic library")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn commit_lib_id() {
        let lib = rgb_commit_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_COMMIT);
    }

    #[test]
    fn logic_lib_id() {
        let lib = rgb_logic_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_LOGIC);
    }
}
