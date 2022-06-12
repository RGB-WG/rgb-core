// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Components related to the scripting system used by schema or applied at the
//! specific contract node level

use amplify::num::u24;
use commit_verify::commit_encode;
use strict_encoding::MediumVec;

/// Virtual machine types.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(Debug)]
pub enum VmType {
    /// Embedded code (not a virtual machine) which is the part of this RGB
    /// Core Library.
    Embedded,

    /// AluVM: pure functional register-based virtual machine designed for RGB
    /// and multiparty computing.
    AluVM,
}

/// Virtual machine and machine-specific script data.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_value, repr = u8)]
pub enum VmScript {
    /// Embedded code (not a virtual machine) which is the part of this RGB
    /// Core Library. Using this option results in the fact that the schema
    /// does not commit to the actual validating code and the validation logic
    /// may change in the future (like to be patched) with new RGB Core Lib
    /// releases.
    #[strict_encoding(value = 0x00)]
    Embedded,

    /// AluVM: pure functional register-based virtual machine designed for RGB
    /// and multiparty computing.
    ///
    /// The inner data contains actual executable code in form of complete set
    /// of AliVM libraries, which must be holistic and not dependent on any
    /// external libraries (i.e. must contain all libraries embedded).
    ///
    /// Its routines can be accessed only through well-typed ABI entrance
    /// pointers, defined as a part of the schema.
    #[strict_encoding(value = 0x01)]
    // TODO: Use library-based approach with `aluvm::Lib` type and special
    //       RGB AluVM runtime environment controlling the total number of
    //       libraries used is below 256.
    AluVM(MediumVec<u8>),
}

impl Default for VmScript {
    // TODO: Update default VM type to AluVM in RGBv1 release
    fn default() -> Self { VmScript::Embedded }
}

impl commit_encode::Strategy for VmScript {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl VmScript {
    pub fn vm_type(&self) -> VmType {
        match self {
            VmScript::Embedded => VmType::Embedded,
            VmScript::AluVM(_) => VmType::AluVM,
        }
    }
}

/// VM and script overwrite rules by subschemata.
///
/// Defines whether subschemata are allowed to replace (overwrite) the type of
/// VM and scripts.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[derive(StrictEncode, StrictDecode)]
#[repr(u8)]
pub enum OverrideRules {
    #[display("deny")]
    /// Denies overwrites
    Deny = 0u8,

    #[display("allow-same-vm")]
    /// Allows overwrite only if the same VM is used
    AllowSameVm = 1u8,

    #[display("allow-any-vm")]
    /// Allows overwrite of both executable code and type of VM
    AllowAnyVm = 2u8,
}

impl Default for OverrideRules {
    fn default() -> Self { OverrideRules::Deny }
}

/// Offset within script data for the procedure entry point.
///
/// Part of the ABI data.
///
/// NB: For embedded procedures this is a code name of the embedded procedure
///     as defined by [`EmbeddedProcedure`]
pub type EntryPoint = u24;
