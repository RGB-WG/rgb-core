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

#![allow(clippy::unnecessary_cast)]

//! Components related to the scripting system used by schema or applied at the
//! specific contract node level

/// Virtual machine types.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(Debug)]
pub enum VmType {
    /// AluVM: pure functional register-based virtual machine designed for RGB
    /// and multiparty computing.
    AluVM,
}

/// Virtual machine and machine-specific script data.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub enum ValidationScript {
    /// AluVM: pure functional register-based virtual machine designed for RGB
    /// and multiparty computing.
    ///
    /// The inner data contains actual executable code in form of complete set
    /// of AliVM libraries, which must be holistic and not dependent on any
    /// external libraries (i.e. must contain all libraries embedded).
    ///
    /// Its routines can be accessed only through well-typed ABI entrance
    /// pointers, defined as a part of the schema.
    AluVM(Vec<u8>),
}

impl ValidationScript {
    pub fn vm_type(&self) -> VmType {
        match self {
            ValidationScript::AluVM(_) => VmType::AluVM,
        }
    }
}
