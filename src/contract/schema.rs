// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use aluvm::isa::ISA_GFA128;
use aluvm::{IsaId, LibId, LibSite, ISA_ALU128};
use amplify::confinement::{NonEmptyOrdSet, TinyOrdMap, TinyOrdSet};
use commit_verify::{CommitEncode, CommitId, ReservedBytes};
use strict_encoding::{StrictDeserialize, StrictSerialize, TypeName};
use strict_types::SemId;

use crate::{ExtensionType, Ffv, GlobalStateType, Identity, SchemaId, TransitionType, ISA_RGB1, LIB_NAME_RGB_COMMIT};

pub const SCHEMA_LIBS_MAX_COUNT: usize = 0xFF * 3 + 3;

/// RGB contract schema: a template used by a contract genesis.
///
/// Schema contains information required for the contract consensus verification.
///
/// Contents of the contract, including types of state data, their composition inside genesis,
/// state extensions and state transitions, as well as any other contract consistency criteria are
/// verified exclusively by the verification scripts, which are run per-operation basis.
///
/// A schema doesn't commit to the set of allowed state and operation types; instead, scripts should
/// check whether an operation or a state type is acceptable.
///
/// A schema commits to a set of blockchains or hash functions which can be used by it in an
/// implicit way: via the used AluVM instruction set architectures.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = SchemaId)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Schema {
    pub ffv: Ffv,
    pub flags: ReservedBytes<1>,

    pub name: TypeName,
    pub timestamp: i64,
    pub developer: Identity,

    /// The global state types outside the scope defined in this map are allowed during validation;
    /// they are validated using [`GlobalStateSchema::default()`].
    pub global: TinyOrdMap<GlobalStateType, GlobalStateSchema>,

    // Validation logic
    pub vm: VmSchema,
    pub validators: Validators,

    /// Reserved for the future schema extensions
    pub reserved: ReservedBytes<8>,
}

impl StrictSerialize for Schema {}
impl StrictDeserialize for Schema {}

impl Schema {
    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.commit_id() }

    pub fn libs(&self) -> NonEmptyOrdSet<LibId, SCHEMA_LIBS_MAX_COUNT> { self.validators.libs() }
}

/// # Validation
///
/// Global schema validation enforces the maximum limit for the number of state elements of the same
/// time. It doesn't enforce semantic type ids.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct GlobalStateSchema {
    pub max_len: u16,
    pub sem_id: Option<SemId>,
    pub reserved: ReservedBytes<4>,
}

impl Default for GlobalStateSchema {
    /// Default value allows up to [`u16::MAX`] state elements with any semantic id.
    fn default() -> Self {
        Self {
            max_len: u16::MAX,
            sem_id: None,
            reserved: none!(),
        }
    }
}

impl GlobalStateSchema {
    pub fn any_single() -> Self {
        GlobalStateSchema {
            max_len: 1,
            sem_id: None,
            reserved: none!(),
        }
    }
    pub fn any() -> Self {
        GlobalStateSchema {
            max_len: u16::MAX,
            sem_id: None,
            reserved: none!(),
        }
    }
    pub fn single(sem_id: SemId) -> Self {
        GlobalStateSchema {
            max_len: 1,
            sem_id: Some(sem_id),
            reserved: none!(),
        }
    }
    pub fn multiple(sem_id: SemId) -> Self {
        GlobalStateSchema {
            max_len: u16::MAX,
            sem_id: Some(sem_id),
            reserved: none!(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = custom)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase", untagged))]
pub enum VmSchema {
    #[strict_type(tag = 0x01)]
    AluVm(IsaId, TinyOrdSet<IsaId>, aluvm::CoreConfig),
}

impl Default for VmSchema {
    fn default() -> Self {
        // TODO: Use ISA constants
        Self::AluVm(
            IsaId::from(ISA_ALU128),
            tiny_bset![IsaId::from(ISA_GFA128), IsaId::from(ISA_RGB1)],
            aluvm::CoreConfig {
                halt: true,
                complexity_lim: None,
                field_order: aluvm::gfa::Fq::F1137119,
            },
        )
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Validators {
    pub genesis_validator: LibSite,
    pub extension_validators: TinyOrdMap<ExtensionType, LibSite>,
    pub transition_validators: TinyOrdMap<TransitionType, LibSite>,
    pub default_transition_validator: LibSite,
    pub default_extension_validator: LibSite,
}

impl Validators {
    pub fn libs(&self) -> NonEmptyOrdSet<LibId, SCHEMA_LIBS_MAX_COUNT> {
        NonEmptyOrdSet::from_iter_checked(
            [self.genesis_validator, self.default_transition_validator, self.default_extension_validator]
                .into_iter()
                .chain(self.transition_validators.values().copied())
                .chain(self.extension_validators.values().copied())
                .map(|site| site.lib_id),
        )
    }
}
