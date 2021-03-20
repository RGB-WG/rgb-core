// RGB-22 Library: digital identity for bitcoin & lightning
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::ops::Deref;

use rgb::schema::{
    constants::*, script::StandardProcedure, Bits, DataFormat, GenesisAction,
    GenesisSchema, Occurences, Procedure, Schema, StateFormat, StateSchema,
    TransitionAction, TransitionSchema,
};

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    Name,
    Format,
    Identity,
    UsedCryptography,
    PublicKey,
    Signature,
    ValidFrom,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightsType {
    Revocation,
    Extension,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    Identity,
}

pub fn schema() -> Schema {
    Schema {
        rgb_features: none!(),
        root_id: none!(),
        field_types: type_map! {
            FieldType::Name => DataFormat::String(256),
            FieldType::Format => DataFormat::Unsigned(Bits::Bit16, 0, core::u16::MAX as u128),
            FieldType::Identity => DataFormat::Bytes(core::u16::MAX),
            // We allow signatures to be created with different cryptographic
            // methods, so keeping three fields to define them, instead of using
            // `Signature` data format (which will force all contracts to
            // use the same signature and cryptographic algorithm
            FieldType::UsedCryptography => DataFormat::Unsigned(Bits::Bit16, 0, core::u16::MAX as u128),
            FieldType::PublicKey => DataFormat::Bytes(core::u16::MAX),
            FieldType::Signature => DataFormat::Bytes(core::u16::MAX),
            // While UNIX timestamps allow negative numbers; in context of RGB Schema, assets
            // can't be issued in the past before RGB or Bitcoin even existed; so we prohibit
            // all the dates before RGB release
            // TODO: Update lower limit with the first RGB release
            // Current lower time limit is 07/04/2020 @ 1:54pm (UTC)
            FieldType::ValidFrom => DataFormat::Integer(Bits::Bit64, 1593870844, core::i64::MAX as i128)
        },
        owned_right_types: type_map! {
            OwnedRightsType::Revocation => StateSchema {
                format: StateFormat::Declarative,
                abi: bmap! {}
            },
            OwnedRightsType::Extension => StateSchema {
                format: StateFormat::Declarative,
                abi: bmap! {}
            }
        },
        public_right_types: none!(),
        genesis: GenesisSchema {
            metadata: type_map! {
                FieldType::Name => Occurences::Once,
                FieldType::Format => Occurences::Once,
                FieldType::Identity => Occurences::Once,
                FieldType::UsedCryptography => Occurences::Once,
                FieldType::PublicKey => Occurences::Once,
                FieldType::Signature => Occurences::Once,
                FieldType::ValidFrom => Occurences::Once
            },
            owned_rights: type_map! {
                OwnedRightsType::Revocation => Occurences::Once,
                OwnedRightsType::Extension => Occurences::NoneOrUpTo(::core::u16::MAX)
            },
            public_rights: none!(),
            abi: bmap! {
                GenesisAction::Validate => Procedure::Embedded(StandardProcedure::IdentityTransfer)
            },
        },
        extensions: none!(),
        transitions: type_map! {
            TransitionType::Identity => TransitionSchema {
                metadata: type_map! {
                    FieldType::Name => Occurences::Once,
                    FieldType::Format => Occurences::Once,
                    FieldType::Identity => Occurences::Once,
                    FieldType::UsedCryptography => Occurences::Once,
                    FieldType::PublicKey => Occurences::Once,
                    FieldType::Signature => Occurences::Once,
                    // We need this to declare identities ahead of time of their
                    // activation/validity
                    FieldType::ValidFrom => Occurences::Once
                },
                closes: type_map! {
                    OwnedRightsType::Revocation => Occurences::NoneOrUpTo(::core::u16::MAX),
                    OwnedRightsType::Extension => Occurences::NoneOrUpTo(::core::u16::MAX)
                },
                owned_rights: type_map! {
                    OwnedRightsType::Revocation => Occurences::Once,
                    OwnedRightsType::Extension => Occurences::NoneOrUpTo(::core::u16::MAX)
                },
                public_rights: none!(),
                abi: bmap! {
                    TransitionAction::Validate => Procedure::Embedded(StandardProcedure::IdentityTransfer)
                }
            }
        },
    }
}

impl Deref for FieldType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            FieldType::Name => &FIELD_TYPE_NAME,
            FieldType::Format => &FIELD_TYPE_DATA_FORMAT,
            FieldType::ValidFrom => &FIELD_TYPE_TIMESTAMP,
            FieldType::Identity => &0x0101,
            FieldType::UsedCryptography => &0x0110,
            FieldType::PublicKey => &0x0111,
            FieldType::Signature => &0x0112,
        }
    }
}

impl Deref for OwnedRightsType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            OwnedRightsType::Revocation => &0x0101,
            OwnedRightsType::Extension => &0x0102,
        }
    }
}

impl Deref for TransitionType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            TransitionType::Identity => &TRANSITION_TYPE_STATE_MODIFICATION,
        }
    }
}
