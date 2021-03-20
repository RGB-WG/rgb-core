// RGB-24 Library: verifiable audit logs for bitcoin & lightning
// Written in 2021 by
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
    constants::*, Bits, DataFormat, GenesisSchema, Occurences, Schema,
    StateFormat, StateSchema, TransitionSchema,
};
use rgb::ExtensionSchema;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    Name,
    Commentary,
    RicardianContract,
    ValidFrom,
    Data,
    DataFormat,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightsType {
    Ownership,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum PublicRightsType {
    Resolution,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    Transfer,
    Revocation,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum ExtensionType {
    Resolution,
}

pub fn schema() -> Schema {
    use Occurences::*;

    // TODO: Link signatures to identity

    Schema {
        rgb_features: none!(),
        root_id: none!(),
        field_types: type_map! {
            // Human-readable name registered with this schema
            FieldType::Name => DataFormat::String(256),
            // TODO: Consider using data container
            FieldType::RicardianContract => DataFormat::String(core::u16::MAX),
            // Data formats for name resolution, like IP addresses, ONIONs etc.
            // Formats are registered by LNP/BP Association and maintained as
            // a part of LNPBPs standard for RGB-24
            FieldType::DataFormat => DataFormat::Unsigned(Bits::Bit16, 0, core::u16::MAX as u128),
            // Actual resolution for the name
            FieldType::Data => DataFormat::Bytes(core::u16::MAX),
            // While UNIX timestamps allow negative numbers; in context of RGB Schema, assets
            // can't be issued in the past before RGB or Bitcoin even existed; so we prohibit
            // all the dates before RGB release
            // TODO: Update lower limit with the first RGB release
            // Current lower time limit is 07/04/2020 @ 1:54pm (UTC)
            FieldType::ValidFrom => DataFormat::Integer(Bits::Bit64, 1593870844, core::i64::MAX as i128)
        },
        owned_right_types: type_map! {
            OwnedRightsType::Ownership => StateSchema {
                format: StateFormat::Declarative,
                abi: bmap! {}
            }
        },
        public_right_types: none!(),
        genesis: GenesisSchema {
            metadata: type_map! {
                FieldType::Name => Once,
                FieldType::RicardianContract => NoneOrOnce,
                FieldType::ValidFrom => NoneOrOnce
            },
            owned_rights: type_map! {
                OwnedRightsType::Ownership => Once
            },
            public_rights: bset! {
                *PublicRightsType::Resolution
            },
            abi: none!(),
        },
        extensions: type_map! {
            ExtensionType::Resolution => ExtensionSchema {
                metadata: type_map! {
                    FieldType::Commentary => NoneOrOnce,
                    FieldType::DataFormat => Once,
                    FieldType::Data => Once
                },
                extends: bset! {
                    *PublicRightsType::Resolution
                },
                owned_rights: none!(),
                public_rights: none!(),
                abi: none!(),
            }
        },
        transitions: type_map! {
            TransitionType::Transfer => TransitionSchema {
                metadata: type_map! {
                    FieldType::RicardianContract => NoneOrOnce
                },
                closes: type_map! {
                    OwnedRightsType::Ownership => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::Ownership => Once
                },
                public_rights: none!(),
                abi: none!(),
            },
            TransitionType::Revocation => TransitionSchema {
                metadata: type_map! {
                    FieldType::Commentary => NoneOrOnce
                },
                closes: type_map! {
                    OwnedRightsType::Ownership => Once
                },
                owned_rights: none!(),
                public_rights: none!(),
                abi: none!()
            }
        },
    }
}

impl Deref for FieldType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            FieldType::Name => &FIELD_TYPE_NAME,
            FieldType::ValidFrom => &FIELD_TYPE_TIMESTAMP,
            FieldType::Data => &FIELD_TYPE_DATA,
            FieldType::DataFormat => &FIELD_TYPE_DATA_FORMAT,
            FieldType::Commentary => &FIELD_TYPE_COMMENTARY,
            FieldType::RicardianContract => &FIELD_TYPE_CONTRACT_TEXT,
        }
    }
}

impl Deref for OwnedRightsType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            OwnedRightsType::Ownership => &STATE_TYPE_OWNERSHIP_RIGHT,
        }
    }
}

impl Deref for PublicRightsType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            PublicRightsType::Resolution => &0x01,
        }
    }
}

impl Deref for TransitionType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            TransitionType::Transfer => &TRANSITION_TYPE_STATE_MODIFICATION,
            TransitionType::Revocation => &TRANSITION_TYPE_RIGHTS_TERMINATION,
        }
    }
}

impl Deref for ExtensionType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            ExtensionType::Resolution => &0x01,
        }
    }
}
