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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    Name,
    Commentary,
    Data,
    DataFormat,
    UsedCryptography,
    PublicKey,
    Signature,
    ValidFrom,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightsType {
    Revocation,
    Extension,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    Update,
}

pub fn schema() -> Schema {
    use Occurences::*;

    Schema {
        rgb_features: none!(),
        root_id: none!(),
        field_types: type_map! {
            FieldType::Name => DataFormat::String(256),
            // Data format for keeping identity-related information
            // TODO #37: (LNPBPs) Consider using MIME types
            FieldType::DataFormat => DataFormat::Unsigned(Bits::Bit16, 0, core::u16::MAX as u128),
            // Identity-related information (like SSI)
            // TODO #37: Use data container to keep the actual log record
            //       matching the signature
            FieldType::Data => DataFormat::Bytes(core::u16::MAX),
            // We allow signatures to be created with different cryptographic
            // methods, so keeping three fields to define them, instead of using
            // `Signature` data format (which will force all contracts to
            // use the same signature and cryptographic algorithm
            // TODO #37: Consider using DER format instead of using three fields
            FieldType::UsedCryptography => DataFormat::Unsigned(Bits::Bit16, 0, core::u16::MAX as u128),
            FieldType::PublicKey => DataFormat::Bytes(core::u16::MAX),
            // Signature proving ownership over private key, matching the public
            // key
            FieldType::Signature => DataFormat::Bytes(core::u16::MAX),
            // While UNIX timestamps allow negative numbers; in context of RGB
            // Schema, assets can't be issued in the past before RGB or Bitcoin
            // even existed; so we prohibit all the dates before RGB release
            // Current lower time limit is 07/04/2020 @ 1:54pm (UTC)
            // TODO #37: Update lower limit with the first RGB release
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
                FieldType::Name => Once,
                FieldType::DataFormat => Once,
                FieldType::Data => Once,
                FieldType::UsedCryptography => Once,
                FieldType::PublicKey => Once,
                FieldType::Signature => Once,
                FieldType::ValidFrom => Once
            },
            owned_rights: type_map! {
                OwnedRightsType::Revocation => Once,
                OwnedRightsType::Extension => NoneOrUpTo(core::u16::MAX)
            },
            public_rights: none!(),
            abi: bmap! {
                GenesisAction::Validate => Procedure::Embedded(StandardProcedure::IdentityTransfer)
            },
        },
        extensions: none!(),
        transitions: type_map! {
            TransitionType::Update => TransitionSchema {
                metadata: type_map! {
                    FieldType::Name => Once,
                    FieldType::Commentary => NoneOrOnce,
                    FieldType::DataFormat => NoneOrOnce,
                    FieldType::Data => NoneOrOnce,
                    FieldType::UsedCryptography => Once,
                    FieldType::PublicKey => Once,
                    FieldType::Signature => Once,
                    // We need this to declare identities ahead of time of their
                    // activation/validity
                    FieldType::ValidFrom => Once
                },
                closes: type_map! {
                    OwnedRightsType::Revocation => NoneOrUpTo(core::u16::MAX),
                    OwnedRightsType::Extension => NoneOrUpTo(core::u16::MAX)
                },
                owned_rights: type_map! {
                    OwnedRightsType::Revocation => Once,
                    OwnedRightsType::Extension => NoneOrUpTo(core::u16::MAX)
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
            FieldType::DataFormat => &FIELD_TYPE_DATA_FORMAT,
            FieldType::ValidFrom => &FIELD_TYPE_TIMESTAMP,
            FieldType::Commentary => &FIELD_TYPE_COMMENTARY,
            FieldType::Data => &FIELD_TYPE_DATA,
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
            OwnedRightsType::Revocation => &STATE_TYPE_ISSUE_REVOCATION_RIGHT,
            OwnedRightsType::Extension => &STATE_TYPE_ISSUE_REPLACEMENT_RIGHT,
        }
    }
}

impl Deref for TransitionType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            TransitionType::Update => &TRANSITION_TYPE_STATE_MODIFICATION,
        }
    }
}
