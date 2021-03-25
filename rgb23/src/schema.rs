// RGB-23 Library: verifiable audit logs for bitcoin & lightning
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
    constants::*, Bits, DataFormat, GenesisSchema, Occurences, Schema,
    StateFormat, StateSchema, TransitionSchema,
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    Name,
    Commentary,
    RicardianContract,
    StartsFrom,
    Data,
    DataFormat,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightsType {
    Entry,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    Entry,
    Burn,
}

pub fn schema() -> Schema {
    use Occurences::*;

    // TODO #38: Link signatures to identity

    Schema {
        rgb_features: none!(),
        root_id: none!(),
        field_types: type_map! {
            // Human-readable name for UI
            FieldType::Name => DataFormat::String(256),
            // TODO #38: Consider using data container
            FieldType::RicardianContract => DataFormat::String(core::u16::MAX),
            // TODO: 36: (LNPBPs) Consider using MIME types
            FieldType::DataFormat => DataFormat::Unsigned(Bits::Bit16, 0, core::u16::MAX as u128),
            // TODO #38: Use data container to keep the actual log record
            //       matching the signature
            FieldType::Data => DataFormat::Bytes(core::u16::MAX),
            // While UNIX timestamps allow negative numbers; in context of RGB Schema, assets
            // can't be issued in the past before RGB or Bitcoin even existed; so we prohibit
            // all the dates before RGB release
            // Current lower time limit is 07/04/2020 @ 1:54pm (UTC)
            // TODO #38: Update lower limit with the first RGB release
            FieldType::StartsFrom => DataFormat::Integer(Bits::Bit64, 1593870844, core::i64::MAX as i128)
        },
        owned_right_types: type_map! {
            OwnedRightsType::Entry => StateSchema {
                format: StateFormat::Declarative,
                abi: bmap! {}
            }
        },
        public_right_types: none!(),
        genesis: GenesisSchema {
            metadata: type_map! {
                FieldType::Name => Once,
                FieldType::RicardianContract => NoneOrOnce,
                FieldType::DataFormat => Once,
                FieldType::Data => Once,
                FieldType::StartsFrom => Once
            },
            owned_rights: type_map! {
                OwnedRightsType::Entry => Once
            },
            public_rights: none!(),
            abi: bmap! {},
        },
        extensions: none!(),
        transitions: type_map! {
            TransitionType::Entry => TransitionSchema {
                metadata: type_map! {
                    FieldType::Commentary => NoneOrOnce,
                    FieldType::DataFormat => Once,
                    FieldType::Data => Once
                },
                closes: type_map! {
                    OwnedRightsType::Entry => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::Entry => Once
                },
                public_rights: none!(),
                abi: bmap! { }
            },
            TransitionType::Burn => TransitionSchema {
                metadata: type_map! {
                    FieldType::Commentary => NoneOrOnce
                },
                closes: type_map! {
                    OwnedRightsType::Entry => NoneOrOnce
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
            FieldType::StartsFrom => &FIELD_TYPE_TIMESTAMP,
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
            OwnedRightsType::Entry => &0x0101,
        }
    }
}

impl Deref for TransitionType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            TransitionType::Entry => &TRANSITION_TYPE_STATE_MODIFICATION,
            TransitionType::Burn => &TRANSITION_TYPE_RIGHTS_TERMINATION,
        }
    }
}
