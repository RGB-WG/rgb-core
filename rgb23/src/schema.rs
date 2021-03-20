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
    Bits, DataFormat, GenesisSchema, Occurences, Schema, StateFormat,
    StateSchema, TransitionSchema,
};

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    Name,
    StartsFrom,
    Data,
    DataFormat,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightsType {
    Entry,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    Entry,
}

pub fn schema() -> Schema {
    Schema {
        rgb_features: none!(),
        root_id: none!(),
        field_types: type_map! {
            // Human-readable name for UI
            FieldType::Name => DataFormat::String(256),
            // TODO: (LNPBPs) Consider using MIME types
            FieldType::DataFormat => DataFormat::Unsigned(Bits::Bit16, 0, core::u16::MAX as u128),
            FieldType::Data => DataFormat::Bytes(core::u16::MAX),
            // While UNIX timestamps allow negative numbers; in context of RGB Schema, assets
            // can't be issued in the past before RGB or Bitcoin even existed; so we prohibit
            // all the dates before RGB release
            // TODO: Update lower limit with the first RGB release
            // Current lower time limit is 07/04/2020 @ 1:54pm (UTC)
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
                FieldType::Name => Occurences::Once,
                FieldType::DataFormat => Occurences::Once,
                FieldType::Data => Occurences::Once,
                FieldType::StartsFrom => Occurences::Once
            },
            owned_rights: type_map! {
                OwnedRightsType::Entry => Occurences::Once
            },
            public_rights: none!(),
            abi: bmap! {},
        },
        extensions: none!(),
        transitions: type_map! {
            TransitionType::Entry => TransitionSchema {
                metadata: type_map! {
                    FieldType::DataFormat => Occurences::Once,
                    FieldType::Data => Occurences::Once
                },
                closes: type_map! {
                    OwnedRightsType::Entry => Occurences::Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::Entry => Occurences::NoneOrOnce
                },
                public_rights: none!(),
                abi: bmap! { }
            }
        },
    }
}

impl Deref for FieldType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            FieldType::Name => &1,
            FieldType::StartsFrom => &3,
            FieldType::Data => &4,
            FieldType::DataFormat => &5,
        }
    }
}

impl Deref for OwnedRightsType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            OwnedRightsType::Entry => &1,
        }
    }
}

impl Deref for TransitionType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            TransitionType::Entry => &1,
        }
    }
}
