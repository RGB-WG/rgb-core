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

use rgb::schema::{
    constants::*, script, Bits, DataFormat, ExtensionSchema, GenesisSchema,
    Occurences, Schema, StateFormat, StateSchema, TransitionSchema,
};

/// Field types for RGB24 schemata
///
/// Subset of known RGB schema pre-defined types applicable to fungible assets.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    /// Name for the registry
    Name = FIELD_TYPE_NAME,

    /// Text of the registry contract
    RicardianContract = FIELD_TYPE_CONTRACT_TEXT,

    /// Text commentary for registry entry
    Commentary = FIELD_TYPE_COMMENTARY,

    /// Timestamp defining from which point in time the registry is valid
    ValidFrom = FIELD_TYPE_TIMESTAMP,

    /// Registry record
    Data = FIELD_TYPE_DATA,

    /// Format of the binary registry log entry data
    DataFormat = FIELD_TYPE_DATA_FORMAT,
}

impl From<FieldType> for rgb::schema::FieldType {
    #[inline]
    fn from(ft: FieldType) -> Self {
        ft as rgb::schema::FieldType
    }
}

/// Owned right types used by RGB24 schemata
///
/// Subset of known RGB schema pre-defined types applicable to fungible assets.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightType {
    Ownership = STATE_TYPE_OWNERSHIP_RIGHT,
}

impl From<OwnedRightType> for rgb::schema::OwnedRightType {
    #[inline]
    fn from(t: OwnedRightType) -> Self {
        t as rgb::schema::OwnedRightType
    }
}

/// Public right types defined by RGB24 schemata
///
/// Subset of known RGB schema pre-defined types applicable to fungible assets.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum PublicRightType {
    Resolution = 0x01,
}

impl From<PublicRightType> for rgb::schema::PublicRightType {
    #[inline]
    fn from(t: PublicRightType) -> Self {
        t as rgb::schema::PublicRightType
    }
}

/// State transition types defined by RGB24 schemata
///
/// Subset of known RGB schema pre-defined types applicable to fungible assets.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    Transfer = TRANSITION_TYPE_STATE_MODIFICATION,
    Revocation = TRANSITION_TYPE_RIGHTS_TERMINATION,
}

impl From<TransitionType> for rgb::schema::TransitionType {
    #[inline]
    fn from(t: TransitionType) -> Self {
        t as rgb::schema::TransitionType
    }
}

/// State extension types defined by RGB24 schemata
///
/// Subset of known RGB schema pre-defined types applicable to fungible assets.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum ExtensionType {
    Resolution = 0x01,
}

impl From<ExtensionType> for rgb::schema::ExtensionType {
    #[inline]
    fn from(t: ExtensionType) -> Self {
        t as rgb::schema::ExtensionType
    }
}

pub fn schema() -> Schema {
    use Occurences::*;

    // TODO #39: Link signatures to identity

    Schema {
        rgb_features: none!(),
        root_id: none!(),
        field_types: type_map! {
            // Human-readable name registered with this schema
            FieldType::Name => DataFormat::String(256),
            // TODO #39: Consider using data container
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
            // TODO #39: Update lower limit with the first RGB release
            // Current lower time limit is 07/04/2020 @ 1:54pm (UTC)
            FieldType::ValidFrom => DataFormat::Integer(Bits::Bit64, 1593870844, core::i64::MAX as i128)
        },
        owned_right_types: type_map! {
            OwnedRightType::Ownership => StateSchema {
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
                OwnedRightType::Ownership => Once
            },
            public_rights: bset! {
                PublicRightType::Resolution.into()
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
                    PublicRightType::Resolution.into()
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
                    OwnedRightType::Ownership => Once
                },
                owned_rights: type_map! {
                    OwnedRightType::Ownership => Once
                },
                public_rights: none!(),
                abi: none!(),
            },
            TransitionType::Revocation => TransitionSchema {
                metadata: type_map! {
                    FieldType::Commentary => NoneOrOnce
                },
                closes: type_map! {
                    OwnedRightType::Ownership => Once
                },
                owned_rights: none!(),
                public_rights: none!(),
                abi: none!()
            }
        },
        script: script::ExecutableCode {
            vm_type: script::VmType::Embedded,
            byte_code: empty!(),
            override_rules: script::OverrideRules::Deny,
        },
    }
}
