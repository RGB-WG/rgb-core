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

use rgb::schema::{
    constants::*, script, Bits, DataFormat, GenesisSchema, Occurences, Schema,
    StateFormat, StateSchema, TransitionSchema,
};

/// Field types for RGB23 schemata
///
/// Subset of known RGB schema pre-defined types applicable to audit logs.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    /// Name for the audit log
    Name = FIELD_TYPE_NAME,

    /// Text of the asset contract
    RicardianContract = FIELD_TYPE_CONTRACT_TEXT,

    /// Text commentary for an audit log entry
    Commentary = FIELD_TYPE_COMMENTARY,

    /// Timestamp defining from which point in time the audit log was created
    StartsFrom = FIELD_TYPE_TIMESTAMP,

    /// Binary data – audit log commitment or entry data
    Data = FIELD_TYPE_DATA,

    /// Format of the binary audit log entry data
    DataFormat = FIELD_TYPE_DATA_FORMAT,
}

impl From<FieldType> for rgb::schema::FieldType {
    #[inline]
    fn from(ft: FieldType) -> Self {
        ft as rgb::schema::FieldType
    }
}

/// Owned right types used by RGB23 schemata
///
/// Subset of known RGB schema pre-defined types applicable to audit logs.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightType {
    /// Right to create next audit log record
    Entry,
}

impl From<OwnedRightType> for rgb::schema::OwnedRightType {
    #[inline]
    fn from(t: OwnedRightType) -> Self {
        t as rgb::schema::OwnedRightType
    }
}

/// State transition types defined by RGB23 schemata
///
/// Subset of known RGB schema pre-defined types applicable to audit logs.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    /// Creation of next audit log record
    Entry = TRANSITION_TYPE_STATE_MODIFICATION,

    /// Operation terminating audit log record
    Terminate = TRANSITION_TYPE_RIGHTS_TERMINATION,
}

impl From<TransitionType> for rgb::schema::TransitionType {
    #[inline]
    fn from(t: TransitionType) -> Self {
        t as rgb::schema::TransitionType
    }
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
            // TODO #33: Consider using data container
            FieldType::RicardianContract => DataFormat::String(core::u16::MAX),
            // TODO: 36: (LNPBPs) Consider using MIME types
            FieldType::DataFormat => DataFormat::Unsigned(Bits::Bit16, 0, core::u16::MAX as u128),
            // TODO #33: Use data container to keep the actual log record
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
            OwnedRightType::Entry => StateSchema {
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
                OwnedRightType::Entry => Once
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
                    OwnedRightType::Entry => Once
                },
                owned_rights: type_map! {
                    OwnedRightType::Entry => Once
                },
                public_rights: none!(),
                abi: bmap! { }
            },
            TransitionType::Terminate => TransitionSchema {
                metadata: type_map! {
                    FieldType::Commentary => NoneOrOnce
                },
                closes: type_map! {
                    OwnedRightType::Entry => NoneOrOnce
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
