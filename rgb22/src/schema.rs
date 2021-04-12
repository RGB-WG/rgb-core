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

use rgb::schema::{
    constants::*, script, Bits, DataFormat, GenesisSchema, Occurences, Schema,
    StateFormat, StateSchema, TransitionAction, TransitionSchema,
};
use rgb::vm::embedded;

/// Field types for RGB22 schemata
///
/// Subset of known RGB schema pre-defined types applicable to digital identity.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    /// Asset name
    ///
    /// Used within context of genesis or renomination state transition
    Name = FIELD_TYPE_NAME,

    /// Binary data representing the NFT
    Data = FIELD_TYPE_DATA,

    /// Format of the binary NFT data
    DataFormat = FIELD_TYPE_DATA_FORMAT,

    /// Timestamp defining from which point in time the data become valid
    ValidFrom = FIELD_TYPE_TIMESTAMP,

    /// Type of the used elliptic curve for the identity key
    UsedCryptography = 0x0110,

    /// Public key representing identity
    PublicKey = 0x0111,

    /// Self-key signature confirming identity ownership
    Signature = 0x0112,

    /// Text commentary for an NFT operation
    Commentary = FIELD_TYPE_COMMENTARY,
}

impl From<FieldType> for rgb::schema::FieldType {
    #[inline]
    fn from(ft: FieldType) -> Self {
        ft as rgb::schema::FieldType
    }
}

/// Owned right types used by RGB22 schemata
///
/// Subset of known RGB schema pre-defined types applicable to digital identity.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightType {
    /// Revocation right
    Revocation = STATE_TYPE_ISSUE_REVOCATION_RIGHT,

    /// Right to define new (sub)identity
    Extension = STATE_TYPE_ISSUE_REPLACEMENT_RIGHT,
}

impl From<OwnedRightType> for rgb::schema::OwnedRightType {
    #[inline]
    fn from(t: OwnedRightType) -> Self {
        t as rgb::schema::OwnedRightType
    }
}

/// State transition types defined by RGB22 schemata
///
/// Subset of known RGB schema pre-defined types applicable to digital identity.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    /// Modification of the contract state (revocation and extension with new
    /// identities)
    Update = TRANSITION_TYPE_STATE_MODIFICATION,
}

impl From<TransitionType> for rgb::schema::TransitionType {
    #[inline]
    fn from(t: TransitionType) -> Self {
        t as rgb::schema::TransitionType
    }
}

pub fn schema() -> Schema {
    use Occurences::*;

    Schema {
        rgb_features: none!(),
        root_id: none!(),
        field_types: type_map! {
            FieldType::Name => DataFormat::String(256),
            // Data format for keeping identity-related information
            // TODO #36: (LNPBPs) Consider using MIME types
            FieldType::DataFormat => DataFormat::Unsigned(Bits::Bit16, 0, core::u16::MAX as u128),
            // Identity-related information (like SSI)
            // TODO #33: Use data container to keep the actual log record
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
            OwnedRightType::Revocation => StateSchema {
                format: StateFormat::Declarative,
                abi: bmap! {}
            },
            OwnedRightType::Extension => StateSchema {
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
                OwnedRightType::Revocation => Once,
                OwnedRightType::Extension => NoneOrUpTo(core::u16::MAX)
            },
            public_rights: none!(),
            abi: none!(),
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
                    OwnedRightType::Revocation => NoneOrUpTo(core::u16::MAX),
                    OwnedRightType::Extension => NoneOrUpTo(core::u16::MAX)
                },
                owned_rights: type_map! {
                    OwnedRightType::Revocation => Once,
                    OwnedRightType::Extension => NoneOrUpTo(core::u16::MAX)
                },
                public_rights: none!(),
                abi: bmap! {
                    TransitionAction::Validate => embedded::NodeValidator::IdentityTransfer as script::EntryPoint
                }
            }
        },
        script: script::ExecutableCode {
            vm_type: script::VmType::Embedded,
            byte_code: empty!(),
            override_rules: script::OverrideRules::Deny,
        },
    }
}
