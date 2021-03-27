// RGB20 Library: fungible digital assets for bitcoin & lightning
// Written in 2020-2021 by
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

use std::collections::BTreeSet;
use std::ops::Deref;
use std::str::FromStr;

use rgb::schema::{
    constants::*, script, AssignmentAction, Bits, DataFormat,
    DiscreteFiniteFieldFormat, GenesisSchema, Occurences, Schema, SchemaId,
    StateFormat, StateSchema, TransitionAction, TransitionSchema,
};

pub const SCHEMA_ID_BECH32: &'static str =
    "sch1rw6q0s4ynl4k5nmk4u2q25dag4409t7882pq4n6n7ywdrhp4f6cqfaf4xw";
pub const SUBSCHEMA_ID_BECH32: &'static str =
    "sch1zcdeayj9vpv852tx2sjzy7esyy82a6nk0gs854ktam24zxee42rqyzg95g";

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    Error,
    From,
)]
#[display(Debug)]
pub enum Error {
    NotAllFieldsPresent,

    WrongSchemaId,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
pub enum FieldType {
    Ticker,
    Name,
    RicardianContract,
    Precision,
    IssuedSupply,
    BurnedSupply,
    Timestamp,
    BurnUtxo,
    HistoryProof,
    HistoryProofFormat,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightsType {
    Inflation,
    Assets,
    OpenEpoch,
    BurnReplace,
    Renomination,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    Issue,
    Transfer,
    Epoch,
    Burn,
    BurnAndReplace,
    Renomination,
    RightsSplit,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[non_exhaustive]
#[repr(u8)]
pub enum HistoryProofFormat {
    ProofAbsent,
    ProofV1,
    ProofV2,
    ProofV3,
    ProofV4,
    ProofV5,
    ProofV6,
    ProofV7,
    ProofV8,
    ProofV9,
    ProofV10,
    ProofV11,
    ProofV12,
    ProofV13,
    ProofV14,
    ProofV15,
}

impl HistoryProofFormat {
    pub fn all() -> BTreeSet<u8> {
        bset![
            *HistoryProofFormat::ProofAbsent,
            *HistoryProofFormat::ProofV1,
            *HistoryProofFormat::ProofV2,
            *HistoryProofFormat::ProofV3,
            *HistoryProofFormat::ProofV4,
            *HistoryProofFormat::ProofV5,
            *HistoryProofFormat::ProofV6,
            *HistoryProofFormat::ProofV7,
            *HistoryProofFormat::ProofV8,
            *HistoryProofFormat::ProofV9,
            *HistoryProofFormat::ProofV10,
            *HistoryProofFormat::ProofV11,
            *HistoryProofFormat::ProofV12,
            *HistoryProofFormat::ProofV13,
            *HistoryProofFormat::ProofV14,
            *HistoryProofFormat::ProofV15
        ]
    }
}

pub fn schema() -> Schema {
    use Occurences::*;

    // TODO #33: Consider using data containers + state extensions for
    //       providing issuer-created asset meta-information

    Schema {
        rgb_features: none!(),
        root_id: none!(),
        genesis: GenesisSchema {
            metadata: type_map! {
                FieldType::Ticker => Once,
                FieldType::Name => Once,
                FieldType::RicardianContract => NoneOrOnce,
                FieldType::Precision => Once,
                FieldType::Timestamp => Once,
                // We need this field in order to be able to verify pedersen
                // commitments
                FieldType::IssuedSupply => Once
            },
            owned_rights: type_map! {
                OwnedRightsType::Inflation => NoneOrMore,
                OwnedRightsType::OpenEpoch => NoneOrOnce,
                OwnedRightsType::Assets => NoneOrMore,
                OwnedRightsType::Renomination => NoneOrOnce
            },
            public_rights: none!(),
            abi: none!(),
        },
        extensions: none!(),
        transitions: type_map! {
            TransitionType::Issue => TransitionSchema {
                metadata: type_map! {
                    // We need this field in order to be able to verify pedersen
                    // commitments
                    FieldType::IssuedSupply => Once
                },
                closes: type_map! {
                    OwnedRightsType::Inflation => OnceOrMore
                },
                owned_rights: type_map! {
                    OwnedRightsType::Inflation => NoneOrMore,
                    OwnedRightsType::OpenEpoch => NoneOrOnce,
                    OwnedRightsType::Assets => NoneOrMore
                },
                public_rights: none!(),
                abi: bmap! {
                    // sum(in(inflation)) >= sum(out(inflation), out(assets))
                    TransitionAction::Validate => script::EmbeddedProcedure::FungibleIssue as script::EntryPoint
                }
            },
            TransitionType::Transfer => TransitionSchema {
                metadata: none!(),
                closes: type_map! {
                    OwnedRightsType::Assets => OnceOrMore
                },
                owned_rights: type_map! {
                    OwnedRightsType::Assets => NoneOrMore
                },
                public_rights: none!(),
                abi: none!()
            },
            TransitionType::Epoch => TransitionSchema {
                metadata: none!(),
                closes: type_map! {
                    OwnedRightsType::OpenEpoch => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::OpenEpoch => NoneOrOnce,
                    OwnedRightsType::BurnReplace => NoneOrOnce
                },
                public_rights: none!(),
                abi: none!()
            },
            TransitionType::Burn => TransitionSchema {
                metadata: type_map! {
                    FieldType::BurnedSupply => Once,
                    // Normally issuer should aggregate burned assets into a
                    // single UTXO; however if burn happens as a result of
                    // mistake this will be impossible, so we allow to have
                    // multiple burned UTXOs as a part of a single operation
                    FieldType::BurnUtxo => OnceOrMore,
                    FieldType::HistoryProofFormat => Once,
                    FieldType::HistoryProof => NoneOrMore
                },
                closes: type_map! {
                    OwnedRightsType::BurnReplace => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::BurnReplace => NoneOrOnce
                },
                public_rights: none!(),
                abi: bmap! {
                    TransitionAction::Validate => script::EmbeddedProcedure::ProofOfBurn as script::EntryPoint
                }
            },
            TransitionType::BurnAndReplace => TransitionSchema {
                metadata: type_map! {
                    FieldType::BurnedSupply => Once,
                    // Normally issuer should aggregate burned assets into a
                    // single UTXO; however if burn happens as a result of
                    // mistake this will be impossible, so we allow to have
                    // multiple burned UTXOs as a part of a single operation
                    FieldType::BurnUtxo => OnceOrMore,
                    // We need this field in order to be able to verify pedersen
                    // commitments
                    FieldType::IssuedSupply => Once,
                    FieldType::HistoryProofFormat => Once,
                    FieldType::HistoryProof => NoneOrMore
                },
                closes: type_map! {
                    OwnedRightsType::BurnReplace => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::BurnReplace => NoneOrOnce,
                    OwnedRightsType::Assets => OnceOrMore
                },
                public_rights: none!(),
                abi: bmap! {
                    TransitionAction::Validate => script::EmbeddedProcedure::ProofOfBurn as script::EntryPoint
                }
            },
            TransitionType::Renomination => TransitionSchema {
                metadata: type_map! {
                    FieldType::Ticker => NoneOrOnce,
                    FieldType::Name => NoneOrOnce,
                    FieldType::RicardianContract => NoneOrOnce,
                    FieldType::Precision => NoneOrOnce
                },
                closes: type_map! {
                    OwnedRightsType::Renomination => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::Renomination => NoneOrOnce
                },
                public_rights: none!(),
                abi: none!()
            },
            // Allows split of rights if they were occasionally allocated to the
            // same UTXO, for instance both assets and issuance right. Without
            // this type of transition either assets or inflation rights will be
            // lost.
            TransitionType::RightsSplit => TransitionSchema {
                metadata: type_map! {},
                closes: type_map! {
                    OwnedRightsType::Inflation => NoneOrMore,
                    OwnedRightsType::Assets => NoneOrMore,
                    OwnedRightsType::OpenEpoch => NoneOrOnce,
                    OwnedRightsType::BurnReplace => NoneOrMore,
                    OwnedRightsType::Renomination => NoneOrOnce
                },
                owned_rights: type_map! {
                    OwnedRightsType::Inflation => NoneOrMore,
                    OwnedRightsType::Assets => NoneOrMore,
                    OwnedRightsType::OpenEpoch => NoneOrOnce,
                    OwnedRightsType::BurnReplace => NoneOrMore,
                    OwnedRightsType::Renomination => NoneOrOnce
                },
                public_rights: none!(),
                abi: bmap! {
                    // We must allocate exactly one or none rights per each
                    // right used as input (i.e. closed seal); plus we need to
                    // control that sum of inputs is equal to the sum of outputs
                    // for each of state types having assigned confidential
                    // amounts
                    TransitionAction::Validate => script::EmbeddedProcedure::RightsSplit as script::EntryPoint
                }
            }
        },
        field_types: type_map! {
            // Rational: if we will use just 26 letters of English alphabet (and
            // we are not limited by them), we will have 26^8 possible tickers,
            // i.e. > 208 trillions, which is sufficient amount
            FieldType::Ticker => DataFormat::String(8),
            FieldType::Name => DataFormat::String(256),
            // Contract text may contain URL, text or text representation of
            // Ricardian contract, up to 64kb. If the contract doesn't fit, a
            // double SHA256 hash and URL should be used instead, pointing to
            // the full contract text, where hash must be represented by a
            // hexadecimal string, optionally followed by `\n` and text URL
            // TODO #33: Consider using data container instead of the above ^^^
            FieldType::RicardianContract => DataFormat::String(core::u16::MAX),
            FieldType::Precision => DataFormat::Unsigned(Bits::Bit8, 0, 18u128),
            // We need this b/c allocated amounts are hidden behind Pedersen
            // commitments
            FieldType::IssuedSupply => DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128),
            // Supply in either burn or burn-and-replace procedure
            FieldType::BurnedSupply => DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128),
            // While UNIX timestamps allow negative numbers; in context of RGB
            // Schema, assets can't be issued in the past before RGB or Bitcoin
            // even existed; so we prohibit all the dates before RGB release
            // This timestamp is equal to 10/10/2020 @ 2:37pm (UTC)
            FieldType::Timestamp => DataFormat::Integer(Bits::Bit64, 1602340666, core::i64::MAX as i128),
            FieldType::HistoryProof => DataFormat::Bytes(core::u16::MAX),
            FieldType::HistoryProofFormat => DataFormat::Enum(HistoryProofFormat::all()),
            FieldType::BurnUtxo => DataFormat::TxOutPoint
        },
        owned_right_types: type_map! {
            OwnedRightsType::Inflation => StateSchema {
                // How much issuer can issue tokens on this path. If there is no
                // limit, than `core::u64::MAX` / sum(inflation_assignments)
                // must be used, as this will be a de-facto limit to the
                // issuance
                format: StateFormat::CustomData(DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128)),
                // Validation involves other state data, so it is performed
                // at the level of `issue` state transition
                abi: none!()
            },
            OwnedRightsType::Assets => StateSchema {
                format: StateFormat::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
                abi: bmap! {
                    // sum(inputs) == sum(outputs)
                    AssignmentAction::Validate => script::EmbeddedProcedure::FungibleNoInflation as script::EntryPoint
                }
            },
            OwnedRightsType::OpenEpoch => StateSchema {
                format: StateFormat::Declarative,
                abi: none!()
            },
            OwnedRightsType::BurnReplace => StateSchema {
                format: StateFormat::Declarative,
                abi: none!()
            },
            OwnedRightsType::Renomination => StateSchema {
                format: StateFormat::Declarative,
                abi: none!()
            }
        },
        public_right_types: none!(),
        script: script::ExecutableCode {
            vm_type: script::VmType::Embedded,
            byte_code: empty!(),
            override_rules: script::OverrideRules::Deny,
        },
    }
}

/// Provides the only defined RGB20 subschema, which prohibits replace procedure
/// and allows only burn operations
pub fn subschema() -> Schema {
    use Occurences::*;

    // TODO #33: Consider using data containers + state extensions for
    //       providing issuer-created asset meta-information
    // TODO #33: Consider adding Ricardian contracts to secondary issues and
    //       transfers

    Schema {
        rgb_features: none!(),
        root_id: SchemaId::from_str(SCHEMA_ID_BECH32)
            .expect("Broken root schema ID for RGB20 sub-schema"),
        genesis: GenesisSchema {
            metadata: type_map! {
                FieldType::Ticker => Once,
                FieldType::Name => Once,
                FieldType::RicardianContract => NoneOrOnce,
                FieldType::Precision => Once,
                FieldType::Timestamp => Once,
                FieldType::IssuedSupply => Once
            },
            owned_rights: type_map! {
                OwnedRightsType::Inflation => NoneOrMore,
                OwnedRightsType::OpenEpoch => NoneOrOnce,
                OwnedRightsType::Assets => NoneOrMore,
                OwnedRightsType::Renomination => NoneOrOnce
            },
            public_rights: none!(),
            abi: none!(),
        },
        extensions: none!(),
        transitions: type_map! {
            TransitionType::Issue => TransitionSchema {
                metadata: type_map! {
                    FieldType::IssuedSupply => Once
                },
                closes: type_map! {
                    OwnedRightsType::Inflation => OnceOrMore
                },
                owned_rights: type_map! {
                    OwnedRightsType::Inflation => NoneOrMore,
                    OwnedRightsType::OpenEpoch => NoneOrOnce,
                    OwnedRightsType::Assets => NoneOrMore
                },
                public_rights: none!(),
                abi: bmap! {
                    // sum(in(inflation)) >= sum(out(inflation), out(assets))
                    TransitionAction::Validate => script::EmbeddedProcedure::FungibleIssue as script::EntryPoint
                }
            },
            TransitionType::Transfer => TransitionSchema {
                metadata: none!(),
                closes: type_map! {
                    OwnedRightsType::Assets => OnceOrMore
                },
                owned_rights: type_map! {
                    OwnedRightsType::Assets => NoneOrMore
                },
                public_rights: none!(),
                abi: none!()
            },
            TransitionType::Epoch => TransitionSchema {
                metadata: none!(),
                closes: type_map! {
                    OwnedRightsType::OpenEpoch => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::BurnReplace => NoneOrOnce
                },
                public_rights: none!(),
                abi: none!()
            },
            TransitionType::Burn => TransitionSchema {
                metadata: type_map! {
                    FieldType::BurnedSupply => Once,
                    // Normally issuer should aggregate burned assets into a
                    // single UTXO; however if burn happens as a result of
                    // mistake this will be impossible, so we allow to have
                    // multiple burned UTXOs as a part of a single operation
                    FieldType::BurnUtxo => OnceOrMore,
                    FieldType::HistoryProofFormat => Once,
                    FieldType::HistoryProof => NoneOrMore
                },
                closes: type_map! {
                    OwnedRightsType::BurnReplace => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::BurnReplace => NoneOrOnce
                },
                public_rights: none!(),
                abi: bmap! {
                    TransitionAction::Validate => script::EmbeddedProcedure::ProofOfBurn as script::EntryPoint
                }
            },
            TransitionType::Renomination => TransitionSchema {
                metadata: type_map! {
                    FieldType::Ticker => NoneOrOnce,
                    FieldType::Name => NoneOrOnce,
                    FieldType::RicardianContract => NoneOrOnce,
                    FieldType::Precision => NoneOrOnce
                },
                closes: type_map! {
                    OwnedRightsType::Renomination => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::Renomination => NoneOrOnce
                },
                public_rights: none!(),
                abi: none!()
            },
            // Allows split of rights if they were occasionally allocated to the
            // same UTXO, for instance both assets and issuance right. Without
            // this type of transition either assets or inflation rights will be
            // lost.
            TransitionType::RightsSplit => TransitionSchema {
                metadata: type_map! {},
                closes: type_map! {
                    OwnedRightsType::Inflation => NoneOrMore,
                    OwnedRightsType::Assets => NoneOrMore,
                    OwnedRightsType::BurnReplace => NoneOrMore,
                    OwnedRightsType::Renomination => NoneOrOnce
                },
                owned_rights: type_map! {
                    OwnedRightsType::Inflation => NoneOrMore,
                    OwnedRightsType::Assets => NoneOrMore,
                    OwnedRightsType::BurnReplace => NoneOrMore,
                    OwnedRightsType::Renomination => NoneOrOnce
                },
                public_rights: none!(),
                abi: bmap! {
                    // We must allocate exactly one or none rights per each
                    // right used as input (i.e. closed seal); plus we need to
                    // control that sum of inputs is equal to the sum of outputs
                    // for each of state types having assigned confidential
                    // amounts
                    TransitionAction::Validate => script::EmbeddedProcedure::RightsSplit as script::EntryPoint
                }
            }
        },
        field_types: type_map! {
            // Rational: if we will use just 26 letters of English alphabet (and
            // we are not limited by them), we will have 26^8 possible tickers,
            // i.e. > 208 trillions, which is sufficient amount
            FieldType::Ticker => DataFormat::String(8),
            FieldType::Name => DataFormat::String(256),
            // Contract text may contain URL, text or text representation of
            // Ricardian contract, up to 64kb. If the contract doesn't fit, a
            // double SHA256 hash and URL should be used instead, pointing to
            // the full contract text, where hash must be represented by a
            // hexadecimal string, optionally followed by `\n` and text URL
            // TODO #33: Consider using data container instead of the above ^^^
            FieldType::RicardianContract => DataFormat::String(core::u16::MAX),
            FieldType::Precision => DataFormat::Unsigned(Bits::Bit8, 0, 18u128),
            // We need this b/c allocated amounts are hidden behind Pedersen
            // commitments
            FieldType::IssuedSupply => DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128),
            // Supply in either burn or burn-and-replace procedure
            FieldType::BurnedSupply => DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128),
            // While UNIX timestamps allow negative numbers; in context of RGB
            // Schema, assets can't be issued in the past before RGB or Bitcoin
            // even existed; so we prohibit all the dates before RGB release
            // This timestamp is equal to 10/10/2020 @ 2:37pm (UTC)
            FieldType::Timestamp => DataFormat::Integer(Bits::Bit64, 1602340666, core::i64::MAX as i128),
            FieldType::BurnUtxo => DataFormat::TxOutPoint
        },
        owned_right_types: type_map! {
            OwnedRightsType::Inflation => StateSchema {
                // How much issuer can issue tokens on this path. If there is no
                // limit, than `core::u64::MAX` / sum(inflation_assignments)
                // must be used, as this will be a de-facto limit to the
                // issuance
                format: StateFormat::CustomData(DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128)),
                // Validation involves other state data, so it is performed
                // at the level of `issue` state transition
                abi: none!()
            },
            OwnedRightsType::Assets => StateSchema {
                format: StateFormat::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
                abi: bmap! {
                    // sum(inputs) == sum(outputs)
                    AssignmentAction::Validate => script::EmbeddedProcedure::FungibleNoInflation as script::EntryPoint
                }
            },
            OwnedRightsType::OpenEpoch => StateSchema {
                format: StateFormat::Declarative,
                abi: none!()
            },
            OwnedRightsType::BurnReplace => StateSchema {
                format: StateFormat::Declarative,
                abi: none!()
            },
            OwnedRightsType::Renomination => StateSchema {
                format: StateFormat::Declarative,
                abi: none!()
            }
        },
        public_right_types: none!(),
        script: script::ExecutableCode {
            vm_type: script::VmType::Embedded,
            byte_code: empty!(),
            override_rules: script::OverrideRules::Deny,
        },
    }
}

impl Deref for FieldType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            // Nomination fields:
            FieldType::Ticker => &FIELD_TYPE_TICKER,
            FieldType::Name => &FIELD_TYPE_NAME,
            FieldType::RicardianContract => &FIELD_TYPE_CONTRACT_TEXT,
            FieldType::Precision => &FIELD_TYPE_PRECISION,
            FieldType::Timestamp => &FIELD_TYPE_TIMESTAMP,
            // Inflation fields:
            FieldType::IssuedSupply => &FIELD_TYPE_ISSUED_SUPPLY,
            // Proof-of-burn fields:
            FieldType::BurnedSupply => &FIELD_TYPE_BURN_SUPPLY,
            FieldType::BurnUtxo => &FIELD_TYPE_BURN_UTXO,
            FieldType::HistoryProof => &FIELD_TYPE_HISTORY_PROOF,
            FieldType::HistoryProofFormat => &FIELD_TYPE_HISTORY_PROOF_FORMAT,
        }
    }
}

impl Deref for OwnedRightsType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            // Nomination rights:
            OwnedRightsType::Renomination => &STATE_TYPE_RENOMINATION_RIGHT,
            // Inflation-control-related rights:
            OwnedRightsType::Inflation => &STATE_TYPE_INFLATION_RIGHT,
            OwnedRightsType::Assets => &STATE_TYPE_OWNED_AMOUNT,
            OwnedRightsType::OpenEpoch => &STATE_TYPE_ISSUE_EPOCH_RIGHT,
            OwnedRightsType::BurnReplace => &STATE_TYPE_ISSUE_REPLACEMENT_RIGHT,
        }
    }
}

impl Deref for TransitionType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            // Asset transfers:
            TransitionType::Transfer => &TRANSITION_TYPE_OWNERSHIP_TRANSFER,
            // Nomination transitions:
            TransitionType::Renomination => &TRANSITION_TYPE_RENOMINATION,
            // Inflation-related transitions:
            TransitionType::Issue => &TRANSITION_TYPE_ISSUE,
            TransitionType::Epoch => &TRANSITION_TYPE_ISSUE_EPOCH,
            TransitionType::Burn => &TRANSITION_TYPE_ISSUE_BURN,
            TransitionType::BurnAndReplace => &TRANSITION_TYPE_ISSUE_REPLACE,
            TransitionType::RightsSplit => &TRANSITION_TYPE_RIGHTS_SPLIT,
        }
    }
}

impl Deref for HistoryProofFormat {
    type Target = u8;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            HistoryProofFormat::ProofAbsent => &0x0,
            HistoryProofFormat::ProofV1 => &0x1,
            HistoryProofFormat::ProofV2 => &0x2,
            HistoryProofFormat::ProofV3 => &0x3,
            HistoryProofFormat::ProofV4 => &0x4,
            HistoryProofFormat::ProofV5 => &0x5,
            HistoryProofFormat::ProofV6 => &0x6,
            HistoryProofFormat::ProofV7 => &0x7,
            HistoryProofFormat::ProofV8 => &0x8,
            HistoryProofFormat::ProofV9 => &0x9,
            HistoryProofFormat::ProofV10 => &0xA,
            HistoryProofFormat::ProofV11 => &0xB,
            HistoryProofFormat::ProofV12 => &0xC,
            HistoryProofFormat::ProofV13 => &0xD,
            HistoryProofFormat::ProofV14 => &0xE,
            HistoryProofFormat::ProofV15 => &0xF,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use lnpbp::bech32::Bech32DataString;
    use lnpbp::strict_encoding::{StrictDecode, StrictEncode};
    use rgb::schema::SchemaVerify;
    use rgb::{FromBech32, ToBech32, Validity};

    #[test]
    fn schema_id() {
        let id = schema().schema_id();
        println!("{}", id);
        assert_eq!(id.to_string(), SCHEMA_ID_BECH32);
        assert_eq!(
            id.to_string(),
            "sch1rw6q0s4ynl4k5nmk4u2q25dag4409t7882pq4n6n7ywdrhp4f6cqfaf4xw"
        );
    }

    #[test]
    fn schema_strict_encode() {
        let data = schema()
            .strict_serialize()
            .expect("RGB-20 schema serialization failed");

        let bech32data = data.bech32_data_string();
        println!("{}", bech32data);

        let schema20 = Schema::strict_deserialize(data)
            .expect("RGB-20 schema deserialization failed");

        assert_eq!(schema(), schema20);
        assert_eq!(format!("{:#?}", schema()), format!("{:#?}", schema20));
        assert_eq!(
            bech32data,
            "data1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2qqqqq\
            pqgqqqsqpqqqypqqp8llupsqqqpqqfqgqqppqav0q2lqqqqqq8llllllllllal6qqqq\
            pqqqqqqqqqqqqq8llllllllllllmqqqqpqqqqqqqqqqqqq8llllllllllllmzqpqkgq\
            qtlllkvqqxyqqqqqsyqcyq5rqwzqfpg9scrgwpuzsqqgqqqqqpgqqqgqqsqqqqqqqqq\
            qqqrllllllllllllcqqzssqqgqpqqqqqqqqqqqqq8llllllllllllszqqqqyqqqq92q\
            qqqqq9tqqqqqqqqqqrqqqqqqyqqzqqpqqqsqqgqqgqqqqqpqqpsqqgqqyqqgqqpqqqs\
            pgqqqyqqzqqyqqqsqqqqqyq2qqqqqrlllggqqqq0lla2qqqqqqgqqqqqqqqqqqqqqpc\
            qqqqqqqqpqzssqqgqlllszq9pqqqqplllqqqqqqqqqqgqqpqqqqqqqqqpqqqsqqqqqy\
            qqyqqqqqqsqqcqqqqqzqqpqqqsqqgqqyqqzqqpqqqqqqgqqqqqqqqqqzsqqqgq5qqqz\
            qqpqqqspgqqqyq0llcrqzsqqqqqlll6zqqqqrlll2sqqqqqzqqqqqqsqqqzqqqqqqqq\
            5yqqqqqpqz4qqqgqqyqqyq92qqqqqqgq4vqqqqqpqqqqqqqqqqq2yqqyqzcqqqgqqyq\
            tzqqpqrlllvsqqqq0llanqqqsqqgqqyq2kqqpqqqsqqgq4vqqqqqpqqqqqqgqqqsqqq\
            qqqqq2xqq9qzsqqqgqqyqtqqqpqqqspvgqqyq0llajqqqqplllkvqqzqqpqqqsp2cqq\
            yqqzqqzqzssqqgqlll6kqqqqqqsqqqqqyqqqgqqqqqqqq8sqqqqqpgqqyqqqqqpqzsq\
            qqqqlll6zqqqqrlll2sqqqqqzq9tqqqqplllq5qqzqqqqqqspgqqqqq0llapqqqqpll\
            l4gqqqqqpqz4sqqqqlllsqqqpqqqrqqqqqqqqqqqqqqqq4f8w33"
        );
    }

    #[test]
    fn schema_bech32_encode() {
        let data = schema().to_bech32_string();

        println!("{}", data);

        let schema20 = Schema::from_bech32_str(&data)
            .expect("RGB-20 schema deserialization failed");

        assert_eq!(schema(), schema20);
        assert_eq!(format!("{:#?}", schema()), format!("{:#?}", schema20));
        assert_eq!(
            schema20.to_string(),
            "schema1qxz4pkcdsvcqc0zzq22tu5p8vzz8uaue3ef82ymgllsg03cstkn3hfywr53\
            zf2rsjjrhmwdmcnvge89xecgyzg6j6rtvdg8ygfvhd7eualhg49tc23qrd5tue4mzhd\
            g7u5qx8mvghqsrz9ttjwjdjtklr7820vepwk9q56jfq34yy9l9prxxjh9dz55gr26dg\
            dc3du6e7ddg2vecwd3rttcdg3xj9ef4vf0kwfrhqs4csrl0swvuhhrecgj24cpvhd47\
            dx3hfhzcfx5ncel59crkymu2yfm53nmzcdasen5zmk4sqlvey6t0rrlcutdj7gl47jr\
            udxdtlmttlx7gtv7uxh605pcw79337"
        );
    }

    #[test]
    fn subschema_verify() {
        assert_eq!(
            subschema().schema_verify(&schema()).validity(),
            Validity::Valid
        );
    }
}
