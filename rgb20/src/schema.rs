// RGB20 Library: fungible digital assets for bitcoin & lightning
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

use std::collections::BTreeSet;
use std::ops::Deref;

use rgb::schema::{
    constants::*,
    script::{Procedure, StandardProcedure},
    AssignmentAction, Bits, DataFormat, DiscreteFiniteFieldFormat,
    GenesisSchema, Occurences, Schema, StateFormat, StateSchema,
    TransitionAction, TransitionSchema,
};

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
    ContractText,
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
    Epoch,
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
    ProovV1,
    ProovV2,
    ProovV3,
    ProovV4,
    ProovV5,
    ProovV6,
    ProovV7,
    ProovV8,
    ProovV9,
    ProovV10,
    ProovV11,
    ProovV12,
    ProovV13,
    ProovV14,
    ProovV15,
}

impl HistoryProofFormat {
    pub fn all() -> BTreeSet<u8> {
        bset![
            *HistoryProofFormat::ProofAbsent,
            *HistoryProofFormat::ProovV1,
            *HistoryProofFormat::ProovV2,
            *HistoryProofFormat::ProovV3,
            *HistoryProofFormat::ProovV4,
            *HistoryProofFormat::ProovV5,
            *HistoryProofFormat::ProovV6,
            *HistoryProofFormat::ProovV7,
            *HistoryProofFormat::ProovV8,
            *HistoryProofFormat::ProovV9,
            *HistoryProofFormat::ProovV10,
            *HistoryProofFormat::ProovV11,
            *HistoryProofFormat::ProovV12,
            *HistoryProofFormat::ProovV13,
            *HistoryProofFormat::ProovV14,
            *HistoryProofFormat::ProovV15
        ]
    }
}

pub fn schema() -> Schema {
    use Occurences::*;

    Schema {
        rgb_features: none!(),
        root_id: none!(),
        genesis: GenesisSchema {
            metadata: type_map! {
                FieldType::Ticker => Once,
                FieldType::Name => Once,
                FieldType::ContractText => NoneOrOnce,
                FieldType::Precision => Once,
                FieldType::Timestamp => Once,
                FieldType::IssuedSupply => Once
            },
            owned_rights: type_map! {
                OwnedRightsType::Inflation => NoneOrMore,
                OwnedRightsType::Epoch => NoneOrOnce,
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
                    OwnedRightsType::Epoch => NoneOrOnce,
                    OwnedRightsType::Assets => NoneOrMore
                },
                public_rights: none!(),
                abi: bmap! {
                    // sum(in(inflation)) >= sum(out(inflation), out(assets))
                    TransitionAction::Validate => Procedure::Embedded(StandardProcedure::FungibleInflation)
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
                    OwnedRightsType::Epoch => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::Epoch => NoneOrOnce,
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
                    TransitionAction::Validate => Procedure::Embedded(StandardProcedure::ProofOfBurn)
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
                    TransitionAction::Validate => Procedure::Embedded(StandardProcedure::ProofOfBurn)
                }
            },
            TransitionType::Renomination => TransitionSchema {
                metadata: type_map! {
                    FieldType::Ticker => NoneOrOnce,
                    FieldType::Name => NoneOrOnce,
                    FieldType::ContractText => NoneOrOnce,
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
                    OwnedRightsType::Epoch => NoneOrOnce,
                    OwnedRightsType::BurnReplace => NoneOrMore,
                    OwnedRightsType::Renomination => NoneOrOnce
                },
                owned_rights: type_map! {
                    OwnedRightsType::Inflation => NoneOrMore,
                    OwnedRightsType::Assets => NoneOrMore,
                    OwnedRightsType::Epoch => NoneOrOnce,
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
                    TransitionAction::Validate => Procedure::Embedded(StandardProcedure::RightsSplit)
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
            FieldType::ContractText => DataFormat::String(core::u16::MAX),
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
                    AssignmentAction::Validate => Procedure::Embedded(StandardProcedure::NoInflationBySum)
                }
            },
            OwnedRightsType::Epoch => StateSchema {
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
    }
}

impl Deref for FieldType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            // Nomination fields:
            FieldType::Ticker => &0,
            FieldType::Name => &1,
            FieldType::ContractText => &2,
            FieldType::Precision => &3,
            FieldType::Timestamp => &4,
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
            OwnedRightsType::Renomination => &1,
            // Inflation-control-related rights:
            OwnedRightsType::Inflation => &STATE_TYPE_FUNGIBLE_INFLATION,
            OwnedRightsType::Assets => &STATE_TYPE_FUNGIBLE_ASSETS,
            OwnedRightsType::Epoch => &(STATE_TYPE_FUNGIBLE_INFLATION + 0xA),
            OwnedRightsType::BurnReplace => {
                &(STATE_TYPE_FUNGIBLE_INFLATION + 0xB)
            }
        }
    }
}

impl Deref for TransitionType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            // Asset transfers:
            TransitionType::Transfer => &0x00,
            // Nomination transitions:
            TransitionType::Renomination => &0x10,
            // Inflation-related transitions:
            TransitionType::Issue => &TRANSITION_TYPE_FUNGIBLE_ISSUE,
            TransitionType::Epoch => &(TRANSITION_TYPE_FUNGIBLE_ISSUE + 1),
            TransitionType::Burn => &(TRANSITION_TYPE_FUNGIBLE_ISSUE + 2),
            TransitionType::BurnAndReplace => {
                &(TRANSITION_TYPE_FUNGIBLE_ISSUE + 3)
            }
            TransitionType::RightsSplit => &0xF0,
        }
    }
}

impl Deref for HistoryProofFormat {
    type Target = u8;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            HistoryProofFormat::ProofAbsent => &0x0,
            HistoryProofFormat::ProovV1 => &0x1,
            HistoryProofFormat::ProovV2 => &0x2,
            HistoryProofFormat::ProovV3 => &0x3,
            HistoryProofFormat::ProovV4 => &0x4,
            HistoryProofFormat::ProovV5 => &0x5,
            HistoryProofFormat::ProovV6 => &0x6,
            HistoryProofFormat::ProovV7 => &0x7,
            HistoryProofFormat::ProovV8 => &0x8,
            HistoryProofFormat::ProovV9 => &0x9,
            HistoryProofFormat::ProovV10 => &0xA,
            HistoryProofFormat::ProovV11 => &0xB,
            HistoryProofFormat::ProovV12 => &0xC,
            HistoryProofFormat::ProovV13 => &0xD,
            HistoryProofFormat::ProovV14 => &0xE,
            HistoryProofFormat::ProovV15 => &0xF,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use lnpbp::bech32::Bech32DataString;
    use lnpbp::strict_encoding::{StrictDecode, StrictEncode};
    use rgb::{FromBech32, ToBech32};

    #[test]
    fn schema_id() {
        let id = schema().schema_id();
        println!("{}", id);
        assert_eq!(
            id.to_string(),
            "sch1zcdeayj9vpv852tx2sjzy7esyy82a6nk0gs854ktam24zxee42rqyzg95g"
        );
    }

    #[test]
    fn schema_structure() {
        let debug = format!("{:#?}", schema());
        assert_eq!(
            debug,
            "Schema {
    rgb_features: flags:,
    root_id: 0000000000000000000000000000000000000000000000000000000000000000,
    field_types: {
        0: String(
            8,
        ),
        1: String(
            256,
        ),
        2: String(
            65535,
        ),
        3: Unsigned(
            Bit8,
            0,
            18,
        ),
        4: Integer(
            Bit64,
            1602340666,
            9223372036854775807,
        ),
        160: Unsigned(
            Bit64,
            0,
            18446744073709551615,
        ),
        176: Unsigned(
            Bit64,
            0,
            18446744073709551615,
        ),
        177: TxOutPoint,
        178: Bytes(
            65535,
        ),
        179: Enum(
            {
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
            },
        ),
    },
    owned_right_types: {
        1: StateSchema {
            format: Declarative,
            abi: {},
        },
        160: StateSchema {
            format: CustomData(
                Unsigned(
                    Bit64,
                    0,
                    18446744073709551615,
                ),
            ),
            abi: {},
        },
        161: StateSchema {
            format: DiscreteFiniteField(
                Unsigned64bit,
            ),
            abi: {
                Validate: Embedded(
                    NoInflationBySum,
                ),
            },
        },
        170: StateSchema {
            format: Declarative,
            abi: {},
        },
        171: StateSchema {
            format: Declarative,
            abi: {},
        },
    },
    public_right_types: {},
    genesis: GenesisSchema {
        metadata: {
            0: Once,
            1: Once,
            2: NoneOrOnce,
            3: Once,
            4: Once,
            160: Once,
        },
        owned_rights: {
            1: NoneOrOnce,
            160: NoneOrMore,
            161: NoneOrMore,
            170: NoneOrOnce,
        },
        public_rights: {},
        abi: {},
    },
    extensions: {},
    transitions: {
        0: TransitionSchema {
            metadata: {},
            closes: {
                161: OnceOrMore,
            },
            owned_rights: {
                161: NoneOrMore,
            },
            public_rights: {},
            abi: {},
        },
        16: TransitionSchema {
            metadata: {
                0: NoneOrOnce,
                1: NoneOrOnce,
                2: NoneOrOnce,
                3: NoneOrOnce,
            },
            closes: {
                1: Once,
            },
            owned_rights: {
                1: NoneOrOnce,
            },
            public_rights: {},
            abi: {},
        },
        160: TransitionSchema {
            metadata: {
                160: Once,
            },
            closes: {
                160: OnceOrMore,
            },
            owned_rights: {
                160: NoneOrMore,
                161: NoneOrMore,
                170: NoneOrOnce,
            },
            public_rights: {},
            abi: {
                Validate: Embedded(
                    FungibleInflation,
                ),
            },
        },
        161: TransitionSchema {
            metadata: {},
            closes: {
                170: Once,
            },
            owned_rights: {
                170: NoneOrOnce,
                171: NoneOrOnce,
            },
            public_rights: {},
            abi: {},
        },
        162: TransitionSchema {
            metadata: {
                176: Once,
                177: OnceOrMore,
                178: NoneOrMore,
                179: Once,
            },
            closes: {
                171: Once,
            },
            owned_rights: {
                171: NoneOrOnce,
            },
            public_rights: {},
            abi: {
                Validate: Embedded(
                    ProofOfBurn,
                ),
            },
        },
        163: TransitionSchema {
            metadata: {
                176: Once,
                177: OnceOrMore,
                178: NoneOrMore,
                179: Once,
            },
            closes: {
                171: Once,
            },
            owned_rights: {
                161: OnceOrMore,
                171: NoneOrOnce,
            },
            public_rights: {},
            abi: {
                Validate: Embedded(
                    ProofOfBurn,
                ),
            },
        },
        240: TransitionSchema {
            metadata: {},
            closes: {
                1: NoneOrOnce,
                160: NoneOrMore,
                161: NoneOrMore,
                170: NoneOrOnce,
                171: NoneOrMore,
            },
            owned_rights: {
                1: NoneOrOnce,
                160: NoneOrMore,
                161: NoneOrMore,
                170: NoneOrOnce,
                171: NoneOrMore,
            },
            public_rights: {},
            abi: {
                Validate: Embedded(
                    RightsSplit,
                ),
            },
        },
    },
}"
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
            "data1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\
        qqqqqqqqqqq2qqqqqpqgqqqsqpqqqypqqp8llupsqqqpqqfqgqqppqav0q2lqqqqqq8llll\
        llllllal6qqqqpqqqqqqqqqqqqq8llllllllllllmqqqqpqqqqqqqqqqqqq8lllllllllll\
        lmzqpqkgqqtlllkvqqxyqqqqqsyqcyq5rqwzqfpg9scrgwpuzsqqgqqqqqpgqqqgqqsqqqq\
        qqqqqqqqrllllllllllllcqqzssqqgqpqqqqqqqqqqqqq8llllllllllllszqqqluq65qqq\
        qqq2kqqqqqqqqqqxqqqqqqgqqyqqzqqpqqqsqqsqqqqqzqqrqqqsqqgqqsqqzqqpqzsqqqg\
        qqyqqgqqpqqqqqqgq5qqqqq8ll7ssqqqqlll65qqqqqqsqqqqqqqqqqqqqqrsqqqqqqqqzq\
        9pqqqsplllqyq2zqqqqrll7qqqqqqqqqqsqqzqqqqqqqqqzqqpqqqqqqgqqgqqqqqpqqpsq\
        qqqqyqqzqqpqqqsqqgqqyqqzqqqqqqsqqqqqqqqqq9qqqqspgqqqyqqzqqpqzsqqqgqllls\
        xq9qqqqqplll5yqqqq8ll74qqqqqqyqqqqqpqqq07qsqqzssqqqqqyq25qqpqqqsqqsq4gq\
        qqqqpqz4sqqqqqyqqqqqqqqqqpgsqqsqtqqqpqqqspvgqqyq0llajqqqqplllkvqqzqqpqq\
        qsp2cqqyqqzqqpqz4sqqqqqyqqqqqpqqq07yqqqz3sqpqqkqqqzqqpqzcsqqgqlllmyqqqq\
        rlllvcqqyqqzqqpqz4sqqgqqyqqyq9pqqqsplll4vqqqqqpqqqqqqgqqrl3qqqq7qqqqqq9\
        qqqsqqqqqyq2qqqqqrlllggqqqq0lla2qqqqqqgq4vqqqq8lluzsqqgqqqqqzq9qqqqqpll\
        l5yqqqq8ll74qqqqqqyq2kqqqqrll7qqqqyqqpleqqqqqqqqz8ypqa"
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
            "schema1qxx4qkcjsgcqehyk7gg9lrp8uqw9a34r8r0qfay0lm\
        cr3pxh7yrr2n2mvszq0s7symvkvdcf2ck6whm9zpgpqyk2nqypf8pget8vlk798ccuats4j\
        zzn98ena4p2us7eyvmxvsz5zzvcc4yu5nvjdhlw76rkxn8vvs27f0qs4qyemfdfczyvve45\
        qvfds8kryuuc4kzh03t2xruw932u6e7rn9szn8uz2kkcc7lrkzpw4ct4xpgej2s8e3vn224\
        mmwh8yjwm3c3uzcsz350urqt6gfm6wpj6gcajd6uevncqy74u87jtfmx8raza9nlm2hazyd\
        l7hyevmls6amyy4kl7rv6skggq"
        );
    }
}
