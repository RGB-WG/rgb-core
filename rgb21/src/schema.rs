// RGB-21 Library: non-fungible tokens (collectibles) for bitcoin & lightning
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
    constants::*,
    script::{Procedure, StandardProcedure},
    Bits, DataFormat, GenesisAction, GenesisSchema, Occurences, Schema,
    StateFormat, StateSchema, TransitionAction, TransitionSchema,
};

#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display, Error, From,
)]
#[display(Debug)]
pub enum SchemaError {
    NotAllFieldsPresent,

    WrongSchemaId,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    Name,
    RicardianContract,
    Data,
    DataFormat,
    Timestamp,
    LockDescriptor,
    LockUtxo,
    BurnUtxo,
    Commentary,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightsType {
    Inflation,
    Ownership,
    EngravedOwnership,
    Renomination,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    Issue,
    Transfer,
    Engraving,
    Renomination,
    RightsSplit,
    Burn,
}

pub fn schema() -> Schema {
    use Occurences::*;

    // NFT source data are kept as metadata, not state,
    Schema {
        rgb_features: none!(),
        root_id: none!(),
        genesis: GenesisSchema {
            metadata: type_map! {
                FieldType::Name => Once,
                FieldType::RicardianContract => NoneOrOnce,
                FieldType::Commentary => NoneOrOnce,
                // Data common for all tokens
                FieldType::Data => NoneOrOnce,
                // Data format
                FieldType::DataFormat => NoneOrOnce,
                // Proof of reserves UTXO
                FieldType::LockUtxo => NoneOrMore,
                // Proof of reserves scriptPubkey descriptor used for
                // verification
                FieldType::LockDescriptor => NoneOrOnce,
                FieldType::Timestamp => Once
            },
            owned_rights: type_map! {
                OwnedRightsType::Inflation => NoneOrOnce,
                OwnedRightsType::Renomination => NoneOrOnce,
                // We have an option of issuing zero tokens here and just
                // declaring future issuance
                OwnedRightsType::Ownership => NoneOrMore
            },
            public_rights: none!(),
            abi: bmap! {
                // Here we validate hash uniqueness of state values for all
                // issued token ownerships
                GenesisAction::Validate => Procedure::Embedded(StandardProcedure::NonfungibleInflation)
            },
        },
        extensions: bmap! {},
        transitions: type_map! {
            TransitionType::Issue => TransitionSchema {
                metadata: type_map! {
                    // Proof of reserves UTXOs (relate to all tokens in the
                    // issue)
                    FieldType::LockUtxo => NoneOrMore,
                    // Proof of reserves scriptPubkey descriptor used for
                    // verification.
                    FieldType::LockDescriptor => NoneOrOnce
                },
                closes: type_map! {
                    OwnedRightsType::Inflation => Once
                },
                owned_rights: type_map! {
                    OwnedRightsType::Inflation => NoneOrOnce,
                    OwnedRightsType::Ownership => OnceOrMore
                },
                public_rights: none!(),
                abi: bmap! {
                    // Here we validate hash uniqueness of state values for all
                    // issued token ownerships
                    TransitionAction::Validate => Procedure::Embedded(StandardProcedure::NonfungibleInflation)
                }
            },
            // We match input and output tokens by ordering outputs in the same
            // way as the inputs. NodeId are lexicographically ordered by the
            // same procedure as it is in the parent owned rights data structure
            TransitionType::Transfer => TransitionSchema {
                metadata: type_map! {
                },
                closes: type_map! {
                    OwnedRightsType::Ownership => OnceOrMore,
                    OwnedRightsType::EngravedOwnership => OnceOrMore
                },
                owned_rights: type_map! {
                    OwnedRightsType::Ownership => OnceOrMore
                },
                public_rights: none!(),
                abi: bmap! {
                    // Here we ensure that each unique NFT is transferred once
                    // and only once, i.e. that number of inputs is equal to the
                    // number of outputs
                    TransitionAction::Validate => Procedure::Embedded(StandardProcedure::IdentityTransfer)
                }
            },
            // One engraving per set of tokens
            TransitionType::Engraving => TransitionSchema {
                metadata: type_map! {
                    FieldType::Data => NoneOrOnce,
                    FieldType::DataFormat => Once
                },
                closes: type_map! {
                    OwnedRightsType::Ownership => OnceOrMore,
                    OwnedRightsType::EngravedOwnership => OnceOrMore
                },
                owned_rights: type_map! {
                    OwnedRightsType::EngravedOwnership => OnceOrMore
                },
                public_rights: none!(),
                abi: bmap! {
                    // Here we ensure that each unique NFT is transferred once
                    // and only once, i.e. that number of inputs is equal to the
                    // number of outputs
                    TransitionAction::Validate => Procedure::Embedded(StandardProcedure::IdentityTransfer)
                }
            },
            TransitionType::Renomination => TransitionSchema {
                metadata: type_map! {
                    FieldType::Name => NoneOrOnce,
                    FieldType::RicardianContract => NoneOrOnce,
                    FieldType::Data => NoneOrOnce,
                    FieldType::DataFormat => Once
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
                metadata: type_map! {
                },
                closes: type_map! {
                    OwnedRightsType::Inflation => NoneOrMore,
                    OwnedRightsType::Ownership => NoneOrMore,
                    OwnedRightsType::EngravedOwnership => NoneOrMore,
                    OwnedRightsType::Renomination => NoneOrOnce
                },
                owned_rights: type_map! {
                    OwnedRightsType::Inflation => NoneOrMore,
                    OwnedRightsType::Ownership => NoneOrMore,
                    OwnedRightsType::EngravedOwnership => NoneOrMore,
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
            },
            TransitionType::Burn => TransitionSchema {
                metadata: type_map! {
                    // Some comment explaining the reasoning behind the burn
                    // operation
                    FieldType::Commentary => NoneOrOnce,
                    // Contained data which may contain "burn performance"
                    FieldType::Data => NoneOrOnce,
                    FieldType::DataFormat => NoneOrOnce
                },
                closes: type_map! {
                    OwnedRightsType::Inflation => NoneOrMore,
                    OwnedRightsType::Ownership => NoneOrMore,
                    OwnedRightsType::EngravedOwnership => NoneOrMore,
                    OwnedRightsType::Renomination => NoneOrOnce
                },
                owned_rights: none!(),
                public_rights: none!(),
                abi: none!()
            }
        },
        field_types: type_map! {
            FieldType::Name => DataFormat::String(256),
            // TODO #35: Consider using data container
            FieldType::RicardianContract => DataFormat::String(core::u16::MAX),
            // Data common for all NFTs inside specific state transition or
            // genesis.
            // TODO #35: Add DataContainer for common data kept inside external
            //       data container
            FieldType::Data => DataFormat::Bytes(core::u16::MAX),
            // A set of data formats, corresponding values and user-defined
            // type extensibility must be provided by RGB21 specification
            // TODO #36: (LNPBPs) Consider using MIME types
            FieldType::DataFormat => DataFormat::Unsigned(Bits::Bit32, 0, core::u32::MAX as u128),
            // While UNIX timestamps allow negative numbers; in context of RGB
            // Schema, assets can't be issued in the past before RGB or Bitcoin
            // even existed; so we prohibit all the dates before RGB release
            // This timestamp is equal to 10/10/2020 @ 2:37pm (UTC) - the same
            // as for RGB-20 standard.
            FieldType::Timestamp => DataFormat::Integer(Bits::Bit64, 1602340666, core::i64::MAX as i128),
            FieldType::LockUtxo => DataFormat::TxOutPoint,
            // Descriptor in binary strict encoded format
            FieldType::LockDescriptor => DataFormat::Bytes(core::u16::MAX),
            FieldType::BurnUtxo => DataFormat::TxOutPoint,
            FieldType::Commentary => DataFormat::String(core::u16::MAX)
        },
        owned_right_types: type_map! {
            OwnedRightsType::Inflation => StateSchema {
                // How much issuer can issue tokens on this path
                format: StateFormat::CustomData(DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128)),
                abi: none!()
            },
            OwnedRightsType::Ownership => StateSchema {
                // How much issuer can issue tokens on this path
                format: StateFormat::Declarative,
                abi: none!()
            },
            OwnedRightsType::EngravedOwnership => StateSchema {
                // Engraving data (per-token). Data format is defined by metadata
                // and must be same for all tokens
                // TODO #35: Use `DataFormat::Container` once will be available
                format: StateFormat::CustomData(DataFormat::Bytes(core::u16::MAX)),
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

// TODO #35: Define all standard field, rights & transition types which are
// common       to different schemata as constants
impl Deref for FieldType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            // Nomination fields:
            FieldType::Name => &FIELD_TYPE_NAME,
            FieldType::RicardianContract => &FIELD_TYPE_CONTRACT_TEXT,
            FieldType::Timestamp => &FIELD_TYPE_TIMESTAMP,
            FieldType::Data => &FIELD_TYPE_DATA,
            FieldType::DataFormat => &FIELD_TYPE_DATA_FORMAT,
            FieldType::Commentary => &FIELD_TYPE_COMMENTARY,
            // Proof-of-burn fields:
            FieldType::BurnUtxo => &FIELD_TYPE_BURN_UTXO,
            // Prood-of-reserves fields:
            FieldType::LockDescriptor => &FIELD_TYPE_LOCK_DESCRIPTOR,
            FieldType::LockUtxo => &FIELD_TYPE_LOCK_UTXO,
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
            OwnedRightsType::Ownership => &STATE_TYPE_OWNERSHIP_RIGHT,
            OwnedRightsType::EngravedOwnership => &STATE_TYPE_OWNERSHIP_RIGHT,
        }
    }
}

impl Deref for TransitionType {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        match self {
            // Asset transfers:
            TransitionType::Transfer => &TRANSITION_TYPE_OWNERSHIP_TRANSFER,
            TransitionType::Engraving => &TRANSITION_TYPE_STATE_MODIFICATION,
            // Nomination transitions:
            TransitionType::Renomination => &TRANSITION_TYPE_RENOMINATION,
            // Inflation-related transitions:
            TransitionType::Issue => &TRANSITION_TYPE_ISSUE,
            TransitionType::RightsSplit => &TRANSITION_TYPE_RIGHTS_SPLIT,
            TransitionType::Burn => &TRANSITION_TYPE_RIGHTS_TERMINATION,
        }
    }
}
