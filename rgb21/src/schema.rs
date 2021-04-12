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

use rgb::schema::{
    constants::*, script, AssignmentAction, Bits, DataFormat,
    DiscreteFiniteFieldFormat, GenesisAction, GenesisSchema, Occurences,
    Schema, StateFormat, StateSchema, TransitionAction, TransitionSchema,
};
use rgb::vm::embedded;

/// Field types for RGB21 schemata
///
/// Subset of known RGB schema pre-defined types applicable to NFTs.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum FieldType {
    /// Asset name
    ///
    /// Used within context of genesis or renomination state transition
    Name = FIELD_TYPE_NAME,

    /// Text of the asset contract
    ///
    /// Used within context of genesis or renomination state transition
    RicardianContract = FIELD_TYPE_CONTRACT_TEXT,

    /// Timestamp for genesis
    Timestamp = FIELD_TYPE_TIMESTAMP,

    /// Binary data representing the NFT
    Data = FIELD_TYPE_DATA,

    /// Format of the binary NFT data
    DataFormat = FIELD_TYPE_DATA_FORMAT,

    /// Bitcoin output descriptor for the UTXO containing the locked funds
    LockDescriptor = FIELD_TYPE_LOCK_DESCRIPTOR,

    /// UTXO containing locked funds as a NFT reserve
    LockUtxo = FIELD_TYPE_LOCK_UTXO,

    /// UTXO that is provably unspendable and contains burned NFT
    BurnUtxo = FIELD_TYPE_BURN_UTXO,

    /// Text commentary for an NFT operation
    Commentary = FIELD_TYPE_COMMENTARY,
}

impl From<FieldType> for rgb::schema::FieldType {
    #[inline]
    fn from(ft: FieldType) -> Self {
        ft as rgb::schema::FieldType
    }
}

/// Owned right types used by RGB21 schemata
///
/// Subset of known RGB schema pre-defined types applicable to NFTs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum OwnedRightType {
    /// Inflation control right (secondary issuance right)
    Inflation = STATE_TYPE_INFLATION_RIGHT,

    /// Asset ownership right
    Ownership = STATE_TYPE_OWNERSHIP_RIGHT,

    /// Asset ownership right
    EngravedOwnership = STATE_TYPE_OWNERSHIP_RIGHT + 1,

    /// Right to perform asset renomination
    Renomination = STATE_TYPE_RENOMINATION_RIGHT,
}

impl From<OwnedRightType> for rgb::schema::OwnedRightType {
    #[inline]
    fn from(t: OwnedRightType) -> Self {
        t as rgb::schema::OwnedRightType
    }
}

/// State transition types defined by RGB21 schemata
///
/// Subset of known RGB schema pre-defined types applicable to NFTs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u16)]
pub enum TransitionType {
    /// Secondary issuance
    Issue = TRANSITION_TYPE_ISSUE,

    /// Asset transfer
    Transfer = TRANSITION_TYPE_OWNERSHIP_TRANSFER,

    /// Asset transfer joined with addition of custom data to NFT ("engraving")
    Engraving = TRANSITION_TYPE_STATE_MODIFICATION,

    /// Asset burn operation
    Burn = TRANSITION_TYPE_ISSUE_BURN,

    /// Renomination (change in the NFT metadata).
    Renomination = TRANSITION_TYPE_RENOMINATION,

    /// Operation splitting rights assigned to the same UTXO
    RightsSplit = TRANSITION_TYPE_RIGHTS_SPLIT,
}

impl From<TransitionType> for rgb::schema::TransitionType {
    #[inline]
    fn from(t: TransitionType) -> Self {
        t as rgb::schema::TransitionType
    }
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
                OwnedRightType::Inflation => NoneOrOnce,
                OwnedRightType::Renomination => NoneOrOnce,
                // We have an option of issuing zero tokens here and just
                // declaring future issuance
                OwnedRightType::Ownership => NoneOrMore
            },
            public_rights: none!(),
            abi: bmap! {
                // Here we validate hash uniqueness of state values for all
                // issued token ownerships
                GenesisAction::Validate => embedded::NodeValidator::NftIssue as script::EntryPoint
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
                    OwnedRightType::Inflation => Once
                },
                owned_rights: type_map! {
                    OwnedRightType::Inflation => NoneOrOnce,
                    OwnedRightType::Ownership => OnceOrMore
                },
                public_rights: none!(),
                abi: bmap! {
                    // Here we validate hash uniqueness of state values for all
                    // issued token ownerships
                    TransitionAction::Validate => embedded::NodeValidator::NftIssue as script::EntryPoint
                }
            },
            // We match input and output tokens by ordering outputs in the same
            // way as the inputs. NodeId are lexicographically ordered by the
            // same procedure as it is in the parent owned rights data structure
            TransitionType::Transfer => TransitionSchema {
                metadata: type_map! {
                },
                closes: type_map! {
                    OwnedRightType::Ownership => OnceOrMore,
                    OwnedRightType::EngravedOwnership => OnceOrMore
                },
                owned_rights: type_map! {
                    OwnedRightType::Ownership => OnceOrMore
                },
                public_rights: none!(),
                abi: bmap! {
                    // Here we ensure that each unique NFT is transferred once
                    // and only once, i.e. that number of inputs is equal to the
                    // number of outputs
                    TransitionAction::Validate => embedded::NodeValidator::IdentityTransfer as script::EntryPoint
                }
            },
            // One engraving per set of tokens
            TransitionType::Engraving => TransitionSchema {
                metadata: type_map! {
                    FieldType::Data => NoneOrOnce,
                    FieldType::DataFormat => Once
                },
                closes: type_map! {
                    OwnedRightType::Ownership => OnceOrMore,
                    OwnedRightType::EngravedOwnership => OnceOrMore
                },
                owned_rights: type_map! {
                    OwnedRightType::EngravedOwnership => OnceOrMore
                },
                public_rights: none!(),
                abi: bmap! {
                    // Here we ensure that each unique NFT is transferred once
                    // and only once, i.e. that number of inputs is equal to the
                    // number of outputs
                    TransitionAction::Validate => embedded::NodeValidator::IdentityTransfer as script::EntryPoint
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
                    OwnedRightType::Renomination => Once
                },
                owned_rights: type_map! {
                    OwnedRightType::Renomination => NoneOrOnce
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
                    OwnedRightType::Inflation => NoneOrMore,
                    OwnedRightType::Ownership => NoneOrMore,
                    OwnedRightType::EngravedOwnership => NoneOrMore,
                    OwnedRightType::Renomination => NoneOrOnce
                },
                owned_rights: type_map! {
                    OwnedRightType::Inflation => NoneOrMore,
                    OwnedRightType::Ownership => NoneOrMore,
                    OwnedRightType::EngravedOwnership => NoneOrMore,
                    OwnedRightType::Renomination => NoneOrOnce
                },
                public_rights: none!(),
                abi: bmap! {
                    // We must allocate exactly one or none rights per each
                    // right used as input (i.e. closed seal); plus we need to
                    // control that sum of inputs is equal to the sum of outputs
                    // for each of state types having assigned confidential
                    // amounts
                    TransitionAction::Validate => embedded::NodeValidator::RightsSplit as script::EntryPoint
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
                    OwnedRightType::Inflation => NoneOrMore,
                    OwnedRightType::Ownership => NoneOrMore,
                    OwnedRightType::EngravedOwnership => NoneOrMore,
                    OwnedRightType::Renomination => NoneOrOnce
                },
                owned_rights: none!(),
                public_rights: none!(),
                abi: none!()
            }
        },
        field_types: type_map! {
            FieldType::Name => DataFormat::String(256),
            // TODO #33: Consider using data container
            FieldType::RicardianContract => DataFormat::String(core::u16::MAX),
            // Data common for all NFTs inside specific state transition or
            // genesis.
            // TODO #33: Add DataContainer for common data kept inside external
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
            OwnedRightType::Inflation => StateSchema {
                // How much issuer can issue tokens on this path
                format: StateFormat::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
                abi: bmap! {
                    // make sure we do not overflow 64 bits
                    AssignmentAction::Validate => embedded::AssignmentValidator::NoOverflow as script::EntryPoint
                }
            },
            OwnedRightType::Ownership => StateSchema {
                // How much issuer can issue tokens on this path
                format: StateFormat::Declarative,
                abi: none!()
            },
            OwnedRightType::EngravedOwnership => StateSchema {
                // Engraving data (per-token). Data format is defined by metadata
                // and must be same for all tokens
                // TODO #33: Use `DataFormat::Container` once will be available
                format: StateFormat::CustomData(DataFormat::Bytes(core::u16::MAX)),
                abi: none!()
            },
            OwnedRightType::Renomination => StateSchema {
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
