// LNP/BP Rust Library
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

//! Implementation of the embedded state machine

use std::collections::{BTreeMap, BTreeSet};

use amplify::Wrapper;
use bitcoin::OutPoint;
use commit_verify::CommitConceal;

use super::VmApi;
use crate::script::{Action, EntryPoint};
use crate::{
    schema, schema::constants::*, validation, value, AssignmentVec, Metadata,
    NodeId, NodeOutput, NodeSubtype, OwnedRights, PublicRights, Transition,
};

/// Trait for all embedded handlers which allows their construction from
/// entry point data (which must represent the id of the embedded procedure)
pub trait FromEntryPoint {
    /// Constructs concrete type of embedded action handler from a given entry
    /// point value. Returns `None` if the provided entry point value does not
    /// correspond to any of the embedded procedures
    fn from_entry_point(entry_point: EntryPoint) -> Option<Self>
    where
        Self: Sized;
}

/// Embedded action handlers for state assignments processed by the embedded
/// state machine
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[non_exhaustive]
#[repr(u32)] // We must use the type that fits in the size of `EntryPoint`
pub enum AssignmentValidator {
    /// Non-inflationary fungible asset transfer control
    ///
    /// Checks that the sum of pedersen commitments in the inputs of type
    /// [`crate::schema::constants::STATE_TYPE_OWNED_AMOUNT`] equal to the sum
    /// of the outputs of the same type, plus validates bulletproof data
    #[display("fungible-no-inflation")]
    FungibleNoInflation = 0x01,

    /// Control that multiple rights assigning additive state value do not allow
    /// maximum allowed bit dimensionality
    #[display("no-overflow")]
    NoOverflow = 0x02,
}

impl FromEntryPoint for AssignmentValidator {
    /// Constructs [`AssignmentHandler`] from [`EntryPoint`], or returns `None`
    /// if the provided entry point value does not correspond to any of
    /// the embedded procedures
    fn from_entry_point(entry_point: EntryPoint) -> Option<Self> {
        Some(match entry_point {
            x if x == AssignmentValidator::FungibleNoInflation as u32 => {
                AssignmentValidator::FungibleNoInflation
            }
            x if x == AssignmentValidator::NoOverflow as u32 => {
                AssignmentValidator::NoOverflow
            }
            _ => return None,
        })
    }
}

/// Embedded action handlers for contract nodes processed by the embedded state
/// machine
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[non_exhaustive]
#[repr(u32)] // We must use the type that fits in the size of `EntryPoint`
pub enum NodeValidator {
    /// Fungible asset inflation/issue control
    ///
    /// Checks that inflation of a fungible asset produces no more than was
    /// allowed by [`crate::schema::constants::STATE_TYPE_INFLATION_RIGHT`],
    /// i.e. that the sum of all outputs with
    /// [`crate::schema::constants::STATE_TYPE_OWNED_AMOUNT`] and
    /// [`crate::schema::constants::STATE_TYPE_INFLATION_RIGHT`] types is no
    /// more than that value - plus validates bulletproof data.
    ///
    /// Also validates that the sum of the issued asset is equal to the amount
    /// specified in the [`crate::schema::constants::FIELD_TYPE_ISSUED_SUPPLY`]
    /// metadata field
    #[display("fungible-issue")]
    FungibleIssue = 0x02,

    /// NFT/identity transfer control
    ///
    /// Checks that all identities are transferred once and only once, i.e.
    /// that the _number_ of
    /// [`crate::schema::constants::STATE_TYPE_OWNED_DATA`] inputs is equal
    /// to the _number_ of outputs of this type.
    #[display("nft-transfer")]
    IdentityTransfer = 0x11,

    /// NFT asset secondary issue control
    ///
    /// Checks that inflation of a fungible asset produces no more than was
    /// allowed by [`crate::schema::constants::STATE_TYPE_INFLATION_RIGHT`],
    /// i.e. that the sum of all outputs with
    /// [`crate::schema::constants::STATE_TYPE_OWNED_AMOUNT`] type is no more
    /// than that value
    #[display("nft-issue")]
    NftIssue = 0x12,

    /// Proof-of-burn verification
    ///
    /// Currently not implemented in RGBv0 and always validates to TRUE
    #[display("proof-of-burn")]
    ProofOfBurn = 0x20,

    /// Proof-of-reserve verification
    ///
    /// Currently not implemented in RGBv0 and always validates to TRUE
    #[display("proof-of-reserve")]
    ProofOfReserve = 0x21,

    #[display("rights-split")]
    RightsSplit = 0x30,
}

impl FromEntryPoint for NodeValidator {
    /// Constructs [`NodeHandler`] from [`EntryPoint`], or returns `None` if the
    /// provided entry point value does not correspond to any of
    /// the embedded procedures
    fn from_entry_point(entry_point: EntryPoint) -> Option<Self> {
        Some(match entry_point {
            x if x == NodeValidator::FungibleIssue as u32 => {
                NodeValidator::FungibleIssue
            }
            x if x == NodeValidator::IdentityTransfer as u32 => {
                NodeValidator::IdentityTransfer
            }
            x if x == NodeValidator::NftIssue as u32 => NodeValidator::NftIssue,
            x if x == NodeValidator::ProofOfBurn as u32 => {
                NodeValidator::ProofOfBurn
            }
            x if x == NodeValidator::ProofOfReserve as u32 => {
                NodeValidator::ProofOfReserve
            }
            x if x == NodeValidator::RightsSplit as u32 => {
                NodeValidator::RightsSplit
            }
            _ => return None,
        })
    }
}

/// Embedded action handler for generation of blank transitions
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "kebab-case")
)]
#[non_exhaustive]
#[repr(u32)] // We must use the type that fits in the size of `EntryPoint`
pub enum TransitionConstructor {
    /// Generates blank transition transferring all rights from each single
    /// UTXO to another UTXO, one-to-one
    #[display("one-to-one")]
    OneToOne = 0x80,

    /// Generates transition aggregating all rights from all UTXOs into a
    /// single output assigning to a single destination UTXO
    #[display("aggregate")]
    Aggregate = 0x81,
}

impl FromEntryPoint for TransitionConstructor {
    /// Constructs [`GenerateTransitionHandler`] from [`EntryPoint`], or returns
    /// `None` if the provided entry point value does not correspond to any
    /// of the embedded procedures
    fn from_entry_point(entry_point: u32) -> Option<Self> {
        Some(match entry_point {
            x if x == TransitionConstructor::OneToOne as u32 => {
                TransitionConstructor::OneToOne
            }
            x if x == TransitionConstructor::Aggregate as u32 => {
                TransitionConstructor::Aggregate
            }
            _ => return None,
        })
    }
}

mod _strict_encoding {
    use super::*;
    use std::io;
    use strict_encoding::{Error, StrictDecode, StrictEncode};

    impl StrictEncode for NodeValidator {
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            let val = *self as EntryPoint;
            val.strict_encode(e)
        }
    }

    impl StrictDecode for NodeValidator {
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            let entry_point = EntryPoint::strict_decode(d)?;
            NodeValidator::from_entry_point(entry_point).ok_or(
                Error::DataIntegrityError(format!(
                    "Entry point value {} does not correspond to any of known embedded procedures",
                    entry_point
                )))
        }
    }

    impl StrictEncode for AssignmentValidator {
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            let val = *self as EntryPoint;
            val.strict_encode(e)
        }
    }

    impl StrictDecode for AssignmentValidator {
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            let entry_point = EntryPoint::strict_decode(d)?;
            AssignmentValidator::from_entry_point(entry_point).ok_or(
                Error::DataIntegrityError(format!(
                    "Entry point value {} does not correspond to any of known embedded procedures",
                    entry_point
                )))
        }
    }

    impl StrictEncode for TransitionConstructor {
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            let val = *self as EntryPoint;
            val.strict_encode(e)
        }
    }

    impl StrictDecode for TransitionConstructor {
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            let entry_point = EntryPoint::strict_decode(d)?;
            TransitionConstructor::from_entry_point(entry_point).ok_or(
                Error::DataIntegrityError(format!(
                    "Entry point value {} does not correspond to any of known embedded procedures",
                    entry_point
                )))
        }
    }
}

#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
#[repr(u16)]
pub enum HandlerError {
    /// validation operation is not yet implemented in the embedded VM
    NotImplemented = 0,

    /// asset inflation/excessive issue is detected when it is prohibited by
    /// the contract schema rules (this inflation can be both negative, i.e.
    /// deflation, or positive, i.e. true inflation)
    Inflation,

    /// inconsistent schema data
    ///
    /// NB: Generally we do not validate the schema at the level of VM (the
    /// validation must happen before), but in some cases when we retrieve data
    /// and get results which must be prevented by the schema we
    /// report this error.
    ///
    /// Occurrence of this error possible means that RGB library code has a
    /// bug, since schema MUST be validated before any of the VM methods
    /// are called
    #[display("inconsistent schema data")]
    BrokenSchema,

    /// non-equal input and output assignment types are found when type match
    /// is required
    NonEqualTypes,

    /// non-equal state data are found when state equivalence is required
    NonEqualState,

    /// non-equal number of state assignments when assignments are required to
    /// be translated one-to-one in state transition
    NonEqualAssignmentCount,

    /// confidential state data are found in location where state equivalence
    /// must be checked and the provided state commitments do not match
    ConfidentialState,

    /// sum of assigned values overflows schema-allowed bit dimension
    ValueOverflow,

    /// wrong format for byte-encoded data
    DataEncoding,
}

impl NodeValidator {
    pub(self) fn validate(
        &self,
        _node_subtype: NodeSubtype,
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
        _previous_public_rights: &PublicRights,
        _current_public_rights: &PublicRights,
        current_meta: &Metadata,
    ) -> Result<(), HandlerError> {
        match self {
            NodeValidator::FungibleIssue => Self::fungible_issue(
                current_meta,
                previous_owned_rights,
                current_owned_rights,
            ),
            NodeValidator::IdentityTransfer => Self::input_output_count_eq(
                previous_owned_rights,
                current_owned_rights,
            ),
            NodeValidator::NftIssue => Self::nft_issue(
                current_meta,
                previous_owned_rights,
                current_owned_rights,
            ),
            NodeValidator::ProofOfBurn => Self::proof_of_burn(current_meta),
            NodeValidator::ProofOfReserve => {
                Self::proof_of_reserve(current_meta)
            }
            NodeValidator::RightsSplit => Self::input_output_value_eq(
                previous_owned_rights,
                current_owned_rights,
            ),
        }
    }

    fn fungible_issue(
        meta: &Metadata,
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
    ) -> Result<(), HandlerError> {
        let issued = meta.u64(FIELD_TYPE_ISSUED_SUPPLY).into_iter().sum();

        // [SECURITY-CRITICAL]: First we need to validate that we do not issue
        //                      more assets than allowed by our issue rights
        let allowed_inflation: u64 = previous_owned_rights
            .assignments_by_type(STATE_TYPE_INFLATION_RIGHT)
            .as_revealed_state_values()
            .map_err(|_| HandlerError::ConfidentialState)?
            .into_iter()
            .map(|revealed| revealed.value)
            .sum();
        let future_inflation: u64 = current_owned_rights
            .assignments_by_type(STATE_TYPE_INFLATION_RIGHT)
            .as_revealed_state_values()
            .map_err(|_| HandlerError::ConfidentialState)?
            .into_iter()
            .map(|revealed| revealed.value)
            .sum();
        if issued + future_inflation != allowed_inflation {
            return Err(HandlerError::Inflation);
        }

        // [SECURITY-CRITICAL]: Second, we need to make sure that the amount of
        //                      assigned assets are equal to the number of
        //                      issued assets
        let mut inputs = previous_owned_rights
            .assignments_by_type(STATE_TYPE_OWNERSHIP_RIGHT)
            .to_confidential_state_pedersen()
            .into_iter()
            .map(|v| v.commitment)
            .collect::<Vec<_>>();
        let outputs = current_owned_rights
            .assignments_by_type(STATE_TYPE_OWNERSHIP_RIGHT)
            .to_confidential_state_pedersen()
            .into_iter()
            .map(|v| v.commitment)
            .collect();
        // [SECURITY-CRITICAL]: Adding amount that has to be issued as another
        //                      input
        inputs.push(
            value::Revealed {
                value: issued,
                blinding: secp256k1zkp::key::ONE_KEY.into(),
            }
            .commit_conceal()
            .commitment,
        );
        if !value::Confidential::verify_commit_sum(outputs, inputs) {
            return Err(HandlerError::Inflation);
        }

        Ok(())
    }

    fn nft_issue(
        _meta: &Metadata,
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
    ) -> Result<(), HandlerError> {
        let issued = current_owned_rights
            .assignments_by_type(STATE_TYPE_OWNERSHIP_RIGHT)
            .len();

        // [SECURITY-CRITICAL]: We need to validate that we do not issue more
        //                      asset items than allowed by our issue rights
        let allowed_inflation = previous_owned_rights
            .assignments_by_type(STATE_TYPE_INFLATION_RIGHT)
            .as_revealed_state_values()
            .map_err(|_| HandlerError::ConfidentialState)?
            .len();

        let future_inflation = current_owned_rights
            .assignments_by_type(STATE_TYPE_INFLATION_RIGHT)
            .as_revealed_state_values()
            .map_err(|_| HandlerError::ConfidentialState)?
            .len();

        if issued + future_inflation != allowed_inflation {
            return Err(HandlerError::Inflation);
        }

        Ok(())
    }

    fn proof_of_burn(meta: &Metadata) -> Result<(), HandlerError> {
        let format = meta
            .u8(FIELD_TYPE_HISTORY_PROOF_FORMAT)
            .first()
            .copied()
            .ok_or(HandlerError::BrokenSchema)?;

        match schema::HistoryProofFormat::from_u8(format)
            .ok_or(HandlerError::BrokenSchema)?
        {
            schema::HistoryProofFormat::ProofAbsent => Ok(()),
            _ => Err(HandlerError::NotImplemented),
        }
    }

    fn proof_of_reserve(meta: &Metadata) -> Result<(), HandlerError> {
        let descriptor_data = meta
            .bytes(FIELD_TYPE_LOCK_DESCRIPTOR)
            .first()
            .cloned()
            .ok_or(HandlerError::BrokenSchema)?;
        // let _descriptor =
        //     descriptors::Expanded::strict_deserialize(descriptor_data)
        //        .map_err(|_| HandlerError::DataEncoding)?;
        // TODO #81: Implement blockchain access for the VM
        return Err(HandlerError::NotImplemented);
    }

    fn input_output_value_eq(
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
    ) -> Result<(), HandlerError> {
        let prev = previous_owned_rights.as_inner();
        let curr = current_owned_rights.as_inner();
        if prev.len() != curr.len() {
            return Err(HandlerError::NonEqualTypes);
        }

        for ((prev_type, prev_assignments), (curr_type, curr_assignments)) in
            prev.into_iter().zip(curr)
        {
            if prev_type != curr_type {
                return Err(HandlerError::NonEqualTypes);
            }
            if prev_assignments.state_type() != curr_assignments.state_type() {
                return Err(HandlerError::BrokenSchema);
            }
            if prev_assignments.len() != curr_assignments.len() {
                return Err(HandlerError::NonEqualAssignmentCount);
            }

            match (prev_assignments, curr_assignments) {
                (
                    AssignmentVec::Declarative(_),
                    AssignmentVec::Declarative(_),
                ) => {
                    // This is valid, so passing validation step
                }
                (
                    AssignmentVec::DiscreteFiniteField(prev),
                    AssignmentVec::DiscreteFiniteField(curr),
                ) => {
                    for (prev, curr) in prev.into_iter().zip(curr.into_iter()) {
                        if let (Some(prev), Some(curr)) =
                            (prev.as_revealed_state(), curr.as_revealed_state())
                        {
                            if prev.value != curr.value {
                                return Err(HandlerError::NonEqualState);
                            }
                        } else if prev.to_confidential_state().commitment
                            != curr.to_confidential_state().commitment
                        {
                            return Err(HandlerError::ConfidentialState);
                        }
                    }
                }
                (
                    AssignmentVec::CustomData(prev),
                    AssignmentVec::CustomData(curr),
                ) => {
                    for (prev, curr) in prev.into_iter().zip(curr.into_iter()) {
                        if prev.to_confidential_state()
                            != curr.to_confidential_state()
                        {
                            return Err(HandlerError::NonEqualState);
                        }
                    }
                }
                (_, _) => unreachable!(
                    "assignment formats are equal as checked above"
                ),
            }
        }

        Ok(())
    }

    fn input_output_count_eq(
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
    ) -> Result<(), HandlerError> {
        let prev = previous_owned_rights.as_inner();
        let curr = current_owned_rights.as_inner();
        if prev.len() != curr.len() {
            return Err(HandlerError::NonEqualTypes);
        }

        for ((prev_type, prev_assignments), (curr_type, curr_assignments)) in
            prev.into_iter().zip(curr)
        {
            if prev_type != curr_type {
                return Err(HandlerError::NonEqualTypes);
            }
            if prev_assignments.len() != curr_assignments.len() {
                return Err(HandlerError::NonEqualAssignmentCount);
            }
        }

        Ok(())
    }
}

impl AssignmentValidator {
    pub(self) fn validate(
        &self,
        _node_subtype: NodeSubtype,
        _owned_rights_type: schema::OwnedRightType,
        previous_state: &AssignmentVec,
        current_state: &AssignmentVec,
        _current_meta: &Metadata,
    ) -> Result<(), HandlerError> {
        match self {
            AssignmentValidator::FungibleNoInflation => {
                Self::validate_pedersen_sum(previous_state, current_state)
            }
            AssignmentValidator::NoOverflow => {
                Self::validate_no_overflow(current_state)
            }
        }
    }

    pub(self) fn validate_pedersen_sum(
        previous_state: &AssignmentVec,
        current_state: &AssignmentVec,
    ) -> Result<(), HandlerError> {
        let inputs = previous_state
            .to_confidential_state_pedersen()
            .into_iter()
            .map(|v| v.commitment)
            .collect();
        let outputs = current_state
            .to_confidential_state_pedersen()
            .into_iter()
            .map(|v| v.commitment)
            .collect();

        // [CONSENSUS-CRITICAL]:
        // [SECURITY-CRITICAL]: Validation of the absence of inflation of the
        //                      asset
        // NB: Bulletproofs are validated by the schema for all state which
        //     contains bulletproof data
        if !value::Confidential::verify_commit_sum(inputs, outputs) {
            Err(HandlerError::Inflation)
        } else {
            Ok(())
        }
    }

    pub(self) fn validate_no_overflow(
        current_state: &AssignmentVec,
    ) -> Result<(), HandlerError> {
        current_state
            .as_revealed_state_values()
            .map_err(|_| HandlerError::ConfidentialState)?
            .into_iter()
            .map(|v| v.value)
            .try_fold(0u64, |sum, value| sum.checked_add(value))
            .ok_or(HandlerError::ValueOverflow)
            .map(|_| ())
    }
}

impl TransitionConstructor {
    pub(self) fn construct(
        &self,
        _inputs: &BTreeSet<NodeOutput>,
        _outpoints: &BTreeSet<OutPoint>,
    ) -> Result<Transition, HandlerError> {
        // TODO #17: Implement blank transitions
        return Err(HandlerError::NotImplemented);
    }
}

#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
pub enum InitError {
    /// Byte code for the embedded virtual machine must be an empty string,
    /// otherwise RGB schema using embedded virtual machine must be considered
    /// invalid
    ByteCodeNotEmpty,

    /// The entry point {1} for action {0}, which for embedded machine must
    /// represent a known embedded procedure id, does not match any of
    /// existing procedures
    InvalidActionHandler(Action, EntryPoint),
}

#[derive(Debug, Default)]
pub struct EmbeddedVm {
    pub(self) validate_genesis_handler: Option<NodeValidator>,
    pub(self) validate_transition_handler: Option<NodeValidator>,
    pub(self) validate_extension_handler: Option<NodeValidator>,
    pub(self) validate_assignment_handler: Option<AssignmentValidator>,
    pub(self) blank_transition_handler: Option<TransitionConstructor>,
}

impl VmApi for EmbeddedVm {
    fn with(
        byte_code: &[u8],
        abi: &BTreeMap<impl Into<Action> + Copy, EntryPoint>,
    ) -> Result<Self, validation::Failure>
    where
        Self: Sized,
    {
        // Check that byte_code is empty; otherwise return error
        if !byte_code.is_empty() {
            return Err(validation::Failure::ScriptCodeMustBeEmpty);
        }

        let mut vm = EmbeddedVm::default();

        for (action, id) in abi {
            let action = (*action).into();
            let err = validation::Failure::WrongEntryPoint(*id);
            match action {
                Action::ValidateGenesis => {
                    vm.validate_genesis_handler =
                        Some(NodeValidator::from_entry_point(*id).ok_or(err)?);
                }
                Action::ValidateTransition => {
                    vm.validate_transition_handler =
                        Some(NodeValidator::from_entry_point(*id).ok_or(err)?);
                }
                Action::ValidateExtension => {
                    vm.validate_extension_handler =
                        Some(NodeValidator::from_entry_point(*id).ok_or(err)?);
                }
                Action::ValidateAssignment => {
                    vm.validate_assignment_handler = Some(
                        AssignmentValidator::from_entry_point(*id)
                            .ok_or(err)?,
                    );
                }
                Action::BlankTransition => {
                    vm.blank_transition_handler = Some(
                        TransitionConstructor::from_entry_point(*id)
                            .ok_or(err)?,
                    );
                }
            }
        }

        Ok(vm)
    }

    fn validate_node(
        &self,
        node_id: NodeId,
        node_subtype: schema::NodeSubtype,
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
        previous_public_rights: &PublicRights,
        current_public_rights: &PublicRights,
        current_meta: &Metadata,
    ) -> Result<(), validation::Failure> {
        let validator = match node_subtype {
            NodeSubtype::Genesis => self.validate_genesis_handler,
            NodeSubtype::StateTransition(_) => self.validate_transition_handler,
            NodeSubtype::StateExtension(_) => self.validate_extension_handler,
        };
        Ok(validator
            .map(|handler| {
                handler.validate(
                    node_subtype,
                    previous_owned_rights,
                    current_owned_rights,
                    previous_public_rights,
                    current_public_rights,
                    current_meta,
                )
            })
            .transpose()
            .map_err(|err| {
                validation::Failure::ScriptFailure(node_id, err as u8)
            })?
            .unwrap_or_default())
    }

    fn validate_assignment(
        &self,
        node_id: NodeId,
        node_subtype: NodeSubtype,
        owned_rights_type: schema::OwnedRightType,
        previous_state: &AssignmentVec,
        current_state: &AssignmentVec,
        current_meta: &Metadata,
    ) -> Result<(), validation::Failure> {
        Ok(self
            .validate_assignment_handler
            .map(|handler| {
                handler.validate(
                    node_subtype,
                    owned_rights_type,
                    previous_state,
                    current_state,
                    current_meta,
                )
            })
            .transpose()
            .map_err(|err| {
                validation::Failure::ScriptFailure(node_id, err as u8)
            })?
            .unwrap_or_default())
    }

    fn blank_transition(
        &self,
        node_id: NodeId,
        inputs: &BTreeSet<NodeOutput>,
        outpoints: &BTreeSet<OutPoint>,
    ) -> Result<Transition, validation::Failure> {
        Ok(self
            .blank_transition_handler
            .map(|handler| handler.construct(inputs, outpoints))
            .transpose()
            .map_err(|err| {
                validation::Failure::ScriptFailure(node_id, err as u8)
            })?
            .unwrap_or_default())
    }
}
