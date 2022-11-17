// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

#![allow(dead_code)]

//! Implementation of the embedded state machine

use amplify::Wrapper;
use commit_verify::CommitConceal;

use super::Validate;
use crate::{
    schema, validation, value, Metadata, NodeId, NodeSubtype, OwnedRights, PublicRights,
    TypedAssignments,
};

/// Constants which are common to different schemata and can be recognized
/// by the software even if the specific schema is unknown, since this type ids
/// are reserved to a specific semantic meaning
///
/// These constants are also used by embedded validation procedures representing
/// standard metadata fields, state and transition types analyzed by them
pub mod constants {
    /// Ticker of the asset
    pub const FIELD_TYPE_TICKER: u16 = 0x00;

    /// Contract or asset name
    pub const FIELD_TYPE_NAME: u16 = 0x01;

    /// Ricardian contract text
    pub const FIELD_TYPE_CONTRACT_TEXT: u16 = 0x02;

    /// Decimal precision for some sort of amount values used in a contract
    pub const FIELD_TYPE_PRECISION: u16 = 0x03;

    /// Timestamp used in genesis to indicate moment of contract creation
    pub const FIELD_TYPE_TIMESTAMP: u16 = 0x04;

    /// Generic comment about the contract or a state transitions
    pub const FIELD_TYPE_COMMENTARY: u16 = 0x05;

    /// Data attached to a state transition in binary format
    pub const FIELD_TYPE_DATA: u16 = 0x10;

    /// Format of the attached data, schema-specific
    pub const FIELD_TYPE_DATA_FORMAT: u16 = 0x11;

    /// [`FieldType`] that is used by validation procedures checking the issued
    /// supply & inflation
    pub const FIELD_TYPE_ISSUED_SUPPLY: u16 = 0xA0;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// burn. Must contain amount of the burned supply, expressed as
    /// revealed [`crate::value::Revealed`] data
    pub const FIELD_TYPE_BURN_SUPPLY: u16 = 0xB0;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// burn. Must contain [`bitcoin::OutPoint`] consensus-encoded data.
    pub const FIELD_TYPE_BURN_UTXO: u16 = 0xB1;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// burn. Must contain binary data ([`crate::data::Revealed::Bytes`])
    pub const FIELD_TYPE_HISTORY_PROOF: u16 = 0xB2;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// burn. Must contain format of the provided proofs defined in
    /// [`HistoryProofFormat`]
    pub const FIELD_TYPE_HISTORY_PROOF_FORMAT: u16 = 0xB3;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// reserves. Must contain [`wallet::descriptor::Expanded`] strict encoded
    /// data.
    pub const FIELD_TYPE_LOCK_DESCRIPTOR: u16 = 0xC0;

    /// [`FieldType`] that is used by validation procedures checking proofs of
    /// reserves. Must contain [`bitcoin::OutPoint`] consensus-encoded data
    pub const FIELD_TYPE_LOCK_UTXO: u16 = 0xC1;

    /// Description of the asset
    pub const FIELD_TYPE_DESCRIPTION: u16 = 0xC2;

    /// Parent ID of the asset
    pub const FIELD_TYPE_PARENT_ID: u16 = 0xC3;

    // --------

    /// Renomination of the contract parameters
    pub const STATE_TYPE_RENOMINATION_RIGHT: u16 = 0x01;

    /// [`OwnedRightType`] that is used by the validation procedures checking
    /// asset inflation (applies to both fungible and non-fungible assets)
    pub const STATE_TYPE_INFLATION_RIGHT: u16 = 0xA0;

    /// [`OwnedRightType`] that is used by validation procedures checking for
    /// the equivalence relations between previous and new asset ownership
    /// (applies to both fungible and non-fungible assets).
    ///
    /// NB: STATE_TYPE_OWNERSHIP_RIGHT + N where N = 1..9 are reserved for
    ///     custom forms of ownership (like "engraved ownership" for NFT tokens)
    pub const STATE_TYPE_OWNERSHIP_RIGHT: u16 = 0xA1;

    /// Right to engrave an NFT token
    pub const STATE_TYPE_ENGRAVING_RIGHT: u16 = 0xA2;

    /// Right to define epochs of asset replacement
    pub const STATE_TYPE_ISSUE_EPOCH_RIGHT: u16 = 0xAA;

    /// Right to replace some of the state issued under the contract
    pub const STATE_TYPE_ISSUE_REPLACEMENT_RIGHT: u16 = 0xAB;

    /// Right to replace some of the state issued under the contract
    pub const STATE_TYPE_ISSUE_REVOCATION_RIGHT: u16 = 0xAC;

    // --------

    /// Transitions transferring ownership of a homomorphic value
    pub const TRANSITION_TYPE_VALUE_TRANSFER: u16 = 0x00;

    /// Transitions transferring ownership of a non-fungible identifiable state
    pub const TRANSITION_TYPE_IDENTITY_TRANSFER: u16 = 0x01;

    /// Transition performing renomination of contract metadata
    pub const TRANSITION_TYPE_RENOMINATION: u16 = 0x1010;

    /// [`TransitionType`] that is used by the validation procedures checking
    /// asset inflation (applies to both fungible and non-fungible assets)
    pub const TRANSITION_TYPE_ISSUE_FUNGIBLE: u16 = 0x10A0;

    /// Transition that defines certain grouping of other issue-related
    /// operations
    pub const TRANSITION_TYPE_ISSUE_EPOCH: u16 = 0x10A1;

    /// Transition burning some of the issued contract state.
    ///
    /// NB: It is not the same as [`TRANSITION_TYPE_RIGHTS_TERMINATION`], which
    /// terminates ability to utilize some rights (but not the state)
    pub const TRANSITION_TYPE_ISSUE_BURN: u16 = 0x10A2;

    /// Transition replacing some of the previously issued state with the new
    /// one
    pub const TRANSITION_TYPE_ISSUE_REPLACE: u16 = 0x10A3;

    /// Transition engraving an NFT token
    pub const TRANSITION_TYPE_ENGRAVING: u16 = 0x10A4;

    /// Transition issuing NFT token
    pub const TRANSITION_TYPE_ISSUE_NFT: u16 = 0x10AF;

    /// Transition performing split of rights assigned to the same UTXO by
    /// a mistake
    pub const TRANSITION_TYPE_RIGHTS_SPLIT: u16 = 0x8000;

    /// Transition making certain rights void without executing the right itself
    pub const TRANSITION_TYPE_RIGHTS_TERMINATION: u16 = 0x8001;
}
use constants::*;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
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

    /// incorrect field value
    FieldValue,
}

/// Embedded action handlers for contract nodes processed by the embedded state
/// machine
mod node {
    use super::*;

    pub fn validate(
        node_subtype: NodeSubtype,
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
        _previous_public_rights: &PublicRights,
        _current_public_rights: &PublicRights,
        current_meta: &Metadata,
    ) -> Result<(), HandlerError> {
        for (field_type, fields) in current_meta {
            for data in fields {
                meta::validate(*field_type, data)?;
            }
        }

        match node_subtype {
            NodeSubtype::StateTransition(TRANSITION_TYPE_ISSUE_FUNGIBLE) => {
                fungible_issue(current_meta, previous_owned_rights, current_owned_rights)
            }
            NodeSubtype::StateTransition(TRANSITION_TYPE_VALUE_TRANSFER) => Ok(()),
            NodeSubtype::StateTransition(TRANSITION_TYPE_IDENTITY_TRANSFER) => {
                input_output_count_eq(previous_owned_rights, current_owned_rights)
            }
            NodeSubtype::StateTransition(TRANSITION_TYPE_ISSUE_NFT) => {
                nft_issue(current_meta, previous_owned_rights, current_owned_rights)
            }
            NodeSubtype::StateTransition(TRANSITION_TYPE_ISSUE_BURN)
            | NodeSubtype::StateTransition(TRANSITION_TYPE_ISSUE_REPLACE) => {
                proof_of_burn(current_meta)
            }
            NodeSubtype::StateTransition(TRANSITION_TYPE_RIGHTS_SPLIT) => {
                input_output_value_eq(previous_owned_rights, current_owned_rights)
            }
            // NodeSubtype::StateTransition(..) => Self::proof_of_reserve(current_meta),
            _ => Ok(()),
        }
    }

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

    /// NFT asset secondary issue control
    ///
    /// Checks that inflation of a fungible asset produces no more than was
    /// allowed by [`crate::schema::constants::STATE_TYPE_INFLATION_RIGHT`],
    /// i.e. that the sum of all outputs with
    /// [`crate::schema::constants::STATE_TYPE_OWNED_AMOUNT`] type is no more
    /// than that value
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

    /// Proof-of-burn verification
    ///
    /// Currently not implemented in RGBv0 and always validates to FALSE
    fn proof_of_burn(_meta: &Metadata) -> Result<(), HandlerError> {
        Err(HandlerError::NotImplemented)
    }

    /// Proof-of-reserve verification
    ///
    /// Currently not implemented in RGBv0 and always validates to FALSE
    fn proof_of_reserve(meta: &Metadata) -> Result<(), HandlerError> {
        let _descriptor_data = meta
            .bytes(FIELD_TYPE_LOCK_DESCRIPTOR)
            .first()
            .cloned()
            .ok_or(HandlerError::BrokenSchema)?;
        // let _descriptor =
        //     descriptors::Expanded::confined_deserialize(descriptor_data)
        //        .map_err(|_| HandlerError::DataEncoding)?;
        // TODO #81: Implement blockchain access for the VM
        Err(HandlerError::NotImplemented)
    }

    /// Rights split.
    ///
    /// We must allocate exactly one or none rights per each right used as input
    /// (i.e. closed seal); plus we need to control that sum of inputs is equal
    /// to the sum of outputs for each of state types having assigned
    /// confidential amounts
    fn input_output_value_eq(
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
    ) -> Result<(), HandlerError> {
        let prev = previous_owned_rights.as_inner();
        let curr = current_owned_rights.as_inner();
        if prev.len() != curr.len() {
            return Err(HandlerError::NonEqualTypes);
        }

        for ((prev_type, prev_assignments), (curr_type, curr_assignments)) in prev.iter().zip(curr)
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
                (TypedAssignments::Void(_), TypedAssignments::Void(_)) => {
                    // This is valid, so passing validation step
                }
                (TypedAssignments::Value(prev), TypedAssignments::Value(curr)) => {
                    for (prev, curr) in prev.iter().zip(curr.iter()) {
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
                (TypedAssignments::Data(prev), TypedAssignments::Data(curr)) => {
                    for (prev, curr) in prev.iter().zip(curr.iter()) {
                        if prev.to_confidential_state() != curr.to_confidential_state() {
                            return Err(HandlerError::NonEqualState);
                        }
                    }
                }
                (_, _) => unreachable!("assignment formats are equal as checked above"),
            }
        }

        Ok(())
    }

    /// NFT/identity transfer control
    ///
    /// Checks that all identities are transferred once and only once, i.e.
    /// that the _number_ of
    /// [`crate::schema::constants::STATE_TYPE_OWNED_DATA`] inputs is equal
    /// to the _number_ of outputs of this type.
    fn input_output_count_eq(
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
    ) -> Result<(), HandlerError> {
        let prev = previous_owned_rights.as_inner();
        let curr = current_owned_rights.as_inner();
        if prev.len() != curr.len() {
            return Err(HandlerError::NonEqualTypes);
        }

        for ((prev_type, prev_assignments), (curr_type, curr_assignments)) in prev.iter().zip(curr)
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

/// Embedded action handlers for state assignments processed by the embedded
/// state machine
mod assignment {
    use super::*;

    pub fn validate(
        node_subtype: NodeSubtype,
        owned_rights_type: schema::OwnedRightType,
        previous_state: &TypedAssignments,
        current_state: &TypedAssignments,
        _current_meta: &Metadata,
    ) -> Result<(), HandlerError> {
        match (node_subtype, owned_rights_type) {
            (
                NodeSubtype::StateTransition(TRANSITION_TYPE_VALUE_TRANSFER),
                STATE_TYPE_OWNERSHIP_RIGHT,
            ) => validate_pedersen_sum(previous_state, current_state),
            (
                NodeSubtype::StateTransition(TRANSITION_TYPE_ISSUE_FUNGIBLE) | NodeSubtype::Genesis,
                STATE_TYPE_INFLATION_RIGHT,
            ) => validate_no_overflow(current_state),
            _ => Ok(()),
        }
    }

    /// Non-inflationary fungible asset transfer control
    ///
    /// Checks that the sum of pedersen commitments in the inputs of type
    /// [`crate::schema::constants::STATE_TYPE_OWNED_AMOUNT`] equal to the sum
    /// of the outputs of the same type, plus validates bulletproof data
    fn validate_pedersen_sum(
        previous_state: &TypedAssignments,
        current_state: &TypedAssignments,
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

    /// Control that multiple rights assigning additive state value do not allow
    /// maximum allowed bit dimensionality
    fn validate_no_overflow(current_state: &TypedAssignments) -> Result<(), HandlerError> {
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

mod meta {
    use super::*;
    use crate::data;
    use crate::schema::FieldType;

    /// Validates that field value is withing the allowed ranges.
    pub fn validate(field_type: FieldType, value: &data::Revealed) -> Result<(), HandlerError> {
        match (field_type, value) {
            (FIELD_TYPE_TICKER, data::Revealed::AsciiString(s))
                if s.is_empty() || s.len() > 8 || s.to_ascii_uppercase() != s.to_string() =>
            {
                Err(HandlerError::FieldValue)
            }
            (FIELD_TYPE_NAME, data::Revealed::AsciiString(s)) if s.is_empty() || s.len() > 256 => {
                Err(HandlerError::FieldValue)
            }
            (FIELD_TYPE_PRECISION, data::Revealed::U8(s)) if *s > 18 => {
                Err(HandlerError::FieldValue)
            }
            (FIELD_TYPE_TIMESTAMP, data::Revealed::I64(s)) if *s < 1602340666 => {
                Err(HandlerError::FieldValue)
            }
            (_, _) => Ok(()),
        }
    }
}

#[derive(Debug, Default)]
pub struct EmbeddedVm;

impl EmbeddedVm {
    pub fn new() -> EmbeddedVm { EmbeddedVm }
}

impl Validate for EmbeddedVm {
    fn validate(
        &self,
        node_id: NodeId,
        node_subtype: NodeSubtype,
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
        previous_public_rights: &PublicRights,
        current_public_rights: &PublicRights,
        current_meta: &Metadata,
    ) -> Result<(), validation::Failure> {
        node::validate(
            node_subtype,
            previous_owned_rights,
            current_owned_rights,
            previous_public_rights,
            current_public_rights,
            current_meta,
        )
        .map_err(|_| validation::Failure::ScriptFailure(node_id))?;

        for (state_type, current_state) in current_owned_rights.iter() {
            let previous_state = previous_owned_rights.assignments_by_type(*state_type);
            assignment::validate(
                node_subtype,
                *state_type,
                previous_state,
                current_state,
                current_meta,
            )
            .map_err(|_| validation::Failure::ScriptFailure(node_id))?;
        }

        Ok(())
    }
}
