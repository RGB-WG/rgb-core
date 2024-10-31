// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bp::dbc::opret::{OpretError, OpretProof};
use bp::dbc::tapret::TapretProof;
use bp::dbc::Method;
use bp::{dbc, Tx};
use commit_verify::mpc::Commitment;
use commit_verify::{mpc, ConvolveVerifyError, EmbedVerifyError};
use strict_encoding::{StrictDeserialize, StrictDumb, StrictSerialize};

use crate::LIB_NAME_RGB_LOGIC;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(doc_comments)]
pub enum DbcError {
    /// transaction doesn't contain OP_RETURN output.
    NoOpretOutput,

    /// first OP_RETURN output inside the transaction already contains some
    /// data.
    InvalidOpretScript,

    /// commitment doesn't match the message.
    CommitmentMismatch,

    /// the proof is invalid and the commitment can't be verified since the
    /// original container can't be restored from it.
    UnrestorableProof,

    /// the proof does not match to the proof generated for the same message
    /// during the verification.
    ProofMismatch,

    /// the message is invalid since a valid commitment to it can't be created.
    ImpossibleMessage,

    /// the proof is invalid and the commitment can't be verified.
    InvalidProof,
}

#[derive(Clone, Eq, PartialEq, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC, tags = custom, dumb = Self::Tapret(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
pub enum DbcProof {
    #[from]
    #[strict_type(tag = 0x01)]
    Tapret(TapretProof),

    #[from]
    #[strict_type(tag = 0x02)]
    Opret(OpretProof),
}

impl StrictSerialize for DbcProof {}
impl StrictDeserialize for DbcProof {}

impl dbc::Proof for DbcProof {
    type Error = DbcError;

    fn method(&self) -> Method {
        match self {
            DbcProof::Tapret(_) => Method::TapretFirst,
            DbcProof::Opret(_) => Method::OpretFirst,
        }
    }

    fn verify(&self, msg: &Commitment, tx: &Tx) -> Result<(), Self::Error> {
        match self {
            DbcProof::Tapret(tapret) => tapret.verify(msg, tx).map_err(|err| match err {
                ConvolveVerifyError::CommitmentMismatch => DbcError::CommitmentMismatch,
                ConvolveVerifyError::ImpossibleMessage => DbcError::ImpossibleMessage,
                ConvolveVerifyError::InvalidProof => DbcError::InvalidProof,
            }),
            DbcProof::Opret(opret) => opret.verify(msg, tx).map_err(|err| match err {
                EmbedVerifyError::CommitmentMismatch => DbcError::CommitmentMismatch,
                EmbedVerifyError::InvalidMessage(OpretError::NoOpretOutput) => {
                    DbcError::NoOpretOutput
                }
                EmbedVerifyError::InvalidMessage(OpretError::InvalidOpretScript) => {
                    DbcError::InvalidOpretScript
                }
                EmbedVerifyError::InvalidProof => DbcError::UnrestorableProof,
                EmbedVerifyError::ProofMismatch => DbcError::ProofMismatch,
            }),
        }
    }
}

/// Anchor which DBC proof is either Tapret or Opret.
pub type EAnchor<P = mpc::MerkleProof> = dbc::Anchor<P, DbcProof>;
