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

use std::cmp::Ordering;

use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::dbc::Anchor;
use commit_verify::mpc;
use strict_encoding::StrictDumb;

use crate::{BundleId, ContractId, WitnessOrd, XWitnessId, LIB_NAME_RGB};

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Tapret(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
pub enum AnchorSet<P: mpc::Proof + StrictDumb = mpc::MerkleProof> {
    #[strict_type(tag = 0x01)]
    Tapret(Anchor<P, TapretProof>),
    #[strict_type(tag = 0x02)]
    Opret(Anchor<P, OpretProof>),
}

impl<P: mpc::Proof + StrictDumb> AnchorSet<P> {
    pub fn mpc_proof(&self) -> &P {
        match self {
            AnchorSet::Tapret(Anchor {
                mpc_proof,
                dbc_proof: _,
                _method,
            }) |
            AnchorSet::Opret(Anchor {
                mpc_proof,
                dbc_proof: _,
                _method,
            }) => mpc_proof,
        }
    }
}

impl AnchorSet<mpc::MerkleProof> {
    pub fn to_merkle_block(
        &self,
        contract_id: ContractId,
        bundle_id: BundleId,
    ) -> Result<AnchorSet<mpc::MerkleBlock>, mpc::InvalidProof> {
        self.clone().into_merkle_block(contract_id, bundle_id)
    }

    pub fn into_merkle_block(
        self,
        contract_id: ContractId,
        bundle_id: BundleId,
    ) -> Result<AnchorSet<mpc::MerkleBlock>, mpc::InvalidProof> {
        match self {
            AnchorSet::Tapret(anchor) => anchor
                .into_merkle_block(contract_id, bundle_id)
                .map(AnchorSet::Tapret),
            AnchorSet::Opret(anchor) => anchor
                .into_merkle_block(contract_id, bundle_id)
                .map(AnchorSet::Opret),
        }
    }
}

impl AnchorSet<mpc::MerkleBlock> {
    pub fn known_bundle_ids(&self) -> impl Iterator<Item = (BundleId, ContractId)> + '_ {
        self.mpc_proof()
            .to_known_message_map()
            .into_iter()
            .map(|(p, m)| (m.into(), p.into()))
    }

    pub fn to_merkle_proof(
        &self,
        contract_id: ContractId,
    ) -> Result<AnchorSet<mpc::MerkleProof>, mpc::LeafNotKnown> {
        self.clone().into_merkle_proof(contract_id)
    }

    pub fn into_merkle_proof(
        self,
        contract_id: ContractId,
    ) -> Result<AnchorSet<mpc::MerkleProof>, mpc::LeafNotKnown> {
        match self {
            AnchorSet::Tapret(anchor) => {
                anchor.into_merkle_proof(contract_id).map(AnchorSet::Tapret)
            }
            AnchorSet::Opret(anchor) => anchor.into_merkle_proof(contract_id).map(AnchorSet::Opret),
        }
    }
}

/// Txid and height information ordered according to the RGB consensus rules.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display("{witness_id}/{witness_ord}")]
pub struct WitnessAnchor {
    pub witness_ord: WitnessOrd,
    pub witness_id: XWitnessId,
}

impl PartialOrd for WitnessAnchor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for WitnessAnchor {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        match self.witness_ord.cmp(&other.witness_ord) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => self.witness_id.cmp(&other.witness_id),
        }
    }
}

impl WitnessAnchor {
    pub fn from_mempool(witness_id: XWitnessId) -> Self {
        WitnessAnchor {
            witness_ord: WitnessOrd::OffChain,
            witness_id,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(lowercase)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
pub enum Layer1 {
    #[strict_type(dumb)]
    Bitcoin = 0,
    Liquid = 1,
}
