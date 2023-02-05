// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2023 Dr Maxim Orlovsky. All rights reserved.
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

use bp::dbc::Anchor;
use commit_verify::mpc;

use crate::{reveal, ContractId, MergeReveal};

pub trait ConcealAnchors {
    fn conceal_anchors_except(
        &mut self,
        contracts: impl AsRef<[ContractId]>,
    ) -> Result<usize, mpc::LeafNotKnown>;
}

impl ConcealAnchors for Anchor<mpc::MerkleBlock> {
    fn conceal_anchors_except(
        &mut self,
        contracts: impl AsRef<[ContractId]>,
    ) -> Result<usize, mpc::LeafNotKnown> {
        let protocols = contracts
            .as_ref()
            .iter()
            .copied()
            .map(mpc::ProtocolId::from)
            .collect::<Vec<_>>();
        self.conceal_except(protocols)
    }
}

impl MergeReveal for Anchor<mpc::MerkleBlock> {
    fn merge_reveal(self, other: Self) -> Result<Self, reveal::Error> {
        self.merge_reveal(other).map_err(reveal::Error::from)
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use bitcoin::consensus::deserialize;
    use bitcoin::util::psbt::PartiallySignedTransaction;
    use strict_encoding::StrictDecode;

    use super::*;
    use crate::contract::{Genesis, Node};
    use crate::NodeId;

    static GENESIS: [u8; 2447] = include!("../../test/genesis.in");

    static PSBT: [u8; 462] = include!("../../test/test_transaction.psbt");

    #[test]
    #[ignore]
    fn test_psbt() {
        // Create some dummy NodeId and ContractId for the test
        let genesis = Genesis::strict_decode(&GENESIS[..]).unwrap();

        let contract_id = genesis.contract_id();

        let node_id = genesis.node_id();

        // Get the test psbt
        let source_psbt: PartiallySignedTransaction = deserialize(&PSBT[..]).unwrap();

        // Copy witness psbt for future assertion
        let witness_psbt = source_psbt.clone();

        // Create the transition map for commitment
        let mut map: BTreeMap<ContractId, NodeId> = BTreeMap::new();
        map.insert(contract_id, node_id);

        // Check number of output remains same
        assert_eq!(source_psbt.unsigned_tx.output.len(), witness_psbt.unsigned_tx.output.len());

        // Check output values remains unchanged
        assert_eq!(
            source_psbt.unsigned_tx.output[0].value,
            witness_psbt.unsigned_tx.output[0].value
        );
        assert_eq!(
            source_psbt.unsigned_tx.output[1].value,
            witness_psbt.unsigned_tx.output[1].value
        );
    }
}
