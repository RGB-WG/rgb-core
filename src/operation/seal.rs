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

use core::fmt::Debug;
use std::hash::Hash;

use bc::Txid;
use commit_verify::Conceal;
pub use seals::txout::TxoSeal;
use seals::txout::{ChainBlindSeal, ExplicitSeal, SingleBlindSeal};
pub use seals::SecretSeal;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

pub type GenesisSeal = SingleBlindSeal;
pub type GraphSeal = ChainBlindSeal;

pub type OutputSeal = ExplicitSeal<Txid>;

pub trait ExposedSeal:
    Debug
    + StrictDumb
    + StrictEncode
    + StrictDecode
    + Eq
    + Ord
    + Copy
    + Hash
    + TxoSeal
    + Conceal<Concealed = SecretSeal>
{
    #[inline]
    fn to_output_seal(self) -> Option<OutputSeal> {
        let outpoint = self.outpoint()?;
        Some(ExplicitSeal::new(outpoint))
    }

    fn to_output_seal_or_default(self, witness_id: Txid) -> OutputSeal {
        self.to_output_seal()
            .unwrap_or(ExplicitSeal::new(self.outpoint_or(witness_id)))
    }
}

impl ExposedSeal for GraphSeal {}

impl ExposedSeal for GenesisSeal {}

#[cfg(test)]
mod test {
    use amplify::hex::FromHex;
    use bc::Vout;
    use seals::txout::{BlindSeal, TxPtr};

    use super::*;

    #[test]
    fn secret_seal_is_sha256d() {
        let reveal = BlindSeal {
            blinding: 54683213134637,
            txid: TxPtr::Txid(
                Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839")
                    .unwrap(),
            ),
            vout: Vout::from(2),
        };
        let secret = reveal.to_secret_seal();
        assert_eq!(
            secret.to_string(),
            "utxob:nBRVm39A-ioJydHE-ug2d90m-aZyfPI0-MCc0ZNM-oMXMs2O-opKQ7"
        );
        assert_eq!(reveal.to_secret_seal(), reveal.conceal())
    }
}
