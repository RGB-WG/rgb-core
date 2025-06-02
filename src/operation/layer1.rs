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

use std::str::FromStr;

use bc::BlockHash;
use strict_encoding::{StrictDecode, StrictEncode, StrictType};

use crate::LIB_NAME_RGB_COMMIT;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
#[derive(Default)]
pub enum ChainNet {
    BitcoinMainnet = 0,
    BitcoinTestnet3 = 1,
    #[default]
    BitcoinTestnet4 = 2,
    BitcoinSignet = 3,
    BitcoinRegtest = 4,
    LiquidMainnet = 5,
    LiquidTestnet = 6,
}

impl ChainNet {
    pub fn prefix(&self) -> &str {
        match self {
            ChainNet::BitcoinMainnet => "bc",
            ChainNet::BitcoinTestnet3 => "tb3",
            ChainNet::BitcoinTestnet4 => "tb4",
            ChainNet::BitcoinRegtest => "bcrt",
            ChainNet::BitcoinSignet => "sb",
            ChainNet::LiquidMainnet => "lq",
            ChainNet::LiquidTestnet => "tl",
        }
    }

    pub fn genesis_block_hash(&self) -> BlockHash {
        BlockHash::from_str(match self {
            ChainNet::BitcoinMainnet => {
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            }
            ChainNet::BitcoinTestnet3 => {
                "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
            }
            ChainNet::BitcoinTestnet4 => {
                "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
            }
            ChainNet::BitcoinSignet => {
                "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
            }
            ChainNet::BitcoinRegtest => {
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
            }
            ChainNet::LiquidMainnet => {
                "4f4eac81e5f9f04f5d2a17b03e6726e6a1af69d9c3f00d820f1c82fcb6000000"
            }
            ChainNet::LiquidTestnet => {
                "f9f21a7636b35c12f080ff73fc8bb16bb7c3ceafdc2eb1b673f0ea7a40c00000"
            }
        })
        .unwrap()
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ChainNetParseError {
    /// invalid chain-network pair {0}.
    Invalid(String),
}

impl FromStr for ChainNet {
    type Err = ChainNetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase() {
            x if ChainNet::BitcoinMainnet.prefix() == x => Ok(ChainNet::BitcoinMainnet),
            x if ChainNet::BitcoinRegtest.prefix() == x => Ok(ChainNet::BitcoinRegtest),
            x if ChainNet::BitcoinSignet.prefix() == x => Ok(ChainNet::BitcoinSignet),
            x if ChainNet::BitcoinTestnet3.prefix() == x => Ok(ChainNet::BitcoinTestnet3),
            x if ChainNet::BitcoinTestnet4.prefix() == x => Ok(ChainNet::BitcoinTestnet4),
            x if ChainNet::LiquidMainnet.prefix() == x => Ok(ChainNet::LiquidMainnet),
            x if ChainNet::LiquidTestnet.prefix() == x => Ok(ChainNet::LiquidTestnet),
            _ => Err(ChainNetParseError::Invalid(s.to_owned())),
        }
    }
}
