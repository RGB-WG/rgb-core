// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use core::str::FromStr;

use amplify::Bytes32;
use single_use_seals::SingleUseSeal;
use ultrasonic::AuthToken;

pub trait SonicSeal: SingleUseSeal<Message = Bytes32> {
    fn auth_token(&self) -> AuthToken;
}

// Below are capabilities constants used in the standard library:

#[cfg(feature = "bitcoin")]
pub const BITCOIN_OPRET: u32 = 0x0001_0001_u32;
#[cfg(feature = "bitcoin")]
pub const BITCOIN_TAPRET: u32 = 0x0001_0002_u32;
#[cfg(feature = "liquid")]
pub const LIQUID_OPRET: u32 = 0x0002_0001_u32;
#[cfg(feature = "liquid")]
pub const LIQUID_TAPRET: u32 = 0x0002_0002_u32;
#[cfg(feature = "prime")]
pub const PRIME_SEALS: u32 = 0x0010_0001_u32;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u32)]
pub enum SealType {
    #[cfg(feature = "bitcoin")]
    #[display("bcor")]
    BitcoinOpret = BITCOIN_OPRET,

    #[cfg(feature = "bitcoin")]
    #[display("bctr")]
    BitcoinTapret = BITCOIN_TAPRET,

    #[cfg(feature = "liquid")]
    #[display("lqor")]
    LiquidOpret = LIQUID_OPRET,

    #[cfg(feature = "liquid")]
    #[display("lqtr")]
    LiquidTapret = LIQUID_TAPRET,

    #[cfg(feature = "prime")]
    #[display("prime")]
    Prime = PRIME_SEALS,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("unknown seal type `{0}`")]
pub struct UnknownType(String);

impl FromStr for SealType {
    type Err = UnknownType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "bitcoin")]
            "bcor" => Ok(SealType::BitcoinOpret),
            #[cfg(feature = "bitcoin")]
            "bctr" => Ok(SealType::BitcoinTapret),
            #[cfg(feature = "liquid")]
            "lqtr" => Ok(SealType::LiquidTapret),
            #[cfg(feature = "prime")]
            "prime" => Ok(SealType::Prime),
            _ => Err(UnknownType(s.to_string())),
        }
    }
}

impl From<u32> for SealType {
    fn from(caps: u32) -> Self {
        match caps {
            #[cfg(feature = "bitcoin")]
            BITCOIN_OPRET => Self::BitcoinOpret,
            #[cfg(feature = "bitcoin")]
            BITCOIN_TAPRET => Self::BitcoinTapret,
            #[cfg(feature = "liquid")]
            LIQUID_TAPRET => Self::LiquidTapret,
            #[cfg(feature = "prime")]
            PRIME_SEALS => Self::Prime,
            unknown => panic!("unknown seal type {unknown:#10x}"),
        }
    }
}

#[cfg(any(feature = "bitcoin", feature = "liquid"))]
pub mod bitcoin {
    use bp::dbc;
    use bp::dbc::opret::OpretProof;
    use bp::dbc::tapret::TapretProof;
    use bp::seals::TxoSeal;
    use commit_verify::CommitId;

    use super::*;

    pub type OpretSeal = TxoSeal<OpretProof>;
    pub type TapretSeal = TxoSeal<TapretProof>;

    impl<D: dbc::Proof> SonicSeal for TxoSeal<D> {
        // SECURITY: Here we cut SHA256 tagged hash of a single-use seal definition to 30 bytes in order
        // to fit it into a field element with no overflows. This must be a secure operation since we
        // still have a sufficient 120-bit collision resistance.
        fn auth_token(&self) -> AuthToken {
            let id = self.commit_id().to_byte_array();
            let mut shortened_id = [0u8; 30];
            shortened_id.copy_from_slice(&id[0..30]);
            AuthToken::from_byte_array(shortened_id)
        }
    }
}
