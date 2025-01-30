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

use core::fmt::{Debug, Display};

use bp::seals::mmb;
use single_use_seals::{PublishedWitness, SingleUseSeal};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};
use ultrasonic::AuthToken;

pub trait RgbSealDef: Clone + Debug + Display + StrictDumb + StrictEncode + StrictDecode {
    type Src: RgbSealSrc;
    fn auth_token(&self) -> AuthToken;
    fn resolve(
        &self,
        witness_id: <<Self::Src as SingleUseSeal>::PubWitness as PublishedWitness<Self::Src>>::PubId,
    ) -> Self::Src;
}

pub trait RgbSealSrc: SingleUseSeal<Message = mmb::Message> + Ord {}

// Below are capabilities constants used in the standard library:

#[cfg(any(feature = "bitcoin", feature = "liquid"))]
pub mod bitcoin {
    use bp::seals::{TxoSeal, WOutpoint, WTxoSeal};
    use bp::Outpoint;
    use commit_verify::CommitId;

    use super::*;

    impl RgbSealSrc for TxoSeal {}

    impl RgbSealDef for WTxoSeal {
        type Src = TxoSeal;

        // SECURITY: Here we cut SHA256 tagged hash of a single-use seal definition to 30 bytes in order
        // to fit it into a field element with no overflows. This must be a secure operation since we
        // still have a sufficient 120-bit collision resistance.
        fn auth_token(&self) -> AuthToken {
            let id = self.commit_id().to_byte_array();
            let mut shortened_id = [0u8; 30];
            shortened_id.copy_from_slice(&id[0..30]);
            AuthToken::from_byte_array(shortened_id)
        }

        fn resolve(
            &self,
            witness_id: <<Self::Src as SingleUseSeal>::PubWitness as PublishedWitness<Self::Src>>::PubId,
        ) -> Self::Src {
            let primary = match self.primary {
                WOutpoint::Wout(wout) => Outpoint::new(witness_id, wout),
                WOutpoint::Extern(outpoint) => outpoint,
            };
            TxoSeal { primary, secondary: self.secondary }
        }
    }
}
