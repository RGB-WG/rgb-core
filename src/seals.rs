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
use core::hash::Hash;

use single_use_seals::{ClientSideWitness, PublishedWitness, SingleUseSeal};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};
use ultrasonic::AuthToken;

/// A type which serves as a definition of a single-use seal for RGB contracts.
///
/// The reason why this type is required additionally to the [`RgbSeal`] type: under some protocols
/// (like bitcoin UTXO-based single-use seals) the seal definition may be defined relatively to a
/// witness of previously closed seal, whose id is not known during seal definition construction.
/// In such cases, a seal definition should be converted into a full single-use seal instance using
/// the [`Self::resolve`] method.
pub trait RgbSealDef: Clone + Eq + Debug + Display + StrictDumb + StrictEncode + StrictDecode {
    /// A type providing implementation of a single-use seal protocol, under which this seal
    /// definition is applicable.
    type Src: RgbSeal;

    /// Convert seal definition into an [`AuthToken`] for the SONIC computer.
    fn auth_token(&self) -> AuthToken;

    /// Resolve seal definition into a complete single-use seal instance using the provided witness
    /// id information.
    ///
    /// # Nota bene
    ///
    /// The `witness_id` here is related not to the witness of the closing of this seal, but to a
    /// witness of the closing of some previous seal, relatively to which this seal is defined.
    fn resolve(
        &self,
        witness_id: <<Self::Src as SingleUseSeal>::PubWitness as PublishedWitness<Self::Src>>::PubId,
    ) -> Self::Src;

    /// Try to convert this seal definition into a complete single-use seal instance.
    ///
    /// The operation may result in `None` if additional information about the seal witness is
    /// required. In this case use [`Self::resolve`] method.
    fn to_src(&self) -> Option<Self::Src>;
}

/// A type which serves as a single-use seal protocol implementation for RGB contracts.
pub trait RgbSeal:
    SingleUseSeal<Message: From<[u8; 32]>, PubWitness = Self::Published, CliWitness = Self::Client> + Ord
{
    /// A type providing corresponding single-use seal definitions.
    type Definition: RgbSealDef<Src = Self>;
    /// A type for the published part of the single-use seal witness.
    type Published: PublishedWitness<Self, PubId = Self::WitnessId>;
    /// A type for the client-side part of the single-use seal witness.
    type Client: ClientSideWitness;
    /// A type for the id information about the single-use seal witness.
    type WitnessId: Copy + Ord + Hash + Debug + Display;
}

// Below are capabilities constants used in the standard library:

#[cfg(any(feature = "bitcoin", feature = "liquid"))]
pub mod bitcoin {
    use bp::seals::{Anchor, TxoSeal, WOutpoint, WTxoSeal};
    use bp::{Outpoint, Tx, Txid};
    use commit_verify::CommitId;

    use super::*;

    impl RgbSeal for TxoSeal {
        type Definition = WTxoSeal;
        type Published = Tx;
        type Client = Anchor;
        type WitnessId = Txid;
    }

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

        fn to_src(&self) -> Option<Self::Src> {
            let primary = match self.primary {
                WOutpoint::Wout(_) => return None,
                WOutpoint::Extern(outpoint) => outpoint,
            };
            Some(TxoSeal { primary, secondary: self.secondary })
        }
    }
}

#[cfg(test)]
mod tests {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use amplify::ByteArray;
    use bp::seals::{TxoSealExt, WOutpoint, WTxoSeal};
    use bp::{Outpoint, Txid};

    use super::*;

    #[test]
    fn auth_token() {
        let seal = WTxoSeal {
            primary: WOutpoint::Wout(0u32.into()),
            secondary: TxoSealExt::Fallback(Outpoint::coinbase()),
        };
        assert_eq!(seal.auth_token().to_string(), "at:lIIfSD7P-RQi0r3kA-7gZdmE7Q-S66QSwzG-NCxNnh7V-225u4Q");
    }

    #[test]
    fn resolve() {
        let seal = WTxoSeal {
            primary: WOutpoint::Wout(0u32.into()),
            secondary: TxoSealExt::Fallback(Outpoint::coinbase()),
        };
        let txid = Txid::from_byte_array([0xAD; 32]);
        let resolved_seal = seal.resolve(txid);
        assert_eq!(resolved_seal.primary, Outpoint::new(txid, 0u32));
        assert_eq!(resolved_seal.secondary, TxoSealExt::Fallback(Outpoint::coinbase()));
    }

    #[test]
    fn to_src() {
        let seal = WTxoSeal {
            primary: WOutpoint::Wout(0u32.into()),
            secondary: TxoSealExt::Fallback(Outpoint::coinbase()),
        };
        assert!(seal.to_src().is_none());

        let seal = WTxoSeal {
            primary: WOutpoint::Extern(Outpoint::coinbase()),
            secondary: TxoSealExt::Fallback(Outpoint::coinbase()),
        };
        let txid = Txid::from_byte_array([0xAD; 32]);
        let resolved_seal = seal.resolve(txid);
        assert_eq!(seal.to_src(), Some(resolved_seal));
    }
}
