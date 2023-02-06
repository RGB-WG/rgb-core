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

#![doc = include_str!("../../doc/seals.md")]

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bp::seals::txout::blind::{ConcealedSeal, ParseError, RevealedSeal};
pub use bp::seals::txout::blind::{ConcealedSeal as Confidential, RevealedSeal as Revealed};
use bp::seals::txout::CloseMethod;
use bp::secp256k1::rand::thread_rng;
use bp::Vout;
use commit_verify::Conceal;
use secp256k1_zkp::rand::RngCore;

use crate::LIB_NAME_RGB;

/// Seal definition which re-uses witness transaction id of some other seal,
/// which is not known at the moment of seal construction. Thus, the definition
/// has only information about output number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct VoutSeal {
    /// Commitment to the specific seal close method [`CloseMethod`] which must
    /// be used to close this seal.
    pub method: CloseMethod,

    /// Tx output number, which should be always known.
    pub vout: Vout,

    /// Blinding factor providing confidentiality of the seal definition.
    /// Prevents rainbow table bruteforce attack based on the existing
    /// blockchain txid set.
    pub blinding: u64,
}

impl VoutSeal {
    /// Creates new seal definition for the provided output number and seal
    /// closing method. Uses `thread_rng` to initialize blinding factor.
    #[inline]
    pub fn new(method: CloseMethod, vout: impl Into<Vout>) -> Self {
        VoutSeal::with(method, vout, thread_rng().next_u64())
    }

    /// Creates new opret-seal seal definition for the provided output number
    /// and seal closing method. Uses `thread_rng` to initialize blinding
    /// factor.
    #[inline]
    pub fn new_opret(vout: impl Into<Vout>) -> Self { VoutSeal::new(CloseMethod::OpretFirst, vout) }

    /// Creates new tapret-seal seal definition for the provided output number
    /// and seal closing method. Uses `thread_rng` to initialize blinding
    /// factor.
    #[inline]
    pub fn new_tapret(vout: impl Into<Vout>) -> Self {
        VoutSeal::new(CloseMethod::TapretFirst, vout)
    }

    /// Reconstructs previously defined opret seal given an output number and a
    /// previously generated blinding factor.
    #[inline]
    pub fn with_opret(vout: impl Into<Vout>, blinding: u64) -> Self {
        VoutSeal::with(CloseMethod::OpretFirst, vout, blinding)
    }

    /// Reconstructs previously defined tapret seal given an output number and a
    /// previously generated blinding factor.
    #[inline]
    pub fn with_tapret(vout: impl Into<Vout>, blinding: u64) -> Self {
        VoutSeal::with(CloseMethod::TapretFirst, vout, blinding)
    }

    /// Reconstructs previously defined seal given method, an output number and
    /// a previously generated blinding factor.
    #[inline]
    pub fn with(method: CloseMethod, vout: impl Into<Vout>, blinding: u64) -> Self {
        VoutSeal {
            method,
            vout: vout.into(),
            blinding,
        }
    }
}

impl From<VoutSeal> for RevealedSeal {
    fn from(seal: VoutSeal) -> Self {
        RevealedSeal::with_vout(seal.method, seal.vout, seal.blinding)
    }
}

/// Seal endpoint is a confidential seal which may be linked to the witness
/// transaction, but does not contain information about its id.
///
/// Seal endpoint can be either a pointer to the output in the witness
/// transaction, plus blinding factor value, or a confidential seal
/// [`ConcealedSeal`] value pointing some external unknown transaction
/// output
///
/// Seal endpoint is required in situations where sender assigns state to the
/// witness transaction output on behalf of receiver
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = { Self::ConcealedUtxo(strict_dumb!()) })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum SealEndpoint {
    /// External transaction output in concealed form (see
    /// [`seal::Confidential`])
    #[from]
    #[strict_type(tag = 0)]
    ConcealedUtxo(ConcealedSeal),

    /// Seal contained within the witness transaction
    #[strict_type(tag = 1)]
    WitnessVout(VoutSeal),
}

impl From<RevealedSeal> for SealEndpoint {
    fn from(seal: RevealedSeal) -> Self {
        match seal.txid {
            None => {
                SealEndpoint::WitnessVout(VoutSeal::with(seal.method, seal.vout, seal.blinding))
            }
            Some(_) => SealEndpoint::ConcealedUtxo(seal.conceal()),
        }
    }
}

impl SealEndpoint {
    /// Constructs [`SealEndpoint`] for the witness transaction. Uses
    /// `thread_rng` to initialize blinding factor.
    pub fn new_vout(method: CloseMethod, vout: impl Into<Vout>) -> SealEndpoint {
        SealEndpoint::WitnessVout(VoutSeal::new(method, vout))
    }
}

impl Conceal for SealEndpoint {
    type Concealed = Confidential;

    fn conceal(&self) -> Self::Concealed {
        match *self {
            SealEndpoint::ConcealedUtxo(hash) => hash,
            SealEndpoint::WitnessVout(seal) => RevealedSeal::from(seal).conceal(),
        }
    }
}

impl Display for SealEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            SealEndpoint::ConcealedUtxo(ref seal) => Display::fmt(seal, f),
            SealEndpoint::WitnessVout(seal) => Display::fmt(&RevealedSeal::from(seal), f),
        }
    }
}

impl FromStr for SealEndpoint {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ConcealedSeal::from_str(s)
            .map(SealEndpoint::from)
            .or_else(|_| RevealedSeal::from_str(s).map(SealEndpoint::from))
    }
}
