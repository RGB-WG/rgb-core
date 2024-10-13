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

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::{fmt, vec};

use amplify::confinement::{Confined, MediumOrdMap, U16 as U16MAX};
use amplify::hex::{FromHex, ToHex};
use amplify::num::u256;
use amplify::{hex, ByteArray, Bytes32, FromSliceError, Wrapper};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use commit_verify::{
    mpc, CommitEncode, CommitEngine, CommitId, CommitmentId, Conceal, DigestExt, MerkleHash,
    MerkleLeaves, ReservedBytes, Sha256, StrictHash,
};
use strict_encoding::StrictDumb;

use crate::{
    impl_serde_baid64, Assign, AssignmentType, Assignments, BundleId, ConcealedAttach,
    ConcealedData, ConcealedState, ConfidentialState, DataState, ExposedSeal, ExposedState,
    Extension, ExtensionType, Ffv, Genesis, GlobalState, GlobalStateType, Operation,
    PedersenCommitment, Redeemed, SchemaId, SecretSeal, Transition, TransitionBundle,
    TransitionType, TypedAssigns, XChain, LIB_NAME_RGB_COMMIT,
};

/// Unique contract identifier equivalent to the contract genesis commitment
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
pub struct ContractId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl PartialEq<OpId> for ContractId {
    fn eq(&self, other: &OpId) -> bool { self.to_byte_array() == other.to_byte_array() }
}
impl PartialEq<ContractId> for OpId {
    fn eq(&self, other: &ContractId) -> bool { self.to_byte_array() == other.to_byte_array() }
}

impl ContractId {
    pub fn copy_from_slice(slice: impl AsRef<[u8]>) -> Result<Self, FromSliceError> {
        Bytes32::copy_from_slice(slice).map(Self)
    }
}

impl DisplayBaid64 for ContractId {
    const HRI: &'static str = "rgb";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = false;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for ContractId {}
impl FromStr for ContractId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for ContractId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl From<mpc::ProtocolId> for ContractId {
    fn from(id: mpc::ProtocolId) -> Self { ContractId(id.into_inner()) }
}

impl From<ContractId> for mpc::ProtocolId {
    fn from(id: ContractId) -> Self { mpc::ProtocolId::from_inner(id.into_inner()) }
}

impl_serde_baid64!(ContractId);

/// Unique operation (genesis, extensions & state transition) identifier
/// equivalent to the commitment hash
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_hex)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct OpId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for OpId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for OpId {
    const TAG: &'static str = "urn:lnp-bp:rgb:operation#2024-02-03";
}

impl FromStr for OpId {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_hex(s) }
}

impl OpId {
    pub fn copy_from_slice(slice: impl AsRef<[u8]>) -> Result<Self, FromSliceError> {
        Bytes32::copy_from_slice(slice).map(Self)
    }
}

/// Hash committing to all data which are disclosed by a contract or some part
/// of it (operation, bundle, consignment, disclosure).
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_hex)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct DiscloseHash(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for DiscloseHash {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for DiscloseHash {
    const TAG: &'static str = "urn:lnp-bp:rgb:disclose#2024-02-16";
}

impl FromStr for DiscloseHash {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_hex(s) }
}

impl DiscloseHash {
    pub fn copy_from_slice(slice: impl AsRef<[u8]>) -> Result<Self, FromSliceError> {
        Bytes32::copy_from_slice(slice).map(Self)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
pub struct AssignmentIndex {
    pub ty: AssignmentType,
    pub pos: u16,
}

impl AssignmentIndex {
    pub fn new(ty: AssignmentType, pos: u16) -> Self { AssignmentIndex { ty, pos } }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = DiscloseHash)]
pub struct OpDisclose {
    pub id: OpId,
    pub seals: MediumOrdMap<AssignmentIndex, XChain<SecretSeal>>,
    pub fungible: MediumOrdMap<AssignmentIndex, PedersenCommitment>,
    pub data: MediumOrdMap<AssignmentIndex, ConcealedData>,
    pub attach: MediumOrdMap<AssignmentIndex, ConcealedAttach>,
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = DiscloseHash)]
pub struct BundleDisclosure {
    pub id: BundleId,
    pub known_transitions: Confined<BTreeSet<DiscloseHash>, 1, U16MAX>,
}

impl StrictDumb for BundleDisclosure {
    fn strict_dumb() -> Self {
        Self {
            id: strict_dumb!(),
            known_transitions: Confined::with(strict_dumb!()),
        }
    }
}

impl TransitionBundle {
    /// Provides summary about parts of the bundle which are revealed.
    pub fn disclose(&self) -> BundleDisclosure {
        BundleDisclosure {
            id: self.bundle_id(),
            known_transitions: Confined::from_iter_checked(
                self.known_transitions.values().map(|t| t.disclose_hash()),
            ),
        }
    }

    /// Returns commitment to the bundle plus revealed data within it.
    pub fn disclose_hash(&self) -> DiscloseHash { self.disclose().commit_id() }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
pub struct BaseCommitment {
    pub flags: ReservedBytes<1, 0>,
    pub schema_id: SchemaId,
    pub timestamp: i64,
    pub issuer: StrictHash,
    pub testnet: bool,
    pub alt_layers1: StrictHash,
    pub asset_tags: StrictHash,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = custom, dumb = Self::Transition(strict_dumb!(), strict_dumb!()))]
pub enum TypeCommitment {
    #[strict_type(tag = 0)]
    Genesis(BaseCommitment),

    #[strict_type(tag = 1)]
    Transition(ContractId, TransitionType),

    #[strict_type(tag = 2)]
    Extension(ContractId, ExtensionType),
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = OpId)]
pub struct OpCommitment {
    pub ffv: Ffv,
    pub nonce: u64,
    pub op_type: TypeCommitment,
    pub metadata: StrictHash,
    pub globals: MerkleHash,
    pub inputs: MerkleHash,
    pub assignments: MerkleHash,
    pub redeemed: StrictHash,
    pub valencies: StrictHash,
    pub witness: MerkleHash,
    pub validator: StrictHash,
}

impl Genesis {
    pub fn commit(&self) -> OpCommitment {
        let base = BaseCommitment {
            flags: self.flags,
            schema_id: self.schema_id,
            timestamp: self.timestamp,
            testnet: self.testnet,
            alt_layers1: self.alt_layers1.commit_id(),
            issuer: self.issuer.commit_id(),
            asset_tags: self.asset_tags.commit_id(),
        };
        OpCommitment {
            ffv: self.ffv,
            nonce: u64::MAX,
            op_type: TypeCommitment::Genesis(base),
            metadata: self.metadata.commit_id(),
            globals: MerkleHash::merklize(&self.globals),
            inputs: MerkleHash::void(0, u256::ZERO),
            assignments: MerkleHash::merklize(&self.assignments),
            redeemed: Redeemed::default().commit_id(),
            valencies: self.valencies.commit_id(),
            witness: MerkleHash::void(0, u256::ZERO),
            validator: self.validator.commit_id(),
        }
    }

    pub fn disclose_hash(&self) -> DiscloseHash { self.disclose().commit_id() }
}

impl Transition {
    pub fn commit(&self) -> OpCommitment {
        OpCommitment {
            ffv: self.ffv,
            nonce: self.nonce,
            op_type: TypeCommitment::Transition(self.contract_id, self.transition_type),
            metadata: self.metadata.commit_id(),
            globals: MerkleHash::merklize(&self.globals),
            inputs: MerkleHash::merklize(&self.inputs),
            assignments: MerkleHash::merklize(&self.assignments),
            redeemed: Redeemed::default().commit_id(),
            valencies: self.valencies.commit_id(),
            witness: MerkleHash::void(0, u256::ZERO),
            validator: self.validator.commit_id(),
        }
    }
}

impl Extension {
    pub fn commit(&self) -> OpCommitment {
        OpCommitment {
            ffv: self.ffv,
            nonce: self.nonce,
            op_type: TypeCommitment::Extension(self.contract_id, self.extension_type),
            metadata: self.metadata.commit_id(),
            globals: MerkleHash::merklize(&self.globals),
            inputs: MerkleHash::void(0, u256::ZERO),
            assignments: MerkleHash::merklize(&self.assignments),
            redeemed: self.redeemed.commit_id(),
            valencies: self.valencies.commit_id(),
            witness: MerkleHash::void(0, u256::ZERO),
            validator: self.validator.commit_id(),
        }
    }
}

impl ConcealedState {
    fn commit_encode(&self, e: &mut CommitEngine) {
        match self {
            ConcealedState::Void => {}
            ConcealedState::Fungible(val) => e.commit_to_serialized(&val.commitment()),
            ConcealedState::Structured(dat) => e.commit_to_serialized(dat),
            ConcealedState::Attachment(att) => e.commit_to_serialized(att),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct AssignmentCommitment {
    pub ty: AssignmentType,
    pub state: ConcealedState,
    pub seal: XChain<SecretSeal>,
    pub lock: ReservedBytes<2, 0>,
}

impl CommitEncode for AssignmentCommitment {
    type CommitmentId = MerkleHash;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.ty);
        self.state.commit_encode(e);
        e.commit_to_serialized(&self.seal);
        e.commit_to_serialized(&self.lock);
        e.set_finished();
    }
}

impl<State: ExposedState, Seal: ExposedSeal> Assign<State, Seal> {
    pub fn commitment(&self, ty: AssignmentType) -> AssignmentCommitment {
        let Self::Confidential { seal, state, lock } = self.conceal() else {
            unreachable!();
        };
        AssignmentCommitment {
            ty,
            state: state.state_commitment(),
            seal,
            lock,
        }
    }
}

impl<Seal: ExposedSeal> MerkleLeaves for Assignments<Seal> {
    type Leaf = AssignmentCommitment;
    type LeafIter<'tmp>
        = vec::IntoIter<AssignmentCommitment>
    where Seal: 'tmp;

    fn merkle_leaves(&self) -> Self::LeafIter<'_> {
        self.iter()
            .flat_map(|(ty, a)| {
                match a {
                    TypedAssigns::Declarative(list) => {
                        list.iter().map(|a| a.commitment(*ty)).collect::<Vec<_>>()
                    }
                    TypedAssigns::Fungible(list) => {
                        list.iter().map(|a| a.commitment(*ty)).collect()
                    }
                    TypedAssigns::Structured(list) => {
                        list.iter().map(|a| a.commitment(*ty)).collect()
                    }
                    TypedAssigns::Attachment(list) => {
                        list.iter().map(|a| a.commitment(*ty)).collect()
                    }
                }
                .into_iter()
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct GlobalCommitment {
    pub ty: GlobalStateType,
    pub state: DataState,
}

impl CommitEncode for GlobalCommitment {
    type CommitmentId = MerkleHash;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.ty);
        e.commit_to_serialized(&self.state);
        e.set_finished();
    }
}

impl MerkleLeaves for GlobalState {
    type Leaf = GlobalCommitment;
    type LeafIter<'tmp> = vec::IntoIter<GlobalCommitment>;

    fn merkle_leaves(&self) -> Self::LeafIter<'_> {
        self.iter()
            .flat_map(|(ty, list)| {
                list.iter().map(|val| GlobalCommitment {
                    ty: *ty,
                    state: val.clone(),
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}
