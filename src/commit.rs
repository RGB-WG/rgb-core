// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::{fmt, vec};

use amplify::hex::{FromHex, ToHex};
use amplify::{hex, ByteArray, Bytes32, FromSliceError, Wrapper};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use commit_verify::{
    mpc, CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, MerkleHash, MerkleLeaves, Sha256, StrictHash,
};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::{
    impl_serde_baid64, AssignmentType, Assignments, Extension, Genesis, GlobalState, GlobalStateType, MetaType,
    Metadata, RgbSeal, Transition, LIB_NAME_RGB_COMMIT,
};

/// Schema identifier.
///
/// Schema identifier commits to all the schema data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
pub struct SchemaId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for SchemaId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for SchemaId {
    const TAG: &'static str = "urn:lnp-bp:rgb:schema#2024-10-23";
}

impl DisplayBaid64 for SchemaId {
    const HRI: &'static str = "rgb:sch";
    const CHUNKING: bool = false;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = true;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for SchemaId {}
impl FromStr for SchemaId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for SchemaId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

mod __serde {
    use super::*;
    impl_serde_baid64!(SchemaId);
}

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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
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

impl<Seal: RgbSeal> CommitEncode for Genesis<Seal> {
    type CommitmentId = OpId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.schema.schema_id());
        e.commit_to_serialized(&self.header);
        e.commit_to_merkle(&self.metadata);
        e.commit_to_merkle(&self.globals);
        e.commit_to_merkle(&self.assignments);
        e.commit_to_serialized(&self.reserved);
    }
}

impl<Seal: RgbSeal> CommitEncode for Extension<Seal> {
    type CommitmentId = OpId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.ffv);
        e.commit_to_serialized(&self.contract_id);
        e.commit_to_serialized(&self.extension_type);
        e.commit_to_merkle(&self.metadata);
        e.commit_to_merkle(&self.globals);
        e.commit_to_merkle(&self.assignments);
        e.commit_to_serialized(&self.reserved);
    }
}

impl<Seal: RgbSeal> CommitEncode for Transition<Seal> {
    type CommitmentId = OpId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.ffv);
        e.commit_to_serialized(&self.contract_id);
        e.commit_to_serialized(&self.transition_type);
        e.commit_to_merkle(&self.inputs);
        e.commit_to_merkle(&self.metadata);
        e.commit_to_merkle(&self.globals);
        e.commit_to_merkle(&self.assignments);
        e.commit_to_serialized(&self.reserved);
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
pub struct GlobalCommitment {
    pub ty: GlobalStateType,
    pub state: StrictHash,
}

impl MerkleLeaves for GlobalState {
    type Leaf = GlobalCommitment;
    type LeafIter<'tmp> = vec::IntoIter<GlobalCommitment>;

    fn merkle_leaves(&self) -> Self::LeafIter<'_> {
        self.iter()
            .flat_map(|(ty, list)| {
                list.iter().map(|val| GlobalCommitment {
                    ty: *ty,
                    state: val.commit_id(),
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
pub struct MetaCommitment {
    pub ty: MetaType,
    pub state: StrictHash,
}

impl MerkleLeaves for Metadata {
    type Leaf = MetaCommitment;
    type LeafIter<'tmp> = vec::IntoIter<MetaCommitment>;

    fn merkle_leaves(&self) -> Self::LeafIter<'_> {
        self.iter()
            .map(|(ty, state)| MetaCommitment {
                ty: *ty,
                state: state.commit_id(),
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
pub struct AssignmentCommitment {
    pub ty: AssignmentType,
    pub state: StrictHash,
    pub seal: Bytes32,
    pub lock: StrictHash,
    pub fallback: StrictHash,
}

impl<Seal: RgbSeal> MerkleLeaves for Assignments<Seal> {
    type Leaf = AssignmentCommitment;
    type LeafIter<'tmp>
        = vec::IntoIter<AssignmentCommitment>
    where Seal: 'tmp;

    fn merkle_leaves(&self) -> Self::LeafIter<'_> {
        self.iter()
            .flat_map(|(ty, a)| {
                a.into_iter().map(|a| AssignmentCommitment {
                    ty: *ty,
                    state: a.state.commit_id(),
                    seal: a.seal.commit_id().into(),
                    lock: a.lock.commit_id(),
                    fallback: a.fallback.commit_id(),
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}
