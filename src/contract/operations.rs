// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use std::collections::btree_set;
use std::iter;

use amplify::confinement::{NonEmptyOrdSet, TinyOrdSet, U16 as U16MAX};
use amplify::{ByteArray, Wrapper};
use commit_verify::{CommitId, MerkleHash, MerkleLeaves, ReservedBytes, StrictHash};
use strict_encoding::stl::AsciiPrintable;
use strict_encoding::{RString, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize};

use crate::{
    AssignmentType, Assignments, ContractId, Ffv, GlobalState, Metadata, OpId, RgbSeal, Schema, SchemaId,
    LIB_NAME_RGB_COMMIT,
};

/// RGB contract operation output pointer, defined by the operation ID and
/// output number.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("rgb://{op}/{ty}/{no}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Opout {
    pub op: OpId,
    pub ty: AssignmentType,
    pub no: u16,
}

impl Opout {
    pub fn new(op: OpId, ty: AssignmentType, no: u16) -> Opout { Opout { op, ty, no } }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = merklize, id = MerkleHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Inputs(NonEmptyOrdSet<Input, U16MAX>);

impl<'a> IntoIterator for &'a Inputs {
    type Item = Input;
    type IntoIter = iter::Copied<btree_set::Iter<'a, Input>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter().copied() }
}

impl MerkleLeaves for Inputs {
    type Leaf = Input;
    type LeafIter<'tmp> = <TinyOrdSet<Input> as MerkleLeaves>::LeafIter<'tmp>;

    fn merkle_leaves(&self) -> Self::LeafIter<'_> { self.0.merkle_leaves() }
}

impl StrictDumb for Inputs {
    fn strict_dumb() -> Self { Self(NonEmptyOrdSet::with(strict_dumb!())) }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
#[display("{prev_out}")]
pub struct Input {
    pub prev_out: Opout,
    // reserved for fallback
    #[cfg_attr(feature = "serde", serde(skip))]
    fallback: ReservedBytes<1>,
    // reserved for witness
    #[cfg_attr(feature = "serde", serde(skip))]
    reserved: ReservedBytes<2>,
}

impl Input {
    pub fn with(prev_out: Opout) -> Input { Input { prev_out, fallback: default!(), reserved: default!() } }
}

/// An ASCII printable string up to 4096 chars representing identity of the developer.
///
/// We deliberately do not define the internal structure of the identity such that it can be updated
/// without changes to the consensus level.
///
/// Contract or schema validity doesn't assume any checks on the identity; these checks must be
/// performed at the application level.
#[derive(Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From, Display)]
#[wrapper(Deref, FromStr)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Identity(RString<AsciiPrintable, AsciiPrintable, 1, 4096>);

impl Default for Identity {
    fn default() -> Self { Self::from("ssi:anonymous") }
}

impl From<&'static str> for Identity {
    fn from(s: &'static str) -> Self { Self(RString::from(s)) }
}

impl Identity {
    pub fn is_empty(&self) -> bool { self.is_anonymous() }
    pub fn is_anonymous(&self) -> bool { self == &default!() }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct GenesisHeader {
    pub ffv: Ffv,
    pub flags: ReservedBytes<1, 0>,
    pub timestamp: i64,
    pub issuer: Identity,

    /// Cryptographic hash functions used for operation commitments.
    ///
    /// The only supported function at this moment is SHA-256, encoded by a zero byte in this
    /// position.
    ///
    /// Future support for zk-STARKs would require supporting more zk-friendly hash functions.
    pub chf: ReservedBytes<1>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "Seal: serde::Serialize + serde::de::DeserializeOwned, Seal::Params: serde::Serialize + \
                   serde::de::DeserializeOwned")
)]
pub struct Genesis<Seal: RgbSeal> {
    // Schema
    pub schema: Schema,

    // Single-use seals
    pub seals: Seal::Params,

    // Contract header
    pub header: GenesisHeader,

    // Genesis contract data
    pub metadata: Metadata,
    pub globals: GlobalState,
    pub assignments: Assignments<Seal>,

    // Reserved
    pub reserved: ReservedBytes<4>,
}

impl<Seal: RgbSeal> StrictSerialize for Genesis<Seal> {}
impl<Seal: RgbSeal> StrictDeserialize for Genesis<Seal> {}

impl<Seal: RgbSeal> Genesis<Seal> {
    pub fn schema_id(&self) -> SchemaId { self.schema.schema_id() }
    pub fn contract_id(&self) -> ContractId { ContractId::from_byte_array(self.opid().to_byte_array()) }
    pub fn opid(&self) -> OpId { self.commit_id() }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase", bound = "Seal: serde::Serialize + serde::de::DeserializeOwned")
)]
pub struct Extension<Seal: RgbSeal> {
    // Header
    pub ffv: Ffv,
    pub contract_id: ContractId,
    pub extension_type: ExtensionType,

    // Data
    pub metadata: Metadata,
    pub globals: GlobalState,
    pub assignments: Assignments<Seal>,

    // Reserved
    pub reserved: ReservedBytes<4>,
}

impl<Seal: RgbSeal> StrictSerialize for Extension<Seal> {}
impl<Seal: RgbSeal> StrictDeserialize for Extension<Seal> {}

impl<Seal: RgbSeal> Extension<Seal> {
    pub fn opid(&self) -> OpId { self.commit_id() }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase", bound = "Seal: serde::Serialize + serde::de::DeserializeOwned")
)]
pub struct Transition<Seal: RgbSeal> {
    // Header
    pub ffv: Ffv,
    pub contract_id: ContractId,
    pub transition_type: TransitionType,

    // Data
    pub inputs: Inputs,
    pub metadata: Metadata,
    pub globals: GlobalState,
    pub assignments: Assignments<Seal>,

    // Reserved
    pub reserved: ReservedBytes<4>,
}

impl<Seal: RgbSeal> StrictSerialize for Transition<Seal> {}
impl<Seal: RgbSeal> StrictDeserialize for Transition<Seal> {}

impl<Seal: RgbSeal> Transition<Seal> {
    pub fn opid(&self) -> OpId { self.commit_id() }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct ExtensionType(u8);
impl ExtensionType {
    pub const fn with(ty: u8) -> Self { Self(ty) }
    pub const fn to_u8(&self) -> u8 { self.0 }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct TransitionType(u8);
impl TransitionType {
    pub const fn with(ty: u8) -> Self { Self(ty) }
    pub const fn to_u8(&self) -> u8 { self.0 }
}

impl TransitionType {
    pub const BLANK: Self = TransitionType(u8::MAX);
    /// Easily check if the TransitionType is blank with convention method
    pub fn is_blank(self) -> bool { self == Self::BLANK }
}
