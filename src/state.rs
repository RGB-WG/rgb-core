// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use core::fmt::Debug;
use std::collections::btree_map;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::{fmt, slice};

use amplify::confinement::{Confined, NonEmptyVec, SmallBlob, TinyOrdMap};
use amplify::{confinement, ByteArray, Bytes32, Wrapper};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use commit_verify::{CommitEncode, CommitEngine, MerkleHash, ReservedBytes, StrictHash};
use strict_encoding::{StrictDecode, StrictDeserialize, StrictDumb, StrictEncode, StrictSerialize, StrictType};

use crate::{impl_serde_baid64, RgbSeal, LIB_NAME_RGB_COMMIT};

pub const STATE_DATA_MAX_LEN: usize = confinement::U16;
pub const GLOBAL_STATE_MAX_ITEMS: usize = confinement::U16;
pub const TYPED_ASSIGNMENTS_MAX_ITEMS: usize = confinement::U16;

/// Unique data attachment identifier
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
pub struct AttachId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl DisplayBaid64 for AttachId {
    const HRI: &'static str = "rgb:fs";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = true;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for AttachId {}
impl FromStr for AttachId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for AttachId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl_serde_baid64!(AttachId);

/// Array of a field elements
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = custom)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum FieldArray<F: Copy + Ord + Hash + Debug + StrictEncode + StrictDecode + StrictDumb> {
    #[default]
    #[strict_type(tag = 0x00)]
    None,
    #[strict_type(tag = 0x01)]
    Single(F),
    #[strict_type(tag = 0x02)]
    Double(F, F),
    #[strict_type(tag = 0x03)]
    Three(F, F, F),
    #[strict_type(tag = 0x04)]
    Four(F, F, F, F),
}

/// Verifiable state in a form of a field elements.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = custom)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(tag = "type", content = "elements"))]
pub enum VerifiableState {
    /// Element of a field representable with less than 32 bits of data in little-endian format.
    #[strict_type(tag = 0x10)]
    Le32bit(FieldArray<u32>),

    /// Element of a field representable with less than 64 bits of data in little-endian format.
    #[strict_type(tag = 0x11)]
    Le64bit(FieldArray<u64>),

    /// Element of a field representable with less than 128 bits of data in little-endian format.
    #[strict_type(tag = 0x12)]
    Le128Bit(FieldArray<u128>),
}

impl StrictDumb for VerifiableState {
    fn strict_dumb() -> Self { Self::Le32bit(FieldArray::Single(0)) }
}

/// Binary state data, serialized using strict type notation from the structured data type.
#[derive(Wrapper, Clone, PartialOrd, Ord, Eq, PartialEq, Hash, Debug, Default, From)]
#[wrapper(Deref, AsSlice, BorrowSlice, RangeOps)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UnverifiedState {
    /// Type of the data. Currently only strict-encoded data (0x00) are supported. In a future, this
    /// can be transformed to an enum.
    pub ty: ReservedBytes<1>,

    #[from]
    #[wrap]
    /// Inline unverified state blobs, which are used by interfaces (with strict types parsing),
    /// but not anyhow used or enforced at the consensus level.
    ///
    /// Inline unverified state must fit into 64kiB.
    pub data: SmallBlob,

    /// File id of the attachment used in the state.
    ///
    /// Attachments are pieces of unverified state which exceed 64kiB and/or not encoded with
    /// strict types.
    ///
    /// Consensus doesn't verify presence or data of an attachment.
    pub attach: Option<AttachId>,
}

impl StrictSerialize for UnverifiedState {}
impl StrictDeserialize for UnverifiedState {}

#[derive(Clone, PartialOrd, Ord, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct State {
    pub verifiable: VerifiableState,
    pub unverified: UnverifiedState,
}

// TODO: Add hash strategy to CommitEncode derive and use it here
impl CommitEncode for State {
    type CommitmentId = StrictHash;

    fn commit_encode(&self, e: &mut CommitEngine) {
        // State commits independently to a hashed value of verified part and unverified part, which is
        // required for zk-STARK support in the future.
        e.commit_to_hash(&self.verifiable);
        e.commit_to_hash(&self.unverified);
        e.set_finished();
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MetadataError {
    /// value of metadata type #{0} is already set.
    AlreadyExists(MetaType),

    /// too many metadata values.
    #[from(confinement::Error)]
    TooManyValues,
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = merklize, id = MerkleHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct Metadata(TinyOrdMap<MetaType, VerifiableState>);

impl Metadata {
    pub fn add_value(&mut self, ty: MetaType, meta: VerifiableState) -> Result<(), MetadataError> {
        if self.0.contains_key(&ty) {
            return Err(MetadataError::AlreadyExists(ty));
        }
        self.0.insert(ty, meta)?;
        Ok(())
    }
}

impl<'a> IntoIterator for &'a Metadata {
    type Item = (&'a MetaType, &'a VerifiableState);
    type IntoIter = btree_map::Iter<'a, MetaType, VerifiableState>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct GlobalValues(NonEmptyVec<State, GLOBAL_STATE_MAX_ITEMS>);

impl StrictDumb for GlobalValues {
    fn strict_dumb() -> Self { Self(NonEmptyVec::with(State::strict_dumb())) }
}

impl GlobalValues {
    pub fn with(state: impl Into<State>) -> Self { GlobalValues(Confined::with(state.into())) }
}

impl<'a> IntoIterator for &'a GlobalValues {
    type Item = &'a State;
    type IntoIter = slice::Iter<'a, State>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = merklize, id = MerkleHash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct GlobalState(TinyOrdMap<GlobalStateType, GlobalValues>);

impl GlobalState {
    pub fn add_state(&mut self, ty: GlobalStateType, state: State) -> Result<(), confinement::Error> {
        match self.0.get_mut(&ty) {
            Some(vec) => vec.push(state),
            None => self.insert(ty, GlobalValues::with(state)).map(|_| ()),
        }
    }

    pub fn extend_state(
        &mut self,
        ty: GlobalStateType,
        iter: impl IntoIterator<Item = State>,
    ) -> Result<(), confinement::Error> {
        match self.0.get_mut(&ty) {
            Some(vec) => vec.extend(iter),
            None => self
                .insert(ty, GlobalValues::from_inner(Confined::try_from_iter(iter)?))
                .map(|_| ()),
        }
    }
}

impl<'a> IntoIterator for &'a GlobalState {
    type Item = (&'a GlobalStateType, &'a GlobalValues);
    type IntoIter = btree_map::Iter<'a, GlobalStateType, GlobalValues>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

/// State data are assigned to a seal definition, which means that they are
/// owned by a person controlling spending of the seal UTXO, unless the seal
/// is closed, indicating that a transfer of ownership had taken place
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase", bound = "Seal: serde::Serialize + serde::de::DeserializeOwned")
)]
pub struct Assign<Seal: RgbSeal> {
    pub seal: Seal,
    pub state: VerifiableState,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(super) lock: ReservedBytes<2>,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(super) fallback: ReservedBytes<1>,
}

impl<Seal: RgbSeal> Assign<Seal> {
    pub fn new(seal: Seal, state: VerifiableState) -> Self {
        Self {
            seal,
            state,
            lock: none!(),
            fallback: none!(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(transparent, bound = "Seal: serde::Serialize + serde::de::DeserializeOwned")
)]
pub struct TypedAssigns<Seal: RgbSeal>(NonEmptyVec<Assign<Seal>, TYPED_ASSIGNMENTS_MAX_ITEMS>);

impl<Seal: RgbSeal> StrictDumb for TypedAssigns<Seal> {
    fn strict_dumb() -> Self { Self(NonEmptyVec::with(strict_dumb!())) }
}

impl<'a, Seal: RgbSeal> IntoIterator for &'a TypedAssigns<Seal> {
    type Item = &'a Assign<Seal>;
    type IntoIter = slice::Iter<'a, Assign<Seal>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = merklize, id = MerkleHash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(transparent, bound = "Seal: serde::Serialize + serde::de::DeserializeOwned")
)]
pub struct Assignments<Seal: RgbSeal>(TinyOrdMap<AssignmentType, TypedAssigns<Seal>>);

impl<Seal: RgbSeal> Default for Assignments<Seal> {
    fn default() -> Self { Self(empty!()) }
}

impl<Seal: RgbSeal> Deref for Assignments<Seal> {
    type Target = TinyOrdMap<AssignmentType, TypedAssigns<Seal>>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl<Seal: RgbSeal> DerefMut for Assignments<Seal> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl<Seal: RgbSeal> Assignments<Seal> {
    pub fn all(&self) -> impl Iterator<Item = (AssignmentType, u16, &Assign<Seal>)> {
        self.0.iter().flat_map(|(ty, list)| {
            list.into_iter()
                .enumerate()
                .map(|(no, a)| (*ty, no as u16, a))
        })
    }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct MetaType(u8);
impl MetaType {
    pub const fn with(ty: u8) -> Self { Self(ty) }
    pub const fn to_u8(&self) -> u8 { self.0 }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct GlobalStateType(u8);
impl GlobalStateType {
    pub const fn with(ty: u8) -> Self { Self(ty) }
    pub const fn to_u8(&self) -> u8 { self.0 }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct AssignmentType(u8);
impl AssignmentType {
    pub const fn with(ty: u8) -> Self { Self(ty) }
    pub const fn to_u8(&self) -> u8 { self.0 }
}
