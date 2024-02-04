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

use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter};
use std::io::Write;
use std::str::FromStr;
use std::{fmt, io};

use amplify::confinement::TinyOrdSet;
use bp::{Bp, Outpoint};
use commit_verify::{CommitEncode, Conceal};
use strict_encoding::{
    DecodeError, DefineUnion, ReadTuple, ReadUnion, StrictDecode, StrictDumb, StrictEncode,
    StrictSum, StrictType, StrictUnion, TypedRead, TypedWrite, WriteUnion,
};

use crate::{Layer1, OutputSeal, XOutputSeal, LIB_NAME_RGB};

pub const XCHAIN_BITCOIN_PREFIX: &str = "bc";
pub const XCHAIN_LIQUID_PREFIX: &str = "lq";

pub type XOutpoint = XChain<Outpoint>;

impl From<XOutputSeal> for XOutpoint {
    #[inline]
    fn from(seal: XChain<OutputSeal>) -> Self { seal.to_outpoint() }
}

impl XOutputSeal {
    /// Converts seal into a transaction outpoint.
    #[inline]
    pub fn to_outpoint(&self) -> XOutpoint { self.map_ref(OutputSeal::to_outpoint) }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(lowercase)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
pub enum AltLayer1 {
    #[strict_type(dumb)]
    Liquid = 1,
    // Abraxas = 0x10,
    // Prime = 0x11,
}

impl AltLayer1 {
    pub fn layer1(&self) -> Layer1 {
        match self {
            AltLayer1::Liquid => Layer1::Liquid,
        }
    }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct AltLayer1Set(TinyOrdSet<AltLayer1>);

impl CommitEncode for AltLayer1Set {
    fn commit_encode(&self, e: &mut impl Write) {
        for c in self.iter() {
            e.write_all(&[*c as u8]).ok();
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum XChain<T> {
    Bitcoin(T),

    Liquid(T),
}

impl<T: Ord> PartialOrd for XChain<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<T: Ord> Ord for XChain<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Bitcoin(_), Self::Liquid(_)) => Ordering::Greater,
            (Self::Liquid(_), Self::Bitcoin(_)) => Ordering::Less,
            (Self::Bitcoin(t1) | Self::Liquid(t1), Self::Bitcoin(t2) | Self::Liquid(t2)) => {
                t1.cmp(t2)
            }
        }
    }
}

impl<T: Conceal> Conceal for XChain<T> {
    type Concealed = XChain<T::Concealed>;

    #[inline]
    fn conceal(&self) -> Self::Concealed { self.map_ref(|t| t.conceal()) }
}

impl<T> StrictType for XChain<T>
where T: StrictDumb + StrictType
{
    const STRICT_LIB_NAME: &'static str = crate::LIB_NAME_RGB;
}
impl<T> StrictSum for XChain<T>
where T: StrictDumb + StrictType
{
    const ALL_VARIANTS: &'static [(u8, &'static str)] = &[(0x00, "bitcoin"), (0x01, "liquid")];

    fn variant_name(&self) -> &'static str {
        match self {
            XChain::Bitcoin(_) => Self::ALL_VARIANTS[0].1,
            XChain::Liquid(_) => Self::ALL_VARIANTS[1].1,
        }
    }
}
impl<T> StrictUnion for XChain<T> where T: StrictDumb + StrictType {}
impl<T> StrictDumb for XChain<T>
where T: StrictDumb
{
    fn strict_dumb() -> Self { XChain::Bitcoin(strict_dumb!()) }
}
impl<T> StrictEncode for XChain<T>
where T: StrictDumb + StrictEncode
{
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        writer.write_union::<Self>(|w| {
            let w = w
                .define_newtype::<T>(fname!(Self::ALL_VARIANTS[0].1))
                .define_newtype::<T>(fname!(Self::ALL_VARIANTS[1].1))
                .complete();
            Ok(match self {
                XChain::Bitcoin(t) => w.write_newtype(fname!(Self::ALL_VARIANTS[0].1), t)?,
                XChain::Liquid(t) => w.write_newtype(fname!(Self::ALL_VARIANTS[1].1), t)?,
            }
            .complete())
        })
    }
}
impl<T> StrictDecode for XChain<T>
where T: StrictDumb + StrictDecode
{
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_union(|field, r| match field.as_str() {
            x if x == Self::ALL_VARIANTS[0].1 => {
                r.read_tuple(|r| r.read_field().map(Self::Bitcoin))
            }
            x if x == Self::ALL_VARIANTS[1].1 => r.read_tuple(|r| r.read_field().map(Self::Liquid)),
            _ => unreachable!(),
        })
    }
}

impl<T> XChain<T> {
    pub fn with(layer1: Layer1, data: impl Into<T>) -> Self {
        match layer1 {
            Layer1::Bitcoin => XChain::Bitcoin(data.into()),
            Layer1::Liquid => XChain::Liquid(data.into()),
        }
    }

    pub fn is_bitcoin(&self) -> bool { matches!(self, XChain::Bitcoin(_)) }
    pub fn is_liquid(&self) -> bool { matches!(self, XChain::Liquid(_)) }
    pub fn is_bp(&self) -> bool {
        match self {
            XChain::Bitcoin(_) | XChain::Liquid(_) => true,
        }
    }

    pub fn layer1(&self) -> Layer1 {
        match self {
            XChain::Bitcoin(_) => Layer1::Bitcoin,
            XChain::Liquid(_) => Layer1::Liquid,
        }
    }

    pub fn as_bp(&self) -> Bp<&T>
    where for<'a> &'a T: StrictDumb + StrictEncode + StrictDecode {
        match self {
            XChain::Bitcoin(t) => Bp::Bitcoin(t),
            XChain::Liquid(t) => Bp::Liquid(t),
        }
    }

    pub fn into_bp(self) -> Bp<T>
    where T: StrictDumb + StrictEncode + StrictDecode {
        match self {
            XChain::Bitcoin(t) => Bp::Bitcoin(t),
            XChain::Liquid(t) => Bp::Liquid(t),
        }
    }

    pub fn as_reduced_unsafe(&self) -> &T {
        match self {
            XChain::Bitcoin(t) | XChain::Liquid(t) => t,
        }
    }

    /// Maps the value from one internal type into another.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> XChain<U> {
        match self {
            Self::Bitcoin(t) => XChain::Bitcoin(f(t)),
            Self::Liquid(t) => XChain::Liquid(f(t)),
        }
    }

    /// Maps the value from a reference on internal type into another.
    pub fn map_ref<U>(&self, f: impl FnOnce(&T) -> U) -> XChain<U> {
        match self {
            Self::Bitcoin(t) => XChain::Bitcoin(f(t)),
            Self::Liquid(t) => XChain::Liquid(f(t)),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may error.
    pub fn try_map<U, E>(self, f: impl FnOnce(T) -> Result<U, E>) -> Result<XChain<U>, E> {
        match self {
            Self::Bitcoin(t) => f(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f(t).map(XChain::Liquid),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may error.
    pub fn try_map_ref<U, E>(&self, f: impl FnOnce(&T) -> Result<U, E>) -> Result<XChain<U>, E> {
        match self {
            Self::Bitcoin(t) => f(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f(t).map(XChain::Liquid),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may result in an optional value.
    pub fn maybe_map<U>(self, f: impl FnOnce(T) -> Option<U>) -> Option<XChain<U>> {
        match self {
            Self::Bitcoin(t) => f(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f(t).map(XChain::Liquid),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may result in an optional value.
    pub fn maybe_map_ref<U>(&self, f: impl FnOnce(&T) -> Option<U>) -> Option<XChain<U>> {
        match self {
            Self::Bitcoin(t) => f(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f(t).map(XChain::Liquid),
        }
    }

    /// Returns iterator over elements
    pub fn iter<'i>(
        &'i self,
    ) -> Box<dyn Iterator<Item = XChain<<&'i T as IntoIterator>::Item>> + 'i>
    where &'i T: IntoIterator {
        match self {
            XChain::Bitcoin(t) => Box::new(t.into_iter().map(XChain::Bitcoin)),
            XChain::Liquid(t) => Box::new(t.into_iter().map(XChain::Liquid)),
        }
    }
}

impl<I: Iterator> Iterator for XChain<I> {
    type Item = XChain<<I as Iterator>::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            XChain::Bitcoin(t) => t.next().map(XChain::Bitcoin),
            XChain::Liquid(t) => t.next().map(XChain::Liquid),
        }
    }
}

#[derive(Clone, Debug, Display, Error, From)]
pub enum XChainParseError<E: Debug + Display> {
    #[display("unknown chain prefix '{0}'; only 'bc:' and 'lq:' are currently supported")]
    UnknownPrefix(String),

    #[from]
    #[display(inner)]
    Inner(E),
}

impl<T: FromStr> FromStr for XChain<T>
where
    T: StrictDumb + StrictEncode + StrictDecode,
    T::Err: Debug + Display,
{
    type Err = XChainParseError<T::Err>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((prefix, s)) = s.split_once(':') {
            match prefix {
                XCHAIN_BITCOIN_PREFIX => s
                    .parse()
                    .map(XChain::Bitcoin)
                    .map_err(XChainParseError::from),
                XCHAIN_LIQUID_PREFIX => s
                    .parse()
                    .map(XChain::Liquid)
                    .map_err(XChainParseError::from),
                unknown => Err(XChainParseError::UnknownPrefix(unknown.to_owned())),
            }
        } else {
            s.parse()
                .map(XChain::Bitcoin)
                .map_err(XChainParseError::from)
        }
    }
}

impl<T: Display> Display for XChain<T>
where T: StrictDumb + StrictEncode + StrictDecode
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            XChain::Bitcoin(t) => write!(f, "{XCHAIN_BITCOIN_PREFIX}:{t}"),
            XChain::Liquid(t) => write!(f, "{XCHAIN_LIQUID_PREFIX}:{t}"),
        }
    }
}
