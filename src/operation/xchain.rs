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

use std::cmp::Ordering;
use std::convert::Infallible;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
use std::{fmt, io};

use amplify::confinement::TinyOrdSet;
use bp::{Bp, Outpoint};
use commit_verify::{Conceal, StrictHash};
use strict_encoding::{
    DecodeError, DefineUnion, ReadTuple, ReadUnion, StrictDecode, StrictDumb, StrictEncode,
    StrictEnum, StrictSum, StrictType, StrictUnion, TypedRead, TypedWrite, VariantError,
    WriteUnion,
};

use crate::{OutputSeal, XOutputSeal, LIB_NAME_RGB_COMMIT};

pub const XCHAIN_BITCOIN_PREFIX: &str = "bc";
pub const XCHAIN_LIQUID_PREFIX: &str = "lq";

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(lowercase)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
pub enum Layer1 {
    #[strict_type(dumb)]
    Bitcoin = 0,
    Liquid = 1,
}

#[derive(Wrapper, WrapperMut, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[wrapper(Deref, FromStr, Display)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
pub struct XOutpoint(XChain<Outpoint>);

impl From<XOutputSeal> for XOutpoint {
    #[inline]
    fn from(seal: XOutputSeal) -> Self { seal.to_outpoint() }
}

impl XOutputSeal {
    /// Converts seal into a transaction outpoint.
    #[inline]
    pub fn to_outpoint(&self) -> XOutpoint { self.map_ref(OutputSeal::to_outpoint).into() }
}

#[cfg(feature = "serde")]
mod _serde {
    use serde_crate::de::Error;
    use serde_crate::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for XOutpoint {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_string())
            } else {
                self.0.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for XOutpoint {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                Self::from_str(&s).map_err(D::Error::custom)
            } else {
                XChain::<Outpoint>::deserialize(deserializer).map(Self)
            }
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(lowercase)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = repr, into_u8, try_from_u8)]
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "chain", content = "data")
)]
pub enum Impossible {}

impl TryFrom<u8> for Impossible {
    type Error = VariantError<u8>;

    fn try_from(_: u8) -> Result<Self, Self::Error> { panic!("must not be instantiated") }
}
impl From<Impossible> for u8 {
    fn from(_: Impossible) -> Self { unreachable!() }
}

impl StrictDumb for Impossible {
    fn strict_dumb() -> Self { panic!("must not be instantiated") }
}
impl StrictType for Impossible {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_RGB_COMMIT;
}
impl StrictSum for Impossible {
    const ALL_VARIANTS: &'static [(u8, &'static str)] = &[];
    fn variant_name(&self) -> &'static str { unreachable!() }
}
impl StrictEnum for Impossible {}
impl StrictEncode for Impossible {
    fn strict_encode<W: TypedWrite>(&self, _writer: W) -> io::Result<W> { unreachable!() }
}
impl StrictDecode for Impossible {
    fn strict_decode(_reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        panic!("must not be deserialized")
    }
}

impl Conceal for Impossible {
    type Concealed = Self;
    fn conceal(&self) -> Self::Concealed { unreachable!() }
}

impl Display for Impossible {
    fn fmt(&self, _: &mut Formatter<'_>) -> fmt::Result { unreachable!() }
}
impl FromStr for Impossible {
    type Err = Infallible;
    fn from_str(_: &str) -> Result<Self, Self::Err> { panic!("must not be parsed") }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct AltLayer1Set(TinyOrdSet<AltLayer1>);

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "chain", content = "data")
)]
pub enum XChain<T, X = Impossible> {
    Bitcoin(T),

    Liquid(T),

    Other(X),
}

impl<T: Ord, X: Ord> PartialOrd for XChain<T, X> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<T: Ord, X: Ord> Ord for XChain<T, X> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Bitcoin(t1), Self::Bitcoin(t2)) => t1.cmp(t2),
            (Self::Liquid(t1), Self::Liquid(t2)) => t1.cmp(t2),
            (Self::Bitcoin(_), _) => Ordering::Greater,
            (_, Self::Bitcoin(_)) => Ordering::Less,
            (Self::Liquid(_), _) => Ordering::Greater,
            (_, Self::Liquid(_)) => Ordering::Less,
            (Self::Other(x1), Self::Other(x2)) => x1.cmp(x2),
        }
    }
}

impl<T: Conceal, X: Conceal> Conceal for XChain<T, X> {
    type Concealed = XChain<T::Concealed, X::Concealed>;

    #[inline]
    fn conceal(&self) -> Self::Concealed { self.map2_ref(|t| t.conceal(), |x| x.conceal()) }
}

impl<T> StrictType for XChain<T>
where T: StrictDumb + StrictType
{
    const STRICT_LIB_NAME: &'static str = LIB_NAME_RGB_COMMIT;
}
impl<T> StrictSum for XChain<T>
where T: StrictDumb + StrictType
{
    const ALL_VARIANTS: &'static [(u8, &'static str)] = &[(0x00, "bitcoin"), (0x01, "liquid")];

    fn variant_name(&self) -> &'static str {
        match self {
            XChain::Bitcoin(_) => Self::ALL_VARIANTS[0].1,
            XChain::Liquid(_) => Self::ALL_VARIANTS[1].1,
            XChain::Other(_) => unreachable!(),
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
                .define_newtype::<T>(vname!(Self::ALL_VARIANTS[0].1))
                .define_newtype::<T>(vname!(Self::ALL_VARIANTS[1].1))
                .complete();
            Ok(match self {
                XChain::Bitcoin(t) => w.write_newtype(vname!(Self::ALL_VARIANTS[0].1), t)?,
                XChain::Liquid(t) => w.write_newtype(vname!(Self::ALL_VARIANTS[1].1), t)?,
                XChain::Other(_) => unreachable!(),
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

impl<T> XChain<T, Impossible> {
    pub fn layer1(&self) -> Layer1 {
        match self {
            XChain::Bitcoin(_) => Layer1::Bitcoin,
            XChain::Liquid(_) => Layer1::Liquid,
            XChain::Other(_) => unreachable!(),
        }
    }

    pub fn as_bp(&self) -> Bp<&T>
    where for<'a> &'a T: StrictDumb + StrictEncode + StrictDecode {
        match self {
            XChain::Bitcoin(t) => Bp::Bitcoin(t),
            XChain::Liquid(t) => Bp::Liquid(t),
            XChain::Other(_) => unreachable!(),
        }
    }

    pub fn into_bp(self) -> Bp<T>
    where T: StrictDumb + StrictEncode + StrictDecode {
        match self {
            XChain::Bitcoin(t) => Bp::Bitcoin(t),
            XChain::Liquid(t) => Bp::Liquid(t),
            XChain::Other(_) => unreachable!(),
        }
    }

    pub fn as_reduced_unsafe(&self) -> &T {
        match self {
            XChain::Bitcoin(t) | XChain::Liquid(t) => t,
            XChain::Other(_) => unreachable!(),
        }
    }

    /// Maps the value from one internal type into another.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> XChain<U> {
        match self {
            Self::Bitcoin(t) => XChain::Bitcoin(f(t)),
            Self::Liquid(t) => XChain::Liquid(f(t)),
            Self::Other(_) => unreachable!(),
        }
    }

    /// Maps the value from a reference on internal type into another.
    pub fn map_ref<U>(&self, f: impl FnOnce(&T) -> U) -> XChain<U> {
        match self {
            Self::Bitcoin(t) => XChain::Bitcoin(f(t)),
            Self::Liquid(t) => XChain::Liquid(f(t)),
            Self::Other(_) => unreachable!(),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may error.
    pub fn try_map<U, E>(self, f: impl FnOnce(T) -> Result<U, E>) -> Result<XChain<U>, E> {
        match self {
            Self::Bitcoin(t) => f(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f(t).map(XChain::Liquid),
            Self::Other(_) => unreachable!(),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may error.
    pub fn try_map_ref<U, E>(&self, f: impl FnOnce(&T) -> Result<U, E>) -> Result<XChain<U>, E> {
        match self {
            Self::Bitcoin(t) => f(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f(t).map(XChain::Liquid),
            Self::Other(_) => unreachable!(),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may result in an optional value.
    pub fn maybe_map<U>(self, f: impl FnOnce(T) -> Option<U>) -> Option<XChain<U>> {
        match self {
            Self::Bitcoin(t) => f(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f(t).map(XChain::Liquid),
            Self::Other(_) => unreachable!(),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may result in an optional value.
    pub fn maybe_map_ref<U>(&self, f: impl FnOnce(&T) -> Option<U>) -> Option<XChain<U>> {
        match self {
            Self::Bitcoin(t) => f(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f(t).map(XChain::Liquid),
            Self::Other(_) => unreachable!(),
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
            Self::Other(_) => unreachable!(),
        }
    }
}

impl<T, X> XChain<T, X> {
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
            XChain::Other(_) => false,
        }
    }

    /// Maps the value from one internal type into another.
    pub fn map2<U, Y>(self, f1: impl FnOnce(T) -> U, f2: impl FnOnce(X) -> Y) -> XChain<U, Y> {
        match self {
            Self::Bitcoin(t) => XChain::Bitcoin(f1(t)),
            Self::Liquid(t) => XChain::Liquid(f1(t)),
            Self::Other(x) => XChain::Other(f2(x)),
        }
    }

    /// Maps the value from a reference on internal type into another.
    pub fn map2_ref<U, Y>(
        &self,
        f1: impl FnOnce(&T) -> U,
        f2: impl FnOnce(&X) -> Y,
    ) -> XChain<U, Y> {
        match self {
            Self::Bitcoin(t) => XChain::Bitcoin(f1(t)),
            Self::Liquid(t) => XChain::Liquid(f1(t)),
            Self::Other(x) => XChain::Other(f2(x)),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may error.
    pub fn try_map2<U, Y, E>(
        self,
        f1: impl FnOnce(T) -> Result<U, E>,
        f2: impl FnOnce(X) -> Result<Y, E>,
    ) -> Result<XChain<U, Y>, E> {
        match self {
            Self::Bitcoin(t) => f1(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f1(t).map(XChain::Liquid),
            Self::Other(x) => f2(x).map(XChain::Other),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may error.
    pub fn try_map2_ref<U, Y, E>(
        &self,
        f1: impl FnOnce(&T) -> Result<U, E>,
        f2: impl FnOnce(&X) -> Result<Y, E>,
    ) -> Result<XChain<U, Y>, E> {
        match self {
            Self::Bitcoin(t) => f1(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f1(t).map(XChain::Liquid),
            Self::Other(x) => f2(x).map(XChain::Other),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may result in an optional value.
    pub fn maybe_map2<U, Y>(
        self,
        f1: impl FnOnce(T) -> Option<U>,
        f2: impl FnOnce(X) -> Option<Y>,
    ) -> Option<XChain<U, Y>> {
        match self {
            Self::Bitcoin(t) => f1(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f1(t).map(XChain::Liquid),
            Self::Other(x) => f2(x).map(XChain::Other),
        }
    }

    /// Maps the value from one internal type into another, covering cases which
    /// may result in an optional value.
    pub fn maybe_map2_ref<U, Y>(
        &self,
        f1: impl FnOnce(&T) -> Option<U>,
        f2: impl FnOnce(&X) -> Option<Y>,
    ) -> Option<XChain<U, Y>> {
        match self {
            Self::Bitcoin(t) => f1(t).map(XChain::Bitcoin),
            Self::Liquid(t) => f1(t).map(XChain::Liquid),
            Self::Other(x) => f2(x).map(XChain::Other),
        }
    }
}

impl<'a, T: Copy, X: Copy> XChain<&'a T, &'a X> {
    pub fn copied(self) -> XChain<T, X> { self.map2(|t| *t, |x| *x) }
}

impl<'a, T: Clone, X: Clone> XChain<&'a T, &'a X> {
    pub fn cloned(self) -> XChain<T, X> { self.map2(T::clone, X::clone) }
}

impl<T> XChain<Option<T>, Impossible> {
    pub fn transpose(self) -> Option<XChain<T>> {
        match self {
            XChain::Bitcoin(inner) => inner.map(XChain::Bitcoin),
            XChain::Liquid(inner) => inner.map(XChain::Liquid),
            XChain::Other(_) => unreachable!(),
        }
    }
}

impl<I: Iterator> Iterator for XChain<I, Impossible> {
    type Item = XChain<<I as Iterator>::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            XChain::Bitcoin(t) => t.next().map(XChain::Bitcoin),
            XChain::Liquid(t) => t.next().map(XChain::Liquid),
            XChain::Other(_) => unreachable!(),
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

impl<T: FromStr, X: FromStr> FromStr for XChain<T, X>
where
    T: StrictDumb + StrictEncode + StrictDecode,
    T::Err: Debug + Display,
    X: StrictDumb + StrictEncode + StrictDecode,
    X::Err: Debug + Display,
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

impl<T: Display, X: Display> Display for XChain<T, X>
where
    T: StrictDumb + StrictEncode + StrictDecode,
    X: StrictDumb + StrictEncode + StrictDecode,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            XChain::Bitcoin(t) => write!(f, "{XCHAIN_BITCOIN_PREFIX}:{t}"),
            XChain::Liquid(t) => write!(f, "{XCHAIN_LIQUID_PREFIX}:{t}"),
            XChain::Other(x) => Display::fmt(x, f),
        }
    }
}
