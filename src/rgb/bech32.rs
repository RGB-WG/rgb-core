// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use ::bech32::{self, FromBase32, ToBase32};
use ::core::fmt::{Display, Formatter};
use ::core::str::{pattern::Pattern, FromStr};

use crate::rgb::{seal, Anchor, ContractId, Disclosure, Genesis, Schema, SchemaId, Transition};
use crate::strict_encoding::{self, strict_decode, strict_encode};

#[derive(Clone, Debug)]
pub enum Bech32 {
    Outpoint(seal::Confidential),
    ContractId(ContractId),
    Schema(Schema),
    SchemaId(SchemaId),
    Genesis(Genesis),
    Transition(Transition),
    Anchor(Anchor),
    Disclosure(Disclosure),
    Other(String, Vec<u8>),
}

impl Bech32 {
    pub const HRP: &'static str = "rgb";
    pub const HRP_OUTPOINT: &'static str = "txo";
    pub const HRP_ID: &'static str = "rgb";
    pub const HRP_SCHEMA: &'static str = "schema_data";
    pub const HRP_SCHEMA_ID: &'static str = "schema";
    pub const HRP_GENESIS: &'static str = "genesis";
    pub const HRP_TRANSITION: &'static str = "rgb_ts";
    pub const HRP_ANCHOR: &'static str = "rgb_anc";
    pub const HRP_DISCLOSURE: &'static str = "rgb_disclosure";
}

pub trait ToBech32 {
    fn to_bech32(&self) -> Bech32;
    fn to_bech32_string(&self) -> String {
        self.to_bech32().to_string()
    }
}

impl ToBech32 for seal::Confidential {
    fn to_bech32(&self) -> Bech32 {
        Bech32::Outpoint(self.clone())
    }
}

impl ToBech32 for ContractId {
    fn to_bech32(&self) -> Bech32 {
        Bech32::ContractId(self.clone())
    }
}

impl ToBech32 for Schema {
    fn to_bech32(&self) -> Bech32 {
        Bech32::Schema(self.clone())
    }
}

impl ToBech32 for SchemaId {
    fn to_bech32(&self) -> Bech32 {
        Bech32::SchemaId(self.clone())
    }
}
impl ToBech32 for Genesis {
    fn to_bech32(&self) -> Bech32 {
        Bech32::Genesis(self.clone())
    }
}

impl ToBech32 for Transition {
    fn to_bech32(&self) -> Bech32 {
        Bech32::Transition(self.clone())
    }
}

impl ToBech32 for Anchor {
    fn to_bech32(&self) -> Bech32 {
        Bech32::Anchor(self.clone())
    }
}

impl ToBech32 for Disclosure {
    fn to_bech32(&self) -> Bech32 {
        Bech32::Disclosure(self.clone())
    }
}

#[derive(Debug, Display, From, Error)]
#[display_from(Debug)]
pub enum Error {
    WrongHrp(String),

    #[derive_from]
    Bech32Error(::bech32::Error),

    #[derive_from]
    WrongData(strict_encoding::Error),

    WrongType,

    // TODO: Remove once the default `Display` implementation for
    //       hash-derived types is removed
    #[derive_from(::bitcoin_hashes::hex::Error)]
    HexError,
}

impl FromStr for Bech32 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, data) = bech32::decode(&s)?;
        let data = Vec::<u8>::from_base32(&data)?;

        Ok(match hrp {
            x if x == Self::HRP_OUTPOINT => Self::Outpoint(strict_decode(&data)?),
            x if x == Self::HRP_ID => Self::ContractId(strict_decode(&data)?),
            x if x == Self::HRP_SCHEMA => Self::Schema(strict_decode(&data)?),
            x if x == Self::HRP_SCHEMA_ID => Self::SchemaId(strict_decode(&data)?),
            x if x == Self::HRP_GENESIS => Self::Genesis(strict_decode(&data)?),
            x if x == Self::HRP_TRANSITION => Self::Transition(strict_decode(&data)?),
            x if x == Self::HRP_ANCHOR => Self::Anchor(strict_decode(&data)?),
            x if x == Self::HRP_DISCLOSURE => Self::Disclosure(strict_decode(&data)?),
            other if Self::HRP.is_prefix_of(&other) => Self::Other(other, data),
            other => Err(Error::WrongHrp(other))?,
        })
    }
}

impl Display for Bech32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        let (hrp, data) = match self {
            Self::Outpoint(obj) => (Self::HRP_OUTPOINT, strict_encode(obj)),
            Self::ContractId(obj) => (Self::HRP_ID, strict_encode(obj)),
            Self::Schema(obj) => (Self::HRP_SCHEMA, strict_encode(obj)),
            Self::SchemaId(obj) => (Self::HRP_SCHEMA_ID, strict_encode(obj)),
            Self::Genesis(obj) => (Self::HRP_GENESIS, strict_encode(obj)),
            Self::Transition(obj) => (Self::HRP_TRANSITION, strict_encode(obj)),
            Self::Anchor(obj) => (Self::HRP_ANCHOR, strict_encode(obj)),
            Self::Disclosure(obj) => (Self::HRP_DISCLOSURE, strict_encode(obj)),
            Self::Other(hrp, obj) => (hrp.as_ref(), Ok(obj.clone())),
        };
        let data = data.map_err(|_| ::core::fmt::Error)?;
        let b = ::bech32::encode(hrp, data.to_base32()).map_err(|_| ::core::fmt::Error)?;
        b.fmt(f)
    }
}

impl FromStr for seal::Confidential {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Bech32::from_str(s)? {
            Bech32::Outpoint(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl FromStr for ContractId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Bech32::from_str(s)? {
            Bech32::ContractId(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl FromStr for SchemaId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Bech32::from_str(s)? {
            Bech32::SchemaId(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl FromStr for Schema {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Bech32::from_str(s)? {
            Bech32::Schema(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl FromStr for Genesis {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Bech32::from_str(s)? {
            Bech32::Genesis(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl FromStr for Transition {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Bech32::from_str(s)? {
            Bech32::Transition(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl FromStr for Anchor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Bech32::from_str(s)? {
            Bech32::Anchor(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl FromStr for Disclosure {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Bech32::from_str(s)? {
            Bech32::Disclosure(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

// TODO: Enable after removal of the default `Display` implementation for
//       hash-derived types
/*
impl Display for seal::Confidential {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        Bech32::Outpoint(self.clone()).fmt(f)
    }
}

impl Display for ContractId {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        Bech32::ContractId(self.clone()).fmt(f)
    }
}

impl Display for SchemaId {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        Bech32::SchemaId(self.clone()).fmt(f)
    }
}
 */

impl Display for Schema {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        Bech32::Schema(self.clone()).fmt(f)
    }
}

impl Display for Genesis {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        Bech32::Genesis(self.clone()).fmt(f)
    }
}

impl Display for Transition {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        Bech32::Transition(self.clone()).fmt(f)
    }
}

impl Display for Anchor {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        Bech32::Anchor(self.clone()).fmt(f)
    }
}

impl Display for Disclosure {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        Bech32::Disclosure(self.clone()).fmt(f)
    }
}
