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

use bech32::{self, FromBase32, ToBase32};
use core::fmt::{Display, Formatter};
use core::str::FromStr;
use deflate::{write::DeflateEncoder, Compression};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serializer};
use std::convert::{TryFrom, TryInto};

use lnpbp::secp256k1zkp;
use lnpbp::strict_encoding::{
    self, strict_deserialize, strict_serialize, StrictDecode, StrictEncode,
};

use crate::{
    seal, Anchor, ContractId, Disclosure, Extension, Genesis, Schema, SchemaId,
    Transition,
};

/// Bech32 representation of generic RGB data, that can be generated from
/// some string basing on Bech32 HRP value.
#[derive(Clone, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", untagged)
)]
pub enum Bech32 {
    /// Pedersen commitment
    ///
    /// HRP: `pedersen`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    PedersenCommitment(secp256k1zkp::pedersen::Commitment),

    /// Bulletproofs
    ///
    /// HRP: `bulletproof`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    Bulletproof(secp256k1zkp::pedersen::RangeProof),

    /// Curve25519 public key
    ///
    /// HRP: `curve25519pk`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    Curve25519Pk(ed25519_dalek::PublicKey),

    /// Ed25519 signature
    ///
    /// HRP: `ed25519sign`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    Ed25519Sign(ed25519_dalek::Signature),

    /// Blinded UTXO for assigning RGB state to.
    ///
    /// HRP: `utxob`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    BlindedUtxo(seal::Confidential),

    /// RGB Schema ID (hash of the schema data).
    ///
    /// HRP: `sch`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    SchemaId(SchemaId),

    /// RGB Schema raw data (hash of the genesis).
    ///
    /// HRP: `schema`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    Schema(Schema),

    /// RGB Contract ID (hash of the genesis).
    ///
    /// HRP: `rgb`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    ContractId(ContractId),

    /// RGB Contract genesis raw data
    ///
    /// HRP: `genesis`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    Genesis(Genesis),

    /// Raw data of state transition under some RGB contract
    ///
    /// HRP: `transition`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    Transition(Transition),

    /// Raw data of state extension under some RGB contract
    ///
    /// HRP: `statex`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    Extension(Extension),

    /// Anchor data for some dterministic bitcoin commitment
    ///
    /// HRP: `anchor`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    Anchor(Anchor),

    /// Disclosure data revealing some specific confidential information about
    /// RGB contract
    ///
    /// HRP: `disclosure`
    #[from]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "to_bech32_str",
            deserialize_with = "from_bech32_str"
        )
    )]
    Disclosure(Disclosure),

    /// Binary data for unknown Bech32 HRPs
    Other(String, Vec<u8>),
}

impl Bech32 {
    /// HRP for a Bech32-encoded Pedersen commitment
    pub const HRP_PEDERSEN: &'static str = "pedersen";
    /// HRP for a Bech32-encoded blinded bulletproof range proof data
    pub const HRP_BULLETPROOF: &'static str = "bulletproof";
    /// HRP for a Bech32-encoded blinded bulletproof range proof data
    pub const HRP_CURVE25519OPK: &'static str = "curve25519pk";
    /// HRP for a Bech32-encoded blinded bulletproof range proof data
    pub const HRP_ED25519OSIGN: &'static str = "ed25519sign";
    /// HRP for a Bech32-encoded blinded UTXO data
    pub const HRP_OUTPOINT: &'static str = "utxob";

    /// Bech32 HRP for RGB schema ID encoding
    pub const HRP_SCHEMA_ID: &'static str = "sch";
    /// Bech32 HRP for RGB contract ID encoding
    pub const HRP_CONTRACT_ID: &'static str = "rgb";

    /// HRP for a Bech32-encoded raw RGB schema data
    pub const HRP_SCHEMA: &'static str = "schema";
    /// HRP for a Bech32-encoded raw RGB contract genesis data
    pub const HRP_GENESIS: &'static str = "genesis";
    /// HRP for a Bech32-encoded raw RGB state transition data
    pub const HRP_TRANSITION: &'static str = "transition";
    /// HRP for a Bech32-encoded raw RGB state extension data
    pub const HRP_EXTENSION: &'static str = "statex";
    /// HRP for a Bech32-encoded deterministic bitcoin commitments anchor data
    pub const HRP_ANCHOR: &'static str = "anchor";
    /// HRP for a Bech32-encoded RGB disclosure data
    pub const HRP_DISCLOSURE: &'static str = "disclosure";

    pub(self) const RAW_DATA_ENCODING_PLAIN: u8 = 0u8;
    pub(self) const RAW_DATA_ENCODING_DEFLATE: u8 = 1u8;

    /// Encoder for v0 of raw data encoding algorithm. Uses plain strict encoded
    /// data
    #[allow(dead_code)]
    pub(self) fn plain_encode(
        obj: &impl StrictEncode,
    ) -> Result<Vec<u8>, Error> {
        // We initialize writer with a version byte, indicating plain
        // algorithm used
        let mut writer = vec![Self::RAW_DATA_ENCODING_PLAIN];
        obj.strict_encode(&mut writer)?;
        Ok(writer)
    }

    /// Encoder for v1 of raw data encoding algorithm. Uses deflate
    pub(self) fn deflate_encode(
        obj: &impl StrictEncode,
    ) -> Result<Vec<u8>, Error> {
        // We initialize writer with a version byte, indicating deflation
        // algorithm used
        let writer = vec![Self::RAW_DATA_ENCODING_DEFLATE];
        let mut encoder = DeflateEncoder::new(writer, Compression::Best);
        obj.strict_encode(&mut encoder)?;
        Ok(encoder.finish().map_err(|_| Error::DeflateEncoding)?)
    }

    pub(self) fn raw_decode<T>(data: &impl AsRef<[u8]>) -> Result<T, Error>
    where
        T: StrictDecode,
    {
        let mut reader = data.as_ref();
        Ok(match u8::strict_decode(&mut reader)? {
            Self::RAW_DATA_ENCODING_PLAIN => T::strict_decode(&mut reader)?,
            Self::RAW_DATA_ENCODING_DEFLATE => {
                let decoded = inflate::inflate_bytes(&mut reader)
                    .map_err(|e| Error::InflateError(e))?;
                T::strict_decode(&decoded[..])?
            }
            unknown_ver => Err(Error::UnknownRawDataEncoding(unknown_ver))?,
        })
    }
}

/// Trait for types which data can be represented in form of Bech32 string
pub trait ToBech32 {
    /// Returns [`Bech32`] enum variant for this specific type
    fn to_bech32(&self) -> Bech32;

    /// Converts type to it's Bech32-encoded representation. Default
    /// implementation constructs [`Bech32`] object and converts it to string.
    fn to_bech32_string(&self) -> String {
        self.to_bech32().to_string()
    }
}

/// Trait for types that can be reconstructed from Bech32-encoded data tagged
/// with specific HRP
pub trait FromBech32
where
    Self: Sized,
{
    /// Unwraps [`Bech32`] enum data into a concrete type, if any, or fails with
    /// [`Error::WrongType`] otherwise
    fn from_bech32(bech32: Bech32) -> Result<Self, Error>;

    /// Tries to read Bech32-encoded data from `s` argument, checks it's type
    /// and constructs object if HRP corresponds to the type implementing this
    /// trait. Fails with [`Error`] type
    fn from_bech32_str(s: &str) -> Result<Self, Error> {
        Self::from_bech32(s.parse()?)
    }
}

impl<T> ToBech32 for T
where
    T: Into<Bech32> + Clone,
{
    fn to_bech32(&self) -> Bech32 {
        self.clone().into()
    }
}

impl<T> FromBech32 for T
where
    T: TryFrom<Bech32, Error = Error>,
{
    fn from_bech32(bech32: Bech32) -> Result<Self, Error> {
        Self::try_from(bech32)
    }
}

/// Errors generated by Bech32 conversion functions (both parsing and
/// type-specific conversion errors)
#[derive(Clone, PartialEq, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// Bech32 string parse error: {0}
    #[from]
    Bech32Error(::bech32::Error),

    /// Payload data parse error: {0}
    #[from]
    WrongData(strict_encoding::Error),

    /// Requested object type does not match used Bech32 HRP
    WrongType,

    /// Provided raw data use unknown encoding version {0}
    UnknownRawDataEncoding(u8),

    /// Can not encode raw data with DEFLATE algorithm
    DeflateEncoding,

    /// Error inflating compressed data from payload: {0}
    InflateError(String),
}

impl From<Error> for ::core::fmt::Error {
    fn from(_: Error) -> Self {
        ::core::fmt::Error
    }
}

impl TryFrom<Bech32> for secp256k1zkp::pedersen::Commitment {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::PedersenCommitment(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for secp256k1zkp::pedersen::RangeProof {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::Bulletproof(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for ed25519_dalek::PublicKey {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::Curve25519Pk(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for ed25519_dalek::Signature {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::Ed25519Sign(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for seal::Confidential {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::BlindedUtxo(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for ContractId {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::ContractId(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for SchemaId {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::SchemaId(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for Schema {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::Schema(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for Genesis {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::Genesis(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for Extension {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::Extension(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for Transition {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::Transition(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for Anchor {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::Anchor(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl TryFrom<Bech32> for Disclosure {
    type Error = Error;

    fn try_from(bech32: Bech32) -> Result<Self, Self::Error> {
        match bech32 {
            Bech32::Disclosure(obj) => Ok(obj),
            _ => Err(Error::WrongType),
        }
    }
}

impl FromStr for Bech32 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, data) = bech32::decode(&s)?;
        let data = Vec::<u8>::from_base32(&data)?;

        Ok(match hrp {
            x if x == Self::HRP_PEDERSEN => {
                Self::PedersenCommitment(strict_deserialize(&data)?)
            }
            x if x == Self::HRP_BULLETPROOF => {
                Self::Bulletproof(strict_deserialize(&data)?)
            }
            x if x == Self::HRP_CURVE25519OPK => {
                Self::Curve25519Pk(strict_deserialize(&data)?)
            }
            x if x == Self::HRP_ED25519OSIGN => {
                Self::Ed25519Sign(strict_deserialize(&data)?)
            }
            x if x == Self::HRP_OUTPOINT => {
                Self::BlindedUtxo(strict_deserialize(&data)?)
            }
            x if x == Self::HRP_SCHEMA_ID => {
                Self::SchemaId(strict_deserialize(&data)?)
            }
            x if x == Self::HRP_CONTRACT_ID => {
                Self::ContractId(strict_deserialize(&data)?)
            }
            x if x == Self::HRP_SCHEMA => {
                Self::Schema(Bech32::raw_decode(&data)?)
            }
            x if x == Self::HRP_GENESIS => {
                Self::Genesis(Bech32::raw_decode(&data)?)
            }
            x if x == Self::HRP_EXTENSION => {
                Self::Extension(Bech32::raw_decode(&data)?)
            }
            x if x == Self::HRP_TRANSITION => {
                Self::Transition(Bech32::raw_decode(&data)?)
            }
            x if x == Self::HRP_ANCHOR => {
                Self::Anchor(Bech32::raw_decode(&data)?)
            }
            x if x == Self::HRP_DISCLOSURE => {
                Self::Disclosure(Bech32::raw_decode(&data)?)
            }
            other => Self::Other(other, data),
        })
    }
}

impl Display for Bech32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        let (hrp, data) = match self {
            Self::PedersenCommitment(obj) => {
                (Self::HRP_PEDERSEN, strict_serialize(obj)?)
            }
            Self::Bulletproof(obj) => {
                (Self::HRP_BULLETPROOF, strict_serialize(obj)?)
            }
            Self::Curve25519Pk(obj) => {
                (Self::HRP_CURVE25519OPK, strict_serialize(obj)?)
            }
            Self::Ed25519Sign(obj) => {
                (Self::HRP_ED25519OSIGN, strict_serialize(obj)?)
            }
            Self::BlindedUtxo(obj) => {
                (Self::HRP_OUTPOINT, strict_serialize(obj)?)
            }
            Self::SchemaId(obj) => {
                (Self::HRP_SCHEMA_ID, strict_serialize(obj)?)
            }
            Self::ContractId(obj) => {
                (Self::HRP_CONTRACT_ID, strict_serialize(obj)?)
            }
            Self::Schema(obj) => {
                (Self::HRP_SCHEMA, Bech32::deflate_encode(obj)?)
            }
            Self::Genesis(obj) => {
                (Self::HRP_GENESIS, Bech32::deflate_encode(obj)?)
            }
            Self::Extension(obj) => {
                (Self::HRP_EXTENSION, Bech32::deflate_encode(obj)?)
            }
            Self::Transition(obj) => {
                (Self::HRP_TRANSITION, Bech32::deflate_encode(obj)?)
            }
            Self::Anchor(obj) => {
                (Self::HRP_ANCHOR, Bech32::deflate_encode(obj)?)
            }
            Self::Disclosure(obj) => {
                (Self::HRP_DISCLOSURE, Bech32::deflate_encode(obj)?)
            }
            Self::Other(hrp, obj) => (hrp.as_ref(), obj.clone()),
        };
        let b = ::bech32::encode(hrp, data.to_base32())
            .map_err(|_| ::core::fmt::Error)?;
        b.fmt(f)
    }
}

impl FromStr for Schema {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bech32::from_str(s)?.try_into()
    }
}

impl FromStr for Genesis {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bech32::from_str(s)?.try_into()
    }
}

impl FromStr for Extension {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bech32::from_str(s)?.try_into()
    }
}

impl FromStr for Transition {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bech32::from_str(s)?.try_into()
    }
}

impl FromStr for Anchor {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bech32::from_str(s)?.try_into()
    }
}

impl FromStr for Disclosure {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bech32::from_str(s)?.try_into()
    }
}

impl FromStr for ContractId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bech32::from_str(s)?.try_into()
    }
}

impl FromStr for SchemaId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bech32::from_str(s)?.try_into()
    }
}

// TODO: Enable after removal of the default `Display` and `FromStr`
//       implementations for hash-derived types
/*
impl FromStr for seal::Confidential {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Bech32::from_str(s).try_into()
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

impl Display for Extension {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        Bech32::Extension(self.clone()).fmt(f)
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

/// Serializes type to a Bech32 string.
#[cfg(feature = "serde")]
pub fn to_bech32_str<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: ToBech32,
    S: Serializer,
{
    serializer.serialize_str(&buffer.to_bech32_string())
}

/// Deserializes a Bech32 to a `Vec<u8>`.
#[cfg(feature = "serde")]
pub fn from_bech32_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromBech32,
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        T::from_bech32_str(&string)
            .map_err(|err| Error::custom(err.to_string()))
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use amplify::DumbDefault;
    use lnpbp::bp::blind::OutpointReveal;
    use lnpbp::client_side_validation::Conceal;

    #[test]
    fn test_bech32_outpoint() {
        let obj = seal::Revealed::TxOutpoint(OutpointReveal {
            blinding: 11645300769465024575,
            txid: "42332750017e9547abf0e975ec92832d8cfe3fbbaa78cec434d22175d5b6e6d9"
                .parse().unwrap(),
            vout: 3,
        }).conceal();
        let bech32 = obj.to_bech32_string();
        assert_eq!(
            bech32,
            "utxob1u4femdvdeztkn5fxvd7zyxe5jzjwh5xgry8lqm2wvyxd2z9pc7vq4k8z0f"
        );
        let decoded = seal::Confidential::from_bech32_str(&bech32).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_bech32_schema_id() {
        let obj = Schema::default().schema_id();
        let bech32 = obj.to_bech32_string();
        assert_eq!(
            bech32,
            "sch1m2xu4jnkhj6683kas3fj67rgp7mrudl6ydrqrg7550cda242e6wsk7a6yd"
        );
        let decoded = SchemaId::from_bech32_str(&bech32).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_bech32_contract_id() {
        let obj = Genesis::default().contract_id();
        let bech32 = obj.to_bech32_string();
        assert_eq!(
            bech32,
            "rgb1eddz5h6cymzmnq4xv4r7w5an2gtdzmlhjcfpzkq3dc7wtn9varsskdzvun"
        );
        let decoded = ContractId::from_bech32_str(&bech32).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_bech32_schema() {
        let obj = Schema::default();
        let bech32 = format!("{}", obj);
        assert_eq!(bech32, "schema1q93jqycqqqu3u9qr");
        let decoded = Schema::from_bech32_str(&bech32).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_bech32_genesis() {
        let obj = Genesis::default();
        let bech32 = format!("{}", obj);
        assert_eq!(
            bech32,
            "genesis1q93jqqqcr8nrzlyn0dnem09cv9ylnqhy74rfka5l4jvlluurhj8f86ktug\
            vc68zqx4kqe3vea9u6jf2uenn36crvy6rf9f9a20m5cegynvqsgjjvzqp4jxy2n4pfe\
            7gcstqu59yuxf9e9uen70s0eckyjt7w9rzvs6r47k2p4gy4jrf3rvxqq4ltfvr"
        );
        let decoded = Genesis::from_bech32_str(&bech32).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_bech32_transition() {
        let obj = Transition::default();
        let bech32 = format!("{}", obj);
        assert_eq!(bech32, "transition1q935qqsqpr0f9t");
        let decoded = Transition::from_bech32_str(&bech32).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_bech32_extension() {
        let obj = Extension::default();
        let bech32 = format!("{}", obj);
        assert_eq!(bech32, "statex1q93jqqgqqq2mqg2z");
        let decoded = Extension::from_bech32_str(&bech32).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_bech32_anchor() {
        let obj = Anchor::dumb_default();
        let bech32 = format!("{}", obj);
        assert_eq!(
            bech32,
            "anchor1q93jqryc9tm6t40ahjehkn0gs2j2ne76h8vejehlhxkhknhrvmj203ngky0\
            7yvccqq8jzvcv"
        );
        let decoded = Anchor::from_bech32_str(&bech32).unwrap();
        assert_eq!(obj, decoded);
    }

    #[test]
    fn test_bech32_disclosure() {
        let obj = Disclosure::default();
        let bech32 = format!("{}", obj);
        assert_eq!(bech32, "disclosure1qypsq90a83g");
        let decoded = Disclosure::from_bech32_str(&bech32).unwrap();
        assert_eq!(obj, decoded);
    }
}
