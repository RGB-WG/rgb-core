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

use amplify::{AsAny, Wrapper};
use core::any::Any;
use core::borrow::Borrow;
use core::convert::TryInto;
use core::marker::PhantomData;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::Arc;

use super::tlv;
use super::{
    Error, EvenOdd, LightningEncode, UnknownTypeError, Unmarshall, UnmarshallFn,
};
use crate::strict_encoding::StrictDecode;

/// Message type field value
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Display,
    Debug,
    From,
)]
#[display(inner)]
#[wrapper(LowerHex, UpperHex, Octal, FromStr)]
pub struct TypeId(u16);

impl EvenOdd for TypeId {}

#[derive(Clone, Debug, Display)]
#[display(Debug)]
pub struct Source(Vec<Arc<dyn Any>>);

pub trait Extract: AsAny {
    fn get_type(&self) -> TypeId;

    fn to_type<T>(&self) -> T
    where
        Self: Sized,
        TypeId: Into<T>,
    {
        self.get_type().into()
    }

    fn try_to_type<T>(&self) -> Result<T, <TypeId as TryInto<T>>::Error>
    where
        Self: Sized,
        TypeId: TryInto<T>,
    {
        self.get_type().try_into()
    }

    fn get_payload(&self) -> Source;

    fn get_tlvs(&self) -> tlv::Stream;
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, AsAny)]
#[display(Debug)]
pub struct Payload {
    pub type_id: TypeId,
    pub payload: Vec<u8>,
}

impl Extract for Payload {
    fn get_type(&self) -> TypeId {
        self.type_id
    }

    fn get_payload(&self) -> Source {
        Source(vec![Arc::new(self.payload.clone())])
    }

    fn get_tlvs(&self) -> tlv::Stream {
        tlv::Stream::new()
    }
}

impl LightningEncode for Payload {
    fn lightning_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, io::Error> {
        Ok(self.type_id.to_inner().lightning_encode(&mut e)?
            + e.write(&self.payload)?)
    }
}

pub trait TypedEnum
where
    Self: Sized + Clone,
{
    fn try_from_type(
        type_id: TypeId,
        data: &dyn Any,
    ) -> Result<Self, UnknownTypeError>;
    fn get_type(&self) -> TypeId;
    fn get_payload(&self) -> Vec<u8>;
    fn serialize(&self) -> Vec<u8>;
}

impl<T> From<T> for Payload
where
    T: TypedEnum,
{
    fn from(msg: T) -> Self {
        Payload {
            type_id: msg.get_type(),
            payload: msg.get_payload(),
        }
    }
}

pub struct Unmarshaller<T>
where
    T: TypedEnum,
{
    known_types: BTreeMap<TypeId, UnmarshallFn<Error>>,
    _phantom: PhantomData<T>,
}

impl<T> Unmarshall for Unmarshaller<T>
where
    T: TypedEnum,
{
    type Data = Arc<T>;
    type Error = Error;

    fn unmarshall(
        &self,
        data: &dyn Borrow<[u8]>,
    ) -> Result<Self::Data, Self::Error> {
        let mut reader = io::Cursor::new(data.borrow());
        let type_id =
            TypeId(u16::strict_decode(&mut reader).map_err(|_| Error::NoData)?);
        match self.known_types.get(&type_id) {
            None if type_id.is_even() => Err(Error::MessageEvenType),
            None => {
                let mut payload = Vec::new();
                reader
                    .read_to_end(&mut payload)
                    .map_err(|e| Error::LightningEncoding(e.into()))?;
                Ok(Arc::new(T::try_from_type(
                    type_id,
                    &Payload { type_id, payload },
                )?))
            }
            Some(parser) => parser(&mut reader).and_then(|data| {
                Ok(Arc::new(T::try_from_type(type_id, &*data)?))
            }),
        }
    }
}

impl<T> Unmarshaller<T>
where
    T: TypedEnum,
{
    pub fn new(known_types: BTreeMap<u16, UnmarshallFn<Error>>) -> Self {
        Self {
            known_types: known_types
                .into_iter()
                .map(|(t, f)| (TypeId(t), f))
                .collect(),
            _phantom: PhantomData,
        }
    }
}
