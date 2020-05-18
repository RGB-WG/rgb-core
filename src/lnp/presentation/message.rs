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

use core::any::Any;
use core::convert::TryInto;
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use super::tlv;
use super::{Encode, Error, EvenOdd, Unmarshall, UnmarshallFn};
use crate::common::{AsAny, Wrapper};
use crate::lnp::presentation::tlv::Stream;
use crate::strict_encoding::{StrictDecode, StrictEncode};

wrapper!(
    Type,
    u16,
    doc = "Message type field value",
    derive = [Copy, PartialEq, Eq, PartialOrd, Ord, Hash]
);

impl EvenOdd for Type {}

#[derive(Debug, Display, Default)]
#[display_from(Debug)]
pub struct Payload(Vec<Arc<dyn Any>>);

impl<E> Encode<E> for Payload
where
    E: io::Write + 'static,
{
    type Error = Error;

    fn encode(&self, e: E) -> Result<usize, Self::Error> {
        self.0.into_iter().try_fold(0usize, |mut len, item| {
            let rec = item
                .downcast_ref::<Arc<dyn Encode<E, Error = Self::Error>>>()
                .ok_or(Error::NoEncoder)?;
            len += rec.encode(e)?;
            Ok(len)
        })
    }
}

pub trait Message: AsAny {
    fn get_type(&self) -> Type;

    fn to_type<T>(&self) -> T
    where
        Self: Sized,
        Type: Into<T>,
    {
        self.get_type().into()
    }

    fn try_to_type<T>(&self) -> Result<T, <Type as TryInto<T>>::Error>
    where
        Self: Sized,
        Type: TryInto<T>,
    {
        self.get_type().try_into()
    }

    fn get_payload(&self) -> Payload;
    fn get_tlvs(&self) -> tlv::Stream;
}

pub struct RawMessage {
    pub type_id: Type,
    pub payload: Vec<u8>,
}

impl AsAny for RawMessage {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Message for RawMessage {
    fn get_type(&self) -> Type {
        self.type_id
    }

    fn get_payload(&self) -> Payload {
        Payload(vec![Arc::new(self.payload.clone())])
    }

    fn get_tlvs(&self) -> Stream {
        Stream::new()
    }
}

impl<T, E> Encode<E> for T
where
    T: Message,
    E: io::Write + 'static,
{
    type Error = Error;

    fn encode(&self, mut e: E) -> Result<usize, Self::Error> {
        let mut len = self
            .get_type()
            .as_inner()
            .strict_encode(&mut e)
            .map_err(|_| Error::Io)?;
        len += self.get_payload().encode(&mut e)?;
        len += self.get_tlvs().encode(e)?;
        Ok(len)
    }
}

pub struct Unmarshaller<R>
where
    R: io::Read,
{
    known_types: BTreeMap<Type, UnmarshallFn<R, Error>>,
}

impl<R> Unmarshall<R, Arc<dyn Any>> for Unmarshaller<R>
where
    R: io::Read,
{
    type Error = Error;

    fn unmarshall(&self, mut reader: R) -> Result<Arc<dyn Any>, Self::Error> {
        let type_id = Type(u16::strict_decode(&mut reader).map_err(|_| Error::NoData)?);
        match self.known_types.get(&type_id) {
            None if type_id.is_even() => Err(Error::MessageEvenType),
            None => {
                let mut payload = Vec::new();
                reader.read_to_end(&mut payload)?;
                Ok(Arc::new(RawMessage { type_id, payload }))
            }
            Some(parser) => parser(&mut reader),
        }
    }
}

impl<R> Unmarshaller<R>
where
    R: io::Read,
{
    pub fn new() -> Self {
        Self {
            known_types: BTreeMap::new(),
        }
    }
}
