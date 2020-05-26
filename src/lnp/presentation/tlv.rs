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
use core::borrow::Borrow;
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use lightning::util::ser::{BigSize, Readable};

use super::{Error, EvenOdd, Unmarshall, UnmarshallFn};
use crate::lnp::LNP_MSG_MAX_LEN;
use lightning::ln::msgs::DecodeError;

wrapper!(
    Type,
    u64,
    doc = "TLV type field value",
    derive = [Copy, PartialEq, Eq, PartialOrd, Ord, Hash]
);
wrapper!(
    RawRecord,
    Vec<u8>,
    doc = "Unknown TLV record represented by raw bytes",
    derive = [PartialEq, Eq, PartialOrd, Ord, Hash]
);

impl EvenOdd for Type {}

#[derive(Debug, Display, Default)]
#[display_from(Debug)]
pub struct Stream(BTreeMap<Type, Arc<dyn Any>>);

impl Stream {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn get<T: Any>(&self, type_id: &Type) -> Option<&T> {
        self.0.get(type_id).and_then(|v| v.downcast_ref::<T>())
    }

    #[inline]
    pub fn insert<T: Any>(&mut self, type_id: Type, value: T) -> bool {
        self.0.insert(type_id, Arc::new(value)).is_none()
    }

    #[inline]
    pub fn contains_key(&self, type_id: &Type) -> bool {
        self.0.contains_key(type_id)
    }
}

pub struct Unmarshaller {
    known_types: BTreeMap<Type, UnmarshallFn<Error>>,
    raw_parser: UnmarshallFn<Error>,
}

impl Unmarshall for Unmarshaller {
    type Data = Stream;
    type Error = Error;

    fn unmarshall(&self, data: &dyn Borrow<[u8]>) -> Result<Stream, Self::Error> {
        let mut reader = io::Cursor::new(data.borrow());
        let mut tlv = Stream::new();
        let mut prev_type_id = Type(0);
        loop {
            match BigSize::read(&mut reader).map(|big_size| Type(big_size.0)) {
                // if zero bytes remain before parsing a type
                // MUST stop parsing the tlv_stream
                Err(DecodeError::ShortRead) => break Ok(tlv),

                // The following rule is handled by BigSize type:
                // if a type or length is not minimally encoded
                // MUST fail to parse the tlv_stream.
                Err(err) => break Err(Error::from(err)),

                // if decoded types are not monotonically-increasing
                // MUST fail to parse the tlv_stream.
                Ok(type_id) if type_id > prev_type_id => break Err(Error::TlvStreamWrongOrder),

                // if decoded `type`s are not strictly-increasing
                // (including situations when two or more occurrences of the \
                // same `type` are met)
                // MUST fail to parse the tlv_stream.
                Ok(type_id) if tlv.contains_key(&type_id) => {
                    break Err(Error::TlvStreamDuplicateItem)
                }

                Ok(type_id) => {
                    let rec = if let Some(parser) = self.known_types.get(&type_id) {
                        // if type is known:
                        // MUST decode the next length bytes using the known
                        // encoding for type.
                        // The rest of rules MUST be supported by the parser:
                        // - if length is not exactly equal to that required for
                        //   the known encoding for type
                        //   MUST fail to parse the tlv_stream.
                        // - if variable-length fields within the known encoding
                        //   for type are not minimal
                        //   MUST fail to parse the tlv_stream.
                        parser(&mut reader)?
                    }
                    // otherwise, if type is unknown:
                    // if type is even:
                    // MUST fail to parse the tlv_stream.
                    else if type_id.is_even() {
                        break Err(Error::TlvRecordEvenType);
                    }
                    // otherwise, if type is odd:
                    // MUST discard the next length bytes.
                    else {
                        // Here we are actually not discarding the bytes but
                        // rather store them for an upstream users of the
                        // library which may know the meaning of the bytes
                        (self.raw_parser)(&mut reader)?
                    };
                    tlv.insert(type_id, rec);
                    prev_type_id = type_id;
                }
            }
        }
    }
}

impl Unmarshaller {
    pub fn new() -> Self {
        Self {
            known_types: BTreeMap::new(),
            raw_parser: Unmarshaller::raw_parser,
        }
    }

    fn raw_parser(mut reader: &mut dyn io::Read) -> Result<Arc<dyn Any>, Error> {
        let len = BigSize::read(&mut reader)?.0 as usize;

        // if length exceeds the number of bytes remaining in the message
        // MUST fail to parse the tlv_stream
        // Here we don't known how many bytes are remaining, but we can be
        // sure that this number is below Lightning message size limit, so we
        // check against this conditions to make sure we are not attacked
        // with excessive memory allocation vector. The actual condition from
        // BOLT-2 is checked during `read_exact` call below: if the length
        // exceeds the number of bytes left in the message it will return
        // a error
        if len > LNP_MSG_MAX_LEN {
            Err(Error::TlvRecordInvalidLen)?;
        }

        let mut buf = vec![0u8; len];
        reader
            .read_exact(&mut buf[..])
            .map_err(|_| Error::TlvRecordInvalidLen)?;

        let rec = RawRecord(buf.to_vec());
        Ok(Arc::new(rec))
    }
}
