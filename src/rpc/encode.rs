// LNP/BP Rust Library
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
// Encoding strategies concept developed by
//     Martin Habovštiak <martin.habovstiak@gmail.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::convert::TryFrom;
use std::vec::IntoIter;
use zmq::Message;

use bitcoin::consensus::encode::{
    deserialize as consensus_deserialize, serialize as consensus_serialize,
};

use super::{Error, Multipart};
use crate::bp::ShortId;
#[cfg(feature = "use-rgb")]
use crate::csv::{self, network_deserialize, network_serialize};
use crate::strategy::Holder;

// 1. Encoding messages
pub trait MessageEncode
where
    Self: Sized,
{
    type Error: std::error::Error;
    fn into_message(self) -> Message;
    fn try_from_message(message: Message) -> Result<Self, Self::Error>;
}

/// This is a trick for rust compiler helping to distinguish types implementing
/// mutually-exclusive traits (required until negative trait impls will be there)
/// Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>
mod strategy {
    use std::fmt;

    // Defining strategies:
    /// Strategy used for encoding data structures that support encoding with
    /// bitcoin consensus rules (`bitcoin::consensus::encode`)
    pub enum BitcoinConsensus {}

    /// Strategy used for encoding data structures that support encoding with
    /// RGB network serialization rules
    #[cfg(feature = "use-rgb")]
    pub enum RGBStrategy {}

    /// Strategy used for encoding data structures that can be directly
    /// represented as `zmq::Message` with `TryFrom<Message>` and
    /// `Into<Message>` trait implementations
    pub enum Native {}

    /// Strategy used for custom implementation of data structure encoding
    pub trait Other {
        type Strategy: Clone + fmt::Debug + fmt::Display;
    }
}

// 1.1. Auto impl for bitcoin-serialized types
impl<T> MessageEncode for Holder<T, strategy::BitcoinConsensus>
where
    T: bitcoin::consensus::encode::Encodable + bitcoin::consensus::encode::Decodable,
{
    type Error = Error;
    fn into_message(self) -> Message {
        Message::from(consensus_serialize(&self.into_inner()))
    }
    fn try_from_message(message: Message) -> Result<Self, Self::Error> {
        Ok(Self::new(consensus_deserialize(&message)?))
    }
}

// 1.2. Auto impl for client-validation-serialized types
#[cfg(feature = "use-rgb")]
impl<T> MessageEncode for Holder<T, strategy::RGBStrategy>
where
    T: csv::serialize::Network,
{
    type Error = Error;
    fn into_message(self) -> Message {
        Message::from(network_serialize(&self.into_inner()).expect("Commitment serialize failed"))
    }
    fn try_from_message(message: Message) -> Result<Self, Self::Error> {
        Ok(Self::new(network_deserialize(&message)?))
    }
}

// 1.3. Auto impl for types defining own Message serialization rules with TryFrom/Into
impl<T> MessageEncode for Holder<T, strategy::Native>
where
    T: TryFrom<Message, Error = Error> + Into<Message>,
{
    type Error = Error;
    fn into_message(self) -> Message {
        self.into_inner().into()
    }
    fn try_from_message(message: Message) -> Result<Self, Self::Error> {
        Ok(Self::new(T::try_from(message)?))
    }
}

// 1.4. Blanket impl
impl<T> MessageEncode for T
where
    T: strategy::Other,
    Holder<T, <T as strategy::Other>::Strategy>: MessageEncode,
{
    type Error = <Holder<T, <T as strategy::Other>::Strategy> as MessageEncode>::Error;
    fn into_message(self) -> Message {
        Holder::new(self).into_message()
    }
    fn try_from_message(message: Message) -> Result<Self, Self::Error> {
        Ok(Holder::try_from_message(message)?.into_inner())
    }
}

// 1.5. Impl for bp::ShortId
impl MessageEncode for ShortId {
    type Error = Error;
    fn into_message(self) -> Message {
        Message::from(&self.into_u64().to_be_bytes()[..])
    }
    fn try_from_message(message: Message) -> Result<Self, Self::Error> {
        if message.len() != 8 {
            Err(Error::MalformedArgument)
        } else {
            let mut buf = [0u8; 8];
            buf.clone_from_slice(&message[..]);
            Ok(Self::from(u64::from_be_bytes(buf)))
        }
    }
}

// 2. Encoding multipart messages
pub trait MultipartEncode<T>: TryFrom<Multipart> + Into<Multipart> {
    fn into_multipart(self) -> Multipart {
        self.into()
    }
}

// Primitive type implementations
// 1. Vector
// We can't use wrapper; in the current version it does not support generics
//wrapper!(ReqVec<'a, T: ReqArg<'a>>, PhantomData<&'a Vec<T>>, Vec<T>,
//         doc="Wrapper around `Vec` supporting `Req` trait");
#[derive(Clone)]
pub struct VecEncoding<T: MessageEncode>(Vec<T>);

// repr(transparent) is not yet working for generics, so we have to implement manually
impl<T> VecEncoding<T>
where
    T: MessageEncode,
{
    pub fn new(vec: Vec<T>) -> Self {
        Self(vec)
    }
    pub fn into_iter(self) -> IntoIter<T> {
        self.0.into_iter()
    }
}

// repr(transparent) is not yet working for generics, so we have to implement manually
impl<T> IntoIterator for VecEncoding<T>
where
    T: MessageEncode,
{
    type Item = <Vec<T> as IntoIterator>::Item;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> MultipartEncode<T> for VecEncoding<T> where T: MessageEncode {}

impl<T> TryFrom<Multipart> for VecEncoding<T>
where
    T: MessageEncode,
{
    type Error = ();

    fn try_from(args: Multipart) -> Result<Self, Self::Error> {
        Ok(VecEncoding::new(args.into_iter().try_fold(
            Vec::<T>::new(),
            |mut vec, arg| {
                vec.push(T::try_from_message(arg).map_err(|_| ())?);
                Ok(vec)
            },
        )?))
    }
}

impl<T> From<VecEncoding<T>> for Multipart
where
    T: MessageEncode,
{
    fn from(vec: VecEncoding<T>) -> Self {
        vec.into_iter().map(T::into_message).collect()
    }
}
