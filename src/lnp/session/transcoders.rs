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

use amplify::Bipolar;
use std::borrow::Borrow;

use crate::lnp::transport::{FRAME_PREFIX_SIZE, FRAME_SUFFIX_SIZE};
#[cfg(feature = "lightning")]
use lightning::ln::peers::{
    encryption::{Decryptor, Encryptor},
    handshake::CompletedHandshakeInfo,
};

#[cfg(feature = "lightning")]
pub struct Transcoder(CompletedHandshakeInfo);

pub trait Encrypt {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8>;
}

pub trait Decrypt {
    type Error: ::std::error::Error;

    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error>;
}

pub trait Transcode: Bipolar + Encrypt + Decrypt {
    type Encryptor: Encrypt;
    type Decryptor: Decrypt;
}

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error,
)]
#[display(Debug)]
pub struct DecryptionError;

#[cfg(feature = "lightning")]
impl Encrypt for Encryptor {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        self.encrypt_buf(buffer.borrow())
    }
}

#[cfg(feature = "lightning")]
impl Decrypt for Decryptor {
    type Error = DecryptionError;

    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        match self.decrypt_next(buffer.borrow()) {
            Ok((Some(data), _)) => Ok(data),
            _ => Err(DecryptionError),
        }
    }
}

#[cfg(feature = "lightning")]
impl Encrypt for Transcoder {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        self.0.encryptor.encrypt_buf(buffer.borrow())
    }
}

#[cfg(feature = "lightning")]
impl Decrypt for Transcoder {
    type Error = DecryptionError;

    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        match self.0.decryptor.decrypt_next(buffer.borrow()) {
            Ok((Some(data), _)) => Ok(data),
            _ => Err(DecryptionError),
        }
    }
}

#[cfg(feature = "lightning")]
impl Transcode for Transcoder {
    type Encryptor = Encryptor;
    type Decryptor = Decryptor;
}

#[cfg(feature = "lightning")]
impl Bipolar for Transcoder {
    type Left = <Self as Transcode>::Encryptor;
    type Right = <Self as Transcode>::Decryptor;

    /// Creates conduit by joining encrypting and decrypting parts
    fn join(encryptor: Self::Left, decryptor: Self::Right) -> Self {
        // TODO: (new) figure out what to do with `their_node_id` field
        Self(CompletedHandshakeInfo {
            decryptor,
            encryptor,
            their_node_id: bitcoin::secp256k1::PublicKey::from_slice(
                &[0u8; 33],
            )
            .unwrap(),
        })
    }

    /// Splits conduit into an encrypting and decrypting parts
    fn split(self) -> (Self::Left, Self::Right) {
        (self.0.encryptor, self.0.decryptor)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
pub struct NoEncryption;

/// Impossible error type
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display(Debug)]
// TODO: (v0.2) Add session-level errors
pub struct NoError;

impl From<NoError> for crate::lnp::transport::Error {
    fn from(_: NoError) -> Self {
        panic!("NoError can't happen!")
    }
}

impl Encrypt for NoEncryption {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        let mut data = vec![];
        let buffer = buffer.borrow().to_vec();
        // TODO: (v0.2) check for length value to fit u16
        let len = buffer.len() as u16;
        data.extend(&len.to_le_bytes());
        data.extend(&[0u8; FRAME_PREFIX_SIZE - 2]);
        data.extend(buffer);
        data.extend(&[0u8; FRAME_SUFFIX_SIZE]);
        data
    }
}

impl Decrypt for NoEncryption {
    type Error = NoError;
    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        // TODO: (v0.2) check for message length to be equal to the length
        //       from the frame
        let buffer = buffer.borrow();
        let len = buffer.len() - FRAME_SUFFIX_SIZE;
        Ok(buffer[FRAME_PREFIX_SIZE..len].to_vec())
    }
}

impl Transcode for NoEncryption {
    type Encryptor = Self;
    type Decryptor = Self;
}

impl Bipolar for NoEncryption {
    type Left = <Self as Transcode>::Encryptor;
    type Right = <Self as Transcode>::Decryptor;

    fn join(encryptor: Self::Left, _decryptor: Self::Right) -> Self {
        encryptor as NoEncryption
    }

    fn split(self) -> (Self::Left, Self::Right) {
        (self.clone(), self)
    }
}
