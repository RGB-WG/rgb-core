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

use std::borrow::Borrow;

use lightning::ln::peers::conduit::{Conduit as Transcoder, Decryptor, Encryptor};
//use lightning::ln::peers::handshake::PeerHandshake;

pub trait Encrypt {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8>;
}

pub trait Decrypt {
    type Error: ::std::error::Error;

    fn decrypt(&mut self, buffer: impl Borrow<[u8]>) -> Result<Vec<u8>, Self::Error>;
}

pub trait Transcode {
    type Encryptor: Encrypt;
    type Decryptor: Decrypt;

    /// Creates conduit by joining encrypting and decrypting parts
    fn join(encryptor: Self::Encryptor, decryptor: Self::Decryptor) -> Self;

    /// Splits conduit into an encrypting and decrypting parts
    fn split(self) -> (Self::Encryptor, Self::Decryptor);
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display_from(Debug)]
pub struct DecryptionError;

impl Encrypt for Encryptor {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        unimplemented!()
    }
}

impl Decrypt for Decryptor {
    type Error = DecryptionError;

    fn decrypt(&mut self, buffer: impl Borrow<[u8]>) -> Result<Vec<u8>, Self::Error> {
        unimplemented!()
    }
}

impl Encrypt for Transcoder {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        unimplemented!()
    }
}

impl Transcode for Transcoder {
    type Encryptor = Encryptor;
    type Decryptor = Decryptor;

    fn join(encryptor: Self::Encryptor, decryptor: Self::Decryptor) -> Self {
        unimplemented!()
    }

    fn split(self) -> (Self::Encryptor, Self::Decryptor) {
        unimplemented!()
    }
}

impl Decrypt for Transcoder {
    type Error = DecryptionError;

    fn decrypt(&mut self, buffer: impl Borrow<[u8]>) -> Result<Vec<u8>, Self::Error> {
        unimplemented!()
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
pub struct NoEncryption;

impl Encrypt for NoEncryption {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        buffer.borrow().to_vec()
    }
}

impl Decrypt for NoEncryption {
    type Error = !;
    fn decrypt(&mut self, buffer: impl Borrow<[u8]>) -> Result<Vec<u8>, Self::Error> {
        Ok(buffer.borrow().to_vec())
    }
}

impl Transcode for NoEncryption {
    type Encryptor = Self;
    type Decryptor = Self;

    fn join(encryptor: Self::Encryptor, decryptor: Self::Decryptor) -> Self {
        encryptor as NoEncryption
    }

    fn split(self) -> (Self::Encryptor, Self::Decryptor) {
        (self.clone(), self)
    }
}
