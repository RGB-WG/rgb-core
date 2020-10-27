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

use crate::lnp::transport::{
    Error, FRAME_PREFIX_SIZE, FRAME_SUFFIX_SIZE, MAX_FRAME_SIZE,
};
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

impl Encrypt for NoEncryption {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        let mut data = vec![];
        let buffer = buffer.borrow().to_vec();
        // TODO: (v0.2) check for length value to fit u16
        let len = buffer.len() as u16;
        data.extend(&len.to_be_bytes());
        data.extend(&[0u8; FRAME_PREFIX_SIZE - 2]);
        data.extend(buffer);
        data.extend(&[0u8; FRAME_SUFFIX_SIZE]);
        data
    }
}

impl Decrypt for NoEncryption {
    type Error = Error;
    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        let buffer = buffer.borrow();
        let frame_len = buffer.len();
        if frame_len < FRAME_PREFIX_SIZE + FRAME_SUFFIX_SIZE {
            return Err(Error::FrameTooSmall(frame_len));
        }
        if frame_len > MAX_FRAME_SIZE {
            return Err(Error::OversizedFrame(frame_len));
        }
        let mut len_buf = [0u8; 2];
        len_buf.copy_from_slice(&buffer[0..2]);
        let data_len = u16::from_be_bytes(len_buf);
        let len = frame_len - FRAME_SUFFIX_SIZE;
        if data_len != (len - FRAME_PREFIX_SIZE) as u16 {
            return Err(Error::InvalidLength);
        }
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_no_encryption() {
        let transcoder = NoEncryption;
        let (mut encoder, mut decoder) = transcoder.split();
        let frame = encoder.encrypt([]);
        assert_eq!(frame, vec![0u8; FRAME_PREFIX_SIZE + FRAME_SUFFIX_SIZE]);
        let data = decoder.decrypt(frame).unwrap();
        assert_eq!(data, Vec::<u8>::new());

        let data = b"Some message";
        let frame = encoder.encrypt(*data);
        assert_eq!(
            frame,
            vec![
                0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 111,
                109, 101, 32, 109, 101, 115, 115, 97, 103, 101, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        let decrypted = decoder.decrypt(frame.as_ref()).unwrap();
        assert_eq!(decrypted, data);

        assert_eq!(
            decoder.decrypt(&frame[2..]).unwrap_err(),
            Error::InvalidLength
        );
    }
}
