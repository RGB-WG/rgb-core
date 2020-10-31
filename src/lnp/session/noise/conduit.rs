use super::{chacha, hkdf};
use crate::lnp::session::transcoders::{Decrypt, Encrypt, Transcode};
use amplify::Bipolar;

use super::handshake::HandshakeError;
use chacha20poly1305::aead::Error;
use std::borrow::Borrow;

pub type SymmetricKey = [u8; 32];

/// Maximum Lightning message data length according to
/// [BOLT-8](https://github.com/lightningnetwork/lightning-rfc/blob/v1.0/08-transport.md#lightning-message-specification)
/// and [BOLT-1](https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md#lightning-message-format):
const LN_MAX_MSG_LEN: usize = ::std::u16::MAX as usize; // Must be equal to 65535

const MESSAGE_LENGTH_HEADER_SIZE: usize = 2;
const TAGGED_MESSAGE_LENGTH_HEADER_SIZE: usize =
    MESSAGE_LENGTH_HEADER_SIZE + chacha::TAG_SIZE;

const KEY_ROTATION_INDEX: u32 = 1000;

pub struct Encryptor {
    sending_key: SymmetricKey,
    sending_chaining_key: SymmetricKey,
    sending_nonce: u32,
}

impl Encryptor {
    pub fn encrypt(&mut self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
        if buffer.len() > LN_MAX_MSG_LEN {
            panic!("Attempted to encrypt message longer than 65535 bytes!");
        }

        let length = buffer.len() as u16;
        let length_bytes = length.to_be_bytes();

        let mut ciphertext = vec![
            0u8;
            TAGGED_MESSAGE_LENGTH_HEADER_SIZE
                + length as usize
                + chacha::TAG_SIZE
        ];

        chacha::encrypt(
            &self.sending_key,
            self.sending_nonce as u64,
            &[0; 0],
            &length_bytes,
            &mut ciphertext[..TAGGED_MESSAGE_LENGTH_HEADER_SIZE],
        )?;
        self.increment_nonce();

        &chacha::encrypt(
            &self.sending_key,
            self.sending_nonce as u64,
            &[0; 0],
            buffer,
            &mut ciphertext[TAGGED_MESSAGE_LENGTH_HEADER_SIZE..],
        )?;
        self.increment_nonce();

        Ok(ciphertext)
    }

    fn increment_nonce(&mut self) {
        Conduit::increment_nonce(
            &mut self.sending_nonce,
            &mut self.sending_chaining_key,
            &mut self.sending_key,
        );
    }
}

impl Encrypt for Encryptor {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        match self.encrypt(buffer.borrow()) {
            Ok(values) => return values,
            Err(_) => return Vec::new(),
        }
    }
}

pub struct Decryptor {
    receiving_key: SymmetricKey,
    receiving_chaining_key: SymmetricKey,
    receiving_nonce: u32,

    pending_message_length: Option<usize>,
    read_buffer: Option<Vec<u8>>,
    poisoned: bool, /* signal an error has occurred so None is returned on
                     * iteration after failure */
}

impl Decryptor {
    pub fn read(&mut self, data: &[u8]) {
        let read_buffer = self.read_buffer.get_or_insert(Vec::new());
        read_buffer.extend_from_slice(data);
    }

    /// Decrypt a single message. If data containing more than one message has
    /// been received, only the first message will be returned, and the rest
    /// stored in the internal buffer. If a message pending in the buffer
    /// still hasn't been decrypted, that message will be returned in lieu
    /// of anything new, even if new data is provided.
    pub fn decrypt_single_message(
        &mut self,
        new_data: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let mut read_buffer = if let Some(buffer) = self.read_buffer.take() {
            buffer
        } else {
            Vec::new()
        };

        if let Some(data) = new_data {
            read_buffer.extend_from_slice(data);
        }

        if read_buffer.len() > LN_MAX_MSG_LEN + 16 {
            panic!(
                "Attempted to decrypt message longer than 65535 + 16 bytes!"
            );
        }

        let (current_message, offset) = self.decrypt(&read_buffer[..])?;
        read_buffer.drain(..offset); // drain the read buffer
        self.read_buffer = Some(read_buffer); // assign the new value to the built-in buffer
        Ok(current_message)
    }

    fn decrypt(
        &mut self,
        buffer: &[u8],
    ) -> Result<(Option<Vec<u8>>, usize), Error> {
        let message_length = if let Some(length) = self.pending_message_length {
            // we have already decrypted the header
            length
        } else {
            if buffer.len() < TAGGED_MESSAGE_LENGTH_HEADER_SIZE {
                // A message must be at least 18 bytes (2 for encrypted length,
                // 16 for the tag)
                return Ok((None, 0));
            }

            let encrypted_length =
                &buffer[0..TAGGED_MESSAGE_LENGTH_HEADER_SIZE];
            let mut length_bytes = [0u8; MESSAGE_LENGTH_HEADER_SIZE];
            chacha::decrypt(
                &self.receiving_key,
                self.receiving_nonce as u64,
                &[0; 0],
                encrypted_length,
                &mut length_bytes,
            )?;

            self.increment_nonce();

            // the message length
            //byte_utils::slice_to_be16(&length_bytes) as usize
            u16::from_be_bytes(length_bytes) as usize
        };

        let message_end_index = TAGGED_MESSAGE_LENGTH_HEADER_SIZE
            + message_length
            + chacha::TAG_SIZE;

        if buffer.len() < message_end_index {
            self.pending_message_length = Some(message_length);
            return Ok((None, 0));
        }

        self.pending_message_length = None;

        let encrypted_message =
            &buffer[TAGGED_MESSAGE_LENGTH_HEADER_SIZE..message_end_index];
        let mut message = vec![0u8; message_length];

        chacha::decrypt(
            &self.receiving_key,
            self.receiving_nonce as u64,
            &[0; 0],
            encrypted_message,
            &mut message,
        )?;

        self.increment_nonce();

        Ok((Some(message), message_end_index))
    }

    fn increment_nonce(&mut self) {
        Conduit::increment_nonce(
            &mut self.receiving_nonce,
            &mut self.receiving_chaining_key,
            &mut self.receiving_key,
        );
    }

    // Used in tests to determine whether or not excess bytes entered the
    // conduit without needing to bring up infrastructure to properly encode
    // it
    #[cfg(test)]
    pub fn read_buffer_length(&self) -> usize {
        match &self.read_buffer {
            &Some(ref vec) => vec.len(),
            &None => 0,
        }
    }
}

impl Iterator for Decryptor {
    type Item = Result<Option<Vec<u8>>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned {
            return None;
        }

        match self.decrypt_single_message(None) {
            Ok(Some(result)) => Some(Ok(Some(result))),
            Ok(None) => None,
            Err(e) => {
                self.poisoned = true;
                Some(Err(e))
            }
        }
    }
}

impl Decrypt for Decryptor {
    type Error = HandshakeError;
    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        match self.decrypt_single_message(Some(buffer.borrow())) {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(HandshakeError::ChaCha20(e)),
        }
    }
}

/// Returned after a successful handshake to encrypt and decrypt communication
/// with peer nodes. It should not normally be manually instantiated.
/// Automatically handles key rotation.
/// For decryption, it is recommended to call `decrypt_message_stream` for
/// automatic buffering.
pub struct Conduit {
    pub encryptor: Encryptor,
    pub decryptor: Decryptor,
}

impl Conduit {
    /// Instantiate a new Conduit with specified sending and receiving keys
    pub fn new(
        sending_key: SymmetricKey,
        receiving_key: SymmetricKey,
        chaining_key: SymmetricKey,
    ) -> Self {
        Conduit {
            encryptor: Encryptor {
                sending_key,
                sending_chaining_key: chaining_key,
                sending_nonce: 0,
            },
            decryptor: Decryptor {
                receiving_key,
                receiving_chaining_key: chaining_key,
                receiving_nonce: 0,
                read_buffer: None,
                pending_message_length: None,
                poisoned: false,
            },
        }
    }

    /// Encrypt data to be sent to peer
    pub fn encrypt(&mut self, buffer: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.encryptor.encrypt(buffer)?)
    }

    pub fn read(&mut self, data: &[u8]) {
        self.decryptor.read(data)
    }

    /// Decrypt a single message. If data containing more than one message has
    /// been received, only the first message will be returned, and the rest
    /// stored in the internal buffer. If a message pending in the buffer
    /// still hasn't been decrypted, that message will be returned in lieu
    /// of anything new, even if new data is provided.
    pub fn decrypt_single_message(
        &mut self,
        new_data: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.decryptor.decrypt_single_message(new_data)?)
    }

    fn increment_nonce(
        nonce: &mut u32,
        chaining_key: &mut SymmetricKey,
        key: &mut SymmetricKey,
    ) {
        *nonce += 1;
        if *nonce == KEY_ROTATION_INDEX {
            Self::rotate_key(chaining_key, key);
            *nonce = 0;
        }
    }

    fn rotate_key(chaining_key: &mut SymmetricKey, key: &mut SymmetricKey) {
        let (new_chaining_key, new_key) = hkdf::derive(chaining_key, key);
        chaining_key.copy_from_slice(&new_chaining_key);
        key.copy_from_slice(&new_key);
    }
}

impl Encrypt for Conduit {
    fn encrypt(&mut self, buffer: impl Borrow<[u8]>) -> Vec<u8> {
        match self.encrypt(buffer.borrow()) {
            Ok(values) => return values,
            Err(_) => return Vec::new(),
        }
    }
}

impl Decrypt for Conduit {
    type Error = HandshakeError;
    fn decrypt(
        &mut self,
        buffer: impl Borrow<[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        match self.decrypt_single_message(Some(buffer.borrow())) {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(HandshakeError::ChaCha20(e)),
        }
    }
}

impl Transcode for Conduit {
    type Encryptor = Encryptor;
    type Decryptor = Decryptor;
}

impl Bipolar for Conduit {
    type Left = <Self as Transcode>::Encryptor;
    type Right = <Self as Transcode>::Decryptor;

    fn join(encryptor: Self::Left, decryptor: Self::Right) -> Self {
        Self {
            encryptor: encryptor,
            decryptor: decryptor,
        }
    }

    fn split(self) -> (Self::Left, Self::Right) {
        (self.encryptor, self.decryptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_hashes::hex::FromHex;

    fn setup_peers() -> (Conduit, Conduit) {
        let chaining_key_vec = Vec::<u8>::from_hex(
            "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01",
        )
        .unwrap();
        let mut chaining_key = [0u8; 32];
        chaining_key.copy_from_slice(&chaining_key_vec);

        let sending_key_vec = Vec::<u8>::from_hex(
            "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9",
        )
        .unwrap();
        let mut sending_key = [0u8; 32];
        sending_key.copy_from_slice(&sending_key_vec);

        let receiving_key_vec = Vec::<u8>::from_hex(
            "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442",
        )
        .unwrap();
        let mut receiving_key = [0u8; 32];
        receiving_key.copy_from_slice(&receiving_key_vec);

        let connected_peer =
            Conduit::new(sending_key, receiving_key, chaining_key);
        let remote_peer =
            Conduit::new(receiving_key, sending_key, chaining_key);

        (connected_peer, remote_peer)
    }

    #[test]
    fn test_empty_message() {
        let (mut connected_peer, mut remote_peer) = setup_peers();

        let message: Vec<u8> = vec![];
        let encrypted_message = connected_peer.encrypt(&message).unwrap();
        assert_eq!(encrypted_message.len(), 2 + 16 + 16);

        let decrypted_message = remote_peer
            .decrypt_single_message(Some(&encrypted_message))
            .unwrap()
            .unwrap();
        assert_eq!(decrypted_message, Vec::<u8>::new());
    }

    #[test]
    fn test_nonce_chaining() {
        let (mut connected_peer, _remote_peer) = setup_peers();
        let message = Vec::<u8>::from_hex("68656c6c6f").unwrap();

        let encrypted_message = connected_peer.encrypt(&message).unwrap();
        assert_eq!(encrypted_message, Vec::<u8>::from_hex("cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95").unwrap());

        // the second time the same message is encrypted, the ciphertext should
        // be different
        let encrypted_message = connected_peer.encrypt(&message).unwrap();
        assert_eq!(encrypted_message, Vec::<u8>::from_hex("72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1").unwrap());
    }

    #[test]
    /// Based on RFC test vectors: https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#message-encryption-tests
    fn test_key_rotation() {
        let (mut connected_peer, _remote_peer) = setup_peers();

        let message = Vec::<u8>::from_hex("68656c6c6f").unwrap();
        let mut encrypted_messages: Vec<Vec<u8>> = Vec::new();

        for _ in 0..1002 {
            let encrypted_message = connected_peer.encrypt(&message).unwrap();
            encrypted_messages.push(encrypted_message);
        }

        assert_eq!(encrypted_messages[500], Vec::<u8>::from_hex("178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8").unwrap());
        assert_eq!(encrypted_messages[501], Vec::<u8>::from_hex("1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd").unwrap());
        assert_eq!(encrypted_messages[1000], Vec::<u8>::from_hex("4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09").unwrap());
        assert_eq!(encrypted_messages[1001], Vec::<u8>::from_hex("2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36").unwrap());
    }

    #[test]
    fn test_decryption_buffering() {
        let (mut connected_peer, mut remote_peer) = setup_peers();

        let message = Vec::<u8>::from_hex("68656c6c6f").unwrap();
        let mut encrypted_messages: Vec<Vec<u8>> = Vec::new();

        for _ in 0..1002 {
            let encrypted_message = connected_peer.encrypt(&message).unwrap();
            encrypted_messages.push(encrypted_message);
        }

        for _ in 0..501 {
            // read two messages at once, filling buffer
            let mut current_encrypted_message = encrypted_messages.remove(0);
            let next_encrypted_message = encrypted_messages.remove(0);
            current_encrypted_message
                .extend_from_slice(&next_encrypted_message);
            let decrypted_message = remote_peer
                .decrypt_single_message(Some(&current_encrypted_message))
                .unwrap()
                .unwrap();
            assert_eq!(decrypted_message, message);
        }

        for _ in 0..501 {
            // decrypt messages directly from buffer without adding to it
            let decrypted_message =
                remote_peer.decrypt_single_message(None).unwrap().unwrap();
            assert_eq!(decrypted_message, message);
        }
    }

    // Decryption errors should result in Err
    #[test]
    fn decryption_failure_errors() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt(&[1]).unwrap();

        connected_peer.decryptor.receiving_key = [0; 32];
        assert_eq!(
            connected_peer
                .decrypt_single_message(Some(&encrypted))
                .err()
                .unwrap(),
            chacha20poly1305::aead::Error
        );
    }

    // Test next()::None
    #[test]
    fn decryptor_iterator_empty() {
        let (mut connected_peer, _) = setup_peers();

        assert_eq!(connected_peer.decryptor.next(), None);
    }

    // Test next() -> next()::None
    #[test]
    fn decryptor_iterator_one_item_valid() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt(&[1]).unwrap();
        connected_peer.read(&encrypted);

        assert_eq!(connected_peer.decryptor.next(), Some(Ok(Some(vec![1]))));
        assert_eq!(connected_peer.decryptor.next(), None);
    }

    // Test next()::err -> next()::None
    #[test]
    fn decryptor_iterator_error() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt(&[1]).unwrap();
        connected_peer.read(&encrypted);

        connected_peer.decryptor.receiving_key = [0; 32];
        assert_eq!(
            connected_peer.decryptor.next().unwrap().err().unwrap(),
            chacha20poly1305::aead::Error
        );
        assert_eq!(connected_peer.decryptor.next(), None);
    }

    // Test next()::Some -> next()::err -> next()::None
    #[test]
    fn decryptor_iterator_error_after_success() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt(&[1]).unwrap();
        connected_peer.read(&encrypted);
        let encrypted = remote_peer.encrypt(&[2]).unwrap();
        connected_peer.read(&encrypted);

        assert_eq!(connected_peer.decryptor.next(), Some(Ok(Some(vec![1]))));
        connected_peer.decryptor.receiving_key = [0; 32];
        assert_eq!(
            connected_peer.decryptor.next().unwrap().err().unwrap(),
            chacha20poly1305::aead::Error
        );
        assert_eq!(connected_peer.decryptor.next(), None);
    }

    // Test that next()::Some -> next()::err -> next()::None
    // Error should poison decryptor
    #[test]
    fn decryptor_iterator_next_after_error_returns_none() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt(&[1]).unwrap();
        connected_peer.read(&encrypted);
        let encrypted = remote_peer.encrypt(&[2]).unwrap();
        connected_peer.read(&encrypted);
        let encrypted = remote_peer.encrypt(&[3]).unwrap();
        connected_peer.read(&encrypted);

        // Get one valid value
        assert_eq!(connected_peer.decryptor.next(), Some(Ok(Some(vec![1]))));
        let valid_receiving_key = connected_peer.decryptor.receiving_key;

        // Corrupt the receiving key and ensure we get a failure
        connected_peer.decryptor.receiving_key = [0; 32];
        assert_eq!(
            connected_peer.decryptor.next().unwrap().err().unwrap(),
            chacha20poly1305::aead::Error
        );

        // Restore the receiving key, do a read and ensure None is returned
        // (poisoned)
        connected_peer.decryptor.receiving_key = valid_receiving_key;
        assert_eq!(connected_peer.decryptor.next(), None);
    }

    // Test next()::Some -> next()::err -> read() -> next()::None
    // Error should poison decryptor even after future reads
    #[test]
    fn decryptor_iterator_read_next_after_error_returns_none() {
        let (mut connected_peer, mut remote_peer) = setup_peers();
        let encrypted = remote_peer.encrypt(&[1]).unwrap();
        connected_peer.read(&encrypted);
        let encrypted = remote_peer.encrypt(&[2]).unwrap();
        connected_peer.read(&encrypted);

        // Get one valid value
        assert_eq!(connected_peer.decryptor.next(), Some(Ok(Some(vec![1]))));
        let valid_receiving_key = connected_peer.decryptor.receiving_key;

        // Corrupt the receiving key and ensure we get a failure
        connected_peer.decryptor.receiving_key = [0; 32];
        assert_eq!(
            connected_peer.decryptor.next().unwrap().err().unwrap(),
            chacha20poly1305::aead::Error
        );

        // Restore the receiving key, do a read and ensure None is returned
        // (poisoned)
        let encrypted = remote_peer.encrypt(&[3]).unwrap();
        connected_peer.read(&encrypted);
        connected_peer.decryptor.receiving_key = valid_receiving_key;
        assert_eq!(connected_peer.decryptor.next(), None);
    }

    #[test]
    fn max_msg_len_limit_value() {
        assert_eq!(LN_MAX_MSG_LEN, 65535);
        assert_eq!(LN_MAX_MSG_LEN, ::std::u16::MAX as usize);
    }
    #[test]
    #[should_panic(
        expected = "Attempted to encrypt message longer than 65535 bytes!"
    )]
    fn max_message_len_encryption() {
        let (mut connected_peer, _) = setup_peers();
        let msg = [4u8; LN_MAX_MSG_LEN + 1];
        connected_peer.encrypt(&msg).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "Attempted to decrypt message longer than 65535 + 16 bytes!"
    )]
    fn max_message_len_decryption() {
        let (mut connected_peer, _) = setup_peers();

        // MSG should not exceed LN_MAX_MSG_LEN + 16
        let msg = [4u8; LN_MAX_MSG_LEN + 17];
        connected_peer.decrypt_single_message(Some(&msg)).unwrap();
    }
}
