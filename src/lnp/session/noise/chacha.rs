// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Rajarshi Maitra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use chacha20poly1305::aead::{Aead, Error, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; /* Or `XChaCha20Poly1305` */

pub const TAG_SIZE: usize = 16;

// Encrypt a plaintext with associated data using the key and nonce.
// Returns the encrypted msg by mutating cipher_text array
pub fn encrypt(
    key: &[u8],
    nonce: u64,
    associated_data: &[u8],
    plaintext: &[u8],
    cipher_text: &mut [u8],
) -> Result<(), Error> {
    let mut chacha_nonce = [0u8; 12];
    chacha_nonce[4..].copy_from_slice(&nonce.to_le_bytes());

    let nonce = Nonce::from_slice(&chacha_nonce[..]);

    let key = Key::from_slice(key);

    let cipher = ChaCha20Poly1305::new(key);

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    let encrypted = cipher.encrypt(nonce, payload)?;

    cipher_text.copy_from_slice(&encrypted[..]);

    Ok(())
}

// Decrypts the ciphertext with key, nonce and associated data
// Returns the decrypted plaintext
pub fn decrypt(
    key: &[u8],
    nonce: u64,
    associated_data: &[u8],
    ciphertext: &[u8],
    plain_text: &mut [u8],
) -> Result<(), Error> {
    let mut chacha_nonce = [0u8; 12];
    chacha_nonce[4..].copy_from_slice(&nonce.to_le_bytes());

    let nonce = Nonce::from_slice(&chacha_nonce[..]);

    let key = Key::from_slice(key);

    let cipher = ChaCha20Poly1305::new(key);

    let payload = Payload {
        msg: ciphertext,
        aad: associated_data,
    };

    let decrypted = cipher.decrypt(nonce, payload)?;

    plain_text.copy_from_slice(&decrypted[..]);

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::chacha20poly1305::aead::AeadInPlace;
    use chacha20poly1305::aead::{Aead, NewAead};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; /* Or `XChaCha20Poly1305` */

    #[test]
    fn test1() {
        // Encrypt decrypt a plain text
        let key = Key::from_slice(b"an example very very secret key."); // 32-bytes
        let cipher = ChaCha20Poly1305::new(key);

        let nonce = Nonce::from_slice(b"unique nonce"); // 12-bytes; unique per message

        let ciphertext = cipher
            .encrypt(nonce, b"plaintext message".as_ref())
            .expect("encryption failure!"); // NOTE: handle this error to avoid panics!
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .expect("decryption failure!"); // NOTE: handle this error to avoid panics!

        assert_eq!(&plaintext, b"plaintext message");
    }

    #[test]
    fn test2() {
        let key = Key::from_slice(b"an example very very secret key.");
        let cipher = ChaCha20Poly1305::new(key);

        let nonce = Nonce::from_slice(b"unique nonce"); // 128-bits; unique per message

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(b"plaintext message");

        // Encrypt `buffer` in-place, replacing the plaintext contents with
        // ciphertext
        cipher
            .encrypt_in_place(nonce, b"", &mut buffer)
            .expect("encryption failure!");

        // `buffer` now contains the message ciphertext
        assert_ne!(&buffer, b"plaintext message");

        // Decrypt `buffer` in-place, replacing its ciphertext context with the
        // original plaintext
        cipher
            .decrypt_in_place(nonce, b"", &mut buffer)
            .expect("decryption failure!");
        assert_eq!(&buffer, b"plaintext message");
    }
}
