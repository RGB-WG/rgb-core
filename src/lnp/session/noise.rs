#[cfg(test)]
mod test {
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce}; // Or `XChaCha20Poly1305`
    use chacha20poly1305::aead::{Aead, NewAead};
    use crate::chacha20poly1305::aead::AeadInPlace;

    #[test]
    fn test1() {
        // Encrypt decrypt a plain text
        let key = Key::from_slice(b"an example very very secret key."); // 32-bytes
        let cipher = ChaCha20Poly1305::new(key);

        let nonce = Nonce::from_slice(b"unique nonce"); // 12-bytes; unique per message

        let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
            .expect("encryption failure!");  // NOTE: handle this error to avoid panics!
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .expect("decryption failure!");  // NOTE: handle this error to avoid panics!

        assert_eq!(&plaintext, b"plaintext message");
    }

    #[test]
    fn test2() {
        let key = Key::from_slice(b"an example very very secret key.");
        let cipher = ChaCha20Poly1305::new(key);

        let nonce = Nonce::from_slice(b"unique nonce"); // 128-bits; unique per message

        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(b"plaintext message");

        // Encrypt `buffer` in-place, replacing the plaintext contents with ciphertext
        cipher.encrypt_in_place(nonce, b"", &mut buffer).expect("encryption failure!");

        // `buffer` now contains the message ciphertext
        assert_ne!(&buffer, b"plaintext message");

        // Decrypt `buffer` in-place, replacing its ciphertext context with the original plaintext
        cipher.decrypt_in_place(nonce, b"", &mut buffer).expect("decryption failure!");
        assert_eq!(&buffer, b"plaintext message");
    }


}