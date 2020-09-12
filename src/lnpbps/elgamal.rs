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

//! ElGamal encryption scheme with SECP256k1 curve.
//! According to <https://crypto.stackexchange.com/a/45042>

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1;

use crate::SECP256K1;

#[derive(Clone, Debug, Display, Error, From)]
#[display_from(Debug)]
pub enum Error {
    /// Encrypted message length is incorrect: it must be proportional to
    /// 32 bytes.
    UnpaddedLength,

    /// The provided encrypted message has internal inconsistency and is not
    /// a message encrypted with the current ElGamal algorithm
    InvalidEncryptedMessage,

    /// Secp256k1 operation error (has negligible probability)
    #[derive_from]
    Secp256k1(secp256k1::Error),
}

pub fn encrypt_elgamal(
    message: &[u8],
    mut encryption_key: secp256k1::PublicKey,
    blinding_key: &mut secp256k1::SecretKey,
) -> Result<Vec<u8>, Error> {
    // Compute hash of the encryption key, which will be used later as an
    // entropy for both data padding and deterministic bidirectional message
    // chunk-to-elliptic point mapping function
    let mut engine = sha256::Hash::engine();
    engine.input(&encryption_key.serialize());
    let mut hash = sha256::Hash::from_engine(engine);

    // Tweaking the encryption key with the blinding factor
    encryption_key.add_exp_assign(&SECP256K1, &blinding_key[..])?;

    // Pad the message to the round number of 30-byte chunks with the generated
    // entropy
    let mut buf = message.to_vec();
    if buf.len() % 30 != 0 {
        let even = (buf.len() / 30 + 1) * 30;
        buf.extend_from_slice(&hash[..even - buf.len()])
    }

    // Encrypt message, chunk by chunk
    let mut buf = &buf[..];
    let mut acc = vec![];
    while buf.len() > 0 {
        let chunk30 = &buf[..30];
        let mut chunk33 = [0u8; 33];
        // Deterministically select one of two possible keys for a given x-point:
        chunk33[1..31].copy_from_slice(&chunk30);
        acc.push(loop {
            chunk33[31..33].copy_from_slice(&hash[..2]);

            chunk33[0] = 2;
            let key1 = secp256k1::PublicKey::from_slice(&chunk33);
            chunk33[0] = 3;
            let key2 = secp256k1::PublicKey::from_slice(&chunk33);
            if let (Ok(pubkey1), Ok(pubkey2)) = (key1, key2) {
                let encrypted1 = pubkey1.combine(&encryption_key)?.serialize();
                let encrypted2 = pubkey2.combine(&encryption_key)?.serialize();
                if encrypted1[0] == 0x2 {
                    break encrypted1[1..].to_vec();
                } else if encrypted2[0] == 0x2 {
                    break encrypted2[1..].to_vec();
                }
            }

            let mut engine = sha256::Hash::engine();
            engine.input(&hash);
            hash = sha256::Hash::from_engine(engine);
        });
        buf = &buf[30..];
    }

    // Destroy blinding factor
    *blinding_key = secp256k1::key::ONE_KEY;

    Ok(acc.concat())
}

pub fn decrypt_elgamal(
    mut encrypted: &[u8],
    decryption_key: &mut secp256k1::SecretKey,
    mut unblinding_key: secp256k1::PublicKey,
) -> Result<Vec<u8>, Error> {
    if encrypted.len() % 32 != 0 {
        return Err(Error::UnpaddedLength);
    }

    // Tweak the encryption key with the blinding factor
    unblinding_key.add_exp_assign(&SECP256K1, &decryption_key[..])?;
    let encryption_key = unblinding_key;

    // Decrypt message chunk by chunk
    let mut acc = vec![];
    while encrypted.len() > 0 {
        // Here we automatically negate the key extracted from the message:
        // it is created with 0x2 first byte and restored with 0x2 byte, then
        // negated
        let chunk33 = [&[2u8], &encrypted[..32]].concat();
        let mut pubkey = secp256k1::PublicKey::from_slice(&chunk33)
            .map_err(|_| Error::InvalidEncryptedMessage)?;
        pubkey.negate_assign(&SECP256K1);
        let unencrypted = pubkey.combine(&encryption_key)?;
        // Remove random tail from the data
        let chunk30 = &unencrypted.serialize()[1..31];
        acc.push(chunk30.to_vec());
        encrypted = &encrypted[32..];
    }

    // Destroy decryption key
    *decryption_key = secp256k1::key::ONE_KEY;

    Ok(acc.concat())
}

#[cfg(test)]
mod test {
    use super::*;
    use secp256k1::rand::{thread_rng, RngCore};

    fn run_test_text(msg1: &str) {
        let source = msg1.as_bytes();
        let decrypted = run_test_bin(source);
        let msg2 = String::from_utf8(decrypted).unwrap();
        assert_eq!(msg1, msg2);
    }

    fn run_test_bin(source: &[u8]) -> Vec<u8> {
        let len = source.len();
        let mut entropy = [0u8; 32];

        thread_rng().fill_bytes(&mut entropy);
        let mut decryption_key = secp256k1::SecretKey::from_slice(&entropy).unwrap();
        let encryption_key = secp256k1::PublicKey::from_secret_key(&SECP256K1, &decryption_key);
        // Checking that we have a random key
        assert_ne!(decryption_key[..], secp256k1::key::ONE_KEY[..]);

        thread_rng().fill_bytes(&mut entropy);
        let mut blinding_key = secp256k1::SecretKey::from_slice(&entropy).unwrap();
        let unblinding_key = secp256k1::PublicKey::from_secret_key(&SECP256K1, &blinding_key);
        // Checking that we have a random key
        assert_ne!(blinding_key[..], secp256k1::key::ONE_KEY[..]);
        assert_ne!(blinding_key[..], decryption_key[..]);

        let mut uk = unblinding_key.clone();
        let mut ek = encryption_key.clone();
        assert_eq!(
            ek.add_exp_assign(&SECP256K1, &blinding_key[..]),
            uk.add_exp_assign(&SECP256K1, &decryption_key[..])
        );

        let encrypted = encrypt_elgamal(source, encryption_key, &mut blinding_key).unwrap();
        // Checking that we have wiped out our blinding key
        assert_ne!(source[..], encrypted[..len]);
        assert_eq!(blinding_key[..], secp256k1::key::ONE_KEY[..]);
        assert_eq!(encrypted.len(), (len / 30 + 1) * 32);

        let decrypted = decrypt_elgamal(&encrypted, &mut decryption_key, unblinding_key).unwrap();
        let result = &decrypted[..];
        // Checking that we have wiped out our decryption key
        assert_eq!(decryption_key[..], secp256k1::key::ONE_KEY[..]);
        assert_eq!(decrypted.len(), (len / 30 + 1) * 30);
        assert_eq!(result[..len], source[..]);

        decrypted[..len].to_vec()
    }

    #[test]
    fn test_text_short() {
        run_test_text("Some test message of a short length");
    }

    #[test]
    fn test_text_long() {
        run_test_text(
            "Yes, there is a elliptic curve based public key encryption
                        Let 𝑎 be A's private key and 𝛼=𝑎𝐺 be his public key. 
                        B who wants to send an encrypted message to A, does the 
                        following :
                        
                        B chooses a random number 𝑟, 1≤𝑟≤𝑛−1 and computes 𝑟𝐺
                        B then computes 𝑀+𝑟𝛼. Here the message 𝑀 (a binary string) 
                        has been represented as a point in ⟨𝐺⟩
                        B sends the encrypted text pair ⟨𝑟𝐺,𝑀+𝑟𝛼⟩ to A
                        On receiving this encrypted text A decrypts in the 
                        following manner
                        
                        A extracts 𝑟𝐺 and computes 𝑎⋅(𝑟𝐺)=𝑟⋅(𝑎𝐺)=𝑟𝛼
                        A extracts the second part of the pair 𝑀+𝑟𝛼 and subtracts 
                        out 𝑟𝛼 to obtain 𝑀+𝑟𝛼−𝑟𝛼=𝑀
                        There is a drawback in this as block of plaintext has to 
                        be converted to a point before being encrypted, denoted 
                        by 𝑀 above. After the decryption it has to be 
                        re-converted to plain text.",
        );
    }

    #[test]
    fn test_text_rand() {
        let mut entropy = [0u8; 24345];
        thread_rng().fill_bytes(&mut entropy);
        run_test_bin(&entropy);
    }
}
