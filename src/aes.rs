use crate::common::{random_array, Encrypt};
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Error, Key, KeyInit, Nonce};

pub struct AesGcm256;

impl Encrypt for AesGcm256 {
    fn key_size() -> usize {
        32
    }

    fn generate_key() -> Vec<u8> {
        let arr: [u8; 32] = random_array();

        arr.to_vec()
    }

    fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
        let key = Key::<Aes256Gcm>::from_slice(key);

        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext);
        
        if (ciphertext.is_err()) {
            return Err(ciphertext.err().unwrap());
        }

        Ok(vec![nonce.as_slice().to_vec(), ciphertext?].concat())
    }

    fn decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
        assert!(ciphertext.len() > 12);
        assert_eq!(key.len(), 32);

        let (nonce, ciphertext) = ciphertext.split_at(12);

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(&key);

        let nonce = Nonce::from_slice(&nonce);
        cipher.decrypt(&nonce, ciphertext)
    }
}