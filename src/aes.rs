use crate::common::{random_array, Encrypt};
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Error, Key, KeyInit, Nonce};

pub struct AesGcm256 {
    pub key: Vec<u8>
}

impl Encrypt for AesGcm256 {
    fn key_size() -> usize {
        32
    }

    fn generate_key() -> Self {
        let arr: [u8; 32] = random_array();

        Self {
            key: arr.to_vec()
        }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let key = Key::<Aes256Gcm>::from_slice(self.key.as_slice());

        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext);

        if ciphertext.is_err() {
            Err(ciphertext.err().unwrap())
        } else {
            Ok(vec![nonce.as_slice().to_vec(), ciphertext?].concat())
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        assert!(ciphertext.len() > 12);
        assert_eq!(self.key.len(), 32);

        let (nonce, ciphertext) = ciphertext.split_at(12);

        let key = Key::<Aes256Gcm>::from_slice(self.key.as_slice());
        let cipher = Aes256Gcm::new(&key);

        let nonce = Nonce::from_slice(&nonce);
        cipher.decrypt(&nonce, ciphertext)
    }
}