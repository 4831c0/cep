extern crate core;

use crate::aes::AesGcm256;
use crate::common::{Encapsulate, Encrypt, Keypair};
use crate::error::CepError;
use crate::mlkem::{MlKem1024Encapsulation, MlKem512Encapsulation, MlKem768Encapsulation};
use crate::x25519::X25519Encapsulation;

pub mod mlkem;
pub mod common;
pub mod x25519;
pub mod aes;
pub mod e2echannel;
pub mod error;

#[cfg(test)]
mod tests {
    use crate::aes::AesGcm256;
    use crate::mlkem::*;
    use crate::common::*;
    use crate::e2echannel::{EncryptedChannelA, EncryptedChannelB};
    use crate::x25519::X25519Encapsulation;

    #[test]
    fn ml_kem512_key_size() {
        let size = MlKem512Encapsulation::key_size();
        let pair = MlKem512Encapsulation::generate_keypair();

        assert_eq!(size.0, pair.keypair.public.len());
        assert_eq!(size.1, pair.keypair.private.len());
    }

    #[test]
    fn ml_kem512_encryption_decryption() {
        let pair_pubpriv = MlKem512Encapsulation::generate_keypair();
        let pair_pub = MlKem512Encapsulation::from_pk(pair_pubpriv.keypair.public.as_slice());
        let cap = pair_pub.encapsulate();
        let decap = pair_pubpriv.decapsulate(cap.ciphertext.as_slice());

        assert_eq!(cap.shared_key, decap);
    }

    #[test]
    fn ml_kem768_key_size() {
        let size = MlKem768Encapsulation::key_size();
        let pair = MlKem768Encapsulation::generate_keypair();

        assert_eq!(size.0, pair.keypair.public.len());
        assert_eq!(size.1, pair.keypair.private.len());
    }

    #[test]
    fn ml_kem768_encryption_decryption() {
        let pair_pubpriv = MlKem768Encapsulation::generate_keypair();
        let pair_pub = MlKem768Encapsulation::from_pk(pair_pubpriv.keypair.public.as_slice());
        let cap = pair_pub.encapsulate();
        let decap = pair_pubpriv.decapsulate(cap.ciphertext.as_slice());

        assert_eq!(cap.shared_key, decap);
    }

    #[test]
    fn ml_kem1024_key_size() {
        let size = MlKem1024Encapsulation::key_size();
        let pair = MlKem1024Encapsulation::generate_keypair();

        assert_eq!(size.0, pair.keypair.public.len());
        assert_eq!(size.1, pair.keypair.private.len());
    }

    #[test]
    fn ml_kem1024_encryption_decryption() {
        let pair_pubpriv = MlKem1024Encapsulation::generate_keypair();
        let pair_pub = MlKem1024Encapsulation::from_pk(pair_pubpriv.keypair.public.as_slice());
        let cap = pair_pub.encapsulate();
        let decap = pair_pubpriv.decapsulate(cap.ciphertext.as_slice());

        assert_eq!(cap.shared_key, decap);
    }

    #[test]
    fn x25519_key_size() {
        let size = X25519Encapsulation::key_size();
        let pair = X25519Encapsulation::generate_keypair();

        assert_eq!(size.0, pair.keypair.public.len());
        assert_eq!(size.1, pair.keypair.private.len());
    }

    #[test]
    fn x25519_encryption_decryption() {
        let pair_pubpriv = X25519Encapsulation::generate_keypair();
        let pair_pub = X25519Encapsulation::from_pk(pair_pubpriv.keypair.public.as_slice());
        let cap = pair_pub.encapsulate();
        let decap = pair_pubpriv.decapsulate(cap.ciphertext.as_slice());

        assert_eq!(cap.shared_key, decap);
    }

    #[test]
    fn aes_gcm256_key_size() {
        let cipher = AesGcm256::generate_key();

        assert_eq!(AesGcm256::key_size(), cipher.key.len());
    }

    fn aes_256_gcm_enc_dec(plain : &[u8]) -> (Vec<u8>, Vec<u8>) {
        let cipher = AesGcm256::generate_key();
        let ciphertext = cipher.encrypt(plain);
        let plain2 = cipher.decrypt(ciphertext.unwrap().as_slice());

        (plain.to_vec(), plain2.unwrap())
    }

    #[test]
    fn aes_gcm256_encrypt_decrypt() {
        let test1 = aes_256_gcm_enc_dec(b"");
        let test2 = aes_256_gcm_enc_dec(b"Hello");
        let test3 = aes_256_gcm_enc_dec(b"Hello, World!");
        let test4 = aes_256_gcm_enc_dec(b"Hello, World!Hello, World!Hello");

        assert_eq!(test1.0, test1.1);
        assert_eq!(test2.0, test2.1);
        assert_eq!(test3.0, test3.1);
        assert_eq!(test4.0, test4.1);
    }

    #[test]
    fn e2ee_channel() {
        let mut channel_a = EncryptedChannelA::<MlKem1024Encapsulation, AesGcm256>::new();
        let mut channel_b = EncryptedChannelB::<MlKem1024Encapsulation, AesGcm256>::new();

        let handshake_a = channel_a.handshake_start().unwrap();
        let handshake_b = channel_b.handshake(handshake_a).unwrap();
        channel_a.handshake_finish(handshake_b).unwrap();

        let channel_a_enc = channel_a.enc.as_ref().unwrap();
        let channel_b_enc = channel_b.enc.as_ref().unwrap();

        let plain_msg = b"Hello, World!";
        let enc_msg = channel_a_enc.encrypt(plain_msg).unwrap();
        let dec_msg = channel_b_enc.decrypt(enc_msg.as_slice()).unwrap();

        assert_eq!(plain_msg, dec_msg.as_slice());

    }
}


uniffi::include_scaffolding!("cep");

fn aes_encrypt(key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, CepError> {
    let c = AesGcm256::from_key(key.as_slice())?;
    let e = c.encrypt(plaintext.as_slice());

    if e.is_err() {
        Err(CepError::EncryptionFailure)
    } else {
        Ok(e.unwrap())
    }
}

fn aes_decrypt(key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, CepError> {
    let c = AesGcm256::from_key(key.as_slice())?;
    let e = c.decrypt(ciphertext.as_slice());

    if e.is_err() {
        Err(CepError::EncryptionFailure)
    } else {
        Ok(e.unwrap())
    }
}

struct CepKeypair {
    public: Vec<u8>,
    private: Vec<u8>
}

struct CepEncapsulation {
    ciphertext: Vec<u8>,
    shared_key: Vec<u8>
}

fn x25519_generate_pair() -> CepKeypair {
    let pair = X25519Encapsulation::generate_keypair();

    CepKeypair {
        public: pair.keypair.public.clone(),
        private: pair.keypair.private.clone()
    }
}

fn x25519_encapsulate(public_key: Vec<u8>) -> CepEncapsulation {
    let pair = X25519Encapsulation::from_pk(public_key.as_slice());
    let cap = pair.encapsulate();

    CepEncapsulation {
        ciphertext: cap.ciphertext,
        shared_key: cap.shared_key,
    }
}

fn x25519_decapsulate(private_key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let pair = X25519Encapsulation {
        keypair: Keypair {
            public: vec![],
            private: private_key,
        },
    };

    pair.decapsulate(ciphertext.as_slice())
}


fn mlkem512_generate_pair() -> CepKeypair {
    let pair = MlKem512Encapsulation::generate_keypair();

    CepKeypair {
        public: pair.keypair.public.clone(),
        private: pair.keypair.private.clone()
    }
}

fn mlkem512_encapsulate(public_key: Vec<u8>) -> CepEncapsulation {
    let pair = MlKem512Encapsulation::from_pk(public_key.as_slice());
    let cap = pair.encapsulate();

    CepEncapsulation {
        ciphertext: cap.ciphertext,
        shared_key: cap.shared_key,
    }
}

fn mlkem512_decapsulate(private_key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let pair = MlKem512Encapsulation {
        keypair: Keypair {
            public: vec![],
            private: private_key,
        },
    };

    pair.decapsulate(ciphertext.as_slice())
}

fn mlkem768_generate_pair() -> CepKeypair {
    let pair = MlKem768Encapsulation::generate_keypair();

    CepKeypair {
        public: pair.keypair.public.clone(),
        private: pair.keypair.private.clone()
    }
}

fn mlkem768_encapsulate(public_key: Vec<u8>) -> CepEncapsulation {
    let pair = MlKem768Encapsulation::from_pk(public_key.as_slice());
    let cap = pair.encapsulate();

    CepEncapsulation {
        ciphertext: cap.ciphertext,
        shared_key: cap.shared_key,
    }
}

fn mlkem768_decapsulate(private_key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let pair = MlKem768Encapsulation {
        keypair: Keypair {
            public: vec![],
            private: private_key,
        },
    };

    pair.decapsulate(ciphertext.as_slice())
}

fn mlkem1024_generate_pair() -> CepKeypair {
    let pair = MlKem1024Encapsulation::generate_keypair();

    CepKeypair {
        public: pair.keypair.public.clone(),
        private: pair.keypair.private.clone()
    }
}

fn mlkem1024_encapsulate(public_key: Vec<u8>) -> CepEncapsulation {
    let pair = MlKem1024Encapsulation::from_pk(public_key.as_slice());
    let cap = pair.encapsulate();

    CepEncapsulation {
        ciphertext: cap.ciphertext,
        shared_key: cap.shared_key,
    }
}

fn mlkem1024_decapsulate(private_key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let pair = MlKem1024Encapsulation {
        keypair: Keypair {
            public: vec![],
            private: private_key,
        },
    };

    pair.decapsulate(ciphertext.as_slice())
}
