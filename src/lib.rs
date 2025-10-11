extern crate core;

mod mlkem;
mod common;
mod x25519;
mod aes;

#[cfg(test)]
mod tests {
    use crate::aes::AesGcm256;
    use crate::mlkem::*;
    use crate::common::*;
    use crate::x25519::X25519Encapsulation;

    #[test]
    fn ml_kem512_key_size() {
        let size = MlKem512Encapsulation::key_size();
        let pair = MlKem512Encapsulation::generate_keypair();

        assert_eq!(size.0, pair.public.len());
        assert_eq!(size.1, pair.private.len());
    }

    #[test]
    fn ml_kem512_encryption_decryption() {
        let pair = MlKem512Encapsulation::generate_keypair();
        let cap = MlKem512Encapsulation::encapsulate(&*pair.public);
        let decap = MlKem512Encapsulation::decapsulate(&*cap.ciphertext, &*pair.private);

        assert_eq!(cap.shared_key, decap);
    }

    #[test]
    fn ml_kem768_key_size() {
        let size = MlKem768Encapsulation::key_size();
        let pair = MlKem768Encapsulation::generate_keypair();

        assert_eq!(size.0, pair.public.len());
        assert_eq!(size.1, pair.private.len());
    }

    #[test]
    fn ml_kem768_encryption_decryption() {
        let pair = MlKem768Encapsulation::generate_keypair();
        let cap = MlKem768Encapsulation::encapsulate(&*pair.public);
        let decap = MlKem768Encapsulation::decapsulate(&*cap.ciphertext, &*pair.private);

        assert_eq!(cap.shared_key, decap);
    }

    #[test]
    fn ml_kem1024_key_size() {
        let size = MlKem1024Encapsulation::key_size();
        let pair = MlKem1024Encapsulation::generate_keypair();

        assert_eq!(size.0, pair.public.len());
        assert_eq!(size.1, pair.private.len());
    }

    #[test]
    fn ml_kem1024_encryption_decryption() {
        let pair = MlKem1024Encapsulation::generate_keypair();
        let cap = MlKem1024Encapsulation::encapsulate(&*pair.public);
        let decap = MlKem1024Encapsulation::decapsulate(&*cap.ciphertext, &*pair.private);

        assert_eq!(cap.shared_key, decap);
    }

    #[test]
    fn x25519_key_size() {
        let size = X25519Encapsulation::key_size();
        let pair = X25519Encapsulation::generate_keypair();

        assert_eq!(size.0, pair.public.len());
        assert_eq!(size.1, pair.private.len());
    }

    #[test]
    fn x25519_encryption_decryption() {
        let pair = X25519Encapsulation::generate_keypair();
        let cap = X25519Encapsulation::encapsulate(&*pair.public);
        let decap = X25519Encapsulation::decapsulate(&*cap.ciphertext, &*pair.private);

        assert_eq!(cap.shared_key, decap);
    }

    #[test]
    fn aes_gcm256_key_size() {
        let key = AesGcm256::generate_key();

        assert_eq!(AesGcm256::key_size(), key.len());
    }

    fn aes_256_gcm_enc_dec(plain : &[u8]) -> (Vec<u8>, Vec<u8>) {
        let key = AesGcm256::generate_key();
        let ciphertext = AesGcm256::encrypt(plain, key.as_slice());
        let plain2 = AesGcm256::decrypt(ciphertext.unwrap().as_slice(), key.as_slice());

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
}
