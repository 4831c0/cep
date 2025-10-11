extern crate core;

mod mlkem;
mod common;
mod x25519;

#[cfg(test)]
mod tests {
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
    fn x25519_keysize() {
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
}
