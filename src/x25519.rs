use rand::{CryptoRng, RngCore};
use crate::common::{EncapsulatedKey, Encapsulate, Keypair, random_array};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct X25519Encapsulation;

struct FakeRandom {
    data: Vec<u8>
}

impl RngCore for FakeRandom {
    fn next_u32(&mut self) -> u32 {
        todo!()
    }

    fn next_u64(&mut self) -> u64 {
        todo!()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        dst.copy_from_slice(&self.data);
    }
}

impl CryptoRng for FakeRandom {

}

impl Encapsulate for X25519Encapsulation {
    fn key_size() -> (usize, usize) {
        (32, 32)
    }

    fn generate_keypair() -> Keypair {
        let secret: [u8; 32] = random_array();
        let mut fake_random = FakeRandom {
            data: secret.to_vec(),
        };
        let secret_e = EphemeralSecret::random_from_rng(&mut fake_random);
        let public = PublicKey::from(&secret_e);

        Keypair {
            public: public.to_bytes().to_vec(),
            private: secret.to_vec()
        }
    }

    fn encapsulate(pub_key: &[u8]) -> EncapsulatedKey {
        assert_eq!(pub_key.len(), 32);

        let mut orig_pk = [0u8; 32];
        orig_pk.copy_from_slice(pub_key);
        let orig_public = PublicKey::from(orig_pk);


        let secret: [u8; 32] = random_array();
        let mut fake_random = FakeRandom {
            data: secret.to_vec(),
        };
        let secret_e = EphemeralSecret::random_from_rng(&mut fake_random);
        let public = PublicKey::from(&secret_e);

        let shared_key = secret_e.diffie_hellman(&orig_public);

        EncapsulatedKey {
            ciphertext: public.to_bytes().to_vec(),
            shared_key: shared_key.to_bytes().to_vec()
        }
    }

    fn decapsulate(ciphertext: &[u8], priv_key: &[u8]) -> Vec<u8> {
        assert_eq!(ciphertext.len(), 32);
        assert_eq!(priv_key.len(), 32);

        let mut other_pk = [0u8; 32];
        other_pk.copy_from_slice(ciphertext);
        let orig_public = PublicKey::from(other_pk);

        let mut secret = [0u8; 32];
        secret.copy_from_slice(priv_key);
        let mut fake_random = FakeRandom {
            data: secret.to_vec(),
        };
        let secret_e = EphemeralSecret::random_from_rng(&mut fake_random);

        let shared_key = secret_e.diffie_hellman(&orig_public);

        shared_key.to_bytes().to_vec()
    }
}