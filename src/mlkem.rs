use crate::common::{random_array, Encapsulate, EncapsulatedKey, Keypair};
use libcrux_ml_kem::*;

pub struct MlKem512Encapsulation {
    pub keypair: Keypair
}
pub struct MlKem768Encapsulation {
    pub keypair: Keypair
}
pub struct MlKem1024Encapsulation {
    pub keypair: Keypair
}

impl Encapsulate for MlKem512Encapsulation {
    fn key_size() -> (usize, usize) {
        (800, 1632)
    }

    fn generate_keypair() -> Self {
        let p = mlkem512::generate_key_pair(random_array());
        let pub_key = p.public_key().as_slice().to_vec();
        let priv_key = p.private_key().as_slice().to_vec();

        Self {
            keypair: Keypair {
                public: pub_key,
                private: priv_key
            }
        }
    }

    fn from_pk(pk: &[u8]) -> Self {
        Self {
            keypair: Keypair {
                public: pk.to_vec(),
                private: vec![]
            }
        }
    }

    fn encapsulate(&self) -> EncapsulatedKey {
        assert_eq!(self.keypair.public.len(), 800);

        let mut k = [0u8; 800];
        k.copy_from_slice(self.keypair.public.as_slice());

        let pk = mlkem512::MlKem512PublicKey::from(k);

        let (ciphertext, shared_secret) = {
            let randomness = random_array();

            mlkem512::encapsulate(&pk, randomness)
        };

        EncapsulatedKey{
            ciphertext: ciphertext.as_slice().to_vec(),
            shared_key: shared_secret.as_slice().to_vec()
        }
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut k = [0u8; 1632];
        k.copy_from_slice(self.keypair.private.as_slice());

        let mut c = [0u8; 768];
        c.copy_from_slice(ciphertext);

        let pk = mlkem512::MlKem512PrivateKey::from(k);
        let ct = mlkem512::MlKem512Ciphertext::from(c);

        let sk = mlkem512::decapsulate(&pk, &ct);

        sk.to_vec()
    }
}

impl Encapsulate for MlKem768Encapsulation {
    fn key_size() -> (usize, usize) {
        (1184, 2400)
    }

    fn generate_keypair() -> Self {
        let p = mlkem768::generate_key_pair(random_array());
        let pub_key = p.public_key().as_slice().to_vec();
        let priv_key = p.private_key().as_slice().to_vec();

        Self {
            keypair: Keypair {
                public: pub_key,
                private: priv_key
            }
        }
    }

    fn from_pk(pk: &[u8]) -> Self {
        Self {
            keypair: Keypair {
                public: pk.to_vec(),
                private: vec![]
            }
        }
    }

    fn encapsulate(&self) -> EncapsulatedKey {
        assert_eq!(self.keypair.public.len(), 1184);

        let mut k = [0u8; 1184];
        k.copy_from_slice(self.keypair.public.as_slice());

        let pk = mlkem768::MlKem768PublicKey::from(k);

        let (ciphertext, shared_secret) = {
            let randomness = random_array();

            mlkem768::encapsulate(&pk, randomness)
        };

        EncapsulatedKey{
            ciphertext: ciphertext.as_slice().to_vec(),
            shared_key: shared_secret.as_slice().to_vec()
        }
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut k = [0u8; 2400];
        k.copy_from_slice(self.keypair.private.as_slice());

        let mut c = [0u8; 1088];
        c.copy_from_slice(ciphertext);

        let pk = mlkem768::MlKem768PrivateKey::from(k);
        let ct = mlkem768::MlKem768Ciphertext::from(c);

        let sk = mlkem768::decapsulate(&pk, &ct);

        sk.to_vec()
    }
}

impl Encapsulate for MlKem1024Encapsulation {
    fn key_size() -> (usize, usize) {
        (1568, 3168)
    }

    fn generate_keypair() -> Self {
        let p = mlkem1024::generate_key_pair(random_array());
        let pub_key = p.public_key().as_slice().to_vec();
        let priv_key = p.private_key().as_slice().to_vec();

        Self {
            keypair: Keypair {
                public: pub_key,
                private: priv_key
            }
        }
    }

    fn from_pk(pk: &[u8]) -> Self {
        Self {
            keypair: Keypair {
                public: pk.to_vec(),
                private: vec![]
            }
        }
    }

    fn encapsulate(&self) -> EncapsulatedKey {
        assert_eq!(self.keypair.public.len(), 1568);

        let mut k = [0u8; 1568];
        k.copy_from_slice(self.keypair.public.as_slice());

        let pk = mlkem1024::MlKem1024PublicKey::from(k);

        let (ciphertext, shared_secret) = {
            let randomness = random_array();

            mlkem1024::encapsulate(&pk, randomness)
        };

        EncapsulatedKey{
            ciphertext: ciphertext.as_slice().to_vec(),
            shared_key: shared_secret.as_slice().to_vec()
        }
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Vec<u8> {
        let mut k = [0u8; 3168];
        k.copy_from_slice(self.keypair.private.as_slice());

        let mut c = [0u8; 1568];
        c.copy_from_slice(ciphertext);

        let pk = mlkem1024::MlKem1024PrivateKey::from(k);
        let ct = mlkem1024::MlKem1024Ciphertext::from(c);

        let sk = mlkem1024::decapsulate(&pk, &ct);

        sk.to_vec()
    }
}