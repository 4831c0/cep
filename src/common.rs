use aes_gcm::Error;
use rand::rand_core::OsRng;
use rand::TryRngCore;

pub fn random_array<const L: usize>() -> [u8; L] {
    let mut rng = OsRng;
    let mut seed = [0; L];
    rng.try_fill_bytes(&mut seed).unwrap();
    seed
}

pub struct Keypair {
    pub public : Vec<u8>,
    pub private: Vec<u8>
}

pub struct EncapsulatedKey {
    pub ciphertext: Vec<u8>,
    pub shared_key: Vec<u8>
}

pub trait Encapsulate {
    fn key_size() -> (usize, usize);
    fn generate_keypair() -> Self;
    fn from_pk(pk : &[u8]) -> Self;
    fn encapsulate(&self) -> EncapsulatedKey;
    fn decapsulate(&self, ciphertext: &[u8]) -> Vec<u8>;
}

pub trait Encrypt {
    fn key_size() -> usize;
    fn generate_key() -> Self;
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}