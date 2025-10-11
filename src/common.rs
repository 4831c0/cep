use rand::rand_core::OsRng;
use rand::TryRngCore;

pub struct Keypair {
    pub public : Vec<u8>,
    pub private: Vec<u8>
}

pub fn random_array<const L: usize>() -> [u8; L] {
    let mut rng = OsRng;
    let mut seed = [0; L];
    rng.try_fill_bytes(&mut seed).unwrap();
    seed
}

pub struct EncapsulatedKey {
    pub ciphertext: Vec<u8>,
    pub shared_key: Vec<u8>
}

pub trait Encapsulate {
    fn key_size() -> (usize, usize);
    fn generate_keypair() -> Keypair;
    fn encapsulate(pub_key: &[u8]) -> EncapsulatedKey;
    fn decapsulate(ciphertext: &[u8], priv_key: &[u8]) -> Vec<u8>;
}