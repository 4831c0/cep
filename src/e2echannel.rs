use crate::common::{Encapsulate, EncapsulatedKey, Encrypt};
use crate::error::{CepError};

pub struct EncryptedChannelA<C : Encapsulate, E : Encrypt> {
    kem: Option<C>,
    cap: Option<EncapsulatedKey>,
    pub enc: Option<E>
}
pub struct EncryptedChannelB<C : Encapsulate, E : Encrypt> {
    kem: Option<C>,
    cap: Option<EncapsulatedKey>,
    pub enc: Option<E>
}

impl<C : Encapsulate, E : Encrypt> EncryptedChannelA<C, E> {
    pub fn new() -> Self {
        Self {
            kem: Some(C::generate_keypair()),
            cap: None,
            enc: None,
        }
    }

    pub fn handshake_start(&mut self) -> Result<Vec<u8>, CepError> {
        if self.kem.is_none() {
            return Err(CepError::StructUninitialized);
        }
        let kem = self.kem.as_ref().unwrap();

        self.cap = Some(kem.encapsulate());
        Ok(kem.get_keypair().public.clone())
    }

    pub fn handshake_finish(&mut self, handshake : Vec<u8>) -> Result<(), CepError> {
        if self.kem.is_none() {
            return Err(CepError::StructUninitialized);
        }
        let kem = self.kem.as_ref().unwrap();

        let k = kem.decapsulate(handshake.as_slice());
        match E::from_key(k.as_slice()) {
            Ok(v) => {
                self.enc = Some(v);
            }
            Err(v) => return Err(v)
        }

        Ok(())
    }
}

impl<C : Encapsulate, E : Encrypt> EncryptedChannelB<C, E> {
    pub fn new() -> Self {
        Self {
            kem: None,
            cap: None,
            enc: None,
        }
    }

    pub fn handshake(&mut self, pk : Vec<u8>) -> Result<Vec<u8>, CepError> {
        self.kem = Some(C::from_pk(pk.as_slice()));
        let kem = self.kem.as_ref().unwrap();
        self.cap = Some(kem.encapsulate());
        let cap = self.cap.as_ref().unwrap();
        let e = E::from_key(cap.shared_key.as_slice());
        if e.is_err() {
            return Err(e.err().unwrap());
        }
        self.enc = Some(e?);

        Ok(self.cap.as_ref().unwrap().ciphertext.clone())
    }
}