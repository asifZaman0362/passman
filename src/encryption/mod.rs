use aes::{
    Aes256,
    cipher::{
        BlockEncrypt, BlockDecrypt, KeyInit,
        generic_array::{ 
            GenericArray, typenum::U32, typenum::U16
        }
    }
};
use pbkdf2::{
    Pbkdf2, password_hash::{
        SaltString, PasswordHasher
    }
};
use rand::rngs::OsRng;

type Block = GenericArray<u8, U16>;

pub struct DbEncryption {
    cipher: Aes256
}

impl DbEncryption {

    pub fn new(key: &str) -> DbEncryption {
        let key = derive_key(key);
        let cipher = Aes256::new(&key);
        DbEncryption { cipher }
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut ciphertext: Vec<u8> = vec![];
        let b = [0u8; 16];
        let mut block = GenericArray::clone_from_slice(&b);
        let iter = data.iter();
        let count = 0usize;
        loop {
            match iter.next() {
                Some(byte) => {
                    block[count] = *byte;
                    if count == 15 {
                        self.cipher.encrypt_block(&mut block);
                        ciphertext.push(block.as_slice().try_into().expect("invalid length!"));
                        block = GenericArray::clone_from_slice(&b);
                        count = 0;
                    } else {
                        count += 1;
                    }
                },
                None => break
            };
        }
        if count != 0 {
            self.cipher.encrypt_block(&mut block);
            ciphertext.push(block.as_slice().try_into().expect("invalid length!"));
        }
        ciphertext
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut plaintext: Vec<u8> = vec![];
        plaintext
    }

}

fn derive_key(key: &str) -> GenericArray<u8, U32> {
    let mut derived_key: GenericArray<u8, U32>;
    let salt = SaltString::generate(&mut OsRng);
    derived_key = match Pbkdf2.hash_password(&key.as_bytes(), &salt) {
        Ok(result) => *GenericArray::from_slice(&result.hash.unwrap().as_bytes()[0..32]),
        Err(msg) => panic!("failed to hash password string!")
    };
    derived_key
}