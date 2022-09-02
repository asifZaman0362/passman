use aes::{
    Aes256,
    cipher::BlockEncrypt, cipher::BlockDecrypt,
    cipher::generic_array::GenericArray,
    cipher::KeyInit,
    cipher::generic_array::typenum::U32
};

use pbkdf2::{
    Pbkdf2, password_hash::{SaltString, PasswordHasher}
};

use rand::rngs::OsRng;

pub struct DbEncryption {
    cipher: Aes256
}

impl DbEncryption {

    pub fn new(key: &str) -> DbEncryption {
        let key = derive_key(key);
        let cipher = Aes256::new(&key);
        DbEncryption { cipher }
    }

    pub fn encrypt(&self, data: &str) -> Vec<u8> {
        let mut cipher_text: Vec<u8> = vec![];
        convert_to_blocks();
        cipher_text
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