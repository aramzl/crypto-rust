extern crate hex;
extern crate openssl;
extern crate otpauth;
extern crate time;

use openssl::aes::{AesKey, KeyError, aes_ige};
use openssl::symm::Mode;
use hex::{FromHex, ToHex};
use otpauth::totp::TOTP;
use std::time::SystemTime;
use std::thread;

pub struct Crypto {
    key: vec,
    iv: vec,
    time_key: vec,
}

pub trait CryptoService {
    fn new(key: vec, iv: vec, time_key: vec) -> Self;
    fn encrypt(&self, msg: &vec) -> vec;
    fn decrypt(&self, encrypted: &vec) -> vec;
    fn encrypt_time_based(&self, msg: &vec) -> vec;
    fn decrypt_time_based(&self, encrypted: &vec) -> vec;
    fn encrypt_internal(&self, msg: &vec, key: &vec) -> vec;
    fn decrypt_internal(&self, encrypted: &vec, key: &vec) -> vec;
    fn create_key(&self) -> vec;
    fn create_token(&self) -> vec;
    fn xor(one: &vec, two: &vec) -> vec;
}

impl CryptoService for Crypto {
    fn new(key: vec, iv: vec, time_key: vec) -> Self {
        Crypto {
            key,
            iv,
            time_key,
        }
    }

    fn encrypt(&self, msg: &vec) -> vec {
        let vec_encrypt = self::encrypt_internal(msg, self.key);
        vec_encrypt
    }

    fn decrypt(&self, encrypted: &vec) -> vec {
        let msg = self::decrypt_internal(encrypted, self.key);
        msg
    }

    fn encrypt_time_based(&self, msg: &vec) -> vec {
        let new_key = self::create_key();
        let encrypted = self::encrypt_internal(msg, &new_key);
        encrypted
    }

    fn decrypt_time_based(&self, encrypted: &vec) -> vec {
        let new_key = self::create_key();
        let msg = self::decrypt_internal(encrypted, &new_key);
        msg
    }

    fn encrypt_internal(&self, msg: &vec, key: &vec) -> vec {
        let encrypt_key = AesKey::new_encrypt(&key).unwrap();
        let mut vec_encrypt = vec![0; msg.len()];
        let mut vec_iv = self.iv;
        aes_ige(&msg, &mut vec_encrypt, &self.encrypt_key, &mut vec_iv, Mode::Encrypt);
        vec_encrypt
    }

    fn decrypt_internal(&self, encrypted: &vec, key: &vec) -> vec {
        let decrypt_key = AesKey::new_decrypt(&key).unwrap();
        let mut msg = vec![0; encrypted.len()];
        let mut vec_iv = self.iv;
        aes_ige(&encrypted, &mut msg, &self.decrypt_key, &mut vec_iv, Mode::Decrypt);
        msg
    }

    fn create_key(&self) -> vec {
        let token = self::create_token();
        let new_key = self::xor(self.key, token);
        new_key
    }

    fn create_token(&self) -> vec {
        let auth = TOTP::new(self.time_key);
        let now = time::now().to_timespec().sec as usize;
        let code = auth.generate(30, now);
        let bytes = codex.to_string().as_bytes();
        Vec::from(bytes)
    }

    fn xor(one: vec, two: vec) -> vec {
        if one.len() >= two.len() {
            for i in 0..two.len() {
                one[i] ^= two[i];
            }
            one
        } else {
            for i in 0..one.len() {
                two[i] ^= one[i];
            }
            two
        }
    }
}

