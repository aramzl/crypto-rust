//! Combining AES with TOTP for time-based key derivation.
//!
//! A new AES key is derived every `PERIOD` seconds by mixing the master key
//! with the current TOTP code, so both sides stay in sync without exchanging
//! anything beyond the original shared secrets.

use openssl::aes::{aes_ige, AesKey};
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::Mode;
use otpauth::TOTP;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds a derived key stays valid.
pub const PERIOD: u64 = 30;

/// AES-IGE operates on two blocks at a time, so the IV is twice the block size.
const IV_LEN: usize = 32;

/// Block size, in bytes, that messages must be a multiple of.
const BLOCK_LEN: usize = 16;

/// Length of the HMAC-SHA256 authentication tag appended to time-based
/// ciphertexts.
const TAG_LEN: usize = 32;

/// How far into a new period the *previous* period's key is still accepted,
/// as a percentage of `PERIOD`. Bounds how long a stale ciphertext stays
/// decryptable: with `PERIOD` 30 and 20%, that is 6 seconds.
const TOLERANCE_PERCENT: u64 = 20;

/// Domain separator so the MAC subkey can never collide with the AES subkey.
const MAC_LABEL: &[u8] = b"crypto-service:mac-v1";

/// Seconds into a period during which the previous period's key is accepted.
pub const fn tolerance() -> u64 {
    PERIOD * TOLERANCE_PERCENT / 100
}

/// Why a time-based decryption was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Fewer bytes than the authentication tag alone requires.
    TooShort,
    /// The tag matched neither the current period's key nor, where the
    /// tolerance window allowed it, the previous period's.
    NotAuthenticated,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::TooShort => write!(f, "ciphertext is shorter than the authentication tag"),
            CryptoError::NotAuthenticated => {
                write!(f, "authentication failed for every candidate period key")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

pub struct Crypto {
    key: Vec<u8>,
    iv: Vec<u8>,
    time_key: Vec<u8>,
}

pub trait CryptoService {
    fn new(key: Vec<u8>, iv: Vec<u8>, time_key: Vec<u8>) -> Self;
    fn encrypt(&self, msg: &[u8]) -> Vec<u8>;
    fn decrypt(&self, encrypted: &[u8]) -> Vec<u8>;
    fn encrypt_time_based(&self, msg: &[u8]) -> Vec<u8>;
    fn decrypt_time_based(&self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn encrypt_time_based_at(&self, msg: &[u8], timestamp: u64) -> Vec<u8>;
    fn decrypt_time_based_at(
        &self,
        encrypted: &[u8],
        timestamp: u64,
    ) -> Result<Vec<u8>, CryptoError>;
    fn encrypt_internal(&self, msg: &[u8], key: &[u8]) -> Vec<u8>;
    fn decrypt_internal(&self, encrypted: &[u8], key: &[u8]) -> Vec<u8>;
    fn create_key(&self, timestamp: u64) -> Vec<u8>;
    fn create_token(&self, timestamp: u64) -> Vec<u8>;
}

/// Seconds since the Unix epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs()
}

/// HMAC-SHA256 of `data` under `key`.
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let pkey = PKey::hmac(key).expect("HMAC keys accept any length");
    let mut signer =
        Signer::new(MessageDigest::sha256(), &pkey).expect("SHA-256 is always available");
    signer.sign_oneshot_to_vec(data).expect("HMAC cannot fail")
}

/// XOR `b` into a copy of `a`, stopping at whichever is shorter.
fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = a.to_vec();
    for (dst, src) in out.iter_mut().zip(b) {
        *dst ^= src;
    }
    out
}

impl CryptoService for Crypto {
    fn new(key: Vec<u8>, iv: Vec<u8>, time_key: Vec<u8>) -> Self {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            panic!("Error creating AES key (must be 128, 192, or 256 bits)");
        }
        if iv.len() != IV_LEN {
            panic!("Error creating IV (must be exactly {IV_LEN} bytes)");
        }
        if time_key.len() < 4 {
            panic!("Error creating TOTP key (must be at least 32 bits)");
        }
        Crypto { key, iv, time_key }
    }

    fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        self.encrypt_internal(msg, &self.key)
    }

    fn decrypt(&self, encrypted: &[u8]) -> Vec<u8> {
        self.decrypt_internal(encrypted, &self.key)
    }

    /// Encrypts under the current period's key and appends an authentication
    /// tag. Output is `ciphertext || tag`, `TAG_LEN` bytes longer than `msg`.
    fn encrypt_time_based(&self, msg: &[u8]) -> Vec<u8> {
        self.encrypt_time_based_at(msg, now())
    }

    /// Authenticates and decrypts, accepting the previous period's key while
    /// inside the tolerance window. See
    /// [`decrypt_time_based_at`](Self::decrypt_time_based_at).
    fn decrypt_time_based(&self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_time_based_at(encrypted, now())
    }

    /// Like [`encrypt_time_based`](Self::encrypt_time_based) but pinned to an
    /// explicit timestamp, so callers (and tests) control which period is used.
    ///
    /// Messages are *always* encrypted under the current period's key; the
    /// previous key is only ever a decryption candidate.
    fn encrypt_time_based_at(&self, msg: &[u8], timestamp: u64) -> Vec<u8> {
        let counter = timestamp / PERIOD;
        let mut out = self.encrypt_internal(msg, &self.key_for(counter));
        let tag = hmac(&self.mac_key_for(counter), &out);
        out.extend_from_slice(&tag);
        out
    }

    /// Counterpart to [`encrypt_time_based_at`](Self::encrypt_time_based_at).
    ///
    /// Tries the current period's key first. If its tag does not verify and
    /// `timestamp` is within [`tolerance`] seconds of the period start, the
    /// previous period's key is tried as well — this is what lets a message
    /// sent just before a rotation still arrive just after one.
    ///
    /// The tag is what makes the fallback safe: a wrong key is *detected*
    /// rather than silently yielding garbage, so trying a second key cannot
    /// return the wrong plaintext.
    fn decrypt_time_based_at(
        &self,
        encrypted: &[u8],
        timestamp: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        if encrypted.len() < TAG_LEN {
            return Err(CryptoError::TooShort);
        }
        let (ciphertext, tag) = encrypted.split_at(encrypted.len() - TAG_LEN);

        let counter = timestamp / PERIOD;
        let mut candidates = vec![counter];
        if counter > 0 && timestamp % PERIOD < tolerance() {
            candidates.push(counter - 1);
        }

        for candidate in candidates {
            let expected = hmac(&self.mac_key_for(candidate), ciphertext);
            if memcmp::eq(&expected, tag) {
                return Ok(self.decrypt_internal(ciphertext, &self.key_for(candidate)));
            }
        }
        Err(CryptoError::NotAuthenticated)
    }

    fn encrypt_internal(&self, msg: &[u8], key: &[u8]) -> Vec<u8> {
        if !msg.len().is_multiple_of(BLOCK_LEN) {
            panic!(
                "Message vec size must be multiple of {} current {}",
                BLOCK_LEN,
                msg.len()
            );
        }
        let encrypt_key = AesKey::new_encrypt(key).unwrap();
        let mut vec_encrypt = vec![0; msg.len()];
        let mut vec_iv = self.iv.clone();
        aes_ige(
            msg,
            &mut vec_encrypt,
            &encrypt_key,
            &mut vec_iv,
            Mode::Encrypt,
        );
        vec_encrypt
    }

    fn decrypt_internal(&self, encrypted: &[u8], key: &[u8]) -> Vec<u8> {
        if !encrypted.len().is_multiple_of(BLOCK_LEN) {
            panic!(
                "Encrypted vec size must be multiple of {} current {}",
                BLOCK_LEN,
                encrypted.len()
            );
        }
        let decrypt_key = AesKey::new_decrypt(key).unwrap();
        let mut msg = vec![0; encrypted.len()];
        let mut vec_iv = self.iv.clone();
        aes_ige(
            encrypted,
            &mut msg,
            &decrypt_key,
            &mut vec_iv,
            Mode::Decrypt,
        );
        msg
    }

    fn create_key(&self, timestamp: u64) -> Vec<u8> {
        let token = self.create_token(timestamp);
        xor(&self.key, &token)
    }

    fn create_token(&self, timestamp: u64) -> Vec<u8> {
        let auth = TOTP::from_bytes(&self.time_key);
        let code = auth.generate(PERIOD, timestamp);
        // Zero-padded so the token is always 6 bytes; without this a code below
        // 100000 would perturb fewer bytes of the derived key.
        format!("{code:06}").into_bytes()
    }
}

impl Crypto {
    /// AES key for a specific period counter.
    fn key_for(&self, counter: u64) -> Vec<u8> {
        self.create_key(counter * PERIOD)
    }

    /// MAC key for a specific period counter.
    ///
    /// Derived from the master key and the period's token under a domain
    /// separator, so it is independent of the AES subkey and rotates on the
    /// same schedule. Verifying a tag therefore identifies *which* period a
    /// ciphertext belongs to.
    fn mac_key_for(&self, counter: u64) -> Vec<u8> {
        let token = self.create_token(counter * PERIOD);
        let mut data = MAC_LABEL.to_vec();
        data.extend_from_slice(&token);
        hmac(&self.key, &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto() -> Crypto {
        Crypto::new(
            b"12345678901234567890123456789012".to_vec(),
            b"21098765432109876543210987654321".to_vec(),
            b"00010203040506070809".to_vec(),
        )
    }

    #[test]
    fn xor_stops_at_the_shorter_input() {
        assert_eq!(
            xor(&[0xff, 0x0f, 0xaa], &[0x0f, 0xff]),
            vec![0xf0, 0xf0, 0xaa]
        );
    }

    #[test]
    fn xor_with_empty_is_identity() {
        assert_eq!(xor(&[1, 2, 3], &[]), vec![1, 2, 3]);
    }

    #[test]
    fn token_is_always_six_bytes() {
        let crypto = crypto();
        // Walk a spread of periods; every code must render zero-padded.
        for i in 0..500u64 {
            let token = crypto.create_token(i * PERIOD);
            assert_eq!(token.len(), 6, "token {token:?} was not 6 bytes");
            assert!(token.iter().all(u8::is_ascii_digit));
        }
    }

    #[test]
    fn token_is_stable_within_a_period() {
        let crypto = crypto();
        assert_eq!(crypto.create_token(0), crypto.create_token(PERIOD - 1));
    }

    #[test]
    fn derived_key_keeps_the_master_key_length() {
        let crypto = crypto();
        assert_eq!(crypto.create_key(0).len(), crypto.key.len());
    }

    #[test]
    fn derived_key_differs_from_the_master_key() {
        let crypto = crypto();
        assert_ne!(crypto.create_key(0), crypto.key);
    }

    #[test]
    fn mac_key_is_independent_of_the_aes_key() {
        // Domain separation: if these ever coincided, the tag would leak
        // information about the encryption key.
        let crypto = crypto();
        assert_ne!(crypto.mac_key_for(0), crypto.key_for(0));
        assert_ne!(crypto.mac_key_for(0), crypto.key);
    }

    #[test]
    fn mac_key_rotates_with_the_period() {
        let crypto = crypto();
        assert_ne!(crypto.mac_key_for(0), crypto.mac_key_for(1));
        // ...but is stable for a given counter.
        assert_eq!(crypto.mac_key_for(7), crypto.mac_key_for(7));
    }

    #[test]
    fn tolerance_is_a_fraction_of_the_period() {
        assert_eq!(tolerance(), PERIOD * TOLERANCE_PERCENT / 100);
        assert!(tolerance() > 0 && tolerance() < PERIOD);
    }
}
