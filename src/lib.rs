//! Combining AES with TOTP for time-based key derivation.
//!
//! A new AES key is derived every [`PERIOD`] seconds from the master key and
//! the current TOTP code, so both sides stay in sync without exchanging
//! anything beyond the original shared secrets.
//!
//! ```
//! use crypto_service::{Crypto, CryptoService};
//!
//! // Both ends hold the same three secrets; nothing else is exchanged.
//! let crypto = Crypto::new(
//!     b"12345678901234567890123456789012".to_vec(), // AES key
//!     b"21098765432109876543210987654321".to_vec(), // IV
//!     b"00010203040506070809".to_vec(),             // TOTP secret
//! )?;
//!
//! let msg = b"sixteen byte msg";
//! let encrypted = crypto.encrypt_time_based(msg)?;
//! assert_eq!(crypto.decrypt_time_based(&encrypted)?, msg);
//! # Ok::<(), crypto_service::CryptoError>(())
//! ```

#![warn(missing_docs)]

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
pub const IV_LEN: usize = 32;

/// Block size, in bytes, that messages must be a multiple of.
pub const BLOCK_LEN: usize = 16;

/// Length of the HMAC-SHA256 authentication tag appended to time-based
/// ciphertexts.
pub const TAG_LEN: usize = 32;

/// How far into a new period the *previous* period's key is still accepted,
/// as a percentage of `PERIOD`. Bounds how long a stale ciphertext stays
/// decryptable: with `PERIOD` 30 and 20%, that is 6 seconds.
const TOLERANCE_PERCENT: u64 = 20;

/// Domain separators keeping the two per-period subkeys independent.
const ENC_LABEL: &[u8] = b"crypto-service:enc-v1";
const MAC_LABEL: &[u8] = b"crypto-service:mac-v1";

/// Seconds into a period during which the previous period's key is accepted.
pub const fn tolerance() -> u64 {
    PERIOD * TOLERANCE_PERCENT / 100
}

/// Anything that can go wrong in this crate.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// AES keys must be 128, 192 or 256 bits. Carries the length supplied.
    InvalidKeyLength(usize),
    /// AES-IGE needs an IV of exactly [`IV_LEN`] bytes. Carries the length
    /// supplied.
    InvalidIvLength(usize),
    /// The TOTP secret was shorter than 32 bits. Carries the length supplied.
    InvalidTimeKeyLength(usize),
    /// AES-IGE is a block cipher with no padding, so input length must be a
    /// multiple of [`BLOCK_LEN`]. Carries the length supplied.
    NotBlockAligned(usize),
    /// Fewer bytes than the authentication tag alone requires.
    TooShort,
    /// The tag matched neither the current period's key nor, where the
    /// tolerance window allowed it, the previous period's.
    NotAuthenticated,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeyLength(n) => {
                write!(f, "AES key must be 16, 24 or 32 bytes, got {n}")
            }
            CryptoError::InvalidIvLength(n) => {
                write!(f, "IV must be exactly {IV_LEN} bytes, got {n}")
            }
            CryptoError::InvalidTimeKeyLength(n) => {
                write!(f, "TOTP secret must be at least 4 bytes, got {n}")
            }
            CryptoError::NotBlockAligned(n) => {
                write!(f, "input must be a multiple of {BLOCK_LEN} bytes, got {n}")
            }
            CryptoError::TooShort => write!(f, "ciphertext is shorter than the authentication tag"),
            CryptoError::NotAuthenticated => {
                write!(f, "authentication failed for every candidate period key")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Holds the three shared secrets both ends of a conversation must agree on:
/// the AES master key, the IV, and the TOTP secret.
///
/// None of the three is ever transmitted. Per-period keys are derived from the
/// master key and the TOTP secret, so two parties with the same secrets and
/// roughly synchronised clocks arrive at the same key independently.
///
/// Construct one with [`CryptoService::new`], which validates all three
/// lengths. The struct deliberately implements neither `Debug` nor `Clone`, so
/// the secrets cannot be printed into a log or duplicated by accident.
pub struct Crypto {
    key: Vec<u8>,
    iv: Vec<u8>,
    time_key: Vec<u8>,
}

/// The operations [`Crypto`] provides.
///
/// Two families of methods:
///
/// * [`encrypt`](Self::encrypt) / [`decrypt`](Self::decrypt) use the master key
///   directly. They are unauthenticated: a modified ciphertext decrypts to
///   plausible-looking garbage with no error.
/// * [`encrypt_time_based`](Self::encrypt_time_based) /
///   [`decrypt_time_based`](Self::decrypt_time_based) use a key that rotates
///   every [`PERIOD`] seconds and append an HMAC-SHA256 tag, so a wrong key or
///   a tampered message is detected rather than silently mis-decrypted.
///
/// Prefer the time-based pair unless you specifically need a static key.
pub trait CryptoService {
    /// Validates the three shared secrets and builds a [`Crypto`].
    ///
    /// `key` must be 16, 24 or 32 bytes (AES-128/192/256), `iv` exactly
    /// [`IV_LEN`] bytes, and `time_key` at least 4 bytes. The TOTP secret is
    /// taken as raw bytes, not as text.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKeyLength`], [`CryptoError::InvalidIvLength`] or
    /// [`CryptoError::InvalidTimeKeyLength`], each carrying the length given.
    ///
    /// ```
    /// use crypto_service::{Crypto, CryptoError, CryptoService};
    ///
    /// let ok = Crypto::new(
    ///     vec![0; 32],
    ///     vec![0; 32],
    ///     b"00010203040506070809".to_vec(),
    /// );
    /// assert!(ok.is_ok());
    ///
    /// let bad = Crypto::new(vec![0; 20], vec![0; 32], vec![0; 20]);
    /// assert_eq!(bad.err(), Some(CryptoError::InvalidKeyLength(20)));
    /// ```
    fn new(key: Vec<u8>, iv: Vec<u8>, time_key: Vec<u8>) -> Result<Self, CryptoError>
    where
        Self: Sized;

    /// Encrypts under the static master key, with no authentication tag.
    ///
    /// Output is the same length as `msg`. Because the IV is fixed, encrypting
    /// the same plaintext twice produces identical ciphertext.
    ///
    /// # Errors
    ///
    /// [`CryptoError::NotBlockAligned`] if `msg` is not a multiple of
    /// [`BLOCK_LEN`] bytes.
    fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypts what [`encrypt`](Self::encrypt) produced.
    ///
    /// There is no integrity check: if `encrypted` was modified or truncated in
    /// transit, this returns the resulting bytes without complaint. Use
    /// [`decrypt_time_based`](Self::decrypt_time_based) where that matters.
    ///
    /// # Errors
    ///
    /// [`CryptoError::NotBlockAligned`] if `encrypted` is not a multiple of
    /// [`BLOCK_LEN`] bytes.
    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Encrypts under the current period's key and appends an authentication
    /// tag.
    ///
    /// Output is [`TAG_LEN`] bytes longer than `msg`. Messages are always
    /// encrypted with the *current* key, never the previous one.
    ///
    /// # Errors
    ///
    /// [`CryptoError::NotBlockAligned`] if `msg` is not a multiple of
    /// [`BLOCK_LEN`] bytes.
    ///
    /// ```
    /// use crypto_service::{Crypto, CryptoService};
    ///
    /// let crypto = Crypto::new(
    ///     b"12345678901234567890123456789012".to_vec(),
    ///     b"21098765432109876543210987654321".to_vec(),
    ///     b"00010203040506070809".to_vec(),
    /// )?;
    ///
    /// let msg = b"sixteen byte msg";
    /// let encrypted = crypto.encrypt_time_based(msg)?;
    /// assert_eq!(encrypted.len(), msg.len() + 32);
    /// assert_eq!(crypto.decrypt_time_based(&encrypted)?, msg);
    /// # Ok::<(), crypto_service::CryptoError>(())
    /// ```
    fn encrypt_time_based(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Authenticates and decrypts against the current clock.
    ///
    /// Equivalent to [`decrypt_time_based_at`](Self::decrypt_time_based_at)
    /// with the current Unix time, including its tolerance window.
    ///
    /// # Errors
    ///
    /// [`CryptoError::TooShort`] if smaller than the tag,
    /// [`CryptoError::NotAuthenticated`] if no candidate key verifies.
    fn decrypt_time_based(&self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// [`encrypt_time_based`](Self::encrypt_time_based) pinned to an explicit
    /// Unix timestamp instead of the system clock.
    ///
    /// Useful in tests, and for replaying a known instant. The period used is
    /// `timestamp / PERIOD`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::NotBlockAligned`] if `msg` is not a multiple of
    /// [`BLOCK_LEN`] bytes.
    fn encrypt_time_based_at(&self, msg: &[u8], timestamp: u64) -> Result<Vec<u8>, CryptoError>;

    /// Authenticates and decrypts as of `timestamp`.
    ///
    /// Tries the current period's key first. If its tag does not verify and
    /// `timestamp` falls within [`tolerance`] seconds of the period start, the
    /// previous period's key is tried too — so a message sent just before a
    /// rotation still arrives just after one.
    ///
    /// # Errors
    ///
    /// [`CryptoError::TooShort`] if `encrypted` is smaller than the tag,
    /// [`CryptoError::NotAuthenticated`] if no candidate key verifies — which
    /// covers a wrong period, a tampered message and a truncated one alike.
    ///
    /// ```
    /// use crypto_service::{tolerance, Crypto, CryptoService, PERIOD};
    ///
    /// let crypto = Crypto::new(
    ///     b"12345678901234567890123456789012".to_vec(),
    ///     b"21098765432109876543210987654321".to_vec(),
    ///     b"00010203040506070809".to_vec(),
    /// )?;
    ///
    /// let base = 1_700_000_010; // period-aligned
    /// let msg = b"sixteen byte msg";
    ///
    /// // Sent in the last second of a period.
    /// let sent = crypto.encrypt_time_based_at(msg, base + PERIOD - 1)?;
    ///
    /// // Still readable inside the next period's tolerance window...
    /// assert!(crypto.decrypt_time_based_at(&sent, base + PERIOD).is_ok());
    ///
    /// // ...but not after it closes.
    /// assert!(crypto
    ///     .decrypt_time_based_at(&sent, base + PERIOD + tolerance())
    ///     .is_err());
    /// # Ok::<(), crypto_service::CryptoError>(())
    /// ```
    fn decrypt_time_based_at(
        &self,
        encrypted: &[u8],
        timestamp: u64,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Raw AES-IGE encryption under an explicit `key`, with no tag.
    ///
    /// The building block the methods above are written in terms of. Prefer
    /// those; this is exposed only because it is part of the trait.
    ///
    /// # Errors
    ///
    /// [`CryptoError::NotBlockAligned`] if `msg` is misaligned, or
    /// [`CryptoError::InvalidKeyLength`] if `key` is not a valid AES size.
    fn encrypt_internal(&self, msg: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Raw AES-IGE decryption under an explicit `key`. Counterpart to
    /// [`encrypt_internal`](Self::encrypt_internal), with the same caveats.
    ///
    /// # Errors
    ///
    /// [`CryptoError::NotBlockAligned`] if `encrypted` is misaligned, or
    /// [`CryptoError::InvalidKeyLength`] if `key` is not a valid AES size.
    fn decrypt_internal(&self, encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// The AES key for the period containing `timestamp`.
    ///
    /// `HMAC-SHA256(master_key, label || counter || totp_code)`, truncated to
    /// the master key's length. HMAC is a pseudo-random function, so holding
    /// one period's key reveals nothing about the master key or about any
    /// other period.
    fn create_key(&self, timestamp: u64) -> Vec<u8>;

    /// The TOTP code for the period containing `timestamp`, as six ASCII
    /// digits.
    ///
    /// Always six bytes: codes below 100000 are zero-padded, so the value fed
    /// into key derivation has a fixed width.
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

impl CryptoService for Crypto {
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKeyLength`], [`CryptoError::InvalidIvLength`]
    /// or [`CryptoError::InvalidTimeKeyLength`] if a secret is the wrong size.
    fn new(key: Vec<u8>, iv: Vec<u8>, time_key: Vec<u8>) -> Result<Self, CryptoError> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        if iv.len() != IV_LEN {
            return Err(CryptoError::InvalidIvLength(iv.len()));
        }
        if time_key.len() < 4 {
            return Err(CryptoError::InvalidTimeKeyLength(time_key.len()));
        }
        Ok(Crypto { key, iv, time_key })
    }

    /// # Errors
    ///
    /// Returns [`CryptoError::NotBlockAligned`] if `msg` is not a multiple of
    /// [`BLOCK_LEN`] bytes.
    fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt_internal(msg, &self.key)
    }

    /// # Errors
    ///
    /// Returns [`CryptoError::NotBlockAligned`] if `encrypted` is not a
    /// multiple of [`BLOCK_LEN`] bytes.
    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_internal(encrypted, &self.key)
    }

    /// Encrypts under the current period's key and appends an authentication
    /// tag. Output is `ciphertext || tag`, `TAG_LEN` bytes longer than `msg`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::NotBlockAligned`] if `msg` is not a multiple of
    /// [`BLOCK_LEN`] bytes.
    fn encrypt_time_based(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt_time_based_at(msg, now())
    }

    /// Authenticates and decrypts, accepting the previous period's key while
    /// inside the tolerance window. See
    /// [`decrypt_time_based_at`](Self::decrypt_time_based_at).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::TooShort`] or [`CryptoError::NotAuthenticated`].
    fn decrypt_time_based(&self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_time_based_at(encrypted, now())
    }

    /// Like [`encrypt_time_based`](Self::encrypt_time_based) but pinned to an
    /// explicit timestamp, so callers (and tests) control which period is used.
    ///
    /// Messages are *always* encrypted under the current period's key; the
    /// previous key is only ever a decryption candidate.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::NotBlockAligned`] if `msg` is not a multiple of
    /// [`BLOCK_LEN`] bytes.
    fn encrypt_time_based_at(&self, msg: &[u8], timestamp: u64) -> Result<Vec<u8>, CryptoError> {
        let counter = timestamp / PERIOD;
        let mut out = self.encrypt_internal(msg, &self.key_for(counter))?;
        let tag = hmac(&self.mac_key_for(counter), &out);
        out.extend_from_slice(&tag);
        Ok(out)
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
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::TooShort`] if `encrypted` is smaller than the
    /// tag, or [`CryptoError::NotAuthenticated`] if no candidate key verifies.
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
                return self.decrypt_internal(ciphertext, &self.key_for(candidate));
            }
        }
        Err(CryptoError::NotAuthenticated)
    }

    /// # Errors
    ///
    /// Returns [`CryptoError::NotBlockAligned`] if `msg` is misaligned, or
    /// [`CryptoError::InvalidKeyLength`] if `key` is not a valid AES size.
    fn encrypt_internal(&self, msg: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !msg.len().is_multiple_of(BLOCK_LEN) {
            return Err(CryptoError::NotBlockAligned(msg.len()));
        }
        let encrypt_key =
            AesKey::new_encrypt(key).map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
        let mut vec_encrypt = vec![0; msg.len()];
        let mut vec_iv = self.iv.clone();
        aes_ige(
            msg,
            &mut vec_encrypt,
            &encrypt_key,
            &mut vec_iv,
            Mode::Encrypt,
        );
        Ok(vec_encrypt)
    }

    /// # Errors
    ///
    /// Returns [`CryptoError::NotBlockAligned`] if `encrypted` is misaligned,
    /// or [`CryptoError::InvalidKeyLength`] if `key` is not a valid AES size.
    fn decrypt_internal(&self, encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !encrypted.len().is_multiple_of(BLOCK_LEN) {
            return Err(CryptoError::NotBlockAligned(encrypted.len()));
        }
        let decrypt_key =
            AesKey::new_decrypt(key).map_err(|_| CryptoError::InvalidKeyLength(key.len()))?;
        let mut msg = vec![0; encrypted.len()];
        let mut vec_iv = self.iv.clone();
        aes_ige(
            encrypted,
            &mut msg,
            &decrypt_key,
            &mut vec_iv,
            Mode::Decrypt,
        );
        Ok(msg)
    }

    fn create_key(&self, timestamp: u64) -> Vec<u8> {
        self.key_for(timestamp / PERIOD)
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
    /// Derive a per-period subkey from the master key.
    ///
    /// `HMAC-SHA256(master_key, label || counter || token)`. HMAC is a
    /// pseudo-random function, so an attacker who obtains one period's subkey
    /// learns nothing about the master key or about any other period — which
    /// is what makes rotation meaningful. The `label` keeps the encryption and
    /// MAC subkeys independent of each other, and the `counter` keeps two
    /// periods distinct even in the rare case their TOTP codes collide.
    fn derive(&self, label: &[u8], counter: u64) -> Vec<u8> {
        let token = self.create_token(counter * PERIOD);
        let mut data = label.to_vec();
        data.extend_from_slice(&counter.to_be_bytes());
        data.extend_from_slice(&token);
        hmac(&self.key, &data)
    }

    /// AES key for a specific period counter, truncated to the master key's
    /// length so 128-, 192- and 256-bit master keys all stay valid.
    fn key_for(&self, counter: u64) -> Vec<u8> {
        let mut key = self.derive(ENC_LABEL, counter);
        key.truncate(self.key.len());
        key
    }

    /// MAC key for a specific period counter. Rotates on the same schedule as
    /// the AES subkey, so verifying a tag identifies *which* period a
    /// ciphertext belongs to.
    fn mac_key_for(&self, counter: u64) -> Vec<u8> {
        self.derive(MAC_LABEL, counter)
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
        .expect("fixture secrets are valid")
    }

    #[test]
    fn period_key_leaks_no_master_key_bytes() {
        // The property the HMAC derivation exists for. The previous XOR scheme
        // passed 26 of 32 master-key bytes through untouched, so leaking one
        // period key gave up the master key.
        let crypto = crypto();
        let derived = crypto.create_key(0);
        let shared = derived
            .iter()
            .zip(&crypto.key)
            .filter(|(a, b)| a == b)
            .count();
        // A handful of coincidental byte matches is expected; a systematic
        // prefix is not.
        assert!(
            shared < 4,
            "{shared}/{} bytes match the master key",
            derived.len()
        );
    }

    #[test]
    fn period_keys_are_independent_of_each_other() {
        let crypto = crypto();
        let a = crypto.key_for(0);
        let b = crypto.key_for(1);
        let shared = a.iter().zip(&b).filter(|(x, y)| x == y).count();
        assert!(
            shared < 4,
            "{shared}/{} bytes shared between periods",
            a.len()
        );
    }

    #[test]
    fn constructor_rejects_bad_secrets() {
        let good_iv = b"21098765432109876543210987654321".to_vec();
        let good_tk = b"00010203040506070809".to_vec();

        // `.err()` rather than `.unwrap_err()`: the latter would need a Debug
        // impl on Crypto, and Crypto holds secrets we do not want printable.
        assert_eq!(
            Crypto::new(vec![0; 20], good_iv.clone(), good_tk.clone()).err(),
            Some(CryptoError::InvalidKeyLength(20))
        );
        assert_eq!(
            Crypto::new(vec![0; 32], vec![0; 16], good_tk).err(),
            Some(CryptoError::InvalidIvLength(16))
        );
        assert_eq!(
            Crypto::new(vec![0; 32], good_iv, vec![0; 2]).err(),
            Some(CryptoError::InvalidTimeKeyLength(2))
        );
        // All three valid AES sizes are accepted.
        for len in [16, 24, 32] {
            assert!(Crypto::new(
                vec![0; len],
                vec![0; IV_LEN],
                b"00010203040506070809".to_vec()
            )
            .is_ok());
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        let crypto = crypto();
        assert_eq!(crypto.key_for(42), crypto.key_for(42));
        assert_eq!(crypto.mac_key_for(42), crypto.mac_key_for(42));
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
