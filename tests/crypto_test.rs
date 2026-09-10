//! Integration tests: these exercise only the public API, the way a dependent
//! crate would. Unit tests for the private helpers live in `src/lib.rs`.

use crypto_service::{tolerance, Crypto, CryptoError, CryptoService, PERIOD};

/// A fixed, period-aligned point in time. Alignment matters: TOTP periods run
/// from absolute multiples of PERIOD, so an unaligned BASE would put
/// `BASE + PERIOD - 1` in the *next* period. Pinning keeps derived keys — and
/// therefore every assertion below — reproducible across runs.
const BASE: u64 = 1_700_000_010;

/// Both parties hold the same three shared secrets; that is all the scheme
/// assumes. Calling this twice models two independent ends of a conversation.
fn create_crypto() -> Crypto {
    Crypto::new(
        b"12345678901234567890123456789012".to_vec(),
        b"21098765432109876543210987654321".to_vec(),
        b"00010203040506070809".to_vec(),
    )
}

#[test]
fn aes_encryption_round_trips() {
    let msg = b"Hello world from rust. Secret.!!";
    let crypto = create_crypto();

    let encrypted = crypto.encrypt(msg);
    assert_ne!(msg.as_slice(), encrypted.as_slice());

    let original = crypto.decrypt(&encrypted);
    assert_eq!(msg.as_slice(), original.as_slice());
}

#[test]
fn synced_parties_exchange_messages_within_a_period() {
    let msg = b"Time based tests rust. Secret.!!";
    let alice = create_crypto();
    let bob = create_crypto();

    // Alice sends early in the period, Bob reads late in the same period.
    let encrypted = alice.encrypt_time_based_at(msg, BASE);
    assert_ne!(msg.as_slice(), encrypted.as_slice());

    let original = bob
        .decrypt_time_based_at(&encrypted, BASE + PERIOD - 1)
        .expect("same period must decrypt");
    assert_eq!(msg.as_slice(), original.as_slice());
}

#[test]
fn message_is_rejected_once_the_tolerance_window_closes() {
    let msg = b"Time based tests rust. Secret2!!";
    let alice = create_crypto();
    let bob = create_crypto();

    let encrypted = alice.encrypt_time_based_at(msg, BASE);

    // One full period later, past the grace window, the key has rotated away.
    let err = bob
        .decrypt_time_based_at(&encrypted, BASE + PERIOD + tolerance())
        .unwrap_err();
    assert_eq!(err, CryptoError::NotAuthenticated);
}

#[test]
fn previous_period_key_is_accepted_inside_the_tolerance_window() {
    let msg = b"Sent just before rotation!!!!!!!";
    let alice = create_crypto();
    let bob = create_crypto();

    // Sent in the last second of a period.
    let sent_at = BASE + PERIOD - 1;
    let encrypted = alice.encrypt_time_based_at(msg, sent_at);

    // Every instant inside the next period's grace window still decrypts.
    for offset in 0..tolerance() {
        let received_at = BASE + PERIOD + offset;
        let original = bob
            .decrypt_time_based_at(&encrypted, received_at)
            .unwrap_or_else(|e| panic!("+{offset}s into the window should decrypt, got {e}"));
        assert_eq!(msg.as_slice(), original.as_slice());
    }

    // The first instant past the window does not.
    assert_eq!(
        bob.decrypt_time_based_at(&encrypted, BASE + PERIOD + tolerance())
            .unwrap_err(),
        CryptoError::NotAuthenticated
    );
}

#[test]
fn messages_are_always_encrypted_with_the_current_key() {
    let msg = b"Time based tests rust. Secret3!!";
    let crypto = create_crypto();

    // Encrypting inside the tolerance window must use the *new* key, never the
    // old one that decryption would also accept there.
    let during_grace = crypto.encrypt_time_based_at(msg, BASE + PERIOD + 1);
    let previous_period = crypto.encrypt_time_based_at(msg, BASE + PERIOD - 1);
    assert_ne!(during_grace, previous_period);

    // Proof it used the new key: it decrypts at a point where only the new key
    // is a candidate, i.e. past that period's own grace window.
    let original = crypto
        .decrypt_time_based_at(&during_grace, BASE + PERIOD + tolerance() + 1)
        .expect("current-period key must decrypt");
    assert_eq!(msg.as_slice(), original.as_slice());
}

#[test]
fn ciphertext_changes_between_periods() {
    let msg = b"Time based tests rust. Secret3!!";
    let crypto = create_crypto();

    let first = crypto.encrypt_time_based_at(msg, BASE);
    let second = crypto.encrypt_time_based_at(msg, BASE + PERIOD);
    assert_ne!(first, second);
}

#[test]
fn tampering_is_detected() {
    let msg = b"Time based tests rust. Secret4!!";
    let crypto = create_crypto();

    let encrypted = crypto.encrypt_time_based_at(msg, BASE);

    // Flip one bit of the ciphertext...
    let mut flipped = encrypted.clone();
    flipped[0] ^= 0x01;
    assert_eq!(
        crypto.decrypt_time_based_at(&flipped, BASE).unwrap_err(),
        CryptoError::NotAuthenticated
    );

    // ...and one bit of the tag.
    let mut bad_tag = encrypted.clone();
    let last = bad_tag.len() - 1;
    bad_tag[last] ^= 0x01;
    assert_eq!(
        crypto.decrypt_time_based_at(&bad_tag, BASE).unwrap_err(),
        CryptoError::NotAuthenticated
    );
}

#[test]
fn truncated_input_is_rejected() {
    let crypto = create_crypto();
    assert_eq!(
        crypto.decrypt_time_based_at(&[0u8; 8], BASE).unwrap_err(),
        CryptoError::TooShort
    );
}

#[test]
fn time_based_encryption_round_trips_against_the_wall_clock() {
    let msg = b"Wall clock round trip. Secret!!!";
    let crypto = create_crypto();

    // Covers the default now()-based path. The tolerance window now absorbs a
    // period boundary landing between these two calls.
    let encrypted = crypto.encrypt_time_based(msg);
    let original = crypto
        .decrypt_time_based(&encrypted)
        .expect("wall-clock round trip must decrypt");
    assert_eq!(msg.as_slice(), original.as_slice());
}
