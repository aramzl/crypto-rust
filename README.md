# crypto-service-rust

Combining [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) with [TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
for a more secure AES encryption. (rust implementation)


## Getting started

* Using Timebase algorithm from https://github.com/messense/otpauth-rs
* Using AES encryption from https://github.com/sfackler/rust-openssl

A new AES key is generated every 30 seconds with the TOTP algorithm.
The client needs the original AES key to decrypt the messages but the key-synchronization happens with the help of the TOTP.

Requires OpenSSL 3.x on the build machine (`brew install openssl@3` on macOS).

### Usage

```rust
use crypto_service::{Crypto, CryptoService, PERIOD};

fn create_crypto() -> Crypto {
    Crypto::new(
        b"12345678901234567890123456789012".to_vec(), // AES key: 16, 24 or 32 bytes
        b"21098765432109876543210987654321".to_vec(), // IV: exactly 32 bytes
        b"00010203040506070809".to_vec(),             // TOTP secret
    )
}

let crypto = create_crypto();
let msg = b"Time based tests rust. Secret.!!"; // length must be a multiple of 16

let encrypted = crypto.encrypt_time_based(msg);
let original = crypto.decrypt_time_based(&encrypted);

println!("Original {}", String::from_utf8_lossy(&original));
```

Keys rotate on absolute multiples of `PERIOD`, so a message sent just before a
rotation would otherwise be undecryptable a second later. To absorb that, the
previous period's key stays valid for the first `tolerance()` seconds of a new
period — 20% of `PERIOD`, so 6 seconds by default:

```
period N                     period N+1
|----------------------------|------|---------------------|
                             ^ grace ^
                    both N and N+1 keys accepted
```

Messages are **always** encrypted with the current period's key; the previous
key is only ever a decryption candidate. A ciphertext therefore stays valid for
at most `PERIOD + tolerance()` seconds after it was produced.

Decryption is authenticated, so it reports failure instead of returning garbage:

```rust
match crypto.decrypt_time_based(&encrypted) {
    Ok(plaintext) => { /* tag verified against one of the candidate keys */ }
    Err(CryptoError::NotAuthenticated) => { /* wrong period, or tampered */ }
    Err(CryptoError::TooShort) => { /* shorter than the 32-byte tag */ }
}
```

`encrypt_time_based` appends a 32-byte HMAC-SHA256 tag, so the ciphertext is 32
bytes longer than the plaintext. The MAC key is derived separately from the AES
key and rotates on the same schedule, which is what lets decryption tell *which*
period a message belongs to rather than guessing.

To pin a specific window — in tests, or to replay a known instant — use the
`_at` variants:

```rust
let encrypted = crypto.encrypt_time_based_at(msg, timestamp);
let original = crypto.decrypt_time_based_at(&encrypted, timestamp)?;
```

For encryption with the static master key only, use `encrypt` / `decrypt`.
Note that those two are **not** authenticated and have no tag.

### Tests

```sh
cargo test
```

## TODO

* Sign the payload with an RSA private/public key pair, so the recipient can
  verify who sent a message rather than only that it decrypted. This is
  deliberately kept out of the AES + TOTP implementation above — signing is a
  separate concern from the time-based key derivation this crate exists to
  demonstrate.

  Until then, `encrypt` / `decrypt` carry no integrity check at all: a modified
  or truncated ciphertext decrypts to plausible-looking output with no error.
  Only the `*_time_based` pair is authenticated, via its HMAC tag.
