//! Small demo of the library. Run with `cargo run`.

use crypto_service::{tolerance, Crypto, CryptoService, PERIOD};

fn main() {
    let crypto = Crypto::new(
        b"12345678901234567890123456789012".to_vec(),
        b"21098765432109876543210987654321".to_vec(),
        b"00010203040506070809".to_vec(),
    );

    let msg = b"this is a secret message. secret";
    println!("original:  {}", String::from_utf8_lossy(msg));

    let encrypted = crypto.encrypt(msg);
    println!("encrypted: {}", hex::encode(&encrypted));
    println!(
        "decrypted: {}",
        String::from_utf8_lossy(&crypto.decrypt(&encrypted))
    );

    // A period-aligned instant, so the offsets below are easy to follow.
    let base = 1_700_000_010;
    println!("\nPERIOD = {PERIOD}s, tolerance = {}s", tolerance());

    // Sent one second before the key rotates.
    let sent_at = base + PERIOD - 1;
    let ct = crypto.encrypt_time_based_at(msg, sent_at);
    println!(
        "\nsent at +{}s (last second of the period):",
        sent_at - base
    );

    for received_at in [sent_at, base + PERIOD, base + PERIOD + tolerance() - 1] {
        report(&crypto, &ct, base, received_at);
    }

    // Just past the tolerance window the message is refused outright.
    report(&crypto, &ct, base, base + PERIOD + tolerance());
}

fn report(crypto: &Crypto, ct: &[u8], base: u64, at: u64) {
    let offset = at - base;
    match crypto.decrypt_time_based_at(ct, at) {
        Ok(pt) => println!(
            "  received at +{offset:>2}s -> ok: {}",
            String::from_utf8_lossy(&pt)
        ),
        Err(e) => println!("  received at +{offset:>2}s -> rejected: {e}"),
    }
}
