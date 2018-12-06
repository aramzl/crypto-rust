extern crate crypto_service;

use crypto_service::*;
use std::thread;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_cypto() -> Crypto {
        let key = "12345678901234567890123456789012";
        let vec_key = Vec::from(key.as_bytes());
        let iv = "21098765432109876543210987654321";
        let vec_iv = Vec::from(iv.as_bytes());
        let time_key = "00010203040506070809";
        let vec_time_key = Vec::from(time_key.as_bytes());
        let crypto = Crypto::new(vec_key, vec_iv, vec_time_key);
        println!("Crypto created");
        crypto
    }

    #[test]
    fn aes_encryption() {
        let msg_bytes = "Hello world from rust. Secret.!!".as_bytes();
        let msg = Vec::from(msg_bytes);
        println!("Original: {}", String::from_utf8_lossy(&msg));
        let crypto = create_cypto();

        let encrypted = CryptoService::encrypt(&crypto, &msg);

        println!("Encrypted {}", String::from_utf8_lossy(&encrypted));
        assert_ne!("Hello world from rust. Secret.!!", String::from_utf8_lossy(&encrypted));

        let original = CryptoService::decrypt(&crypto, &encrypted);

        println!("Original {}", String::from_utf8_lossy(&original));
        assert_eq!("Hello world from rust. Secret.!!", String::from_utf8_lossy(&original));
    }

    #[test]
    fn time_based_aes_encryption() {
        let msg_bytes = "Time based tests rust. Secret.!!".as_bytes();
        let msg = Vec::from(msg_bytes);
        println!("Original: {}", String::from_utf8_lossy(&msg));
        let crypto = create_cypto();

        let encrypted = CryptoService::encrypt_time_based(&crypto, &msg);

        println!("Encrypted {}", String::from_utf8_lossy(&encrypted));
        assert_ne!("Time based tests rust. Secret.!!", String::from_utf8_lossy(&encrypted));

        let original = CryptoService::decrypt_time_based(&crypto, &encrypted);

        println!("Original {}", String::from_utf8_lossy(&original));
        assert_eq!("Time based tests rust. Secret.!!", String::from_utf8_lossy(&original));
    }

    #[test]
    fn time_based_aes_encryption_after_30_secs() {
        let msg_bytes = "Time based tests rust. Secret2!!".as_bytes();
        let msg = Vec::from(msg_bytes);
        println!("Original: {}", String::from_utf8_lossy(&msg));
        let crypto = create_cypto();

        let encrypted = CryptoService::encrypt_time_based(&crypto, &msg);

        println!("Encrypted {}", String::from_utf8_lossy(&encrypted));
        assert_ne!("Time based tests rust. Secret2!!", String::from_utf8_lossy(&encrypted));

        let ten_millis = std::time::Duration::from_millis(30000);
        thread::sleep(ten_millis);

        let original = CryptoService::decrypt_time_based(&crypto, &encrypted);

        println!("Original {}", String::from_utf8_lossy(&original));
        assert_ne!("Time based tests rust. Secret2!!", String::from_utf8_lossy(&original));
    }

    #[test]
    fn time_based_aes_encryption_repeated() {
        let msg_bytes = "Time based tests rust. Secret3!!".as_bytes();
        let msg = Vec::from(msg_bytes);
        println!("Original: {}", String::from_utf8_lossy(&msg));
        let crypto = create_cypto();

        let encrypted = CryptoService::encrypt_time_based(&crypto, &msg);

        println!("Encrypted {}", String::from_utf8_lossy(&encrypted));
        assert_ne!("Time based tests rust. Secret3!!", String::from_utf8_lossy(&encrypted));

        let ten_millis = std::time::Duration::from_millis(30000);
        thread::sleep(ten_millis);

        let encrypted_2 = CryptoService::encrypt_time_based(&crypto, &msg);
        let original = CryptoService::decrypt_time_based(&crypto, &encrypted_2);

        println!("Original {}", String::from_utf8_lossy(&original));
        assert_eq!("Time based tests rust. Secret3!!", String::from_utf8_lossy(&original));
        assert_ne!(String::from_utf8_lossy(&encrypted), String::from_utf8_lossy(&encrypted_2));
    }
}
