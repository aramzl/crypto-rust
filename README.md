# crypto-service-rust

Combining [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) with [TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
for a more secure AES encryption. (rust implementation)


## Getting started

* Using Timebase algorithm from https://github.com/messense/otpauth-rs
* Using AES encryption from https://github.com/sfackler/rust-openssl

A new AES key is generated every 30 seconds with the TOTP algorithm.
The client needs the original AES key to decrypt the messages but the key-synchronization happens with the help of the TOTP.

### Usage

 ```
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


  let msg_bytes = "Time based tests rust. Secret.!!".as_bytes();
  let msg = Vec::from(msg_bytes);

  let crypto = create_cypto();

  let encrypted = CryptoService::encrypt_time_based(&crypto, &msg);
  let original = CryptoService::decrypt_time_based(&crypto, &encrypted);

  println!("Original {}", String::from_utf8_lossy(&original));
 ```
