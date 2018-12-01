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


fn aes_test() {
    let raw_key = "000102030405060708090A0B0C0D0E0F10111212121212121212121212121212";
    let raw_iv = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    let raw_msg = "this is a secret message. secret";
    println!("raw {}", raw_msg.len());


    let vec_key = Vec::from_hex(raw_key).unwrap();
    let mut vec_iv = Vec::from_hex(raw_iv).unwrap();
    let bytes = raw_msg.as_bytes();
    let vec_msg = Vec::from(bytes);
    println!("{}", vec_key.len());

    let key = AesKey::new_encrypt(&vec_key);
    if key.is_err() {
        panic!("called `Result::unwrap()` on an `Err` value: {:?}", key.err());
    }

    let mut vec_encrypt = vec![0; vec_msg.len()];
    aes_ige(&vec_msg, &mut vec_encrypt, &key.unwrap(), &mut vec_iv, Mode::Encrypt);
    println!("{:?}", vec_msg);
    println!("---");
    println!("{:?}", vec_encrypt);
    println!("---");

    let key = AesKey::new_decrypt(&vec_key).unwrap();
    let mut iv = Vec::from_hex(raw_iv).unwrap();
    let mut pt_actual = vec![0; vec_msg.len()];
    aes_ige(&vec_encrypt, &mut pt_actual, &key, &mut iv, Mode::Decrypt);

    println!("{:?}", pt_actual);
    println!("{}", String::from_utf8_lossy(&pt_actual));
}

fn totp_test() {
    let key = "12345678901234567890";
    let ten_millis = std::time::Duration::from_millis(1000);
    let auth = TOTP::new(key);

    for x in 0..50 {
        let timestamp1 = time::now().to_timespec().sec as usize;
        let code = auth.generate(30, timestamp1);
        //println!("{}", code);
        println!("{} now", x); // x: i32
        thread::sleep(ten_millis);
        let timestamp2 = time::now().to_timespec().sec as usize;
        let verification = auth.verify(code, 30, timestamp2);
        if !verification {
            println!("CODE: {}", code);
        }
        //println!("verify {}", verification);
    }
}

fn plus_one(number: i32) {
    println!("{}", number);
    //*number = *number + 1;
    let other = number +1;
    println!("{}", other);
}

fn main() {
    let x1 = "Guess";

    println!("{}", x1);
    println!("{}", x1.bytes().len());

    println!("Please input your guess.");

    let mut guess = String::new();

   // io::stdin().read_line(&mut guess)
    //    .expect("Failed to read line");

    println!("You guessed: {}", guess);

    let mut x = 200;
    plus_one( x);
    println!("{}", x);
    aes_test();
    totp_test();
}
