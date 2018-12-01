

//use crypto_service::Crypto;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_test_will_pass() {
        let key = "000102030405060708090A0B0C0D0E0F10111212121212121212121212121212";
        let vec_key = Vec::from(key.as_bytes());
        let iv = "000102030405060708090A0B0C0D0E0F10111212121212121212121212121212";
        let vec_iv = Vec::from(iv.as_bytes());
        let time_key = "000102030405060708090A0B0C0D0E0F10111212121212121212121212121212";
        let vec_time_key = Vec::from(iv.as_bytes());
        //let mut crypto = Crypto::new(vec_key, vec_iv, vec_time_key);
        let value = 10;
        assert_eq!(10, value);
    }

}
