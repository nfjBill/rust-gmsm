use crate::g4::cipher::{sm4_ecb, sm4_cbc};
use crate::utils::slice::{SliceDisplay};

// ecb encrypt

pub fn sm4_ecb_encrypt_byte<'a>(ins: &'a [u8], key: &'a [u8]) -> Vec<u8> {
    sm4_ecb(&key, ins, 0)
}

pub fn sm4_ecb_encrypt_hex<'a>(plain: &'a str, secret_key: &'a str) -> String {
    let string = String::from(plain);
    let s = string.as_bytes();
    let key = hex::decode(secret_key).unwrap();
    let enc_msg = sm4_ecb_encrypt_byte(s, &key);

    hex::encode_upper(enc_msg)
}

// ecb decrypt

pub fn sm4_ecb_decrypt_byte<'a>(ins: &'a [u8], key: &'a [u8]) -> Vec<u8> {
    sm4_ecb(&key, ins, 1)
}

pub fn sm4_ecb_decrypt_hex<'a>(cipher: &'a str, secret_key: &'a str) -> String {
    let s = hex::decode(cipher).unwrap();
    let key = hex::decode(secret_key.clone()).unwrap();
    let dec_msg = sm4_ecb_decrypt_byte(&s, &key);

    String::from_utf8_lossy(&dec_msg).to_string()
}

// cbc encrypt

pub fn sm4_cbc_encrypt_byte<'a>(ins: &'a [u8], key: &'a [u8], iv: &'a [u8]) -> Vec<u8> {
    sm4_cbc(&key, &iv, ins, 0)
}

pub fn sm4_cbc_encrypt_hex<'a>(plain: &'a str, secret_key: &'a str, secret_iv: &'a str) -> String {
    let string = String::from(plain);
    let s = string.as_bytes();
    let key = hex::decode(secret_key).unwrap();
    let iv = hex::decode(secret_iv).unwrap();
    let enc_msg = sm4_cbc_encrypt_byte(s, &key, &iv);

    hex::encode_upper(enc_msg)
}

// cbc decrypt

pub fn sm4_cbc_decrypt_byte<'a>(ins: &'a [u8], key: &'a [u8], iv: &'a [u8]) -> Vec<u8> {
    sm4_cbc(&key, &iv, ins, 1)
}

pub fn sm4_cbc_decrypt_hex<'a>(cipher: &'a str, secret_key: &'a str, secret_iv: &'a str) -> String {
    let s = hex::decode(cipher).unwrap();
    let key = hex::decode(secret_key.clone()).unwrap();
    let iv = hex::decode(secret_iv).unwrap();
    let dec_msg = sm4_cbc_decrypt_byte(&s, &key, &iv);

    String::from_utf8_lossy(&dec_msg).to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sm4_ecb_test() {
        let key = "8A3F8665AAEE6F7A0CB8F40B971E3373";
        let plain_str = "hello world, this is sm4 test!";
        let cipher_str = "9AA0BCBF487682AEAF7C640230568083452F4EDE1B8E265CC07A2F8CE07FC2E7";

        let cipher = sm4_ecb_encrypt_hex(plain_str, key);
        assert_eq!(cipher_str, cipher);

        let plain = sm4_ecb_decrypt_hex(cipher_str, key);
        assert_eq!(plain, plain_str);
    }

    #[test]
    fn sm4_cbc_test() {
        let key = "8A3F8665AAEE6F7A0CB8F40B971E3373";
        let iv = "88BA27B390F466ABE7C4327E1E60270B";
        let plain_str = "hello world, this is sm4 test!";
        let cipher_str = "92662AD8A11D165EEF617AE3EDC4F9D4012A4C3CE7F42B15F26D1DA404CD97E0";

        let cipher = sm4_cbc_encrypt_hex(plain_str, key, iv);
        assert_eq!(cipher_str, cipher);

        let plain = sm4_cbc_decrypt_hex(cipher_str, key, iv);
        assert_eq!(plain, plain_str);
    }
}