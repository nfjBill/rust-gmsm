use crate::g2::p256::Sm2P256Curve;
use crate::g2::subject::*;
use crate::g2::consts::{C1C2C3, C1C3C2};
use num::{BigUint, Num};

#[derive(Clone)]
pub struct Keypair {
    pub pri_hex: String,
    pub pub_hex: String,
}

pub fn sm2_generate_key() -> PrivateKey {
    generate_key()
}

pub fn sm2_generate_key_hex() -> Keypair {
    let pri = sm2_generate_key();
    let pub_key = pri.clone().public_key;
    let pri_buf = raw_pri_byte(pri);
    let pub_buf = raw_pub_byte(pub_key);
    let pri_hex = hex::encode(pri_buf.clone());
    let pub_hex = hex::encode(pub_buf.clone());
    Keypair {
        pri_hex,
        pub_hex,
    }
}

fn s_e<'a>(plain: &'a str, pub_key: &'a str, mode: usize) -> String {
    let pub_hex_trim = pub_key.trim_start_matches("04");
    let pub_buf = hex::decode(pub_hex_trim.clone()).unwrap();
    let pub_key_convert = bytes_to_public_key(pub_buf);
    let plain_buf = plain.as_bytes().to_vec();
    let cipher_buf = encrypt(pub_key_convert, plain_buf, mode);
    hex::encode(cipher_buf)
}

fn s_d<'a>(cipher: &'a str, pri_key: &'a str, mode: usize) -> String {
    let sm2_p256 = Sm2P256Curve::new();
    let pri = BigUint::from_str_radix(pri_key, 16).unwrap();
    let (pkx, pky) = sm2_p256.scalar_base_mult(pri.to_bytes_be());
    let priv_g = PrivateKey{
        curve: sm2_p256.params().clone(),
        public_key: PublicKey{
            x: pkx,
            y: pky,
        },
        d: pri,
    };
    let cipher_buf = hex::decode(cipher).unwrap();
    let plain_buf = decrypt(priv_g, cipher_buf, mode);
    String::from_utf8_lossy(plain_buf.as_slice()).to_string()
}

pub fn sm2_encrypt<'a>(plain: &'a str, pub_key: &'a str) -> String {
    s_e(plain, pub_key, C1C2C3)
}

pub fn sm2_decrypt<'a>(cipher: &'a str, pri_key: &'a str) -> String {
    s_d(cipher, pri_key, C1C2C3)
}

pub fn sm2_encrypt_c1c3c2<'a>(plain: &'a str, pub_key: &'a str) -> String {
    s_e(plain, pub_key, C1C3C2)
}

pub fn sm2_decrypt_c1c3c2<'a>(cipher: &'a str, pri_key: &'a str) -> String {
    s_d(cipher, pri_key, C1C3C2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sm2_encrypt_and_decrypt() {
        let keypair = sm2_generate_key_hex();
        let pri_key = keypair.pri_hex;
        let pub_hex = keypair.pub_hex;
        let plain_str = "hello world, this is sm2 test!";
        let cipher = sm2_encrypt(plain_str, &pub_hex);
        let plain = sm2_decrypt(&cipher, &pri_key);
        assert_eq!(plain, plain_str);
    }

    #[test]
    fn sm2_encrypt_and_decrypt_c1c3c2() {
        let keypair = sm2_generate_key_hex();
        let pri_key = keypair.pri_hex;
        let pub_hex = keypair.pub_hex;
        let plain_str = "hello world, this is sm2 test!";
        let cipher = sm2_encrypt_c1c3c2(plain_str, &pub_hex);
        let plain = sm2_decrypt_c1c3c2(&cipher, &pri_key);
        assert_eq!(plain, plain_str);
    }
}
