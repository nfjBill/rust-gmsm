# gmsm

gmsm is an open source pure rust library of China Cryptographic Algorithm Standards.

## GM/T Algorithms

* SM2 (GM/T 0003-2012): elliptic curve cryptographic schemes including digital signature scheme, public key encryption, (authenticated) key exchange protocol and one recommended 256-bit prime field curve sm2p256v1.
* SM3 (GM/T 0004-2012): cryptographic hash function with 256-bit digest length.
* SM4 (GM/T 0002-2012): block cipher with 128-bit key length and 128-bit block size, also named SMS4.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
gmsm = "0.1"
```

## Documents

* SM2

```rust
use gmsm::sm2::*;

fn main() {
    let keypair = sm2_generate_key_hex();
    let pri_key = keypair.pri_hex;
    // 78b39862c5c98997bba5c5f8c62db26566329bac2f3d957ddac49f8d890d258a
    let pub_hex = keypair.pub_hex;
    // 04861442c01bd02476b1f30ecff95c8604d4388acc154537c74c437cba59807fb507175fa9b35a9e14c1dbd5c018355300ef593675189eb74af89b0b1030ecef34
    let plain_str = "hello world, this is sm2 test!";
    let cipher = sm2_encrypt_c1c3c2(plain_str, &pub_hex);
    // 0468b34613d746beec82d8db74b401073aa044fbe0e6c0e74d30efa0cf5f7d30ebc2ac6c64e609dc11708cb612d01403f2e5a8b773199191ba7230a47165d69b058ec6a38681aafdb1b4ced7656eba2e3e12e941e3b0fb1ef1d00e15c43ce9a8f5f920a8da4d49b81405e308ef63dc25ffd039d8f1eeafd56de9387f0219a0
    let plain = sm2_decrypt_c1c3c2(&cipher, &pri_key);
    // hello world, this is sm2 test!

    assert_eq!(plain, plain_str);
}
```

* SM3

```rust
use gmsm::sm3::sm3_hex;

fn main() {
    let s = sm3_hex("abc");

    println!("{}", s)
    // "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0";
}
```

* SM4

```rust
use gmsm::sm4::{sm4_ecb_encrypt_hex, sm4_ecb_decrypt_hex, sm4_cbc_encrypt_hex, sm4_cbc_decrypt_hex};

fn main() {
    let key = "8A3F8665AAEE6F7A0CB8F40B971E3373";
    let iv = "88BA27B390F466ABE7C4327E1E60270B";
    let plain_str = "hello world, this is sm4 test!";

    let ecb_cipher = sm4_ecb_encrypt_hex(plain_str, key);
    println!("{}", s);
    // 9AA0BCBF487682AEAF7C640230568083452F4EDE1B8E265CC07A2F8CE07FC2E7
    
    let cbc_cipher = sm4_cbc_encrypt_hex(plain_str, key, iv);
    println!("{}", s);
    // 92662AD8A11D165EEF617AE3EDC4F9D4012A4C3CE7F42B15F26D1DA404CD97E0
    
    // let ecb_plain = sm4_ecb_decrypt_hex(cipher_str, key);
    // let cbc_plain = sm4_cbc_decrypt_hex(cipher_str, key, iv);
}
```

## License

gmsm is currently under the [Apache 2.0 license](LICENSE.txt).
