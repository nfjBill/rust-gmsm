# gmsm

gmsm is an open source pure rust library of China Cryptographic Algorithm Standards.

## GM/T Algorithms

* SM2 (GM/T 0003-2012): In the writing...
* SM3 (GM/T 0004-2012): cryptographic hash function with 256-bit digest length.
* SM4 (GM/T 0002-2012): block cipher with 128-bit key length and 128-bit block size, also named SMS4.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
gmsm = "0.1"
```

## Documents

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
