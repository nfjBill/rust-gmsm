# gmsm

gmsm is an open source pure rust library of China Cryptographic Algorithm Standards.

## GM/T Algorithms

* SM2 (In the writing...)
* SM3 (GM/T 0004-2012): cryptographic hash function with 256-bit digest length.
* SM4 (In the writing...)

## Documents

* SM3

```rust
use gmsm::sm3::sm3_hex;

fn main() {
    let s = sm3_hex("abc");

    println!("{}", s)
}

// "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0";
```

## License

gmsm is currently under the [Apache 2.0 license](LICENSE.txt).
