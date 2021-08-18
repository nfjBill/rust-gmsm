use crate::g3::digest::{Digest, SIZE};

#[allow(dead_code)]
pub fn sm3_byte(data: &str) -> [u8; SIZE] {
    let string = String::from(data);
    let s = string.as_bytes();
    let mut dst = Digest::new();
    dst.reset();
    dst.write(s);
    dst.check_sum()
}

#[allow(dead_code)]
pub fn sm3_hex(data: &str) -> String {
    let buf = sm3_byte(data);
    hex::encode_upper(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lets_hash_1() {
        let hash_str = sm3_hex("abc");

        let hex_str = "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0";

        assert_eq!(hash_str, hex_str);
    }

    #[test]
    fn lets_hash_2() {
        let hash_str = sm3_hex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");

        let hex_str = "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732";

        assert_eq!(hash_str, hex_str);
    }

    #[test]
    fn lets_hex_1() {
        let hash = sm3_byte("abc");

        let standrad_hash: [u8; 32] = [
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
            0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
            0x8f, 0x4b, 0xa8, 0xe0,
        ];

        for i in 0..32 {
            assert_eq!(standrad_hash[i], hash[i]);
        }
    }

    #[test]
    fn lets_hex_2() {
        let hash = sm3_byte("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");

        let standrad_hash: [u8; 32] = [
            0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e,
            0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3,
            0x9c, 0x0c, 0x57, 0x32,
        ];

        for i in 0..32 {
            assert_eq!(standrad_hash[i], hash[i]);
        }
    }
}