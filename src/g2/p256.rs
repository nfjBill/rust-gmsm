use num::bigint::BigUint;
use num_bigint_dig::{BigUint as Bi, ModInverse};
use std::sync::{Once};
use std::{mem};
use num::{Num, Integer, ToPrimitive, signum, FromPrimitive};
use std::ops::{Shl, Shr, Add, Mul, Sub};
use std::cmp::Ordering;
use lazy_static::lazy_static;
use crate::g2::consts::*;
use crate::utils::slice::*;
use num::traits::real::Real;
// use modinverse::modinverse;
use std::str::FromStr;
// use crate::utils::slice::{SliceDisplay};

lazy_static! {
    static ref CURVE_A: BigUint = BigUint::from_str_radix("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16).unwrap();
    static ref CURVE_P: BigUint = BigUint::from_str_radix("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16).unwrap();
    static ref CURVE_P_BI: Bi = Bi::from_str_radix("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16).unwrap();
    static ref CURVE_N: BigUint = BigUint::from_str_radix("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16).unwrap();
    static ref CURVE_B: BigUint = BigUint::from_str_radix("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16).unwrap();
    static ref CURVE_GX: BigUint = BigUint::from_str_radix("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16).unwrap();
    static ref CURVE_GY: BigUint = BigUint::from_str_radix("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16).unwrap();
    static ref CURVE_RINVERSE: BigUint = BigUint::from_str_radix("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16).unwrap();
    static ref CURVE_RINVERSE_BI: Bi = Bi::from_str_radix("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16).unwrap();

    static ref SM256_A: [u32; 9] = sm2p256from_big(CURVE_A.clone());
}

#[derive(Clone)]
pub struct CurveParams {
    pub p: BigUint,
    pub n: BigUint,
    pub b: BigUint,
    pub gx: BigUint,
    pub gy: BigUint,
    pub bit_size: usize,
    pub name: String,
}

#[derive(Clone)]
pub struct Sm2P256Curve {
    pub curve: CurveParams,

    pub r_inverse: BigUint,
    pub a: [u32; 9],
    pub b: [u32; 9],
    pub gx: [u32; 9],
    pub gy: [u32; 9],
}

fn sign_num(k: BigUint) -> usize {
    k.to_f32().unwrap().signum().to_usize().unwrap()
}

// X = a * R mod P
fn sm2p256from_big(a: BigUint) -> [u32; 9] {
    let mut b: [u32; 9] = [0; 9];
    let aa = a.clone();
    let mut x: BigUint = BigUint::shl(aa.clone(), 257);
    x = x.mod_floor(&CURVE_P);
    let mut i = 0;
    while i < 9 {
        let bits = x.to_u64_digits();
        if bits.len() > 0 {
            b[i] = (bits[0] as u32) & BOTTOM29BITS;
        } else {
            b[i] = 0
        }
        x = BigUint::shr(x, 29);
        i += 1;
        if i == 9 {
            break;
        }
        let bits = x.to_u64_digits();
        if bits.len() > 0 {
            b[i] = (bits[0] as u32) & BOTTOM28BITS;
        } else {
            b[i] = 0
        }
        x = BigUint::shr(x, 28);
        i += 1;
    }

    b
}

fn sm2p256to_big(x: &mut [u32; 9]) -> BigUint {
    let mut r: BigUint = BigUint::from_u64(x[8] as u64).unwrap();
    let mut tm: BigUint;
    let mut i: isize = 7;
    while i >= 0 {
        if (i & 1) == 0 {
            r = r.shl(29);
        } else {
            r = r.shl(28);
        }
        tm = BigUint::from_u64(x[i as usize] as u64).unwrap();
        r = r.add(tm);

        i -= 1
    }
    r = r.mul(CURVE_RINVERSE.clone());
    r = r.mod_floor(&CURVE_P);

    r
}

fn sm2p256to_big_bi(x: &mut [u32; 9]) -> Bi {
    let mut r: Bi = Bi::from_u64(x[8] as u64).unwrap();
    let mut tm: Bi;
    let mut i: isize = 7;
    while i >= 0 {
        if (i & 1) == 0 {
            r = r.shl(29);
        } else {
            r = r.shl(28);
        }
        tm = Bi::from_u64(x[i as usize] as u64).unwrap();
        r = r.add(tm);

        i -= 1
    }
    r = r.mul(CURVE_RINVERSE_BI.clone());
    r = r.mod_floor(&CURVE_P_BI);

    r
}

//   0xffffffff for 0 < x <= 2**31
//   0 for x == 0 or x > 2**31.
fn non_zero_to_all_ones(x: u32) -> u32 {
    let mut y = x;
    if y == 0 {
        y = 4294967295;
    } else {
        y -= 1;
    }

    let mut mask =  (y >> 31);
    if mask == 0 {
        mask = 4294967295;
    } else {
        mask -= 1;
    }
    mask

}

fn sm2p256get_scalar(b: &mut [u8; 32], a: Vec<u8>) {
    let scalar_bytes: Vec<u8>;

    let mut n = BigUint::from_bytes_be(a.as_slice());
    let order = n.cmp(&CURVE_N);
    if order == Ordering::Greater {
        n = n.mod_floor(&CURVE_N);
        scalar_bytes = n.to_bytes_be();
    } else {
        scalar_bytes = a
    }
    for (i, v) in scalar_bytes.iter().enumerate() {
        b[scalar_bytes.len() - (1 + i)] = v.clone()
    }
}

// sets out=in if mask = 0xffffffff in constant time.
//
// On entry: mask is either 0 or 0xffffffff.
fn sm2p256copy_conditional(out: &mut [u32; 9], ins: [u32; 9], mask: u32) {
    let mut i = 0;
    while i < 9 {
        let tmp = mask & (ins[i] ^ out[i]);
        out[i] = out[i] ^ tmp;
        i += 1
    }
}

// sets {out_x,out_y} to the index'th entry of table.
// On entry: index < 16, table[0] must be zero.
fn sm2p256select_affine_point(x_out: &mut [u32; 9], y_out: &mut [u32; 9], table: Vec<u32>, index: u32) {
    let mut tb = table.clone();
    // println!("{:?} {:?} {:?} {}", x_out, y_out, table, index);
    for j in 0..9 {
        x_out[j] = 0;
        y_out[j] = 0;
    }

    let mut i: u32 = 1;
    while i < 16 {
        let mut mask: u32 = i ^ index;
        mask |= mask >> 2;
        mask |= mask >> 1;
        mask &= 1;
        if mask == 0 {
            mask = 4294967295;
        } else {
            mask -= 1;
        }

        for j in 0..9 {
            x_out[j] |= tb[0] & mask;
            if tb.len() > 0 {
                tb = tb[1..].to_vec() // !!!
            }
        }
        // println!("{} {} {}", x_out[0], tb[0], mask);
        for j in 0..9 {
            y_out[j] |= tb[0] & mask;
            if tb.len() > 0 {
                tb = tb[1..].to_vec() // !!!
            }
        }
        i += 1;
    }
}

// sets {out_x,out_y,out_z} to the index'th entry of
// table.
// On entry: index < 16, table[0] must be zero.
fn sm2p256select_jacobian_point(x_out: &mut [u32; 9], y_out: &mut [u32; 9], z_out: &mut [u32; 9], table: [[[u32; 9]; 3]; 16], index: u32) {
    for j in 0..9 {
        x_out[j] = 0;
        y_out[j] = 0;
        z_out[j] = 0;
    }

    // The implicit value at index 0 is all zero. We don't need to perform that
    // iteration of the loop because we already set out_* to zero.
    let mut i: u32 = 0;
    while i < 16 {
        let mut mask = i ^ index;
        mask |= mask >> 2;
        mask |= mask >> 1;
        mask &= 1;
        mask -= 1;

        for j in 0..9 {
            x_out[j] |= table[i as usize][0][j] & mask;
        }
        for j in 0..9 {
            y_out[j] |= table[i as usize][1][j] & mask
        }
        for j in 0..9 {
            z_out[j] |= table[i as usize][2][j] & mask
        }

        i += 1
    }
}

// returns the bit'th bit of scalar.
fn sm2p256get_bit(scalar: [u8; 32], bit: usize) -> u32 {
    (((scalar[bit >> 3]) >> (bit & 7)) & 1) as u32
}

// carry < 2 ^ 3
fn sm2p256reduce_carry(a: &mut [u32; 9], carry: usize) {
    a[0] += SM2P256CARRY[carry * 9 + 0];
    a[2] += SM2P256CARRY[carry * 9 + 2];
    a[3] += SM2P256CARRY[carry * 9 + 3];
    a[7] += SM2P256CARRY[carry * 9 + 7];
}

fn sm2p256reduce_degree(a: &mut [u32; 9], b: &mut [u64; 17]) {
    let mut tmp: [u32; 18] = [0; 18];
    let mut carry: u32;
    let mut x: u32;
    let mut x_mask: u32;

    // tmp
    // 0  | 1  | 2  | 3  | 4  | 5  | 6  | 7  | 8  |  9 | 10 ...
    // 29 | 28 | 29 | 28 | 29 | 28 | 29 | 28 | 29 | 28 | 29 ...
    tmp[0] = (b[0] as u32) & BOTTOM29BITS;
    tmp[1] = (b[0] as u32) >> 29;
    tmp[1] |= (((b[0] >> 32) as u32) << 3) & BOTTOM28BITS;
    tmp[1] += (b[1] as u32) & BOTTOM28BITS;
    carry = tmp[1] >> 28;
    tmp[1] &= BOTTOM28BITS;

    let mut i = 2;
    while i < 17 {
        tmp[i] = ((b[i - 2] >> 32) as u32) >> 25;
        tmp[i] += ((b[i - 1]) as u32) >> 28;
        tmp[i] += (((b[i - 1] >> 32) as u32) << 4) & BOTTOM29BITS;
        tmp[i] += (b[i] as u32) & BOTTOM29BITS;
        tmp[i] += carry;
        carry = tmp[i] >> 29;
        tmp[i] &= BOTTOM29BITS;

        i += 1;

        if i == 17 {
            break;
        }
        tmp[i] = ((b[i - 2] >> 32) as u32) >> 25;
        tmp[i] += (b[i - 1] as u32) >> 29;
        tmp[i] += (((b[i - 1] >> 32) as u32) << 3) & BOTTOM28BITS;
        tmp[i] += (b[i] as u32) & BOTTOM28BITS;
        tmp[i] += carry;
        carry = tmp[i] >> 28;
        tmp[i] &= BOTTOM28BITS;

        i += 1
    }

    tmp[17] = ((b[15] >> 32) as u32) >> 25;
    tmp[17] += (b[16] as u32) >> 29;
    tmp[17] += ((b[16] >> 32) as u32) << 3;
    tmp[17] += carry;

    i = 0;
    loop {
        tmp[i + 1] += tmp[i] >> 29;
        x = tmp[i] & BOTTOM29BITS;
        tmp[i] = 0;

        if x > 0 {
            let mut set4: u32 = 0;
            let mut set7: u32 = 0;
            x_mask = non_zero_to_all_ones(x);
            tmp[i + 2] += (x << 7) & BOTTOM29BITS;
            tmp[i + 3] += x >> 22;
            if tmp[i + 3] < 0x10000000 {
                set4 = 1;
                tmp[i + 3] += 0x10000000 & x_mask;
                tmp[i + 3] -= (x << 10) & BOTTOM28BITS;
            } else {
                tmp[i + 3] -= (x << 10) & BOTTOM28BITS;
            }
            if tmp[i + 4] < 0x20000000 {
                tmp[i + 4] += 0x20000000 & x_mask;
                tmp[i + 4] -= set4;
                tmp[i + 4] -= x >> 18;
                if tmp[i + 5] < 0x10000000 {
                    tmp[i + 5] += 0x10000000 & x_mask;
                    tmp[i + 5] -= 1;
                    if tmp[i + 6] < 0x20000000 {
                        set7 = 1;
                        tmp[i + 6] += 0x20000000 & x_mask;
                        tmp[i + 6] -= 1;
                    } else {
                        tmp[i + 6] -= 1;
                    }
                } else {
                    tmp[i + 5] -= 1;
                }
            } else {
                tmp[i + 4] -= set4;
                tmp[i + 4] -= x >> 18;
            }
            if tmp[i + 7] < 0x10000000 {
                tmp[i + 7] += 0x10000000 & x_mask;
                tmp[i + 7] -= set7;
                tmp[i + 7] -= (x << 24) & BOTTOM28BITS;
                tmp[i + 8] += (x << 28) & BOTTOM29BITS;
                if tmp[i + 8] < 0x20000000 {
                    tmp[i + 8] += 0x20000000 & x_mask;
                    tmp[i + 8] -= 1;
                    tmp[i + 8] -= x >> 4;
                    tmp[i + 9] += ((x >> 1) - 1) & x_mask;
                } else {
                    tmp[i + 8] -= 1;
                    tmp[i + 8] -= x >> 4;
                    tmp[i + 9] += (x >> 1) & x_mask;
                }
            } else {
                tmp[i + 7] -= set7;
                tmp[i + 7] -= (x << 24) & BOTTOM28BITS;
                tmp[i + 8] += (x << 28) & BOTTOM29BITS;
                if tmp[i + 8] < 0x20000000 {
                    tmp[i + 8] += 0x20000000 & x_mask;
                    tmp[i + 8] -= x >> 4;
                    tmp[i + 9] += ((x >> 1) - 1) & x_mask;
                } else {
                    tmp[i + 8] -= x >> 4;
                    tmp[i + 9] += (x >> 1) & x_mask;
                }
            }
        }

        if (i + 1) == 9 {
            break;
        }
        tmp[i + 2] += tmp[i + 1] >> 28;
        x = tmp[i + 1] & BOTTOM28BITS;
        tmp[i + 1] = 0;

        if x > 0 {
            let mut set5 = 0;
            let mut set8 = 0;
            let mut set9 = 0;
            x_mask = non_zero_to_all_ones(x);
            tmp[i + 3] += (x << 7) & BOTTOM28BITS;
            tmp[i + 4] += x >> 21;
            if tmp[i + 4] < 0x20000000 {
                set5 = 1;
                tmp[i + 4] += 0x20000000 & x_mask;
                tmp[i + 4] -= (x << 11) & BOTTOM29BITS;
            } else {
                tmp[i + 4] -= (x << 11) & BOTTOM29BITS;
            }
            if tmp[i + 5] < 0x10000000 {
                tmp[i + 5] += 0x10000000 & x_mask;
                tmp[i + 5] -= set5;
                tmp[i + 5] -= x >> 18;
                if tmp[i + 6] < 0x20000000 {
                    tmp[i + 6] += 0x20000000 & x_mask;
                    tmp[i + 6] -= 1;
                    if tmp[i + 7] < 0x10000000 {
                        set8 = 1;
                        tmp[i + 7] += 0x10000000 & x_mask;
                        tmp[i + 7] -= 1;
                    } else {
                        tmp[i + 7] -= 1;
                    }
                } else {
                    tmp[i + 6] -= 1;
                }
            } else {
                tmp[i + 5] -= set5;
                tmp[i + 5] -= x >> 18;
            }
            if tmp[i + 8] < 0x20000000 {
                set9 = 1;
                tmp[i + 8] += 0x20000000 & x_mask;
                tmp[i + 8] -= set8;
                tmp[i + 8] -= (x << 25) & BOTTOM29BITS;
            } else {
                tmp[i + 8] -= set8;
                tmp[i + 8] -= (x << 25) & BOTTOM29BITS;
            }
            if tmp[i + 9] < 0x10000000 {
                tmp[i + 9] += 0x10000000 & x_mask;
                tmp[i + 9] -= set9;
                tmp[i + 9] -= x >> 4;
                tmp[i + 10] += (x - 1) & x_mask;
            } else {
                tmp[i + 9] -= set9;
                tmp[i + 9] -= x >> 4;
                tmp[i + 10] += x & x_mask;
            }
        }

        i += 2;
    }

    carry = 0;
    i = 0;
    while i < 8 {
        a[i] = tmp[i + 9];
        a[i] += carry;
        a[i] += (tmp[i + 10] << 28) & BOTTOM29BITS;
        carry = a[i] >> 29;
        a[i] &= BOTTOM29BITS;

        i += 1;
        a[i] = tmp[i + 9] >> 1;
        a[i] += carry;
        carry = a[i] >> 28;
        a[i] &= BOTTOM28BITS;

        i += 1;
    }

    a[8] = tmp[17];
    a[8] += carry;
    carry = a[8] >> 29;
    a[8] &= BOTTOM29BITS;

    sm2p256reduce_carry(a, carry as usize);
}

// b = a
fn sm2p256dup(b: &mut [u32; 9], a: [u32; 9]) {
    for i in 0..9 {
        b[i] = a[i];
    }
}

fn wnaf_reversed(wnaf: Vec<u8>) -> Vec<u8> {
    let mut wnaf_rev: Vec<u8> = vec![];
    let wi = wnaf.len();
    for i in 0..wi {
        wnaf_rev[wi - (1 + i)] = wnaf[i]
    }
    wnaf_rev
}

fn bool_to_uint(b: bool) -> usize {
    if b {
        return 1;
    }
    return 0;
}

fn abs(a: i8) -> u32 {
    if a < 0 {
        return (-a) as u32;
    }
    return a as u32;
}

fn sm2genrate_wnaf(b: Vec<u8>) -> Vec<u8> {
    let n: BigUint = BigUint::from_bytes_be(b.as_slice());
    let mut k: BigUint;
    if n.cmp(&CURVE_N) == Ordering::Greater {
        n.mod_floor(&CURVE_N);
        k = n;
    } else {
        k = n
    }

    let bit_len: usize = k.bits() as usize; // !!!
    let mut wnaf: Vec<u8> = vec![0; bit_len + 1];
    if sign_num(k.clone()) == 0 { // !!!
        return wnaf;
    }
    let width: usize = 4;
    let pow2: usize = 16;
    let sign: usize = 8;
    let mask: u64 = 0;
    let mut carry: bool = false;
    let mut length: usize = 0;
    let mut pos: usize = 0;
    while pos <= bit_len {
        if k.bit(pos as u64) { // !!!
            pos += 1;
            continue;
        }
        k = k.shr(pos);
        let mut digit: usize = (k.to_u64().unwrap() & mask) as usize;
        if carry {
            digit += 1;
        }
        carry = (digit & sign) != 0;
        if carry {
            digit -= pow2;
        }
        length += pos;
        wnaf[length] = digit as u8;
        pos = width;
    }

    if wnaf.len() > length + 1 {
        let mut t: Vec<u8> = vec![0; length + 1];
        copy_slice(&mut t, &wnaf[0..(length + 1)]);
        wnaf = t
    }

    wnaf
}

fn sm2p256add(c: &mut [u32; 9], a: &mut [u32; 9], b: &mut [u32; 9]) {
    let mut carry: u32 = 0;
    let mut i = 0;
    loop {
        // c[i] = a[i] + b[i];
        // c[i] += carry;
        c[i] = a[i].wrapping_add(b[i]);
        c[i] = c[i].wrapping_add(carry);
        carry = c[i] >> 29;
        c[i] &= BOTTOM29BITS;
        i += 1;
        if i == 9 {
            break;
        }
        c[i] = a[i].wrapping_add(b[i]);
        c[i] = c[i].wrapping_add(carry);
        carry = c[i] >> 28;
        c[i] &= BOTTOM28BITS;

        i += 1
    }
    sm2p256reduce_carry(c, carry as usize)
}

fn sm2p256sub(c: &mut [u32; 9], a: &mut [u32; 9], b: &mut [u32; 9]) {
    let mut carry: u32 = 0;
    let mut i = 0;

    loop {
        // if a[i] >= b[i] {
        //     c[i] = a[i] - b[i];
        // } else {
        //     c[i] = a[i];
        // }
        c[i] = a[i].wrapping_sub(b[i]);
        // println!("{} 3", c[i]);
        // c[i] += SM2P256ZERO31[i];
        // c[i] += carry;
        c[i] = c[i].wrapping_add(SM2P256ZERO31[i]);
        c[i] = c[i].wrapping_add(carry);
        carry = c[i] >> 29;
        c[i] &= BOTTOM29BITS;
        i += 1;
        if i == 9 {
            break;
        }
        // if a[i] >= b[i] {
        //     c[i] = a[i] - b[i];
        // } else {
        //     c[i] = a[i];
        // }
        c[i] = a[i].wrapping_sub(b[i]);
        // c[i] += SM2P256ZERO31[i];
        // c[i] += carry;
        c[i] = c[i].wrapping_add(SM2P256ZERO31[i]);
        c[i] = c[i].wrapping_add(carry);
        carry = c[i] >> 28;
        c[i] &= BOTTOM28BITS;
        i+=1;
    }
    // println!("{:?} 3", c);
    sm2p256reduce_carry(c, carry as usize);
    // println!("{:?} 4", c);
}

fn sm2p256mul(c: &mut [u32; 9], a: &mut [u32; 9], b: &mut [u32; 9]) {
    let mut tmp: [u64; 17] = [0; 17];

    tmp[0] = (a[0] as u64) * (b[0] as u64);
    tmp[1] = (a[0] as u64) * ((b[1] as u64) << 0) +
        (a[1] as u64) * ((b[0] as u64) << 0);
    tmp[2] = (a[0] as u64) * ((b[2] as u64) << 0) +
        (a[1] as u64) * ((b[1] as u64) << 1) +
        (a[2] as u64) * ((b[0] as u64) << 0);
    tmp[3] = (a[0] as u64) * ((b[3] as u64) << 0) +
        (a[1] as u64) * ((b[2] as u64) << 0) +
        (a[2] as u64) * ((b[1] as u64) << 0) +
        (a[3] as u64) * ((b[0] as u64) << 0);
    tmp[4] = (a[0] as u64) * ((b[4] as u64) << 0) +
        (a[1] as u64) * ((b[3] as u64) << 1) +
        (a[2] as u64) * ((b[2] as u64) << 0) +
        (a[3] as u64) * ((b[1] as u64) << 1) +
        (a[4] as u64) * ((b[0] as u64) << 0);
    tmp[5] = (a[0] as u64) * ((b[5] as u64) << 0) +
        (a[1] as u64) * ((b[4] as u64) << 0) +
        (a[2] as u64) * ((b[3] as u64) << 0) +
        (a[3] as u64) * ((b[2] as u64) << 0) +
        (a[4] as u64) * ((b[1] as u64) << 0) +
        (a[5] as u64) * ((b[0] as u64) << 0);
    tmp[6] = (a[0] as u64) * ((b[6] as u64) << 0) +
        (a[1] as u64) * ((b[5] as u64) << 1) +
        (a[2] as u64) * ((b[4] as u64) << 0) +
        (a[3] as u64) * ((b[3] as u64) << 1) +
        (a[4] as u64) * ((b[2] as u64) << 0) +
        (a[5] as u64) * ((b[1] as u64) << 1) +
        (a[6] as u64) * ((b[0] as u64) << 0);
    tmp[7] = (a[0] as u64) * ((b[7] as u64) << 0) +
        (a[1] as u64) * ((b[6] as u64) << 0) +
        (a[2] as u64) * ((b[5] as u64) << 0) +
        (a[3] as u64) * ((b[4] as u64) << 0) +
        (a[4] as u64) * ((b[3] as u64) << 0) +
        (a[5] as u64) * ((b[2] as u64) << 0) +
        (a[6] as u64) * ((b[1] as u64) << 0) +
        (a[7] as u64) * ((b[0] as u64) << 0);
    // tmp[8] has the greatest value but doesn't overflow. See logic in
    // p256Square.
    tmp[8] = (a[0] as u64) * ((b[8] as u64) << 0) +
        (a[1] as u64) * ((b[7] as u64) << 1) +
        (a[2] as u64) * ((b[6] as u64) << 0) +
        (a[3] as u64) * ((b[5] as u64) << 1) +
        (a[4] as u64) * ((b[4] as u64) << 0) +
        (a[5] as u64) * ((b[3] as u64) << 1) +
        (a[6] as u64) * ((b[2] as u64) << 0) +
        (a[7] as u64) * ((b[1] as u64) << 1) +
        (a[8] as u64) * ((b[0] as u64) << 0);
    tmp[9] = (a[1] as u64) * ((b[8] as u64) << 0) +
        (a[2] as u64) * ((b[7] as u64) << 0) +
        (a[3] as u64) * ((b[6] as u64) << 0) +
        (a[4] as u64) * ((b[5] as u64) << 0) +
        (a[5] as u64) * ((b[4] as u64) << 0) +
        (a[6] as u64) * ((b[3] as u64) << 0) +
        (a[7] as u64) * ((b[2] as u64) << 0) +
        (a[8] as u64) * ((b[1] as u64) << 0);
    tmp[10] = (a[2] as u64) * ((b[8] as u64) << 0) +
        (a[3] as u64) * ((b[7] as u64) << 1) +
        (a[4] as u64) * ((b[6] as u64) << 0) +
        (a[5] as u64) * ((b[5] as u64) << 1) +
        (a[6] as u64) * ((b[4] as u64) << 0) +
        (a[7] as u64) * ((b[3] as u64) << 1) +
        (a[8] as u64) * ((b[2] as u64) << 0);
    tmp[11] = (a[3] as u64) * ((b[8] as u64) << 0) +
        (a[4] as u64) * ((b[7] as u64) << 0) +
        (a[5] as u64) * ((b[6] as u64) << 0) +
        (a[6] as u64) * ((b[5] as u64) << 0) +
        (a[7] as u64) * ((b[4] as u64) << 0) +
        (a[8] as u64) * ((b[3] as u64) << 0);
    tmp[12] = (a[4] as u64) * ((b[8] as u64) << 0) +
        (a[5] as u64) * ((b[7] as u64) << 1) +
        (a[6] as u64) * ((b[6] as u64) << 0) +
        (a[7] as u64) * ((b[5] as u64) << 1) +
        (a[8] as u64) * ((b[4] as u64) << 0);
    tmp[13] = (a[5] as u64) * ((b[8] as u64) << 0) +
        (a[6] as u64) * ((b[7] as u64) << 0) +
        (a[7] as u64) * ((b[6] as u64) << 0) +
        (a[8] as u64) * ((b[5] as u64) << 0);
    tmp[14] = (a[6] as u64) * ((b[8] as u64) << 0) +
        (a[7] as u64) * ((b[7] as u64) << 1) +
        (a[8] as u64) * ((b[6] as u64) << 0);
    tmp[15] = (a[7] as u64) * ((b[8] as u64) << 0) +
        (a[8] as u64) * ((b[7] as u64) << 0);
    tmp[16] = (a[8] as u64) * ((b[8] as u64) << 0);
    sm2p256reduce_degree(c, &mut tmp);
}

fn sm2p256square(b: &mut [u32; 9], a: &mut [u32; 9]) {
    let mut tmp: [u64; 17] = [0; 17];

    tmp[0] = (a[0] as u64) * (a[0] as u64);
    tmp[1] = (a[0] as u64) * ((a[1] as u64) << 1);
    tmp[2] = (a[0] as u64) * ((a[2] as u64) << 1) +
        (a[1] as u64) * ((a[1] as u64) << 1);
    tmp[3] = (a[0] as u64) * ((a[3] as u64) << 1) +
        (a[1] as u64) * ((a[2] as u64) << 1);
    tmp[4] = (a[0] as u64) * ((a[4] as u64) << 1) +
        (a[1] as u64) * ((a[3] as u64) << 2) +
        (a[2] as u64) * (a[2] as u64);
    tmp[5] = (a[0] as u64) * ((a[5] as u64) << 1) +
        (a[1] as u64) * ((a[4] as u64) << 1) +
        (a[2] as u64) * ((a[3] as u64) << 1);
    tmp[6] = (a[0] as u64) * ((a[6] as u64) << 1) +
        (a[1] as u64) * ((a[5] as u64) << 2) +
        (a[2] as u64) * ((a[4] as u64) << 1) +
        (a[3] as u64) * ((a[3] as u64) << 1);
    tmp[7] = (a[0] as u64) * ((a[7] as u64) << 1) +
        (a[1] as u64) * ((a[6] as u64) << 1) +
        (a[2] as u64) * ((a[5] as u64) << 1) +
        (a[3] as u64) * ((a[4] as u64) << 1);
    // tmp[8] has the greatest value of 2**61 + 2**60 + 2**61 + 2**60 + 2**60,
    // which is < 2**64 as required.
    tmp[8] = (a[0] as u64) * ((a[8] as u64) << 1) +
        (a[1] as u64) * ((a[7] as u64) << 2) +
        (a[2] as u64) * ((a[6] as u64) << 1) +
        (a[3] as u64) * ((a[5] as u64) << 2) +
        (a[4] as u64) * (a[4] as u64);
    tmp[9] = (a[1] as u64) * ((a[8] as u64) << 1) +
        (a[2] as u64) * ((a[7] as u64) << 1) +
        (a[3] as u64) * ((a[6] as u64) << 1) +
        (a[4] as u64) * ((a[5] as u64) << 1);
    tmp[10] = (a[2] as u64) * ((a[8] as u64) << 1) +
        (a[3] as u64) * ((a[7] as u64) << 2) +
        (a[4] as u64) * ((a[6] as u64) << 1) +
        (a[5] as u64) * ((a[5] as u64) << 1);
    tmp[11] = (a[3] as u64) * ((a[8] as u64) << 1) +
        (a[4] as u64) * ((a[7] as u64) << 1) +
        (a[5] as u64) * ((a[6] as u64) << 1);
    tmp[12] = (a[4] as u64) * ((a[8] as u64) << 1) +
        (a[5] as u64) * ((a[7] as u64) << 2) +
        (a[6] as u64) * (a[6] as u64);
    tmp[13] = (a[5] as u64) * ((a[8] as u64) << 1) +
        (a[6] as u64) * ((a[7] as u64) << 1);
    tmp[14] = (a[6] as u64) * ((a[8] as u64) << 1) +
        (a[7] as u64) * ((a[7] as u64) << 1);
    tmp[15] = (a[7] as u64) * ((a[8] as u64) << 1);
    tmp[16] = (a[8] as u64) * (a[8] as u64);
    sm2p256reduce_degree(b, &mut tmp);
}

fn sm2p256scalar(b: &mut [u32; 9], a: usize) {
    sm2p256mul(b, &mut b.clone(), &mut SM2P256FACTOR[a])
}

// (x3, y3, z3) = (x1, y1, z1) + (x2, y2, z2)
fn sm2p256point_add(x1: &mut [u32; 9], y1: &mut [u32; 9], z1: &mut [u32; 9], x2: &mut [u32; 9], y2: &mut [u32; 9], z2: &mut [u32; 9], x3: &mut [u32; 9], y3: &mut [u32; 9], z3: &mut [u32; 9]) {
    let mut u1: [u32; 9] = [0; 9];
    let mut u2: [u32; 9] = [0; 9];
    let mut z22: [u32; 9] = [0; 9];
    let mut z12: [u32; 9] = [0; 9];
    let mut z23: [u32; 9] = [0; 9];
    let mut z13: [u32; 9] = [0; 9];
    let mut s1: [u32; 9] = [0; 9];
    let mut s2: [u32; 9] = [0; 9];
    let mut h: [u32; 9] = [0; 9];
    let mut h2: [u32; 9] = [0; 9];
    let mut r: [u32; 9] = [0; 9];
    let mut r2: [u32; 9] = [0; 9];
    let mut tm: [u32; 9] = [0; 9];

    if sign_num(sm2p256to_big(z1)) == 0 {
        sm2p256dup(x3, *x2);
        sm2p256dup(y3, *y2);
        sm2p256dup(z3, *z2);
        return;
    }

    if sign_num(sm2p256to_big(z2)) == 0 {
        sm2p256dup(x3, *x1);
        sm2p256dup(y3, *y1);
        sm2p256dup(z3, *z1);
        return;
    }

    sm2p256square(&mut z12, z1);
    sm2p256square(&mut z22, z2);

    sm2p256mul(&mut z13, &mut z12, z1);
    sm2p256mul(&mut z23, &mut z22, z2);

    sm2p256mul(&mut u1, x1, &mut z22);
    sm2p256mul(&mut u2, x2, &mut z12);

    sm2p256mul(&mut s1, y1, &mut z23);
    sm2p256mul(&mut s2, y2, &mut z13);

    if sm2p256to_big(&mut u1).cmp(&sm2p256to_big(&mut u2)) == Ordering::Equal &&
        sm2p256to_big(&mut s1).cmp(&sm2p256to_big(&mut s2)) == Ordering::Equal {
        sm2p256point_double(x1, y1, z1, &mut x1.clone(), &mut y1.clone(), &mut z1.clone())
    }

    sm2p256sub(&mut h, &mut u2, &mut u1);
    sm2p256sub(&mut r, &mut s2, &mut s1);

    sm2p256square(&mut r2, &mut r);
    sm2p256square(&mut h2, &mut h);

    sm2p256mul(&mut tm, &mut h2, &mut h);
    sm2p256sub(x3, &mut r2, &mut tm);
    sm2p256mul(&mut tm, &mut u1, &mut h2);
    sm2p256scalar(&mut tm, 2);
    sm2p256sub(x3, &mut x3.clone(), &mut tm);

    sm2p256mul(&mut tm, &mut u1, &mut h2);
    let mut tmm = tm.clone();
    sm2p256sub(&mut tm, &mut tmm, x3);
    sm2p256mul(y3, &mut r, &mut tm);
    sm2p256mul(&mut tm, &mut h2, &mut h);
    tmm = tm.clone();
    sm2p256mul(&mut tm, &mut tmm, &mut s1);
    sm2p256sub(y3, &mut y3.clone(), &mut tm);

    sm2p256mul(z3, z1, z2);
    sm2p256mul(z3, &mut z3.clone(), &mut h);
}

fn sm2p256point_sub(x1: &mut [u32; 9], y1: &mut [u32; 9], z1: &mut [u32; 9], x2: &mut [u32; 9], y2: &mut [u32; 9], z2: &mut [u32; 9], x3: &mut [u32; 9], y3: &mut [u32; 9], z3: &mut [u32; 9]) {
    let mut u1: [u32; 9] = [0; 9];
    let mut u2: [u32; 9] = [0; 9];
    let mut z22: [u32; 9] = [0; 9];
    let mut z12: [u32; 9] = [0; 9];
    let mut z23: [u32; 9] = [0; 9];
    let mut z13: [u32; 9] = [0; 9];
    let mut s1: [u32; 9] = [0; 9];
    let mut s2: [u32; 9] = [0; 9];
    let mut h: [u32; 9] = [0; 9];
    let mut h2: [u32; 9] = [0; 9];
    let mut r: [u32; 9] = [0; 9];
    let mut r2: [u32; 9] = [0; 9];
    let mut tm: [u32; 9] = [0; 9];

    let mut y = sm2p256to_big(y2);
    let mut zero = BigUint::from_u64(0).unwrap();
    zero = zero.sub(y.clone());
    y = y.sub(zero);
    let yy = sm2p256from_big(y);
    for i in 0..9 {
        y2[i] = yy[i]
    }

    if sign_num(sm2p256to_big(z1)) == 0 {
        sm2p256dup(x3, *x2);
        sm2p256dup(y3, *y2);
        sm2p256dup(z3, *z2);
        return;
    }

    if sign_num(sm2p256to_big(z2)) == 0 {
        sm2p256dup(x3, *x1);
        sm2p256dup(y3, *y1);
        sm2p256dup(z3, *z1);
        return;
    }

    sm2p256square(&mut z12, z1);
    sm2p256square(&mut z22, z2);

    sm2p256mul(&mut z13, &mut z12, z1);
    sm2p256mul(&mut z23, &mut z22, z2);

    sm2p256mul(&mut u1, x1, &mut z22);
    sm2p256mul(&mut u2, x2, &mut z12);

    sm2p256mul(&mut s1, y1, &mut z23);
    sm2p256mul(&mut s2, y2, &mut z13);

    if sm2p256to_big(&mut u1).cmp(&sm2p256to_big(&mut u2)) == Ordering::Equal &&
        sm2p256to_big(&mut s1).cmp(&sm2p256to_big(&mut s2)) == Ordering::Equal {
        sm2p256point_double(x1, y1, z1, &mut x1.clone(), &mut y1.clone(), &mut z1.clone());
    }

    sm2p256sub(&mut h, &mut u2, &mut u1);
    sm2p256sub(&mut r, &mut s2, &mut s1);

    sm2p256square(&mut r2, &mut r);
    sm2p256square(&mut h2, &mut h);

    sm2p256mul(&mut tm, &mut h2, &mut h);
    sm2p256sub(x3, &mut r2, &mut tm);
    sm2p256mul(&mut tm, &mut u1, &mut h2);
    sm2p256scalar(&mut tm, 2);
    sm2p256sub(x3, &mut x3.clone(), &mut tm);

    sm2p256mul(&mut tm, &mut u1, &mut h2);
    let mut tmm = tm.clone();
    sm2p256sub(&mut tm, &mut tmm, x3);
    sm2p256mul(y3, &mut r, &mut tm);
    sm2p256mul(&mut tm, &mut h2, &mut h);
    tmm = tm.clone();
    sm2p256mul(&mut tm, &mut tmm.clone(), &mut s1);
    sm2p256sub(y3, &mut y3.clone(), &mut tm);

    sm2p256mul(z3, z1, z2);
    sm2p256mul(z3, &mut z3.clone(), &mut h);
}

fn sm2p256point_double(x3: &mut [u32; 9], y3: &mut [u32; 9], z3: &mut [u32; 9], x: &mut [u32; 9], y: &mut [u32; 9], z: &mut [u32; 9]) {
    let mut s: [u32; 9] = [0; 9];
    let mut m: [u32; 9] = [0; 9];
    let mut m2: [u32; 9] = [0; 9];
    let mut x2: [u32; 9] = [0; 9];
    let mut y2: [u32; 9] = [0; 9];
    let mut z2: [u32; 9] = [0; 9];
    let mut z4: [u32; 9] = [0; 9];
    let mut y4: [u32; 9] = [0; 9];
    let mut az4: [u32; 9] = [0; 9];

    sm2p256square(&mut x2, x);
    sm2p256square(&mut y2, y);
    sm2p256square(&mut z2, z);

    sm2p256square(&mut z4, z);
    let mut zz4 = z4.clone();
    sm2p256mul(&mut z4, &mut zz4, z);
    zz4 = z4.clone();
    sm2p256mul(&mut z4, &mut zz4, z);

    sm2p256square(&mut y4, y);
    let mut yy4 = y4.clone();
    sm2p256mul(&mut y4, &mut yy4, y);
    yy4 = y4.clone();
    sm2p256mul(&mut y4, &mut yy4, y);
    sm2p256scalar(&mut y4, 8);

    sm2p256mul(&mut s, x, &mut y2);
    sm2p256scalar(&mut s, 4);

    sm2p256dup(&mut m, x2);
    sm2p256scalar(&mut m, 3);
    sm2p256mul(&mut az4, &mut SM256_A.clone(), &mut z4);
    let mut mm = m.clone();
    sm2p256add(&mut m, &mut mm, &mut az4);

    sm2p256square(&mut m2, &mut m);

    sm2p256add(z3, y, z);
    sm2p256square(z3, &mut z3.clone());
    sm2p256sub(z3, &mut z3.clone(), &mut z2);
    sm2p256sub(z3, &mut z3.clone(), &mut y2);

    sm2p256sub(x3, &mut m2, &mut s);
    sm2p256sub(x3, &mut x3.clone(), &mut s);

    sm2p256sub(y3, &mut s, x3);
    sm2p256mul(y3, &mut y3.clone(), &mut m);
    sm2p256sub(y3, &mut y3.clone(), &mut y4);
}

fn sm2p256point_add_mixed(x_out: &mut [u32; 9], y_out: &mut [u32; 9], z_out: &mut [u32; 9], x1: &mut [u32; 9], y1: &mut [u32; 9], z1: &mut [u32; 9], x2: &mut [u32; 9], y2: &mut [u32; 9]) {
    // println!("{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}", x_out, y_out, z_out, x1, y1, z1, x2, y2);
    let mut z1z1: [u32; 9] = [0; 9];
    let mut z1z1z1: [u32; 9] = [0; 9];
    let mut s2: [u32; 9] = [0; 9];
    let mut u2: [u32; 9] = [0; 9];
    let mut h: [u32; 9] = [0; 9];
    let mut i: [u32; 9] = [0; 9];
    let mut j: [u32; 9] = [0; 9];
    let mut r: [u32; 9] = [0; 9];
    let mut rr: [u32; 9] = [0; 9];
    let mut v: [u32; 9] = [0; 9];
    let mut tmp: [u32; 9] = [0; 9];

    sm2p256square(&mut z1z1, z1);
    let mut z11 = z1.clone();
    sm2p256add(&mut tmp, z1, &mut z11);
    // println!("{:?} {:?} {:?}", tmp, z1, z11);

    sm2p256mul(&mut u2, x2, &mut z1z1);
    sm2p256mul(&mut z1z1z1, z1, &mut z1z1);
    sm2p256mul(&mut s2, y2, &mut z1z1z1);
    // println!("{:?} {:?} {:?} 1", h, u2, x1);
    sm2p256sub(&mut h, &mut u2, x1);
    // println!("{:?} 2", h);
    let mut hh = h.clone();
    sm2p256add(&mut i, &mut h, &mut hh);
    let mut ii = i.clone();
    sm2p256square(&mut i, &mut ii);
    // println!("{:?} {:?} {:?} 1", j, h, i);
    sm2p256mul(&mut j, &mut h, &mut i);
    // println!("{:?} 2", j);
    // println!("{:?} {:?} {:?} 1", r, s2, y1);
    sm2p256sub(&mut r, &mut s2, y1);
    // println!("{:?} 2", r);
    let mut rr1 = r.clone();
    let mut rr2 = r.clone();
    sm2p256add(&mut r, &mut rr1, &mut rr2);
    // println!("{:?}", r);
    sm2p256mul(&mut v, x1, &mut i);

    sm2p256mul(z_out, &mut tmp, &mut h);
    sm2p256square(&mut rr, &mut r);
    // println!("{} {:?} {:?} 1", x_out[0], rr, j);
    sm2p256sub(x_out, &mut rr, &mut j);
    // println!("{} 2", x_out[0]);
    // println!("{:?} 1", yy_out);
    let mut xx_out = x_out.clone();
    sm2p256sub(x_out, &mut xx_out, &mut v);
    // println!("{} 3", x_out[0]);
    xx_out = x_out.clone();
    sm2p256sub(x_out, &mut xx_out, &mut v);
    // println!("{} 4", x_out[0]);

    sm2p256sub(&mut tmp, &mut v, x_out);
    sm2p256mul(y_out, &mut tmp, &mut r);
    sm2p256mul(&mut tmp, y1, &mut j);
    let mut yy_out = y_out.clone();
    sm2p256sub(y_out, &mut yy_out, &mut tmp);
    yy_out = y_out.clone();
    sm2p256sub(y_out, &mut yy_out, &mut tmp);
}

fn sm2p256scalar_base_mult(x_out: &mut [u32; 9], y_out: &mut [u32; 9], z_out: &mut [u32; 9], scalar: &mut [u8; 32]) {
    let mut n_is_infinity_mask = !(0 as u32);
    let mut px: [u32; 9] = [0; 9];
    let mut py: [u32; 9] = [0; 9];
    let mut tx: [u32; 9] = [0; 9];
    let mut ty: [u32; 9] = [0; 9];
    let mut tz: [u32; 9] = [0; 9];
    let mut p_is_noninfinite_mask: u32 = 0;
    let mut mask: u32 = 0;
    let mut table_offset: usize = 0;

    for i in 0..9 {
        x_out[i] = 0;
        y_out[i] = 0;
        z_out[i] = 0;
    }

    let mut i = 0;
    while i < 32 {
        if i != 0 {
            // println!("{:?} {:?} {:?} 111", x_out, y_out, z_out);
            sm2p256point_double(x_out, y_out, z_out, &mut x_out.clone(), &mut y_out.clone(), &mut z_out.clone());
            // println!("{:?} {:?} {:?} 222", x_out, y_out, z_out);
        }

        table_offset = 0;
        let mut j = 0;
        while j <= 32 {
            let bit0 = sm2p256get_bit(*scalar, 31 - i + j);
            let bit1 = sm2p256get_bit(*scalar, 95 - i + j);
            let bit2 = sm2p256get_bit(*scalar, 159 - i + j);
            let bit3 = sm2p256get_bit(*scalar, 223 - i + j);
            let index = bit0 | (bit1 << 1) | (bit2 << 2) | (bit3 << 3);

            // println!("{:?} {:?} 111", px, py);
            sm2p256select_affine_point(&mut px, &mut py, Vec::from(&SM2P256PRECOMPUTED[table_offset..]), index);
            table_offset += 30 * 9;
            // println!("{:?} {:?}", px, py);

            // println!("{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} 1", tx, ty, tz, x_out, y_out, z_out, px, py);
            sm2p256point_add_mixed(&mut tx, &mut ty, &mut tz, x_out, y_out, z_out, &mut px, &mut py);
            // println!("{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} 2", tx, ty, tz, x_out, y_out, z_out, px, py);

            sm2p256copy_conditional(x_out, px, n_is_infinity_mask);
            sm2p256copy_conditional(y_out, py, n_is_infinity_mask);
            sm2p256copy_conditional(z_out, SM2P256FACTOR[1], n_is_infinity_mask);
            // println!("{:?} {:?} {:?} {}", x_out, y_out, z_out, mask);

            p_is_noninfinite_mask = non_zero_to_all_ones(index);
            mask = p_is_noninfinite_mask & !n_is_infinity_mask;
            sm2p256copy_conditional(x_out, tx, mask);
            sm2p256copy_conditional(y_out, ty, mask);
            sm2p256copy_conditional(z_out, tz, mask);
            // println!("{:?} {:?} {:?} {}", tx, ty, tz, mask);
            // println!("{:?} {:?} {:?} {}", x_out, y_out, z_out, mask);
            // If p was not zero, then n is now non-zero.
            n_is_infinity_mask = n_is_infinity_mask & !p_is_noninfinite_mask;

            j += 32;
        }

        i += 1;
    }
}

fn sm2p256point_to_affine(x_out: &mut [u32; 9], y_out: &mut [u32; 9], x: &mut [u32; 9], y: &mut [u32; 9], z: &mut [u32; 9]) {
    let mut z_inv: [u32; 9] = [0; 9];
    let mut z_inv_sq: [u32; 9] = [0; 9];

    let mut zzz = z.clone();
    let mut zz = sm2p256to_big(z);
    // let zz2 = zz;
    // let zz3 = CURVE_N.clone();
    // zz = zz.gcd(&zz);
    // println!("{} 1", zz);
    // let bbb = hex::decode("104403759721252389636733147996521724073398695139720300428379110454059678713304").unwrap();
    // zz.ModInverse(zz, sm2P256.P)
    let bbb = sm2p256to_big_bi(&mut zzz);
    let aaa = bbb.mod_inverse(CURVE_P_BI.clone()).unwrap();
    // println!("{} 1", aaa);

    zz = BigUint::from_str(&aaa.to_string()).unwrap(); // big order
    // println!("{} 1", zz);
    // zz = BigUint::from_str("104403759721252389636733147996521724073398695139720300428379110454059678713304").unwrap();

    // let zz1 = modinverse(zz2, zz3).unwrap();
    // zz = BigUint::from(zz1);
    z_inv = sm2p256from_big(zz);

    // println!("{:?} {:?} 1", z_inv_sq, z_inv);
    sm2p256square(&mut z_inv_sq, &mut z_inv);
    // println!("{:?} {:?} 2", z_inv_sq, z_inv);

    sm2p256mul(x_out, x, &mut z_inv_sq);
    let mut zz_inv = z_inv.clone();
    sm2p256mul(&mut z_inv, &mut zz_inv, &mut z_inv_sq);
    sm2p256mul(y_out, y, &mut z_inv);
}

fn sm2p256to_affine(x: &mut [u32; 9], y: &mut [u32; 9], z: &mut [u32; 9]) -> (BigUint, BigUint) {
    let mut xx: [u32; 9] = [0; 9];
    let mut yy: [u32; 9] = [0; 9];

    sm2p256point_to_affine(&mut xx, &mut yy, x, y, z);
    // println!("{:?} {:?} {:?} {:?} {:?}", xx, yy, x, y, z);
    (sm2p256to_big(&mut xx), sm2p256to_big(&mut yy))
}

fn sm2p256scalar_mult(x_out: &mut [u32; 9], y_out: &mut [u32; 9], z_out: &mut [u32; 9], x: &mut [u32; 9], y: &mut [u32; 9], scalar: Vec<u8>) {
    let mut precomp: [[[u32; 9]; 3]; 16] = [[[0; 9]; 3]; 16];
    let mut px: [u32; 9] = [0; 9];
    let mut py: [u32; 9] = [0; 9];
    let mut pz: [u32; 9] = [0; 9];
    let mut tx: [u32; 9] = [0; 9];
    let mut ty: [u32; 9] = [0; 9];
    let mut tz: [u32; 9] = [0; 9];
    let mut n_is_infinity_mask: u32;
    let mut index: u32;
    let mut p_is_noninfinite_mask: u32;
    let mut mask: u32;

    // We precompute 0,1,2,... times {x,y}.
    precomp[1][0] = *x;
    precomp[1][1] = *y;
    precomp[1][2] = SM2P256FACTOR[1];

    let mut i = 2;
    while i < 8 {
        let mut p1 = precomp[i][0].clone();
        let mut p2 = precomp[i][1].clone();
        let mut p3 = precomp[i][2].clone();
        let mut p4 = precomp[i / 2][0].clone();
        let mut p5 = precomp[i / 2][1].clone();
        let mut p6 = precomp[i / 2][2].clone();
        sm2p256point_double(&mut p1, &mut p2, &mut p3, &mut p4, &mut p5, &mut p6);
        precomp[i][0] = p1;
        precomp[i][1] = p1;
        precomp[i][2] = p1;
        precomp[i / 2][0] = p1;
        precomp[i / 2][1] = p1;
        precomp[i / 2][2] = p1;

        p1 = precomp[i + 1][0].clone();
        p2 = precomp[i + 1][1].clone();
        p3 = precomp[i + 1][2].clone();
        p4 = precomp[i][0].clone();
        p5 = precomp[i][1].clone();
        p6 = precomp[i][2].clone();
        sm2p256point_add_mixed(&mut p1, &mut p2, &mut p3, &mut p4, &mut p5, &mut p6, x, y);
        precomp[i + 1][0] = p1;
        precomp[i + 1][1] = p2;
        precomp[i + 1][2] = p3;
        precomp[i][0] = p4;
        precomp[i][1] = p5;
        precomp[i][2] = p6;

        i += 2;
    }

    for j in 0..9 {
        x_out[j] = 0;
        y_out[j] = 0;
        z_out[j] = 0;
    }

    n_is_infinity_mask = !(0 as u32);
    let mut zeroes: u16 = 0;
    let lc = scalar.len();
    while i < lc {
        if scalar[i] == 0 {
            zeroes += 1;
            continue;
        }

        if zeroes > 0 {
            while zeroes > 0 {
                sm2p256point_double(x_out, y_out, z_out, &mut x_out.clone(), &mut y_out.clone(), &mut z_out.clone());
                zeroes -= 1;
            }
        }

        index = ((scalar[i] as f32).abs()) as u32;
        sm2p256point_double(x_out, y_out, z_out, &mut x_out.clone(), &mut y_out.clone(), &mut z_out.clone());
        sm2p256select_jacobian_point(&mut px, &mut py, &mut pz, precomp, index);

        if scalar[i] > 0 {
            sm2p256point_add(x_out, y_out, z_out, &mut px, &mut py, &mut pz, &mut tx, &mut ty, &mut tz);
        } else {
            sm2p256point_add(x_out, y_out, z_out, &mut px, &mut py, &mut pz, &mut tx, &mut ty, &mut tz);
        }

        sm2p256copy_conditional(x_out, px, n_is_infinity_mask);
        sm2p256copy_conditional(y_out, py, n_is_infinity_mask);
        sm2p256copy_conditional(z_out, pz, n_is_infinity_mask);
        p_is_noninfinite_mask = non_zero_to_all_ones(index);
        mask = p_is_noninfinite_mask & !(n_is_infinity_mask.clone());
        sm2p256copy_conditional(x_out, tx, mask);
        sm2p256copy_conditional(y_out, ty, mask);
        sm2p256copy_conditional(z_out, tz, mask);
        n_is_infinity_mask &= !(p_is_noninfinite_mask.clone());

        i += 1;
    }

    if zeroes > 0 {
        while zeroes > 0 {
            sm2p256point_double(x_out, y_out, z_out, &mut x_out.clone(), &mut y_out.clone(), &mut z_out.clone());
            zeroes -= 1;
        }
    }
}

impl Sm2P256Curve {
    pub fn new() -> Sm2P256Curve {
        static mut CURVE: *const Sm2P256Curve = 0 as *const Sm2P256Curve;
        static ONCE: Once = Once::new();
        unsafe {
            ONCE.call_once(|| {
                let mut sm2_crv = Sm2P256Curve {
                    curve: CurveParams {
                        p: CURVE_P.clone(),
                        n: CURVE_N.clone(),
                        b: CURVE_B.clone(),
                        gx: CURVE_GX.clone(),
                        gy: CURVE_GY.clone(),
                        bit_size: BITSIZE,
                        name: "SM2-P-256".to_string(),
                    },
                    r_inverse: CURVE_RINVERSE.clone(),
                    a: [0; 9],
                    b: [0; 9],
                    gx: [0; 9],
                    gy: [0; 9],
                };
                sm2_crv.a = SM256_A.clone();
                sm2_crv.gx = sm2p256from_big(sm2_crv.curve.gx.clone());
                sm2_crv.gy = sm2p256from_big(sm2_crv.curve.gy.clone());
                sm2_crv.b = sm2p256from_big(sm2_crv.curve.b.clone());
                CURVE = mem::transmute(Box::new(sm2_crv));
            });
            (*CURVE).clone()
        }
    }

    pub fn params(&self) -> CurveParams {
        self.curve.clone()
    }

    pub fn scalar_base_mult(&self, k: Vec<u8>) -> (BigUint, BigUint) {
        let mut scalar_reversed: [u8; 32] = [0; 32];
        // let (x, y, z): [u32; 9];
        let mut x: [u32; 9] = [0; 9];
        let mut y: [u32; 9] = [0; 9];
        let mut z: [u32; 9] = [0; 9];

        // println!("{:?}", k);
        sm2p256get_scalar(&mut scalar_reversed, k);
        sm2p256scalar_base_mult(&mut x, &mut y, &mut z, &mut scalar_reversed);
        // println!("{:?}", x);
        // println!("{:?}", y);
        // println!("{:?}", z);
        // println!("{:?}", scalar_reversed);
        sm2p256to_affine(&mut x, &mut y, &mut z)
    }
}


