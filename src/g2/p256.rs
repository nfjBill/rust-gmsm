use num::bigint::BigUint;
use std::sync::{Once};
use std::{mem};
use num::{Num, Integer};
use std::ops::{Shl, Shr};
use std::cmp::Ordering;
use lazy_static::lazy_static;
// use crate::utils::slice::{SliceDisplay};

static BOTTOM28BITS: u32 = 0xFFFFFFF;
static BOTTOM29BITS: u32 = 0x1FFFFFFF;
pub static BITSIZE: usize = 256;

lazy_static! {
    static ref CURVE_A: BigUint = BigUint::from_str_radix("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16).unwrap();
    static ref CURVE_P: BigUint = BigUint::from_str_radix("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16).unwrap();
    static ref CURVE_N: BigUint = BigUint::from_str_radix("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16).unwrap();
    static ref CURVE_B: BigUint = BigUint::from_str_radix("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16).unwrap();
    static ref CURVE_GX: BigUint = BigUint::from_str_radix("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16).unwrap();
    static ref CURVE_GY: BigUint = BigUint::from_str_radix("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16).unwrap();
    static ref CURVE_RINVERSE: BigUint = BigUint::from_str_radix("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16).unwrap();
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

// X = a * R mod P
fn sm2p256from_big(mut b: [u32; 9], a: BigUint) -> [u32; 9] {
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

//   0xffffffff for 0 < x <= 2**31
//   0 for x == 0 or x > 2**31.
fn non_zero_to_all_ones(x: u32) -> u32 {
    ((x - 1) >> 31) - 1
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
                sm2_crv.a = sm2p256from_big(sm2_crv.a, CURVE_A.clone());
                sm2_crv.gx = sm2p256from_big(sm2_crv.gx, sm2_crv.curve.gx.clone());
                sm2_crv.gy = sm2p256from_big(sm2_crv.gy, sm2_crv.curve.gy.clone());
                sm2_crv.b = sm2p256from_big(sm2_crv.b, sm2_crv.curve.b.clone());
                CURVE = mem::transmute(Box::new(sm2_crv));
            });
            (*CURVE).clone()
        }
    }

    pub fn params(&self) -> CurveParams {
        self.curve.clone()
    }

    pub fn scalar_base_mult(&self, k: Vec<u8>) {
        let mut scalar_reversed: [u8; 32] = [0; 32];
        // let (x, y, z): [u32; 9];

        // println!("{:?}", k);
        sm2p256get_scalar(&mut scalar_reversed, k);
        // println!("{:?}", scalar_reversed);
        // sm2P256ScalarBaseMult(&x, &y, &z, &scalar_reversed)
        // return sm2P256ToAffine(&X, &Y, &Z)
    }
}


