use num::bigint::BigUint;
use std::sync::{Once};
use std::{mem};
use num::{Num, Integer};
use std::ops::{Shl, Shr};
use lazy_static::lazy_static;
// use crate::utils::slice::{SliceDisplay};

static BOTTOM28BITS: u32 = 0xFFFFFFF;
static BOTTOM29BITS: u32 = 0x1FFFFFFF;

lazy_static! {
    static ref CURVE_A: BigUint = BigUint::from_str_radix("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16).unwrap();
    static ref CURVE_P: BigUint = BigUint::from_str_radix("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16).unwrap();
    static ref CURVE_N: BigUint = BigUint::from_str_radix("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16).unwrap();
    static ref CURVE_B: BigUint = BigUint::from_str_radix("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16).unwrap();
    static ref CURVE_GX: BigUint = BigUint::from_str_radix("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16).unwrap();
    static ref CURVE_GY: BigUint = BigUint::from_str_radix("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16).unwrap();
    static ref CURVE_RINVERSE: BigUint = BigUint::from_str_radix("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16).unwrap();
}

// pub struct CurveParams {
//     pub p: BigUint,
//     pub n: BigUint,
//     pub b: BigUint,
//     pub gx: BigUint,
//     pub gy: BigUint,
//     pub bit_size: usize,
//     pub name: String,
// }

#[derive(Clone)]
pub struct Sm2P256Curve {
    pub p: BigUint,
    pub n: BigUint,
    pub ca: BigUint,
    pub cb: BigUint,
    pub g_x: BigUint,
    pub g_y: BigUint,
    pub bit_size: usize,
    pub name: String,

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

impl Sm2P256Curve {
    pub fn new() -> Sm2P256Curve {
        static mut CURVE: *const Sm2P256Curve = 0 as *const Sm2P256Curve;
        static ONCE: Once = Once::new();
        unsafe {
            ONCE.call_once(|| {
                let mut curve = Sm2P256Curve {
                    ca: CURVE_A.clone(),
                    p: CURVE_P.clone(),
                    n: CURVE_N.clone(),
                    cb: CURVE_B.clone(),
                    g_x: CURVE_GX.clone(),
                    g_y: CURVE_GY.clone(),
                    r_inverse: CURVE_RINVERSE.clone(),
                    bit_size: 256,
                    name: "SM2-P-256".to_string(),
                    a: [0; 9],
                    b: [0; 9],
                    gx: [0; 9],
                    gy: [0; 9],
                };
                curve.a = sm2p256from_big(curve.a, curve.ca.clone());
                curve.gx = sm2p256from_big(curve.gx, curve.g_x.clone());
                curve.gy = sm2p256from_big(curve.gy, curve.g_y.clone());
                curve.b = sm2p256from_big(curve.b, curve.cb.clone());
                CURVE = mem::transmute(Box::new(curve));
            });
            (*CURVE).clone()
        }
    }

    pub fn params(&self) -> Sm2P256Curve {
        Sm2P256Curve {
            p: self.p.clone(),
            n: self.n.clone(),
            ca: self.ca.clone(),
            cb: self.cb.clone(),
            g_x: self.g_x.clone(),
            g_y: self.g_y.clone(),
            bit_size: self.bit_size,
            name: self.name.clone(),
            r_inverse: self.r_inverse.clone(),
            a: self.a,
            b: self.b,
            gx: self.gx,
            gy: self.gy,
        }
    }
}


