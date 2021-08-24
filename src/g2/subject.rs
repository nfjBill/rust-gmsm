use num::{BigUint, FromPrimitive, Integer};
use rand::Rng;
use crate::g2::p256::{Sm2P256Curve, BITSIZE, CurveParams};
use crate::utils::slice::SliceDisplay;
use std::ops::{Sub, Add};
use lazy_static::lazy_static;

lazy_static! {
    static ref ONE: BigUint = BigUint::from_u64(1).unwrap();
    static ref TWO: BigUint = BigUint::from_u64(2).unwrap();
}

pub struct PublicKey {
    x: BigUint,
    y: BigUint,
}

pub struct PrivateKey {
    curve: CurveParams,
    public_key: PublicKey,
    d: BigUint,
}

pub fn generate_key() -> PrivateKey{
    let c = Sm2P256Curve::new();
    let params = c.params();
    let b: Vec<u8> = (0..BITSIZE/8+8).map(|_| { rand::random::<u8>() }).collect();
    let mut k = BigUint::from_bytes_be(&b); // big order
    let n = BigUint::sub(params.n.clone(), TWO.clone());
    k = k.mod_floor(&n);
    k = k.add(ONE.clone());
    let k_bytes = k.to_bytes_be();
    c.scalar_base_mult(k_bytes);
    PrivateKey {
        curve: params.clone(),
        public_key: PublicKey { x: Default::default(), y: Default::default() },
        d: k,
    }
}
