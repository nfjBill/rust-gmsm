use num::{BigUint, FromPrimitive, Integer};
use rand::Rng;
use crate::g2::p256::{Sm2P256Curve, CurveParams};
use crate::g2::consts::*;
use crate::utils::slice::copy_slice;
use std::ops::{Sub, Add};
use lazy_static::lazy_static;
use std::str::FromStr;

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
    pub public_key: PublicKey,
    d: BigUint,
}

pub fn generate_key() -> PrivateKey {
    let c = Sm2P256Curve::new();
    let params = c.params();
    let mut b: Vec<u8> = (0..BITSIZE / 8 + 8).map(|_| { rand::random::<u8>() }).collect();
    b = hex::decode("b0e289d068d40ad9bc6118b2e000c05ae3af93c2e03980498ee18cd953383dbc8af051d598bd767d").unwrap();
    let mut k = BigUint::from_bytes_be(&b); // big order
    let n = BigUint::sub(params.n.clone(), TWO.clone());
    k = k.mod_floor(&n);
    k = k.add(ONE.clone());
    let k_bytes = k.to_bytes_be();
    let (x, y) = c.scalar_base_mult(k_bytes);
    // let x = BigUint::from_str("106232436169132275020063792326403348975150919484913616784921093913122562537616").unwrap();
    // let y = BigUint::from_str("11773149012160196139417803285138075847025647624416340549715874084457315617910").unwrap();
    // println!("{} {}", x, y);
    PrivateKey {
        curve: params.clone(),
        public_key: PublicKey { x, y },
        d: k,
    }
}

pub fn raw_pri_byte(private_key: PrivateKey) -> Vec<u8> {
    let d_bytes = private_key.d.to_bytes_be();
    let dl = d_bytes.len();

    if dl > KEYBYTES {
        let mut raw: Vec<u8> = vec![0; KEYBYTES];
        copy_slice(&mut raw, &d_bytes[(dl - KEYBYTES)..]);
        return raw;
    } else if dl < KEYBYTES {
        let mut raw: Vec<u8> = vec![0; KEYBYTES];
        copy_slice(&mut raw[(dl - KEYBYTES)..], &d_bytes);
        return raw;
    } else {
        return d_bytes;
    }
}

pub fn raw_pub_byte(public_key: PublicKey) -> Vec<u8> {
    let x_bytes = public_key.x.to_bytes_be();
    let y_bytes = public_key.y.to_bytes_be();
    let xl = x_bytes.len();
    let yl = y_bytes.len();

    let mut raw: Vec<u8> = vec![0; 1 + KEYBYTES * 2];
    raw[0] = UNCOMPRESS;

    if xl > KEYBYTES {
        copy_slice(&mut raw[1..(1 + KEYBYTES)], &x_bytes[(xl - KEYBYTES)..]);
    } else if xl < KEYBYTES {
        copy_slice(&mut raw[(1 + (KEYBYTES - xl))..(1 + KEYBYTES)], &x_bytes);
    } else {
        copy_slice(&mut raw[1..(1 + KEYBYTES)], &x_bytes);
    }

    if yl > KEYBYTES {
        copy_slice(&mut raw[(1 + KEYBYTES)..], &y_bytes[(yl - KEYBYTES).. ]);
    } else if yl < KEYBYTES {
        copy_slice(&mut raw[(1 + KEYBYTES + (KEYBYTES - yl))..], &y_bytes);
    } else {
        copy_slice(&mut raw[(1 + KEYBYTES)..], &y_bytes);
    }

    raw
}