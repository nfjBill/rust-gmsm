use num::{BigUint, FromPrimitive, Integer};
use rand::Rng;
use crate::g2::p256::{Sm2P256Curve, CurveParams, CURVE_N};
use crate::g2::consts::*;
use crate::g3::digest::{sm3sum, Digest};
use crate::utils::slice::*;
use std::ops::{Sub, Add};
use lazy_static::lazy_static;
use std::str::FromStr;

lazy_static! {
    static ref ONE: BigUint = BigUint::from_u64(1).unwrap();
    static ref TWO: BigUint = BigUint::from_u64(2).unwrap();
}

#[derive(Clone)]
pub struct PublicKey {
    pub curve: CurveParams,
    pub x: BigUint,
    pub y: BigUint,
}

#[derive(Clone)]
pub struct PrivateKey {
    pub curve: CurveParams,
    pub public_key: PublicKey,
    pub d: BigUint,
}

pub fn generate_key() -> PrivateKey {
    let c = Sm2P256Curve::new();
    let params = c.params();
    let mut b: Vec<u8> = (0..BITSIZE / 8 + 8).map(|_| { rand::random::<u8>() }).collect();
    // fix random
    // b = hex::decode("b0e289d068d40ad9bc6118b2e000c05ae3af93c2e03980498ee18cd953383dbc8af051d598bd767d").unwrap();
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
        public_key: PublicKey { curve: params.clone(), x, y },
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
        copy_slice(&mut raw[(1 + KEYBYTES)..], &y_bytes[(yl - KEYBYTES)..]);
    } else if yl < KEYBYTES {
        copy_slice(&mut raw[(1 + KEYBYTES + (KEYBYTES - yl))..], &y_bytes);
    } else {
        copy_slice(&mut raw[(1 + KEYBYTES)..], &y_bytes);
    }

    raw
}

pub fn bytes_to_public_key(bytes: Vec<u8>) -> PublicKey {
    let c = Sm2P256Curve::new();
    let params = c.params();

    PublicKey {
        curve: params.clone(),
        x: BigUint::from_bytes_be(&bytes[..KEYBYTES]),
        y: BigUint::from_bytes_be(&bytes[KEYBYTES..]),
    }
}

fn rand_field_element() -> BigUint {
    let sm2_p256 = Sm2P256Curve::new();
    let params = sm2_p256.params();
    let b: Vec<u8> = (0..BITSIZE / 8 + 8).map(|_| { rand::random::<u8>() }).collect();
    // fix random
    // let b = hex::decode("eb8ba241ff968e1ff212ee55eed16e08cf4e4047325fe0907e8d555a4640a3e1917a6f6de2aaca17").unwrap();

    let mut k = BigUint::from_bytes_be(&b);
    let n = CURVE_N.clone().sub(ONE.clone());
    k = k.mod_floor(&n);
    k = k.add(ONE.clone());
    k
}


// 32byte
fn zero_byte_slice() -> Vec<u8> {
    vec![0; 32]
}

fn put_uint32(b: &mut [u8; 4], v: u32) {
    b[0] = (v >> 24) as u8;
    b[1] = (v >> 16) as u8;
    b[2] = (v >> 8) as u8;
    b[3] = v as u8;
}

fn int_to_bytes(x: usize) -> [u8; 4] {
    let mut buf: [u8; 4] = [0; 4];

    put_uint32(&mut buf, x as u32);
    buf
}

fn kdf(length: usize, x: Vec<Vec<u8>>) -> (Vec<u8>, bool) {
    let mut c: Vec<u8> = vec![];
    let mut ct = 1;
    let mut h = Digest::new();
    let mut i: usize = 0;
    let mut j: usize = (length + 31) / 32;
    while i < j {
        h.reset();
        for v in x.iter() {
            h.write(v);
        }
        h.write(&int_to_bytes(ct));
        let hash = h.sum(vec![].as_slice());

        if (i + 1) == j && length % 32 != 0 {
            c = concat_u8(&c, &hash[..(length % 32)]);
        } else {
            c = concat_u8(&c, &hash);
        }
        ct += 1;

        i += 1;
    }

    i = 0;
    while i < length {
        if c[i] != 0 {
            return (c, true);
        }
        i += 1;
    }

    (c, false)
}

pub fn encrypt(pub_key: PublicKey, data: Vec<u8>, mode: usize) -> Vec<u8> {
    let length = data.len();
    let sm2_p256 = Sm2P256Curve::new();

    loop {
        let mut c: Vec<u8> = vec![];
        // let curve = sm2_p256.params().clone();
        let k = rand_field_element();
        let (mut x1, mut y1) = sm2_p256.scalar_base_mult(k.to_bytes_be());
        let pub_k = pub_key.clone();
        let (x2, y2) = sm2_p256.scalar_mult(pub_k.x, pub_k.y, k.to_bytes_be());
        let mut x1buf = x1.to_bytes_be();
        let mut y1buf = y1.to_bytes_be();
        let mut x2buf = x2.to_bytes_be();
        let mut y2buf = y2.to_bytes_be();
        // println!("{:?} {:?} {:?} {:?}", x1buf, y1buf, x2buf, y2buf);
        // -

        let mut n = x1buf.len();
        if n < 32 {
            x1buf = concat_u8(&zero_byte_slice()[..(32 - n)], &x1buf);
        }
        n = y1buf.len();
        if n < 32 {
            y1buf = concat_u8(&zero_byte_slice()[..(32 - n)], &y1buf);
        }
        n = x2buf.len();
        if n < 32 {
            x2buf = concat_u8(&zero_byte_slice()[..(32 - n)], &x2buf);
        }
        n = y2buf.len();
        if n < 32 {
            y2buf = concat_u8(&zero_byte_slice()[..(32 - n)], &y2buf);
        }
        c = [c, x1buf].concat();
        c = [c, y1buf].concat();
        let mut tm: Vec<u8> = vec![];
        tm = concat_u8(&tm, &x2buf);
        tm = [tm, data.clone()].concat();
        tm = concat_u8(&tm, &y2buf);
        let h = sm3sum(tm);
        c = [c, h].concat();
        let (ct, ok) = kdf(length, vec![x2buf.clone(), y2buf.clone()]);
        if !ok {
            continue;
        }
        c = [c, ct].concat();
        let mut i = 0;
        while i < length {
            c[96 + i] ^= data[i];
            i+=1;
        }

        let prefix: Vec<u8> = vec![0x04];

        if mode == C1C2C3 {
            let mut c1: Vec<u8> = vec![0; 64];
            let mut c2: Vec<u8> = vec![0; c.len() - 96];
            let mut c3: Vec<u8> = vec![0; 32];
            copy_slice(&mut c1, &c[..64]);
            copy_slice(&mut c3, &c[64..96]);
            copy_slice(&mut c2, &c[96..]);
            let mut ciphertext: Vec<u8> = vec![];
            ciphertext = [ciphertext, c1].concat();
            ciphertext = [ciphertext, c2].concat();
            ciphertext = [ciphertext, c3].concat();

            break [prefix, ciphertext].concat();
        }

        break [prefix, c].concat()
    }
}

pub fn decrypt(pri_key: PrivateKey, cipher: Vec<u8>, mode: usize) -> Vec<u8> {
    let mut data = cipher.clone()[1..].to_vec();
    if mode == C1C2C3 {
        let mut c1: Vec<u8> = vec![0; 64];
        let mut c2: Vec<u8> = vec![0; data.len() - 96];
        let mut c3: Vec<u8> = vec![0; 32];
        copy_slice(&mut c1, &data.clone()[..64]);
        copy_slice(&mut c2, &data.clone()[64..(data.len() - 32)]);
        copy_slice(&mut c3, &data.clone()[(data.len() - 32)..]);

        let mut c: Vec<u8> = vec![];
        c.append(&mut c1);
        c.append(&mut c3);
        c.append(&mut c2);

        data = c;
    }

    let length = data.len() - 96;
    let sm2_p256 = Sm2P256Curve::new();

    let x = BigUint::from_bytes_be(&data.clone()[..32]);
    let y = BigUint::from_bytes_be(&data.clone()[32..64]);
    let (x2, y2) = sm2_p256.scalar_mult(x, y, pri_key.d.to_bytes_be());
    let mut x2buf = x2.to_bytes_be();
    let mut y2buf = y2.to_bytes_be();
    let mut n = x2buf.len();
    if n < 32 {
        x2buf = concat_u8(&zero_byte_slice()[..(32 - n)], &x2buf);
    }
    n = y2buf.len();
    if n < 32 {
        y2buf = concat_u8(&zero_byte_slice()[..(32 - n)], &y2buf);
    }
    let mut c = kdf(length, vec![x2buf, y2buf]).0;
    let mut i = 0;
    while i < length {
        c[i] ^= data[i+96];
        i+=1;
    }
    // let mut tm: Vec<u8> = vec![];
    // tm.append(&mut x2buf);
    // tm.append(&mut c);
    // tm.append(&mut y2buf);
    // let h = sm3sum(tm);
    c
}

