use crate::g4::consts::{SBOX, FK, CK, ENC, DEC, SBOX0, SBOX1, SBOX2, SBOX3, BLOCKSIZE};
use crate::utils::slice::{copy_slice};

//sbox，(b0,b1,b2,b3)=τ(A)=(sBox(a0),sBox(a1),sBox(a2),sBox(a3))
fn sc_sbox(ins: u8) -> u8 {
    let x = (ins >> 4 & 0x0f) as usize;
    let y = (ins & 0x0f) as usize;
    return SBOX[x][y];
}

//linear transformation L，C=L(B)=B^(B<<<2)^(B<<<10)^(B<<<18)^(B<<<24)
// fn l(ins: u32) -> u32 {
//     ins ^ ins.rotate_left(2) ^ ins.rotate_left(10) ^ ins.rotate_left(18) ^ ins.rotate_left(24)
// }

//linear transformation L'，C=L'(B)=B^(B<<<13)^(B<<<23)
fn key_l(ins: u32) -> u32 {
    ins ^ ins.rotate_left(13) ^ ins.rotate_left(23)
}

//linear transformation τ()
fn tt(ins: u32) -> u32 {
    let tmp: [u8; 4] = [
        (ins >> 24) as u8 & 0xff,
        (ins >> 16) as u8 & 0xff,
        (ins >> 8) as u8 & 0xff,
        ins as u8 & 0xff,
    ];

    (sc_sbox(tmp[3])) as u32 |
        (((sc_sbox(tmp[2])) as u32) << 8) |
        (((sc_sbox(tmp[1])) as u32) << 16) |
        (((sc_sbox(tmp[0])) as u32) << 24)
}

//T'
fn key_t(ins: u32) -> u32 {
    key_l(tt(ins))
}


//key expansion
fn key_exp(key: [u32; 4]) -> [u32; 32] {
    let mut k: [u32; 36] = [0; 36];
    let mut rk: [u32; 32] = [0; 32];
    let mut i = 0;
    while i < 4 {
        k[i] = key[i] ^ FK[i];
        i += 1
    }
    i = 0;
    while i < 32 {
        k[i + 4] = k[i] ^ key_t(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        rk[i] = k[i + 4];
        i += 1
    }
    rk
}

//crypt block,F(X0,X1,X2,X3)=X0^T(X1^X2^X3^rk)
fn crypt_block(rk: &[u32], dst: &mut [u8], src: &[u8], mode: u32) {
    let mut x: usize;
    let mut b: [u32; 4] = [0; 4];
    let mut r: [u8; 16] = [0; 16];
    let mut i = 0;
    while i < 4 {
        //byte to uint32
        b[i] = ((src[i * 4] as u32) << 24) | ((src[i * 4 + 1] as u32) << 16) |
            ((src[i * 4 + 2] as u32) << 8) | (src[i * 4 + 3] as u32);
        i += 1
    }

    if mode == ENC {
        for i in 0..8 {
            x = (b[1] ^ b[2] ^ b[3] ^ rk[4 * i]) as usize;
            b[0] = b[0] ^ SBOX0[x & 0xff] ^ SBOX1[(x >> 8) & 0xff] ^ SBOX2[(x >> 16) & 0xff] ^ SBOX3[(x >> 24) & 0xff];
            x = (b[0] ^ b[2] ^ b[3] ^ rk[4 * i + 1]) as usize;
            b[1] = b[1] ^ SBOX0[x & 0xff] ^ SBOX1[(x >> 8) & 0xff] ^ SBOX2[(x >> 16) & 0xff] ^ SBOX3[(x >> 24) & 0xff];
            x = (b[0] ^ b[1] ^ b[3] ^ rk[4 * i + 2]) as usize;
            b[2] = b[2] ^ SBOX0[x & 0xff] ^ SBOX1[(x >> 8) & 0xff] ^ SBOX2[(x >> 16) & 0xff] ^ SBOX3[(x >> 24) & 0xff];
            x = (b[1] ^ b[2] ^ b[0] ^ rk[4 * i + 3]) as usize;
            b[3] = b[3] ^ SBOX0[x & 0xff] ^ SBOX1[(x >> 8) & 0xff] ^ SBOX2[(x >> 16) & 0xff] ^ SBOX3[(x >> 24) & 0xff];
        }
    } else {
        for i in 0..8 {
            x = (b[1] ^ b[2] ^ b[3] ^ rk[31 - 4 * i]) as usize;
            b[0] = b[0] ^ SBOX0[x & 0xff] ^ SBOX1[(x >> 8) & 0xff] ^ SBOX2[(x >> 16) & 0xff] ^ SBOX3[(x >> 24) & 0xff];
            x = (b[0] ^ b[2] ^ b[3] ^ rk[31 - 4 * i - 1]) as usize;
            b[1] = b[1] ^ SBOX0[x & 0xff] ^ SBOX1[(x >> 8) & 0xff] ^ SBOX2[(x >> 16) & 0xff] ^ SBOX3[(x >> 24) & 0xff];
            x = (b[0] ^ b[1] ^ b[3] ^ rk[31 - 4 * i - 2]) as usize;
            b[2] = b[2] ^ SBOX0[x & 0xff] ^ SBOX1[(x >> 8) & 0xff] ^ SBOX2[(x >> 16) & 0xff] ^ SBOX3[(x >> 24) & 0xff];
            x = (b[1] ^ b[2] ^ b[0] ^ rk[31 - 4 * i - 3]) as usize;
            b[3] = b[3] ^ SBOX0[x & 0xff] ^ SBOX1[(x >> 8) & 0xff] ^ SBOX2[(x >> 16) & 0xff] ^ SBOX3[(x >> 24) & 0xff];
        }
    }
    b.reverse();

    i = 0;
    while i < 4 {
        r[i * 4] = (b[i] >> 24) as u8;
        r[i * 4 + 1] = (b[i] >> 16) as u8;
        r[i * 4 + 2] = (b[i] >> 8) as u8;
        r[i * 4 + 3] = b[i] as u8;
        i += 1
    }
    copy_slice(dst, &r);
}

pub struct Block {
    rk: Vec<u32>,
}

impl Block {
    pub fn new() -> Block {
        let block = Block {
            rk: vec![]
        };

        block
    }

    pub fn block_size() -> u32 {
        BLOCKSIZE as u32
    }

    pub fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        crypt_block(&self.rk, dst, src, ENC)
    }

    pub fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) {
        crypt_block(&self.rk, dst, src, DEC)
    }
}

pub fn new_cipher(key: &[u8]) -> Block {
    if key.len() != BLOCKSIZE as usize {
        panic!("SM4: invalid key size in new_cipher")
    }

    let mut c = Block::new();

    let mut k: [u32; 4] = [0; 4];

    let mut i = 0;
    while i < 4 {
        k[i] = (key[i * 4] as u32) << 24 | ((key[i * 4 + 1] as u32) << 16) |
            ((key[i * 4 + 2] as u32) << 8) | (key[i * 4 + 3] as u32);
        i += 1
    }

    c.rk = Vec::from(key_exp(k));
    c
}

fn repeat(b: &[u8], count: usize) -> Vec<u8> {
    let bl: usize = b.len();

    // if count == 0 {
    //     [BL; 0]
    // }

    // if count < 0 {
    //     panic!("bytes: negative Repeat count")
    // } else if bl * count / count != bl {
    //     panic!("bytes: Repeat count causes overflow")
    // }
    let mut nb: Vec<u8> = vec![0; bl*count];
    let mut bp = copy_slice(&mut nb, &b);
    while bp < nb.len() {
        let bb = nb.clone();
        copy_slice(&mut nb[bp..], &bb[..bp]);
        bp *= 2
    }
    nb
}

fn pkcs7_padding(src: &[u8]) -> Vec<u8> {
    let padding = BLOCKSIZE - src.len() % BLOCKSIZE;
    let a: [u8; 1] = [padding as u8];
    let padtext = repeat(&a, padding);

    let aa = [src, padtext.as_slice()].concat();
    aa
}

fn pkcs7_un_padding(src: Vec<u8>) -> Vec<u8> {
    let length = src.len();
    let unpadding = src[length - 1] as u32;

    // if unpadding > BLOCKSIZE as u32 || unpadding == 0 {
    //     panic!("Invalid pkcs7 padding (unpadding > BlockSize || unpadding == 0)");
    // }

    let pad = &src[(src.len() - unpadding as usize)..];

    for i in 0..unpadding {
        if pad[i as usize] != unpadding as u8 {
            panic!("Invalid pkcs7 padding (pad[i] != unpadding)");
        }
    }

    // while i < unpadding {
    //     if pad[i] != unpadding as u32 {
    //         panic!("Invalid pkcs7 padding (pad[i] != unpadding)");
    //     }
    //     i += 1
    // }
    Vec::from(&src[..(length - unpadding as usize)])
}

//sm4 ecb mode
pub fn sm4_ecb<'a>(key: &'a [u8], ins: &'a [u8], mode: u32) -> Vec<u8> {
    if key.len() != BLOCKSIZE {
        panic!("SM4: invalid key size ")
    }
    let in_data: Vec<u8>;
    if mode == ENC {
        in_data = pkcs7_padding(ins)
    } else {
        in_data = Vec::from(ins)
    }
    let idl: usize = in_data.len();
    let mut out: Vec<u8> = vec![0; idl];
    let mut c = new_cipher(key);
    let mut i = 0;
    if mode == ENC {
        while i < idl / 16 {
            let in_tmp = &in_data[(i * 16)..(i * 16 + 16)];
            let mut out_tmp: [u8; 16] = [0; 16];
            c.encrypt(&mut out_tmp, &in_tmp);
            copy_slice(&mut out[(i * 16)..(i * 16 + 16)], &out_tmp);
            i += 1
        }
    } else {
        while i < idl / 16 {
            let in_tmp = &in_data[(i * 16)..(i * 16 + 16)];
            let mut out_tmp: [u8; 16] = [0; 16];
            c.decrypt(&mut out_tmp, &in_tmp);
            copy_slice(&mut out[(i * 16)..(i * 16 + 16)], &out_tmp);
            i += 1
        }
        return pkcs7_un_padding(out);
    }

    out
}

fn xor<'a>(ins: &'a [u8], iv: &'a [u8]) -> Vec<u8> {
    if ins.len() != iv.len() {
        panic!("xor byte length is error!")
    }
    let inl: usize = ins.len();
    let mut out: Vec<u8> = vec![0; inl];
    let mut i = 0;
    while i < inl {
        out[i] = ins[i] ^ iv[i];
        i += 1
    }
    out
}

//sm4 cbc mode
pub fn sm4_cbc<'a>(key: &'a [u8], key_iv: &'a [u8], ins: &'a [u8], mode: u32) -> Vec<u8> {
    if key.len() != BLOCKSIZE {
        panic!("SM4: invalid key size in sm4_cbc")
    }
    let in_data: Vec<u8>;
    if mode == ENC {
        in_data = pkcs7_padding(ins);
    } else {
        in_data = Vec::from(ins);
    }

    let idl: usize = in_data.len();
    let mut iv = Vec::from(key_iv);

    let mut out: Vec<u8> = vec![0; idl];
    let mut c = new_cipher(key);
    let mut i = 0;
    while i < idl / 16 {
        if mode == ENC {
            let in_tmp = xor(&in_data[(i * 16)..(i * 16 + 16)], iv.as_slice());
            let mut out_tmp: [u8; 16] = [0; 16];
            c.encrypt(&mut out_tmp, in_tmp.as_slice());
            copy_slice(&mut out[(i * 16)..(i * 16 + 16)], &out_tmp);
            iv = Vec::from(out_tmp);
        } else {
            let in_tmp = &in_data[(i * 16)..(i * 16 + 16)];
            let mut out_tmp: [u8; 16] = [0; 16];
            c.decrypt(&mut out_tmp, &in_tmp);
            let out1_tmp = xor(&out_tmp, &iv);
            copy_slice(&mut out[(i * 16)..(i * 16 + 16)], out1_tmp.as_slice());
            iv = Vec::from(in_tmp)
        }
        i += 1
    }

    if mode != ENC {
        return pkcs7_un_padding(out);
    }

    out
}
