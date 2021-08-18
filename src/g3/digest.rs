use crate::g3::hash::c_f;

pub const SIZE: usize = 32;

const CHUNK: u32 = 64;
const INIT0: u32 = 0x7380_166f;
const INIT1: u32 = 0x4914_b2b9;
const INIT2: u32 = 0x1724_42d7;
const INIT3: u32 = 0xda8a_0600;
const INIT4: u32 = 0xa96f_30bc;
const INIT5: u32 = 0x1631_38aa;
const INIT6: u32 = 0xe38d_ee4d;
const INIT7: u32 = 0xb0fb_0e4e;

pub struct Digest {
    h: [u32; 8],
    x: [u8; CHUNK as usize],
    nx: u32,
    len: u64,
}

impl Digest {
    pub fn new() -> Digest {
        let hash = Digest {
            h: [0; 8],
            x: [0; CHUNK as usize],
            nx: 0,
            len: 0
        };

        hash
    }

    pub fn reset(&mut self) {
        self.h[0] = INIT0;
        self.h[1] = INIT1;
        self.h[2] = INIT2;
        self.h[3] = INIT3;
        self.h[4] = INIT4;
        self.h[5] = INIT5;
        self.h[6] = INIT6;
        self.h[7] = INIT7;
        self.nx = 0;
        self.len = 0;
    }

    pub fn block(&mut self, q: Vec<u8>) {
        let mut p = q;
        let mut v: [u32; 8] = [0; 8];
        let mut i = 0;
        while i < 8 {
            v[i] = self.h[i];
            i += 1;
        }
        while p.len() >= 64 {
            let mut m: [u32; 16] = [0; 16];
            let x = &p[..64];
            let mut xi = 0;
            let mut mi = 0;

            while mi < 16 {
                m[mi] = x[xi + 3] as u32 |
                    ((x[xi + 2] as u32) << 8) |
                    ((x[xi + 1] as u32) << 16) |
                    ((x[xi] as u32) << 24);
                mi += 1;
                xi += 4;
            }
            v = c_f(v, m);
            p = Vec::from(&p[64..]);
        }
        i = 0;
        while i < 8 {
            self.h[i] = v[i];
            i+=1
        }
    }

    pub fn write(&mut self, q: &[u8]) {
        let mut p = q;
        let nn = p.len();
        self.len += nn as u64;

        if self.nx > 0 {
            let n = copy_slice(&mut self.x[self.nx as usize..], &p);
            self.nx += n as u32;

            if self.nx == CHUNK {
                // self.block
                let aa: Vec<u8> = Vec::from(self.x);
                self.block(aa);

                self.nx = 0
            }
            p = &p[n..]
        }

        if p.len() >= CHUNK as usize {
            let n = p.len() & !((CHUNK - 1) as usize);
            self.block(Vec::from(p));
            p = &p[n..]
        }
        if p.len() > 0 {
            self.nx = copy_slice(&mut self.x[..], &p) as u32;
        }
    }

    pub fn check_sum(&mut self) -> [u8; SIZE] {
        let mut len = self.len;
        let mut tmp: [u8; 64] = [0; 64];
        tmp[0] = 0x80;
        if len % 64 < 56 {
            self.write(&tmp[0..((56 - len % 64) as usize)]);
        } else {
            self.write(&tmp[0..((64 + 56 - len % 64) as usize)]);
        }
        len = len << 3;
        let mut i: usize = 0;
        while i < 8 {
            tmp[i] = (len >> (56 - 8 * i)) as u8;
            i += 1;
        }
        self.write(&tmp[0..8]);

        if self.nx != 0 {
            panic!("d.nx != 0")
        }

        let h: &[u32] = &self.h[..];
        let mut digest: [u8; SIZE] = [0; SIZE];
        for j in 0..h.len() {
            let s = h[j];

            digest[j * 4] = (s >> 24) as u8;
            digest[j * 4 + 1] = (s >> 16) as u8;
            digest[j * 4 + 2] = (s >> 8) as u8;
            digest[j * 4 + 3] = s as u8;
        }

        return digest;
    }
}

pub fn copy_slice(dst: &mut [u8], src: &[u8]) -> usize {
    let mut c = 0;
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
        c += 1;
    }
    c
}
