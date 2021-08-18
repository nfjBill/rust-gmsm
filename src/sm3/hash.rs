use std::fmt;

struct SliceDisplay<'a, T: 'a>(&'a [T]);

impl<'a, T: fmt::Display + 'a> fmt::Display for SliceDisplay<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for item in self.0 {
            if !first {
                write!(f, ", {}", item)?;
            } else {
                write!(f, "{}", item)?;
            }
            first = false;
        }
        Ok(())
    }
}
// fn left_rotate(x: u32, r: u32) -> u32 { x << (r % 32) | x >> (32 - r % 32) }

fn ff0(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

fn ff1(x: u32, y: u32, z: u32) -> u32 { (x & y) | (x & z) | (y & z) }

fn gg0(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

fn gg1(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }

fn p0(x: u32) -> u32 { x ^ x.rotate_left(9) ^ x.rotate_left(17) }

fn p1(x: u32) -> u32 { x ^ x.rotate_left(15) ^ x.rotate_left(23) }

#[allow(dead_code)]
fn msg_padding(message: Vec<u8>) -> Vec<u8> {
    // Pre-processing:
    let l: u64 = (message.len() * 8) as u64;
    let mut chunk = message;

    // Pre-processing: adding a single 1 bit
    chunk.push(0x80);

    // Pre-processing: padding with zeros
    let padding = 56 - chunk.len() % 64;
    let mut i = 0;
    while i < padding {
        // 循环体
        i += 1;
        chunk.push(0x00)
    }

    chunk.push(((l >> 56) & 0xff) as u8);
    chunk.push(((l >> 48) & 0xff) as u8);
    chunk.push(((l >> 40) & 0xff) as u8);
    chunk.push(((l >> 32) & 0xff) as u8);
    chunk.push(((l >> 24) & 0xff) as u8);
    chunk.push(((l >> 16) & 0xff) as u8);
    chunk.push(((l >> 8) & 0xff) as u8);
    chunk.push((l & 0xff) as u8);

    chunk
}

pub struct W {
    w1: [u32; 68],
    w2: [u32; 64],
}

fn msg_exp(x: [u32; 16]) -> W {
    let mut wtmp: W = W { w1: [0; 68], w2: [0; 64] };

    let mut i = 0;
    while i < 16 {
        wtmp.w1[i] = x[i];
        i += 1;
    }
    i = 16;
    while i < 68 {
        wtmp.w1[i] = p1(wtmp.w1[i - 16] ^ wtmp.w1[i - 9] ^ wtmp.w1[i - 3].rotate_left(15)) ^ (wtmp.w1[i - 13]).rotate_left(7) ^ wtmp.w1[i - 6];
        i += 1;
    }
    i = 0;
    while i < 64 {
        wtmp.w2[i] = wtmp.w1[i] ^ wtmp.w1[i + 4];
        i += 1;
    }

    wtmp
}

pub fn c_f(mut v: [u32; 8], b_msg: [u32; 16]) -> [u32; 8] {
    let mut a = v[0];
    let mut b = v[1];
    let mut c = v[2];
    let mut d = v[3];
    let mut e = v[4];
    let mut f = v[5];
    let mut g = v[6];
    let mut h = v[7];
    let wtmp = msg_exp(b_msg);
    let mut j = 0;

    while j < 16 {
        let jj = j;
        // let ss1 = (a.rotate_left(12) + e + 0x79cc4519u32.rotate_left(jj)).rotate_left(7);
        let ss1 = a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(0x79cc_4519u32.rotate_left(jj as u32))
            .rotate_left(7);
        // let ss1 = left_rotate(left_rotate(a, 12) + e + left_rotate(0x79cc4519, jj as u32), 7);
        // let ss1 = left_rotate(left_rotate(a, 12) + e + left_rotate(0x79cc4519, jj as u32), 7);

        let ss2 = ss1 ^ a.rotate_left(12);
        // let tt1 = ff0(a, b, c) + d + ss2 + wtmp.w2[j as usize];
        // let tt2 = gg0(e, f, g) + h + ss1 + wtmp.w1[j as usize];
        let tt1 = ff0(a, b, c)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(wtmp.w2[j]);
        let tt2 = gg0(e, f, g)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(wtmp.w1[j]);

        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
        j += 1;
    }

    j = 16;
    while j < 64 {
        let jj;
        if j < 33 {
            jj = j;
        } else {
            jj = j - 32;
        }

        // let ss1 = (a.rotate_left(12) + e + 0x7a879d8au32.rotate_left(jj)).rotate_left(7);
        // let ss1 = left_rotate(left_rotate(a, 12) + e + left_rotate(0x7a879d8a, jj as u32), 7);
        let ss1 = a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(0x7a87_9d8au32.rotate_left(jj as u32))
            .rotate_left(7);

        let ss2 = ss1 ^ (a.rotate_left(12));
       // let aa = a.rotate_left(12)+e+0x7a87_9d8au32.rotate_left(jj as u32);
       //  let ss1 = aa.rotate_left(7);
       //  let ss2 = ss1 ^ (a.rotate_left(12));


        // let tt1 = ff1(a, b, c) + d + ss2 + wtmp.w2[j as usize];
        // let tt2 = gg1(e, f, g) + h + ss1 + wtmp.w1[j as usize];

        let tt1 = ff1(a, b, c)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(wtmp.w2[j]);
        let tt2 = gg1(e, f, g)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(wtmp.w1[j]);


        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
        j += 1;
    }

    v[0] = a ^ v[0];
    v[1] = b ^ v[1];
    v[2] = c ^ v[2];
    v[3] = d ^ v[3];
    v[4] = e ^ v[4];
    v[5] = f ^ v[5];
    v[6] = g ^ v[6];
    v[7] = h ^ v[7];

    v
}

// pub fn block(dig: &mut Digest, q: &[u8]) {
//     let mut p = q;
//     let mut v: [u32; 8] = [0; 8];
//     let mut i = 0;
//     while i < 8 {
//         v[i] = dig.h[i];
//         i += 1;
//     }
//     while p.len() >= 64 {
//         let mut m: [u32; 16] = [0; 16];
//         let x = &p[..64];
//         let mut xi = 0;
//         let mut mi = 0;
//
//         while mi < 16 {
//             m[mi] = x[xi + 3] as u32 |
//                 ((x[xi + 2] as u32) << 8) |
//                 ((x[xi + 1] as u32) << 16) |
//                 ((x[xi] as u32) << 24);
//             mi += 1;
//             xi += 4;
//         }
//         p = &p[64..];
//     }
//     i = 0;
//     while i < 8 {
//         dig.h[i] = v[i];
//     }
// }
