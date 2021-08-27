use std::fmt;

pub struct SliceDisplay<'a, T: 'a>(pub &'a [T]);

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

pub fn copy_slice(dst: &mut [u8], src: &[u8]) -> usize {
    let mut c = 0;
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
        c += 1;
    }
    c
}

pub fn copy_slice_i8(dst: &mut [i8], src: &[i8]) -> usize {
    let mut c = 0;
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
        c += 1;
    }
    c
}

pub fn concat_u8(first: &[u8], second: &[u8]) -> Vec<u8> {
    [first, second].concat()
}