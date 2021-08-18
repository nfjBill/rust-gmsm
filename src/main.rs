use gmsm::sm3::sm3::sum_sm3;
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

fn main() {

    println!("Hello, world!");
    let string = String::from("abc");
    //let string = String::from("abcd");

    let s = string.as_bytes();

    let hash = sum_sm3(s);

    let s = hex::encode_upper(hash);
    // let s = (&hash);
    println!("{}", s);
}
