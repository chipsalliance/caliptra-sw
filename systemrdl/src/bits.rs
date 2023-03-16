/*++
Licensed under the Apache-2.0 license.
--*/

use std::{fmt::Display, str::FromStr};

fn mask(w: u64) -> Result<u64, ()> {
    if w > 64 {
        return Err(());
    }
    if w == 64 {
        return Ok(0xffff_ffff_ffff_ffff);
    }
    Ok((1 << w) - 1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bits {
    w: u64,
    val: u64,
}
impl Bits {
    pub fn new(w: u64, val: u64) -> Bits {
        let mask = if w < 64 {
            (1 << w) - 1
        } else {
            0xffff_ffff_ffff_ffff
        };
        Self { w, val: val & mask }
    }
    pub fn w(&self) -> u64 {
        self.w
    }
    pub fn val(&self) -> u64 {
        self.val
    }
}
impl FromStr for Bits {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        let Some(i) = s.find(|ch: char| !ch.is_numeric()) else {
            return Err(());
        };
        let w = u64::from_str(&s[0..i]).map_err(|_| ())?;
        let mut i = s[i..].chars();
        if i.next() != Some('\'') {
            return Err(());
        }
        let radix = match i.next() {
            Some('b') => 2,
            Some('o') => 8,
            Some('d') => 10,
            Some('h') => 16,
            _ => return Err(()),
        };

        let str_val = i.as_str().replace('_', "");
        let val = u64::from_str_radix(&str_val, radix).map_err(|_| ())?;
        if val > mask(w)? {
            return Err(());
        }
        Ok(Bits::new(w, val))
    }
}
impl Display for Bits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}'x{:x}", self.w, self.val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        assert_eq!(Bits { w: 1, val: 0 }, Bits::new(1, 0));
        assert_eq!(Bits { w: 1, val: 1 }, Bits::new(1, 1));
        assert_eq!(Bits { w: 1, val: 0 }, Bits::new(1, 2));
        assert_eq!(Bits { w: 1, val: 1 }, Bits::new(1, 3));

        assert_eq!(Bits { w: 2, val: 0 }, Bits::new(2, 0));
        assert_eq!(Bits { w: 2, val: 1 }, Bits::new(2, 1));
        assert_eq!(Bits { w: 2, val: 2 }, Bits::new(2, 2));
        assert_eq!(Bits { w: 2, val: 3 }, Bits::new(2, 3));
        assert_eq!(Bits { w: 2, val: 0 }, Bits::new(2, 4));

        assert_eq!(
            Bits {
                w: 64,
                val: 0xffff_ffff_ffff_ffff
            },
            Bits::new(64, 0xffff_ffff_ffff_ffff)
        );
    }

    #[test]
    fn test_from_str() {
        assert_eq!(Ok(Bits::new(1, 0)), Bits::from_str("1'b0"));
        assert_eq!(Ok(Bits::new(1, 1)), Bits::from_str("1'b1"));
        assert_eq!(Err(()), Bits::from_str("1'b2"));

        assert_eq!(Ok(Bits::new(3, 0o0)), Bits::from_str("3'o0"));
        assert_eq!(Ok(Bits::new(3, 0o7)), Bits::from_str("3'o7"));
        assert_eq!(Err(()), Bits::from_str("3'o8"));
        assert_eq!(Err(()), Bits::from_str("3'o10"));
        assert_eq!(Ok(Bits::new(12, 0o7263)), Bits::from_str("12'o7263"));

        assert_eq!(Ok(Bits::new(4, 0)), Bits::from_str("4'd0"));
        assert_eq!(Ok(Bits::new(4, 9)), Bits::from_str("4'd9"));
        assert_eq!(Err(()), Bits::from_str("4'da"));
        assert_eq!(Ok(Bits::new(4, 10)), Bits::from_str("4'd10"));
        assert_eq!(Ok(Bits::new(12, 139)), Bits::from_str("12'd139"));

        assert_eq!(Ok(Bits::new(4, 0x0)), Bits::from_str("4'h0"));
        assert_eq!(Ok(Bits::new(4, 0xf)), Bits::from_str("4'hf"));
        assert_eq!(Ok(Bits::new(4, 0xf)), Bits::from_str("4'hF"));
        assert_eq!(Err(()), Bits::from_str("4'h10"));
        assert_eq!(Ok(Bits::new(32, 0xf00d)), Bits::from_str("32'hf00d"));
        assert_eq!(
            Ok(Bits::new(32, 0xf00d_baaf)),
            Bits::from_str("32'hf00d_baaf")
        );
        assert_eq!(
            Ok(Bits::new(32, 0xf00d_baaf)),
            Bits::from_str("32'hf0_0d_ba_af")
        );
    }
}
