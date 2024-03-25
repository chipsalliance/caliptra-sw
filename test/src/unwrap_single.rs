// Licensed under the Apache-2.0 license

pub trait UnwrapSingle {
    type RetVal;
    fn unwrap_single(self) -> Self::RetVal;
}
impl<T: Iterator> UnwrapSingle for T {
    type RetVal = T::Item;

    #[track_caller]
    fn unwrap_single(mut self) -> Self::RetVal {
        let Some(result) = self.next() else {
            panic!("No item found");
        };
        if self.next().is_some() {
            panic!("More than one item found");
        }
        result
    }
}

#[test]
pub fn test_single() {
    assert_eq!([42_u32].into_iter().unwrap_single(), 42);
}

#[test]
#[should_panic(expected = "No item found")]
pub fn test_none() {
    [0_u32; 0].into_iter().unwrap_single();
}

#[test]
#[should_panic(expected = "More than one item found")]
pub fn test_two() {
    [42_u32, 43].into_iter().unwrap_single();
}
