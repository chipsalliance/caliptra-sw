// Licensed under the Apache-2.0 license.

#[macro_export]
macro_rules! cfi_check {
    ($result:expr) => {
        if cfi_launder($result.is_ok()) {
            cfi_assert!($result.is_ok());
        } else {
            cfi_assert!($result.is_err());
        }
    };
}
