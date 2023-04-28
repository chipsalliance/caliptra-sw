// Licensed under the Apache-2.0 license
#![cfg_attr(not(feature = "std"), no_std)]
use core::convert::From;
use core::num::NonZeroU32;
pub enum CaliptraComponent {
    Driver = 0x01,
    Rom = 0x02,
    Fmc = 0x03,
    Runtime = 0x04,
    Fips = 0x05,
    FipsTest = 0x06,
}

/// Calipta common result
/// The Caliptra common result is an alias for the Result type. The purpose of
/// this type is to provide a common result type for all Caliptra components.
pub type CaliptraCommonResult = Result<(), CaliptraCommonError>;

/// Caliptra common error type
pub struct CaliptraCommonError(pub NonZeroU32);

impl From<CaliptraCommonError> for NonZeroU32 {
    /// Converts to this type from the input type.
    fn from(val: CaliptraCommonError) -> Self {
        val.0
    }
}
/// Encode a Caliptra common result
/// # Arguments
/// * `comp_name` - Caliptra component name
/// * `sub_comp_code` - Caliptra sub-component code
/// Example:
/// ```
/// let result = caliptra_error::caliptra_common_err!(Driver, 0x01);
/// ```
/// The above example will return a CaliptraResult with the following value:
/// 0x010001
/// The first byte is the Caliptra component identifier, the second byte is the
/// Caliptra sub-component identifier, and the last two bytes are the Caliptra
/// error code.
#[macro_export]
macro_rules! caliptra_common_err {
    ($comp_name:ident, $sub_comp_code: expr) => {
        $crate::CaliptraCommonError(
            core::num::NonZeroU32::new(
                ((($crate::CaliptraComponent::$comp_name) as u32) << 24) | ($sub_comp_code as u32),
            )
            .unwrap(),
        )
    };
    () => {};
}
