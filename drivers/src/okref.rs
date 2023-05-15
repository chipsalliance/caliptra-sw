// Licensed under the Apache-2.0 license

/// This function makes it easier to efficiently deal with Result types with
/// large `Ok` variants.
///
/// Consider this code:
///
/// ```
/// use caliptra_drivers::okref;
///
/// fn some_function() -> Result<[u32; 64], u32> {
///     Ok([0u32; 64])
/// }
/// fn compute(val: &[u32; 64]) {}
///
/// fn main() -> std::result::Result<(), u32> {
///     let value = some_function()?;
///     compute(&value);
///     Ok(())
/// }
/// ```
///
/// In the above code, the compiler will usually generate a memcpy inside main
/// that copies the large array out of the Result into a separate stack
/// location. `okref` can be used to work with the array directly out of the
/// original stack location, eliminating the memcpy:
///
/// ```
/// use caliptra_drivers::okref;
///
/// fn some_function() -> Result<[u32; 64], u32> {
///     Ok([0u32; 64])
/// }
/// fn compute(val: &[u32; 64]) {}
///
/// fn main() -> std::result::Result<(), u32> {
///     let value = some_function();
///     let value = okref(&value)?;
///     compute(value);
///     Ok(())
/// }
/// ```
///
pub fn okref<T, E: Copy>(r: &Result<T, E>) -> Result<&T, E> {
    match r {
        Ok(r) => Ok(r),
        Err(e) => Err(*e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_okref_ok() {
        let result: Result<[u32; 16], char> = Ok([11u32; 16]);
        let okref_result: Result<&[u32; 16], char> = okref(&result);
        assert_eq!(okref_result.unwrap(), result.as_ref().unwrap());
    }

    #[test]
    fn test_okref_err() {
        let result: Result<[u32; 16], char> = Err('x');
        let okref_result: Result<&[u32; 16], char> = okref(&result);
        assert_eq!('x', okref_result.unwrap_err());
    }
}
