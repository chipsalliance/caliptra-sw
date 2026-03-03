/*++

Licensed under the Apache-2.0 license.

File Name:

    abr.rs

Abstract:

    File contains ABR (Adams Bridge) hardware driver that provides
    closure-based access to ML-KEM and ML-DSA functionality.

--*/

use caliptra_registers::abr::AbrReg;

use crate::{MlKem1024, Mldsa87};

/// ABR (Adams Bridge) hardware driver.
///
/// This driver owns the ABR register block and provides methods to
/// use the ML-KEM and ML-DSA functionality through closures.
/// This ensures that only one driver is using the hardware at a time.
pub struct Abr {
    // We store the AbrReg to signify ownership. The actual access
    // is through temporary drivers created in the closure methods.
    abr: AbrReg,
}

impl Abr {
    /// Create a new ABR driver.
    ///
    /// # Arguments
    ///
    /// * `abr` - The ABR register block
    pub fn new(abr: AbrReg) -> Self {
        Self { abr }
    }

    /// Get a mutable reference to the ABR register block.
    ///
    /// This allows creating `Mldsa87` or `MlKem1024` drivers directly
    /// when the closure-based API is not suitable due to lifetime constraints.
    pub fn abr_reg(&mut self) -> &mut AbrReg {
        &mut self.abr
    }

    /// Execute a closure with access to the ML-DSA-87 driver.
    ///
    /// The closure receives an `Mldsa87` driver by value that can be used
    /// for ML-DSA cryptographic operations. The driver is automatically
    /// dropped when the closure returns.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that receives `Mldsa87`
    ///
    /// # Returns
    ///
    /// The return value of the closure
    ///
    /// # Example
    ///
    /// ```ignore
    /// let pub_key = abr.with_mldsa87(|mut mldsa| {
    ///     mldsa.key_pair(seed, trng, None)
    /// })?;
    /// ```
    pub fn with_mldsa87<'s, F, R>(&'s mut self, f: F) -> R
    where
        F: FnOnce(Mldsa87<'s>) -> R,
    {
        let mldsa87 = Mldsa87::new(&mut self.abr);
        f(mldsa87)
    }

    /// Execute a closure with access to the ML-KEM-1024 driver.
    ///
    /// The closure receives an `MlKem1024` driver by value that can be used
    /// for ML-KEM cryptographic operations. The driver is automatically
    /// dropped when the closure returns.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that receives `MlKem1024`
    ///
    /// # Returns
    ///
    /// The return value of the closure
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (encaps_key, decaps_key) = abr.with_ml_kem(|mut ml_kem| {
    ///     ml_kem.key_pair(seeds)
    /// })?;
    /// ```
    pub fn with_ml_kem<'s, F, R>(&'s mut self, f: F) -> R
    where
        F: FnOnce(MlKem1024<'s>) -> R,
    {
        let ml_kem = MlKem1024::new(&mut self.abr);
        f(ml_kem)
    }
}
