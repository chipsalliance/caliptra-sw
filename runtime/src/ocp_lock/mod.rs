// Licensed under the Apache-2.0 license

use caliptra_drivers::SocIfc;

mod get_algorithms;
pub use get_algorithms::GetAlgorithmsCmd;

/// Provides OCP LOCK functionalities.
pub struct OcpLockContext {
    available: bool,
}

impl OcpLockContext {
    pub fn new(soc_ifc: &SocIfc) -> Self {
        let available = cfg!(feature = "ocp-lock") && soc_ifc.ocp_lock_enabled();
        Self { available }
    }

    /// Checks if the OCP lock is available.
    ///
    /// Returns `true` if the "ocp-lock" feature is enabled and the OCP lock is enabled in the SoC.
    pub fn available(&self) -> bool {
        self.available
    }
}
