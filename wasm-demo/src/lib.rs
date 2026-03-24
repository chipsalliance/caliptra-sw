// Licensed under the Apache-2.0 license

//! WASM wrapper for the Caliptra hardware emulator.
//!
//! Provides a JavaScript-friendly API to initialize and run the Caliptra
//! emulator with custom ROM, vendor/owner PK hashes, FW image, and UART
//! output capture.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use caliptra_api_types::{
    DeviceLifecycle, Fuses, SecurityState, DEFAULT_CPTRA_OBF_KEY, DEFAULT_CSR_HMAC_KEY,
};
use caliptra_emu_periph::MailboxRequester;
use caliptra_hw_model::{BootParams, ExitStatus, HwModel, InitParams, ModelEmulated, TrngMode};
use caliptra_hw_model_types::{EtrngResponse, RandomEtrngResponses, RandomNibbles};
use rand::rngs::StdRng;
use rand::SeedableRng;
use wasm_bindgen::prelude::*;

/// A shared buffer that captures log/UART output via the `Write` trait.
#[derive(Clone)]
struct SharedBuffer(Rc<RefCell<Vec<u8>>>);

impl Write for SharedBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Parse a hex string (e.g. "aabbccdd...") into a `[u32; 12]` array (big-endian words).
/// Expects exactly 96 hex characters (48 bytes = 12 × 4-byte words).
fn parse_pk_hash(hex: &str) -> Result<[u32; 12], String> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Ok([0u32; 12]);
    }

    // Strip optional "0x" prefix
    let hex = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);

    if hex.len() != 96 {
        return Err(format!(
            "PK hash must be 96 hex characters (48 bytes), got {} characters",
            hex.len()
        ));
    }

    let mut result = [0u32; 12];
    for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| format!("Invalid UTF-8: {e}"))?;
        result[i] =
            u32::from_str_radix(s, 16).map_err(|e| format!("Invalid hex at word {i}: {e}"))?;
    }
    Ok(result)
}

/// The Caliptra emulator, exposed to JavaScript via wasm-bindgen.
#[wasm_bindgen]
pub struct CaliptraEmulator {
    model: ModelEmulated,
    log_buffer: SharedBuffer,
    total_steps: u64,
    boot_error: Option<String>,
}

#[wasm_bindgen]
impl CaliptraEmulator {
    /// Create a new emulator instance.
    ///
    /// # Arguments
    /// * `rom` - The ROM binary image (96KB expected)
    /// * `vendor_pk_hash_hex` - Vendor PK hash as 96-char hex string (or empty for zeros)
    /// * `owner_pk_hash_hex` - Owner PK hash as 96-char hex string (or empty for zeros)
    /// * `fw_image` - Optional firmware image bundle (serialized ImageBundle)
    /// * `soc_manifest` - Optional SoC manifest (authorization manifest bytes)
    /// * `lifecycle` - Device lifecycle: "unprovisioned", "manufacturing", or "production"
    #[wasm_bindgen(constructor)]
    pub fn new(
        rom: &[u8],
        vendor_pk_hash_hex: &str,
        owner_pk_hash_hex: &str,
        fw_image: Option<Vec<u8>>,
        soc_manifest: Option<Vec<u8>>,
        lifecycle: &str,
    ) -> Result<CaliptraEmulator, JsValue> {
        // Parse PK hashes
        let vendor_pk_hash =
            parse_pk_hash(vendor_pk_hash_hex).map_err(|e| JsValue::from_str(&e))?;
        let owner_pk_hash =
            parse_pk_hash(owner_pk_hash_hex).map_err(|e| JsValue::from_str(&e))?;

        let log_buffer = SharedBuffer(Rc::new(RefCell::new(Vec::new())));

        let device_lifecycle = match lifecycle.to_lowercase().as_str() {
            "unprovisioned" => DeviceLifecycle::Unprovisioned,
            "manufacturing" => DeviceLifecycle::Manufacturing,
            "production" => DeviceLifecycle::Production,
            _ => DeviceLifecycle::Manufacturing,
        };

        // Use a fixed seed for deterministic TRNG in the browser
        let trng_seed: u64 = 42;
        let itrng_nibbles: Box<dyn Iterator<Item = u8> + Send> =
            Box::new(RandomNibbles(StdRng::seed_from_u64(trng_seed)));
        let etrng_responses: Box<dyn Iterator<Item = EtrngResponse> + Send> =
            Box::new(RandomEtrngResponses(StdRng::seed_from_u64(trng_seed)));

        let fuses = Fuses {
            vendor_pk_hash,
            owner_pk_hash,
            life_cycle: device_lifecycle,
            ..Default::default()
        };

        let init_params = InitParams {
            rom,
            fuses,
            log_writer: Box::new(log_buffer.clone()),
            security_state: *SecurityState::default()
                .set_device_lifecycle(device_lifecycle),
            cptra_obf_key: DEFAULT_CPTRA_OBF_KEY,
            csr_hmac_key: DEFAULT_CSR_HMAC_KEY,
            itrng_nibbles,
            etrng_responses,
            trng_mode: Some(TrngMode::Internal),
            random_sram_puf: false,
            trace_path: None,
            soc_user: MailboxRequester::SocUser(1),
            ..Default::default()
        };

        let boot_params = BootParams {
            fw_image: fw_image.as_deref(),
            soc_manifest: soc_manifest.as_deref(),
            ..Default::default()
        };

        // Use new_unbooted + boot separately so we keep the model even if
        // boot fails (e.g., PK hash mismatch). This lets the user see UART
        // output and logs from the failed boot attempt.
        let mut model = caliptra_hw_model::ModelEmulated::new_unbooted(init_params)
            .map_err(|e| JsValue::from_str(&format!("Failed to create emulator: {e}")))?;

        let boot_error = model.boot(boot_params).err();

        let mut emu = CaliptraEmulator {
            model,
            log_buffer,
            total_steps: 0,
            boot_error: None,
        };

        if let Some(e) = boot_error {
            let msg = format!("[WASM] Boot error: {e}\n");
            emu.boot_error = Some(msg);
        }

        Ok(emu)
    }

    /// Step the emulator by `n` clock cycles. Returns true if the emulator
    /// is still running (has not exited).
    pub fn step(&mut self, n: u32) -> bool {
        for _ in 0..n {
            self.model.step();
            self.total_steps += 1;
        }
        !self.model.output().exit_requested()
    }

    /// Get accumulated UART output text since the last call to this method.
    pub fn get_uart_output(&mut self) -> String {
        self.model.output().take(usize::MAX)
    }

    /// Peek at accumulated UART output without consuming it.
    pub fn peek_uart_output(&mut self) -> String {
        self.model.output().peek().to_string()
    }

    /// Get the full log buffer contents (includes timestamped UART + system messages).
    pub fn get_log(&mut self) -> String {
        let bytes = self.log_buffer.0.borrow().clone();
        self.log_buffer.0.borrow_mut().clear();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Get the total number of steps executed so far.
    pub fn total_steps(&self) -> u64 {
        self.total_steps
    }

    /// Check if the emulator has signaled an exit (pass or fail).
    pub fn has_exited(&mut self) -> bool {
        self.model.output().exit_requested()
    }

    /// Check if the emulator exited with a PASS status.
    pub fn passed(&mut self) -> bool {
        self.model.output().exit_status() == Some(ExitStatus::Passed)
    }

    /// Get the boot error message, if boot failed.
    pub fn boot_error(&self) -> Option<String> {
        self.boot_error.clone()
    }
}
