/*++
Licensed under the Apache-2.0 license.
--*/
mod bindings;
use std::ffi::CString;
use std::ffi::NulError;
use std::ptr::null;

pub use bindings::caliptra_verilated_sig_in as SigIn;
pub use bindings::caliptra_verilated_sig_out as SigOut;

pub struct CaliptraVerilated {
    v: *mut bindings::caliptra_verilated,
    pub input: SigIn,
    pub output: SigOut,
    generic_load_cb: Box<dyn FnMut(u8)>,
}

impl CaliptraVerilated {
    /// Constructs a new model.
    pub fn new() -> Self {
        Self::with_generic_load_cb(Box::new(|_| {}))
    }

    /// Creates a model that calls `generic_load_cb` whenever the
    /// microcontroller CPU does a load to the generic wires.
    pub fn with_generic_load_cb(generic_load_cb: Box<dyn FnMut(u8)>) -> Self {
        unsafe {
            Self {
                v: bindings::caliptra_verilated_new(),
                input: Default::default(),
                output: Default::default(),
                generic_load_cb,
            }
        }
    }
    /// Starts tracing to VCD file `path`, with SystemVerilog module depth
    /// `depth`. If tracing was previously started to another file, that file
    /// will be closed and all new traces will be written to this file.
    pub fn start_tracing(&mut self, path: &str, depth: i32) -> Result<(), NulError> {
        unsafe {
            bindings::caliptra_verilated_trace(self.v, CString::new(path)?.as_ptr(), depth);
        }
        Ok(())
    }

    /// Stop any tracing that might have been previously started with `start_tracing()`.
    pub fn stop_tracing(&mut self) {
        unsafe {
            bindings::caliptra_verilated_trace(self.v, null(), 0);
        }
    }

    /// Evaluates the model into self.output, then copies all `self.input`
    /// signals into psuedo flip-flops that will be visible to always_ff blocks
    /// in subsequent evaluations. Typically `next_cycle_high` is used instead.
    pub fn eval(&mut self) {
        unsafe { bindings::caliptra_verilated_eval(self.v, &self.input, &mut self.output) }
        if self.output.generic_load_en && self.input.core_clk {
            (self.generic_load_cb)(self.output.generic_load_data as u8);
        }
    }

    /// Toggles core_clk until there have been `n_cycles` rising edges.
    pub fn next_cycle_high(&mut self, n_cycles: u32) {
        for _ in 0..n_cycles {
            loop {
                self.input.core_clk = !self.input.core_clk;
                self.eval();
                if self.input.core_clk {
                    break;
                }
            }
        }
    }

    /// Writes a ROM image to the RAM backing the "fake ROM". Typically this should be
    /// done before asserting cptra_pwrgood and cptra_rst_b.
    pub fn write_rom_image(&mut self, image: &[u8]) {
        // TODO: bounds check length against ROM size?
        for (addr, data) in image.chunks_exact(8).enumerate() {
            // panic is impossible because an 8-byte slice-ref will always
            // convert into an 8-byte array-ref.
            let data = u64::from_le_bytes(data.try_into().unwrap());
            self.write_rom_u64(addr as u32, data);
        }
    }

    /// Initiates a read transaction on the SoC->Caliptra APB bus with user
    /// `pauser` and `addr`, and returns the word read from the bus.
    pub fn apb_read_u32(&mut self, pauser: u32, addr: u32) -> u32 {
        self.input.paddr = addr;
        self.input.psel = true;
        self.input.penable = false;
        self.input.pwrite = false;
        self.input.pauser = pauser;

        self.next_cycle_high(1);

        self.input.penable = true;

        loop {
            self.next_cycle_high(1);
            if self.output.pready {
                break;
            }
        }

        self.input.psel = false;
        self.input.penable = false;

        self.output.prdata
    }

    /// Initiates a write transaction on the SoC->Caliptra APB bus with user
    /// `pauser`, `addr` and `data`.
    pub fn apb_write_u32(&mut self, pauser: u32, addr: u32, data: u32) {
        self.input.paddr = addr;
        self.input.psel = true;
        self.input.penable = false;
        self.input.pwrite = true;
        self.input.pwdata = data;
        self.input.pauser = pauser;

        self.next_cycle_high(1);

        self.input.penable = true;

        loop {
            self.next_cycle_high(1);
            if self.output.pready {
                break;
            }
        }

        self.input.psel = false;
        self.input.penable = false;
        self.input.pwrite = false;
        self.input.pwdata = 0;
    }

    fn write_rom_u64(&mut self, addr: u32, data: u64) {
        self.input.imem_addr = addr;
        self.input.imem_wdata = data;
        self.input.imem_we = true;
        self.next_cycle_high(1);
        self.input.imem_we = false;
    }
}
impl Default for CaliptraVerilated {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for CaliptraVerilated {
    fn drop(&mut self) {
        unsafe { bindings::caliptra_verilated_destroy(self.v) }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    // Additional tests in hw-model/src/model_verilated.rs

    #[test]
    fn test_tracing() {
        if !cfg!(feature = "verilator") {
            return;
        }
        let mut v = CaliptraVerilated::new();

        std::fs::remove_file("/tmp/caliptra_verilated_test.vcd").ok();
        std::fs::remove_file("/tmp/caliptra_verilated_test2.vcd").ok();
        assert!(!Path::new("/tmp/caliptra_verilated_test.vcd").exists());
        assert!(!Path::new("/tmp/caliptra_verilated_test2.vcd").exists());

        v.start_tracing("/tmp/caliptra_verilated_test.vcd", 99)
            .unwrap();
        v.next_cycle_high(2);
        v.start_tracing("/tmp/caliptra_verilated_test2.vcd", 99)
            .unwrap();
        v.next_cycle_high(2);
        assert!(Path::new("/tmp/caliptra_verilated_test.vcd").exists());
        assert!(Path::new("/tmp/caliptra_verilated_test2.vcd").exists());
        v.stop_tracing();
        v.next_cycle_high(2);
    }
}
