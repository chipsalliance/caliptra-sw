/*++
Licensed under the Apache-2.0 license.
--*/
mod bindings;
use std::ffi::CString;
use std::ffi::NulError;
use std::ptr::null;

pub use bindings::caliptra_verilated_init_args as InitArgs;
pub use bindings::caliptra_verilated_sig_in as SigIn;
pub use bindings::caliptra_verilated_sig_out as SigOut;
use rand::Rng;

pub type GenericOutputWiresChangedCallbackFn = dyn Fn(&CaliptraVerilated, u64);

pub struct CaliptraVerilated {
    v: *mut bindings::caliptra_verilated,
    pub input: SigIn,
    pub output: SigOut,
    prev_generic_output_wires: Option<u64>,
    generic_output_wires_changed_cb: Box<GenericOutputWiresChangedCallbackFn>,
    total_cycles: u64,
}

impl CaliptraVerilated {
    /// Constructs a new model.
    pub fn new(args: InitArgs) -> Self {
        Self::with_callbacks(args, Box::new(|_, _| {}))
    }

    /// Creates a model that calls `generic_load_cb` whenever the
    /// microcontroller CPU does a load to the generic wires.
    #[allow(clippy::type_complexity)]
    pub fn with_callbacks(
        mut args: InitArgs,
        generic_output_wires_changed_cb: Box<GenericOutputWiresChangedCallbackFn>,
    ) -> Self {
        unsafe {
            Self {
                v: bindings::caliptra_verilated_new(&mut args),
                input: Default::default(),
                output: Default::default(),
                generic_output_wires_changed_cb,
                prev_generic_output_wires: None,
                total_cycles: 0,
            }
        }
    }

    fn iccm_dccm_write(&mut self, addr: u32, data: [u32; 5]) {
        self.input.ext_dccm_we = true;
        self.input.ext_iccm_we = true;
        self.input.ext_xccm_addr = addr;
        self.input.ext_xccm_wdata = data;

        self.next_cycle_high(1);
        self.input.ext_dccm_we = false;
        self.input.ext_iccm_we = false;
    }

    pub fn init_random_puf_state(&mut self, rng: &mut impl Rng) {
        // Randomize all of ICCM and DCCM
        for addr in 0..8192 {
            self.iccm_dccm_write(addr, rng.gen::<[u32; 5]>());
        }
    }

    /// Set all mailbox SRAM cells to value with double-bit ECC errors
    pub fn corrupt_mailbox_ecc_double_bit(&mut self) {
        for addr in 0..32768 {
            self.input.ext_mbox_we = true;
            self.input.ext_xccm_addr = addr;
            self.input.ext_xccm_wdata = [
                0x0000_0003,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
                0x0000_0000,
            ];

            self.next_cycle_high(1);
            self.input.ext_mbox_we = false;
        }
    }

    /// Returns the total number of cycles since simulation start
    pub fn total_cycles(&self) -> u64 {
        self.total_cycles
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
        if !self.input.core_clk {
            return;
        }
        if Some(self.output.generic_output_wires) != self.prev_generic_output_wires {
            self.prev_generic_output_wires = Some(self.output.generic_output_wires);
            (self.generic_output_wires_changed_cb)(self, self.output.generic_output_wires);
        }
    }

    /// Toggles core_clk until there have been `n_cycles` rising edges.
    pub fn next_cycle_high(&mut self, n_cycles: u32) {
        for _ in 0..n_cycles {
            self.total_cycles += 1;
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

    /// Initiates a read transaction on the SoC->Caliptra AXI bus with user
    /// `user` and `addr`, and returns the word read from the bus.
    pub fn axi_read_u32(&mut self, user: u32, addr: u32) -> u32 {
        // AXI Read Address phase
        self.input.s_axi_araddr = addr;
        self.input.s_axi_aruser = user;
        self.input.s_axi_arid = 0;
        self.input.s_axi_arlen = 0; // Single beat
        self.input.s_axi_arsize = 2; // 4 bytes
        self.input.s_axi_arburst = 1; // INCR
        self.input.s_axi_arlock = false;
        self.input.s_axi_arvalid = true;
        self.input.s_axi_rready = true;

        // Wait for arready
        loop {
            self.next_cycle_high(1);
            if self.output.s_axi_arready {
                break;
            }
        }

        self.input.s_axi_arvalid = false;

        // Wait for rvalid
        loop {
            self.next_cycle_high(1);
            if self.output.s_axi_rvalid {
                break;
            }
        }

        let result = self.output.s_axi_rdata;

        self.input.s_axi_rready = false;

        result
    }

    /// Initiates a write transaction on the SoC->Caliptra AXI bus with user
    /// `user`, `addr` and `data`.
    pub fn axi_write_u32(&mut self, user: u32, addr: u32, data: u32) {
        // AXI Write Address phase
        self.input.s_axi_awaddr = addr;
        self.input.s_axi_awuser = user;
        self.input.s_axi_awid = 0;
        self.input.s_axi_awlen = 0; // Single beat
        self.input.s_axi_awsize = 2; // 4 bytes
        self.input.s_axi_awburst = 1; // INCR
        self.input.s_axi_awlock = false;
        self.input.s_axi_awvalid = true;

        // AXI Write Data phase (can be concurrent with address)
        self.input.s_axi_wdata = data;
        self.input.s_axi_wstrb = 0xf; // All bytes valid
        self.input.s_axi_wvalid = true;
        self.input.s_axi_wlast = true;

        // Ready to accept write response
        self.input.s_axi_bready = true;

        // Wait for both awready and wready
        let mut aw_done = false;
        let mut w_done = false;
        loop {
            self.next_cycle_high(1);
            if self.output.s_axi_awready {
                aw_done = true;
                self.input.s_axi_awvalid = false;
            }
            if self.output.s_axi_wready {
                w_done = true;
                self.input.s_axi_wvalid = false;
            }
            if aw_done && w_done {
                break;
            }
        }

        // Wait for bvalid (write response)
        loop {
            self.next_cycle_high(1);
            if self.output.s_axi_bvalid {
                break;
            }
        }

        self.input.s_axi_bready = false;
    }

    fn write_rom_u64(&mut self, addr: u32, data: u64) {
        self.input.imem_addr = addr;
        self.input.imem_wdata = data;
        self.input.imem_we = true;
        self.next_cycle_high(1);
        self.input.imem_we = false;
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
        let mut v = CaliptraVerilated::new(InitArgs {
            security_state: 0,
            cptra_obf_key: [0u32; 8],
            cptra_csr_hmac_key: [0u32; 16],
        });

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
