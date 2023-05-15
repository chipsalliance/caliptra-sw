/*++
Licensed under the Apache-2.0 license.
--*/

#[allow(dead_code)]
mod real;

pub use real::{
    caliptra_verilated, caliptra_verilated_init_args, caliptra_verilated_sig_in,
    caliptra_verilated_sig_out,
};

#[cfg(not(feature = "verilator"))]
mod disabled {
    use super::*;

    const MSG: &str = "Built without verilator support; use --features=verilator to enable";

    pub unsafe fn caliptra_verilated_new(
        _args: *mut caliptra_verilated_init_args,
    ) -> *mut caliptra_verilated {
        panic!("{}", MSG);
    }
    pub unsafe fn caliptra_verilated_destroy(_model: *mut caliptra_verilated) {
        panic!("{}", MSG);
    }
    pub unsafe fn caliptra_verilated_trace(
        _model: *mut caliptra_verilated,
        _vcd_out_path: *const ::std::os::raw::c_char,
        _depth: ::std::os::raw::c_int,
    ) {
        panic!("{}", MSG);
    }
    pub unsafe fn caliptra_verilated_eval(
        _model: *mut caliptra_verilated,
        _in_: *const caliptra_verilated_sig_in,
        _out: *mut caliptra_verilated_sig_out,
    ) {
        panic!("{}", MSG);
    }
}

#[cfg(feature = "verilator")]
pub use real::*;

#[cfg(not(feature = "verilator"))]
pub use disabled::*;
