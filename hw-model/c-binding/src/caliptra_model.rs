// Licensed under the Apache-2.0 license

use caliptra_emu_bus::Bus;
use caliptra_hw_model::{DefaultHwModel, HwModel, InitParams, SecurityState};
use std::ffi::*;
use std::slice;

use caliptra_emu_types::RvSize;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct caliptra_model {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct caliptra_buffer {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct caliptra_model_init_params {
    pub rom: caliptra_buffer,
    pub dccm: caliptra_buffer,
    pub iccm: caliptra_buffer,
    pub security_state: u8,
}

pub const CALIPTRA_SEC_STATE_DBG_UNLOCKED_UNPROVISIONED: c_int = 0b000;
pub const CALIPTRA_SEC_STATE_DBG_LOCKED_MANUFACTURING: c_int = 0b101;
pub const CALIPTRA_SEC_STATE_DBG_UNLOCKED_PRODUCTION: c_int = 0b011;
pub const CALIPTRA_SEC_STATE_DBG_LOCKED_PRODUCTION: c_int = 0b111;

pub const CALIPTRA_MODEL_STATUS_OK: c_int = 0;

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_init_default(
    params: caliptra_model_init_params,
    model: *mut *mut caliptra_model,
) -> c_int {
    // Parameter check
    assert!(!model.is_null());
    // Generate Model and cast to caliptra_model
    *model = Box::into_raw(Box::new(
        caliptra_hw_model::new_unbooted(InitParams {
            rom: slice::from_raw_parts(params.rom.data, params.rom.len),
            dccm: slice::from_raw_parts(params.dccm.data, params.dccm.len),
            iccm: slice::from_raw_parts(params.iccm.data, params.iccm.len),
            security_state: SecurityState::from(params.security_state as u32),
            ..Default::default()
        })
        .unwrap(),
    )) as *mut caliptra_model;

    CALIPTRA_MODEL_STATUS_OK
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_destroy(model: *mut caliptra_model) {
    // Parameter check
    assert!(!model.is_null());

    // This will force model to be freed. Needs the cast to know how much memory to be freed.
    drop(Box::from_raw(model as *mut DefaultHwModel));
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_axi_read_u32(
    model: *mut caliptra_model,
    addr: c_uint,
    data: *mut c_uint,
) -> c_int {
    // Parameter check
    assert!(!model.is_null() || !data.is_null());
    *data = (*{ model as *mut DefaultHwModel })
        .axi_bus()
        .read(RvSize::Word, addr)
        .unwrap();

    CALIPTRA_MODEL_STATUS_OK
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_axi_write_u32(
    model: *mut caliptra_model,
    addr: c_uint,
    data: c_uint,
) -> c_int {
    // Parameter check
    assert!(!model.is_null());
    (*{ model as *mut DefaultHwModel })
        .axi_bus()
        .write(RvSize::Word, addr, data)
        .unwrap();

    CALIPTRA_MODEL_STATUS_OK
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_ready_for_fuses(model: *mut caliptra_model) -> bool {
    // Parameter check
    assert!(!model.is_null());
    !(*{ model as *mut DefaultHwModel })
        .soc_ifc()
        .cptra_fuse_wr_done()
        .read()
        .done()
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_ready_for_fw(model: *mut caliptra_model) -> bool {
    // Parameter check
    assert!(!model.is_null());
    (*{ model as *mut DefaultHwModel }).ready_for_fw()
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_step(model: *mut caliptra_model) -> c_int {
    // Parameter check
    assert!(!model.is_null());
    (*{ model as *mut DefaultHwModel }).step();

    CALIPTRA_MODEL_STATUS_OK
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_exit_requested(model: *mut caliptra_model) -> bool {
    // Parameter check
    assert!(!model.is_null());
    (*{ model as *mut DefaultHwModel })
        .output()
        .exit_requested()
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_output_peek(model: *mut caliptra_model) -> caliptra_buffer {
    // Parameter check
    assert!(!model.is_null());
    let peek_str = (*{ model as *mut DefaultHwModel }).output().peek();
    caliptra_buffer {
        data: peek_str.as_ptr() as *const u8,
        len: peek_str.len(),
    }
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_step_until_boot_status(
    model: *mut caliptra_model,
    boot_status: c_uint,
) {
    // Parameter check
    assert!(!model.is_null());
    (*{ model as *mut DefaultHwModel }).step_until_boot_status(boot_status, true);
}
