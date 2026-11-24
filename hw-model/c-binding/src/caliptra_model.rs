// Licensed under the Apache-2.0 license

use caliptra_api::soc_mgr::SocManager;
use caliptra_cfi_lib::CfiState;
use caliptra_emu_bus::Bus;
use caliptra_emu_periph::MailboxRequester;
use caliptra_emu_types::RvSize;
use caliptra_hw_model::{DefaultHwModel, HwModel, InitParams, SecurityState};
use caliptra_hw_model_types::DEFAULT_CPTRA_OBF_KEY;
use core::mem::size_of_val;
use std::ffi::*;
use std::ptr;
use std::slice;

// These are needed if CFI is enabled.
#[no_mangle]
pub extern "C" fn cfi_panic_handler(code: u32) -> ! {
    std::process::exit(code as i32);
}

#[allow(unused)]
#[no_mangle]
static mut CFI_STATE_ORG: [u8; std::mem::size_of::<CfiState>()] =
    [0; std::mem::size_of::<CfiState>()];

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

#[allow(non_camel_case_types)]
pub type caliptra_hw_version = c_uint;

pub const CALIPTRA_HW_VERSION_LATEST: caliptra_hw_version = 0;
pub const CALIPTRA_HW_VERSION_2_0: caliptra_hw_version = 1;
pub const CALIPTRA_HW_VERSION_2_1: caliptra_hw_version = 2;
pub const CALIPTRA_HW_VERSION_2_2: caliptra_hw_version = 3;

fn parse_hw_version(v: caliptra_hw_version) -> Option<caliptra_hw_model::CaliptraHwVersion> {
    match v {
        CALIPTRA_HW_VERSION_LATEST => Some(caliptra_hw_model::CaliptraHwVersion::Latest),
        CALIPTRA_HW_VERSION_2_0 => Some(caliptra_hw_model::CaliptraHwVersion::V2_0),
        CALIPTRA_HW_VERSION_2_1 => Some(caliptra_hw_model::CaliptraHwVersion::V2_1),
        CALIPTRA_HW_VERSION_2_2 => Some(caliptra_hw_model::CaliptraHwVersion::V2_2),
        _ => None,
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct caliptra_model_init_params {
    pub hw_version: caliptra_hw_version,
    pub rom: caliptra_buffer,
    pub dccm: caliptra_buffer,
    pub iccm: caliptra_buffer,
    pub security_state: u8,
    pub soc_user: u32,

    // When data is null and len is 0, DEFAULT_CPTRA_OBF_KEY is used.
    pub optional_obf_key: caliptra_buffer,
}

pub const CALIPTRA_SEC_STATE_DBG_UNLOCKED_UNPROVISIONED: c_int = 0b000;
pub const CALIPTRA_SEC_STATE_DBG_LOCKED_MANUFACTURING: c_int = 0b101;
pub const CALIPTRA_SEC_STATE_DBG_UNLOCKED_PRODUCTION: c_int = 0b011;
pub const CALIPTRA_SEC_STATE_DBG_LOCKED_PRODUCTION: c_int = 0b111;

pub const CALIPTRA_MODEL_STATUS_OK: c_int = 0;
pub const CALIPTRA_MODEL_INVALID_OBF_KEY_SIZE: c_int = -1;
pub const CALIPTRA_MODEL_INVALID_ARG: c_int = -2;
pub const CALIPTRA_MODEL_ERROR: c_int = -3;

/// # Safety
///
/// `model` must be a valid writable pointer. Each `caliptra_buffer` in `params`
/// must either have `len == 0` or have `data` pointing to at least `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_init_default(
    params: caliptra_model_init_params,
    model: *mut *mut caliptra_model,
) -> c_int {
    // Parameter check
    if model.is_null() {
        return CALIPTRA_MODEL_INVALID_ARG;
    }
    *model = ptr::null_mut();
    if (params.rom.len != 0 && params.rom.data.is_null())
        || (params.dccm.len != 0 && params.dccm.data.is_null())
        || (params.iccm.len != 0 && params.iccm.data.is_null())
    {
        return CALIPTRA_MODEL_INVALID_ARG;
    }

    let cptra_obf_key = if params.optional_obf_key.data.is_null() {
        if params.optional_obf_key.len != 0 {
            return CALIPTRA_MODEL_INVALID_ARG;
        }
        DEFAULT_CPTRA_OBF_KEY
    } else if params.optional_obf_key.len != size_of_val(&DEFAULT_CPTRA_OBF_KEY) {
        return CALIPTRA_MODEL_INVALID_OBF_KEY_SIZE;
    } else {
        let bytes =
            slice::from_raw_parts(params.optional_obf_key.data, params.optional_obf_key.len);
        let mut key = [0u32; 8];
        for (dst, chunk) in key.iter_mut().zip(bytes.chunks_exact(4)) {
            *dst = u32::from_ne_bytes(chunk.try_into().unwrap());
        }
        key
    };

    let Some(hw_version) = parse_hw_version(params.hw_version) else {
        return CALIPTRA_MODEL_INVALID_ARG;
    };

    // Generate Model and cast to caliptra_model
    let hw_model = match caliptra_hw_model::new_unbooted(InitParams {
        hw_version,
        rom: if params.rom.len == 0 {
            &[]
        } else {
            slice::from_raw_parts(params.rom.data, params.rom.len)
        },
        dccm: if params.dccm.len == 0 {
            &[]
        } else {
            slice::from_raw_parts(params.dccm.data, params.dccm.len)
        },
        iccm: if params.iccm.len == 0 {
            &[]
        } else {
            slice::from_raw_parts(params.iccm.data, params.iccm.len)
        },
        security_state: SecurityState::from(params.security_state as u32),
        soc_user: MailboxRequester::SocUser(params.soc_user),
        cptra_obf_key,
        ..Default::default()
    }) {
        Ok(m) => m,
        Err(_) => return CALIPTRA_MODEL_ERROR,
    };
    *model = Box::into_raw(Box::new(hw_model)) as *mut caliptra_model;

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
pub unsafe extern "C" fn caliptra_model_apb_read_u32(
    model: *mut caliptra_model,
    addr: c_uint,
    data: *mut c_uint,
) -> c_int {
    // Parameter check
    if data.is_null() {
        return CALIPTRA_MODEL_INVALID_ARG;
    }
    *data = 0;
    if model.is_null() {
        return CALIPTRA_MODEL_INVALID_ARG;
    }
    match (*{ model as *mut DefaultHwModel })
        .apb_bus()
        .read(RvSize::Word, addr)
    {
        Ok(val) => *data = val,
        Err(_) => return CALIPTRA_MODEL_ERROR,
    }

    CALIPTRA_MODEL_STATUS_OK
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_apb_write_u32(
    model: *mut caliptra_model,
    addr: c_uint,
    data: c_uint,
) -> c_int {
    // Parameter check
    if model.is_null() {
        return CALIPTRA_MODEL_INVALID_ARG;
    }
    if (*{ model as *mut DefaultHwModel })
        .apb_bus()
        .write(RvSize::Word, addr, data)
        .is_err()
    {
        return CALIPTRA_MODEL_ERROR;
    }

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
        data: peek_str.as_ptr(),
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

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn caliptra_model_set_axi_user(model: *mut caliptra_model, pauser: c_uint) {
    // Parameter check
    assert!(!model.is_null());
    (*{ model as *mut DefaultHwModel }).set_axi_user(pauser);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_params() -> caliptra_model_init_params {
        caliptra_model_init_params {
            hw_version: CALIPTRA_HW_VERSION_LATEST,
            rom: caliptra_buffer {
                data: ptr::null(),
                len: 0,
            },
            dccm: caliptra_buffer {
                data: ptr::null(),
                len: 0,
            },
            iccm: caliptra_buffer {
                data: ptr::null(),
                len: 0,
            },
            security_state: CALIPTRA_SEC_STATE_DBG_UNLOCKED_UNPROVISIONED as u8,
            soc_user: 0,
            optional_obf_key: caliptra_buffer {
                data: ptr::null(),
                len: 0,
            },
        }
    }

    #[test]
    fn test_c_binding_rejects_null_and_invalid_args() {
        unsafe {
            assert_eq!(
                caliptra_model_init_default(empty_params(), ptr::null_mut()),
                CALIPTRA_MODEL_INVALID_ARG
            );

            let mut model: *mut caliptra_model = ptr::dangling_mut::<caliptra_model>();
            let mut bad_rom = empty_params();
            bad_rom.rom.len = 4;
            assert_eq!(
                caliptra_model_init_default(bad_rom, &mut model),
                CALIPTRA_MODEL_INVALID_ARG
            );
            assert!(model.is_null());

            let mut bad_obf_null = empty_params();
            bad_obf_null.optional_obf_key.len = 32;
            assert_eq!(
                caliptra_model_init_default(bad_obf_null, &mut model),
                CALIPTRA_MODEL_INVALID_ARG
            );
            assert!(model.is_null());

            let short_key = [1u8; 16];
            let mut bad_obf_len = empty_params();
            bad_obf_len.optional_obf_key = caliptra_buffer {
                data: short_key.as_ptr(),
                len: short_key.len(),
            };
            assert_eq!(
                caliptra_model_init_default(bad_obf_len, &mut model),
                CALIPTRA_MODEL_INVALID_OBF_KEY_SIZE
            );
            assert!(model.is_null());

            let mut bad_hw_ver = empty_params();
            bad_hw_ver.hw_version = 99;
            assert_eq!(
                caliptra_model_init_default(bad_hw_ver, &mut model),
                CALIPTRA_MODEL_INVALID_ARG
            );
            assert!(model.is_null());

            let mut out: c_uint = 0xdead_beef;
            assert_eq!(
                caliptra_model_apb_read_u32(ptr::null_mut(), 0, &mut out),
                CALIPTRA_MODEL_INVALID_ARG
            );
            assert_eq!(out, 0);
            assert_eq!(
                caliptra_model_apb_write_u32(ptr::null_mut(), 0, 0),
                CALIPTRA_MODEL_INVALID_ARG
            );
        }
    }

    #[test]
    fn test_c_binding_unaligned_obf_key() {
        unsafe {
            let mut model: *mut caliptra_model = ptr::null_mut();

            // Unaligned 32-byte optional_obf_key must succeed without UB.
            let unaligned_backing = [0xA5u8; 33];
            let mut ok_params = empty_params();
            ok_params.optional_obf_key = caliptra_buffer {
                data: unaligned_backing.as_ptr().add(1),
                len: 32,
            };
            assert_eq!(
                caliptra_model_init_default(ok_params, &mut model),
                CALIPTRA_MODEL_STATUS_OK
            );
            assert!(!model.is_null());
            assert_eq!(
                caliptra_model_apb_read_u32(model, 0, ptr::null_mut()),
                CALIPTRA_MODEL_INVALID_ARG
            );
            caliptra_model_destroy(model);
        }
    }

    #[cfg(not(feature = "verilator"))]
    #[test]
    fn test_c_binding_init_error_oversized_iccm() {
        unsafe {
            let mut model: *mut caliptra_model = ptr::dangling_mut::<caliptra_model>();

            // Oversized ICCM must return CALIPTRA_MODEL_ERROR instead of aborting
            // on the emulator backend, and clear the output pointer.
            let oversized = vec![0u8; 1024 * 1024];
            let mut bad_iccm = empty_params();
            bad_iccm.iccm = caliptra_buffer {
                data: oversized.as_ptr(),
                len: oversized.len(),
            };
            assert_eq!(
                caliptra_model_init_default(bad_iccm, &mut model),
                CALIPTRA_MODEL_ERROR
            );
            assert!(model.is_null());
        }
    }
}
