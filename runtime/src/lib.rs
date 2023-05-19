// Licensed under the Apache-2.0 license

#![no_std]

pub mod dice;
mod verify;

// Used by runtime tests
pub mod mailbox;

use mailbox::Mailbox;

use caliptra_common::cprintln;
use caliptra_drivers::{caliptra_err_def, CaliptraResult, DataVault, Ecc384};
use caliptra_registers::{
    dv::DvReg,
    ecc::EccReg,
    mbox::{enums::MboxStatusE, MboxCsr},
    sha512_acc::Sha512AccCsr,
};
use zerocopy::{AsBytes, FromBytes};

caliptra_err_def! {
    Runtime,
    RuntimeErr
    {
        // Internal
        InternalErr = 0x1,
        UnimplementedCommand = 0x2,
        InsufficientMemory = 0x3,
        EcdsaVerificationFailed = 0x4,
    }
}

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);

impl CommandId {
    pub const FIRMWARE_LOAD: Self = Self(0x46574C44); // "FWLD"
    pub const GET_IDEV_CSR: Self = Self(0x49444556); // "IDEV"
    pub const GET_LDEV_CERT: Self = Self(0x4C444556); // "LDEV"
    pub const ECDSA384_VERIFY: Self = Self(0x53494756); // "SIGV"
    pub const STASH_MEASUREMENT: Self = Self(0x4D454153); // "MEAS"
    pub const INVOKE_DPE: Self = Self(0x44504543); // "DPEC"
}
impl From<u32> for CommandId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}
impl From<CommandId> for u32 {
    fn from(value: CommandId) -> Self {
        value.0
    }
}

pub struct Drivers {
    pub mbox: Mailbox,
    pub sha_acc: Sha512AccCsr,
    pub ecdsa: Ecc384,
    pub data_vault: DataVault,
}
impl Drivers {
    /// # Safety
    ///
    /// Callers must ensure that this function is called only once, and that
    /// any concurrent access to these register blocks does not conflict with
    /// these drivers.
    pub unsafe fn new_from_registers() -> Self {
        Self {
            mbox: Mailbox::new(MboxCsr::new()),
            sha_acc: Sha512AccCsr::new(),
            ecdsa: Ecc384::new(EccReg::new()),
            data_vault: DataVault::new(DvReg::new()),
        }
    }
}
#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct EcdsaVerifyCmd {
    pub chksum: u32,
    pub pub_key_x: [u8; 48],
    pub pub_key_y: [u8; 48],
    pub signature_r: [u8; 48],
    pub signature_s: [u8; 48],
}

impl Default for EcdsaVerifyCmd {
    fn default() -> Self {
        Self {
            chksum: 0,
            pub_key_x: [0u8; 48],
            pub_key_y: [0u8; 48],
            signature_r: [0u8; 48],
            signature_s: [0u8; 48],
        }
    }
}

fn wait_for_cmd(_mbox: &mut Mailbox) {
    // TODO: Enable interrupts?
    //#[cfg(feature = "riscv")]
    //unsafe {
    //core::arch::asm!("wfi");
    //}
}

fn handle_command(drivers: &mut Drivers) -> CaliptraResult<MboxStatusE> {
    let mbox = &mut drivers.mbox;

    let cmd_id = mbox.cmd();
    let dlen = mbox.dlen() as usize;
    let dlen_words = mbox.dlen_words() as usize;
    let mut buf = [0u32; 1024];
    mbox.copy_from_mbox(buf.get_mut(..dlen_words).ok_or(err_u32!(InternalErr))?);

    if dlen > buf.len() * 4 {
        // dlen larger than max message
        return Err(err_u32!(InsufficientMemory));
    }

    let cmd_bytes = buf
        .as_bytes()
        .get(..dlen)
        .ok_or(err_u32!(InsufficientMemory))?;

    cprintln!("[rt] Received command=0x{:x}, len={}", cmd_id, mbox.dlen());
    match CommandId::from(cmd_id) {
        CommandId::FIRMWARE_LOAD => Err(err_u32!(UnimplementedCommand)),
        CommandId::GET_IDEV_CSR => Err(err_u32!(UnimplementedCommand)),
        CommandId::GET_LDEV_CERT => Err(err_u32!(UnimplementedCommand)),
        CommandId::ECDSA384_VERIFY => {
            verify::handle_ecdsa_verify(drivers, cmd_bytes)?;
            Ok(MboxStatusE::CmdComplete)
        }
        CommandId::STASH_MEASUREMENT => Err(err_u32!(UnimplementedCommand)),
        CommandId::INVOKE_DPE => Err(err_u32!(UnimplementedCommand)),
        _ => Err(err_u32!(UnimplementedCommand)),
    }
}

pub fn handle_mailbox_commands(drivers: &mut Drivers) {
    loop {
        wait_for_cmd(&mut drivers.mbox);

        if drivers.mbox.is_cmd_ready() {
            match handle_command(drivers) {
                Ok(status) => {
                    drivers.mbox.set_status(status);
                }
                Err(e) => {
                    caliptra_drivers::report_fw_error_non_fatal(e.into());
                    drivers.mbox.set_status(MboxStatusE::CmdFailure);
                }
            }
        }
    }
}
