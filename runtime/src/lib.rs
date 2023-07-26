// Licensed under the Apache-2.0 license

#![no_std]

pub mod dice;
mod update;
mod verify;

// Used by runtime tests
pub(crate) mod fips;
pub mod mailbox;

use mailbox::Mailbox;

pub mod packet;
pub use fips::FipsModule;
use packet::Packet;

use caliptra_common::{cprintln, FirmwareHandoffTable};
use caliptra_drivers::{CaliptraError, CaliptraResult, DataVault, Ecc384};
use caliptra_registers::{
    dv::DvReg,
    ecc::EccReg,
    mbox::{enums::MboxStatusE, MboxCsr},
    sha512_acc::Sha512AccCsr,
    soc_ifc::SocIfcReg,
};
use zerocopy::{AsBytes, FromBytes};

#[derive(PartialEq, Eq)]
pub struct CommandId(pub u32);

impl CommandId {
    pub const FIRMWARE_LOAD: Self = Self(0x46574C44); // "FWLD"
    pub const GET_IDEV_CSR: Self = Self(0x49444556); // "IDEV"
    pub const GET_LDEV_CERT: Self = Self(0x4C444556); // "LDEV"
    pub const ECDSA384_VERIFY: Self = Self(0x53494756); // "SIGV"
    pub const STASH_MEASUREMENT: Self = Self(0x4D454153); // "MEAS"
    pub const INVOKE_DPE: Self = Self(0x44504543); // "DPEC"

    pub const TEST_ONLY_GET_LDEV_CERT: Self = Self(0x4345524c); // "CERL"
    pub const TEST_ONLY_GET_FMC_ALIAS_CERT: Self = Self(0x43455246); // "CERF"

    /// FIPS module commands.
    /// The status command.
    pub const VERSION: Self = Self(0x4650_5652); // "FPVR"
    /// The self-test command.
    pub const SELF_TEST: Self = Self(0x4650_4C54); // "FPST"
    /// The shutdown command.
    pub const SHUTDOWN: Self = Self(0x4650_5344); // "FPSD"
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

pub struct Drivers<'a> {
    pub mbox: Mailbox,
    pub sha_acc: Sha512AccCsr,
    pub ecdsa: Ecc384,
    pub data_vault: DataVault,
    pub soc_ifc: SocIfcReg,
    pub fht: &'a mut FirmwareHandoffTable,
}
impl<'a> Drivers<'a> {
    /// # Safety
    ///
    /// Callers must ensure that this function is called only once, and that
    /// any concurrent access to these register blocks does not conflict with
    /// these drivers.
    pub unsafe fn new_from_registers(fht: &'a mut FirmwareHandoffTable) -> Self {
        Self {
            mbox: Mailbox::new(MboxCsr::new()),
            sha_acc: Sha512AccCsr::new(),
            ecdsa: Ecc384::new(EccReg::new()),
            data_vault: DataVault::new(DvReg::new()),
            soc_ifc: SocIfcReg::new(),
            fht,
        }
    }
}
#[repr(C)]
#[derive(AsBytes, FromBytes)]
pub struct EcdsaVerifyCmd {
    pub chksum: i32,
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
    // For firmware update, don't read data from the mailbox
    if drivers.mbox.cmd() == CommandId::FIRMWARE_LOAD.into() {
        update::handle_impactless_update(drivers)?;

        // If the handler succeeds but does not invoke reset that is
        // unexpected. Denote that the update failed.
        return Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN);
    }

    // Get the command bytes
    let packet = Packet::copy_from_mbox(drivers)?;
    let cmd_bytes = packet.as_bytes()?;

    cprintln!(
        "[rt] Received command=0x{:x}, len={}",
        packet.cmd,
        packet.len
    );

    match CommandId::from(packet.cmd) {
        // FIRMWARE_LOAD expected to already be handled
        CommandId::FIRMWARE_LOAD => Err(CaliptraError::RUNTIME_UNEXPECTED_UPDATE_RETURN),
        CommandId::GET_IDEV_CSR => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::GET_LDEV_CERT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::ECDSA384_VERIFY => {
            verify::handle_ecdsa_verify(drivers, cmd_bytes)?;
            Ok(MboxStatusE::CmdComplete)
        }
        CommandId::STASH_MEASUREMENT => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        CommandId::INVOKE_DPE => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_LDEV_CERT => {
            let mut cert = [0u8; 1024];
            let cert_len = dice::copy_ldevid_cert(&drivers.data_vault, &mut cert)?;
            drivers.mbox.write_response(
                cert.get(..cert_len)
                    .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
            )?;
            Ok(MboxStatusE::DataReady)
        }
        #[cfg(feature = "test_only_commands")]
        CommandId::TEST_ONLY_GET_FMC_ALIAS_CERT => {
            let mut cert = [0u8; 1024];
            let cert_len = dice::copy_fmc_alias_cert(&drivers.data_vault, &mut cert)?;
            drivers.mbox.write_response(
                cert.get(..cert_len)
                    .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?,
            )?;
            Ok(MboxStatusE::DataReady)
        }
        CommandId::VERSION => FipsModule::version(drivers),
        CommandId::SELF_TEST => FipsModule::self_test(drivers),
        CommandId::SHUTDOWN => FipsModule::shutdown(drivers),
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
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
