/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains the root Bus implementation for a full-featured Caliptra emulator.

--*/

use crate::{
    iccm::Iccm, AsymEcc384, Doe, EmuCtrl, HashSha256, HashSha512, HmacSha384, KeyVault, Mailbox,
    MailboxRam, Sha512Accelerator, SocRegisters, Uart,
};
use caliptra_emu_bus::{Clock, Ram, Rom};
use caliptra_emu_derive::Bus;
use std::path::PathBuf;

pub struct TbServicesCb(pub Box<dyn FnMut(u8)>);
impl TbServicesCb {
    pub fn new(f: impl FnMut(u8) + 'static) -> Self {
        Self(Box::new(f))
    }
    pub(crate) fn take(&mut self) -> Box<dyn FnMut(u8)> {
        std::mem::take(self).0
    }
}
impl Default for TbServicesCb {
    fn default() -> Self {
        Self(Box::new(|_| {}))
    }
}
impl std::fmt::Debug for TbServicesCb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TbServicesCb")
            .field(&"<unknown closure>")
            .finish()
    }
}
impl From<Box<dyn FnMut(u8) + 'static>> for TbServicesCb {
    fn from(value: Box<dyn FnMut(u8)>) -> Self {
        Self(value)
    }
}

type ReadyForFwFn = Box<dyn FnMut(&mut Mailbox)>;
pub struct ReadyForFwCb(pub ReadyForFwFn);
impl ReadyForFwCb {
    pub fn new(f: impl FnMut(&mut Mailbox) + 'static) -> Self {
        Self(Box::new(f))
    }
    pub(crate) fn take(&mut self) -> ReadyForFwFn {
        std::mem::take(self).0
    }
}
impl Default for ReadyForFwCb {
    fn default() -> Self {
        Self(Box::new(|_| {}))
    }
}
impl std::fmt::Debug for ReadyForFwCb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ReadyForFwCb")
            .field(&"<unknown closure>")
            .finish()
    }
}
impl From<Box<dyn FnMut(&mut Mailbox) + 'static>> for ReadyForFwCb {
    fn from(value: Box<dyn FnMut(&mut Mailbox)>) -> Self {
        Self(value)
    }
}

/// Caliptra Root Bus Arguments
#[derive(Default, Debug)]
pub struct CaliptraRootBusArgs {
    pub rom: Vec<u8>,
    pub log_dir: PathBuf,
    pub ueid: u64,
    pub idev_key_id_algo: String,
    pub req_idevid_csr: bool,
    pub req_ldevid_cert: bool,
    /// Callback to customize application behavior when
    /// a write to the tb-services register write is performed.
    pub tb_services_cb: TbServicesCb,
    pub ready_for_fw_cb: ReadyForFwCb,
    pub mfg_pk_hash: Vec<u8>,
    pub owner_pk_hash: Vec<u8>,
    pub device_lifecycle: String,
}

#[derive(Bus)]
pub struct CaliptraRootBus {
    #[peripheral(offset = 0x0000_0000, mask = 0x0fff_ffff)]
    pub rom: Rom,

    #[peripheral(offset = 0x1000_0000, mask = 0x0000_7fff)]
    pub doe: Doe,

    #[peripheral(offset = 0x1000_8000, mask = 0x0000_7fff)]
    pub ecc384: AsymEcc384,

    #[peripheral(offset = 0x1001_0000, mask = 0x0000_07ff)]
    pub hmac: HmacSha384,

    #[peripheral(offset = 0x1001_8000, mask = 0x0000_7fff)]
    pub key_vault: KeyVault,

    #[peripheral(offset = 0x1002_0000, mask = 0x0000_7fff)]
    pub sha512: HashSha512,

    #[peripheral(offset = 0x1002_8000, mask = 0x0000_7fff)]
    pub sha256: HashSha256,

    #[peripheral(offset = 0x4000_0000, mask = 0x0fff_ffff)]
    pub iccm: Iccm,

    #[peripheral(offset = 0x2000_1000, mask = 0x0000_0fff)]
    pub uart: Uart,

    #[peripheral(offset = 0x2000_f000, mask = 0x0000_0fff)]
    pub ctrl: EmuCtrl,

    #[peripheral(offset = 0x3000_0000, mask = 0x0001_ffff)]
    pub mailbox_sram: MailboxRam,

    #[peripheral(offset = 0x3002_0000, mask = 0x0000_0fff)]
    pub mailbox: Mailbox,

    #[peripheral(offset = 0x3002_1000, mask = 0x0000_0fff)]
    pub sha512_acc: Sha512Accelerator,

    #[peripheral(offset = 0x3003_0000, mask = 0x0000_ffff)]
    pub soc_reg: SocRegisters,

    #[peripheral(offset = 0x5000_0000, mask = 0x0fff_ffff)]
    pub dccm: Ram,
}

impl CaliptraRootBus {
    pub const ROM_SIZE: usize = 32 * 1024;
    pub const ICCM_SIZE: usize = 128 * 1024;
    pub const DCCM_SIZE: usize = 128 * 1024;

    pub fn new(clock: &Clock, mut args: CaliptraRootBusArgs) -> Self {
        let key_vault = KeyVault::new();
        let mailbox_ram = MailboxRam::new();
        let mailbox = Mailbox::new(mailbox_ram.clone());
        let rom = Rom::new(std::mem::take(&mut args.rom));
        let iccm = Iccm::new();
        let soc_reg = SocRegisters::new(clock, mailbox.clone(), iccm.clone(), args);

        Self {
            rom,
            doe: Doe::new(clock, key_vault.clone(), soc_reg.clone()),
            ecc384: AsymEcc384::new(clock, key_vault.clone()),
            hmac: HmacSha384::new(clock, key_vault.clone()),
            key_vault: key_vault.clone(),
            sha512: HashSha512::new(clock, key_vault),
            sha256: HashSha256::new(clock),
            iccm,
            dccm: Ram::new(vec![0; Self::DCCM_SIZE]),
            uart: Uart::new(),
            ctrl: EmuCtrl::new(),
            soc_reg,
            mailbox_sram: mailbox_ram.clone(),
            mailbox,
            sha512_acc: Sha512Accelerator::new(clock, mailbox_ram),
        }
    }
}
