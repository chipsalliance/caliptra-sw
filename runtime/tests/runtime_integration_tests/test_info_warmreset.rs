// Licensed under the Apache-2.0 license

use crate::common::{build_ready_runtime_model, wait_runtime_ready, BuildArgs};

use caliptra_common::mailbox_api::{CommandId, FwInfoResp, MailboxReqHeader, MailboxRespHeader};
use caliptra_hw_model::{DefaultHwModel, DeviceLifecycle, HwModel, SecurityState};

use zerocopy::{FromBytes, IntoBytes};

fn get_fw_info(model: &mut DefaultHwModel) -> FwInfoResp {
    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(u32::from(CommandId::FW_INFO), &[]),
    };

    let resp = model
        .mailbox_execute(u32::from(CommandId::FW_INFO), payload.as_bytes())
        .unwrap()
        .unwrap();

    let info = FwInfoResp::read_from_bytes(resp.as_slice()).unwrap();

    // Verify checksum
    assert!(caliptra_common::checksum::verify_checksum(
        info.hdr.chksum,
        0x0,
        &info.as_bytes()[core::mem::size_of_val(&info.hdr.chksum)..],
    ));

    // Verify FIPS status
    assert_eq!(
        info.hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    info
}

#[inline]
fn sha384_words_to_bytes(words: &[u32; 12]) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

#[inline]
fn sha256_words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

trait Sha384Bytes {
    fn to_sha384_bytes(&self) -> [u8; 48];
}
trait Sha256Bytes {
    fn to_sha256_bytes(&self) -> [u8; 32];
}

impl Sha384Bytes for [u8; 48] {
    #[inline]
    fn to_sha384_bytes(&self) -> [u8; 48] {
        *self
    }
}
impl Sha384Bytes for [u32; 12] {
    #[inline]
    fn to_sha384_bytes(&self) -> [u8; 48] {
        sha384_words_to_bytes(self)
    }
}
impl Sha256Bytes for [u8; 32] {
    #[inline]
    fn to_sha256_bytes(&self) -> [u8; 32] {
        *self
    }
}
impl Sha256Bytes for [u32; 8] {
    #[inline]
    fn to_sha256_bytes(&self) -> [u8; 32] {
        sha256_words_to_bytes(self)
    }
}

#[test]
fn test_fw_info_after_warm_reset() {
    let args = BuildArgs {
        security_state: *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production),
        fmc_version: 3,
        app_version: 5,
        fw_svn: 9,
    };
    let (mut model, image, rom_info, owner_pub_key_hash) = build_ready_runtime_model(args);

    let info_before = get_fw_info(&mut model);

    // Scalars
    assert_eq!(info_before.pl0_pauser, 0x1);
    assert_eq!(info_before.fw_svn, 9);
    assert_eq!(info_before.min_fw_svn, 9);
    assert_eq!(info_before.cold_boot_fw_svn, 9);
    assert_eq!(info_before.attestation_disabled, 0);

    // Revisions (commit IDs)
    assert_eq!(info_before.rom_revision, rom_info.revision);
    assert_eq!(info_before.fmc_revision, image.manifest.fmc.revision);
    assert_eq!(
        info_before.runtime_revision,
        image.manifest.runtime.revision
    );

    // Digests (normalize types if needed)
    let rom_sha256_ref = Sha256Bytes::to_sha256_bytes(&rom_info.sha256_digest);
    let fmc_sha384_ref = Sha384Bytes::to_sha384_bytes(&image.manifest.fmc.digest);
    let rt_sha384_ref = Sha384Bytes::to_sha384_bytes(&image.manifest.runtime.digest);

    let rom_sha256_before = Sha256Bytes::to_sha256_bytes(&info_before.rom_sha256_digest);
    let fmc_sha384_before = Sha384Bytes::to_sha384_bytes(&info_before.fmc_sha384_digest);
    let rt_sha384_before = Sha384Bytes::to_sha384_bytes(&info_before.runtime_sha384_digest);

    assert_eq!(rom_sha256_before, rom_sha256_ref);
    assert_eq!(fmc_sha384_before, fmc_sha384_ref);
    assert_ne!(
        rt_sha384_before, [0u8; 48],
        "runtime digest before reset is zero"
    );
    assert_eq!(rt_sha384_before, rt_sha384_ref);

    // Owner key hash
    assert_eq!(info_before.owner_pub_key_hash, owner_pub_key_hash);

    // ---- Warm reset (keep same image/fuses) ----
    // Warm reset
    model.warm_reset();
    wait_runtime_ready(&mut model);

    let info_after = get_fw_info(&mut model);

    assert_eq!(info_after.pl0_pauser, info_before.pl0_pauser);
    assert_eq!(info_after.fw_svn, info_before.fw_svn);
    assert_eq!(info_after.min_fw_svn, info_before.min_fw_svn);
    assert_eq!(info_after.cold_boot_fw_svn, info_before.cold_boot_fw_svn);
    assert_eq!(
        info_after.attestation_disabled,
        info_before.attestation_disabled
    );

    assert_eq!(info_after.rom_revision, info_before.rom_revision);
    assert_eq!(info_after.fmc_revision, info_before.fmc_revision);
    assert_eq!(info_after.runtime_revision, info_before.runtime_revision);

    let rom_sha256_after = Sha256Bytes::to_sha256_bytes(&info_after.rom_sha256_digest);
    let fmc_sha384_after = Sha384Bytes::to_sha384_bytes(&info_after.fmc_sha384_digest);
    let rt_sha384_after = Sha384Bytes::to_sha384_bytes(&info_after.runtime_sha384_digest);

    assert_eq!(rom_sha256_after, rom_sha256_ref);
    assert_eq!(fmc_sha384_after, fmc_sha384_ref);
    assert_ne!(
        rt_sha384_after, [0u8; 48],
        "runtime digest after reset is zero"
    );
    assert_eq!(rt_sha384_after, rt_sha384_ref);
    assert_eq!(
        rt_sha384_after, rt_sha384_before,
        "runtime digest changed across warm reset"
    );

    // No recent FW error
    assert_eq!(info_after.most_recent_fw_error, 0x0);
}
