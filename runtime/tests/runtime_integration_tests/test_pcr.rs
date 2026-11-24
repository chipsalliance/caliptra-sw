// Licensed under the Apache-2.0 license

use crate::common::{
    get_ecc_fmc_alias_cert, get_mldsa_fmc_alias_cert, run_rt_test, RuntimeTestArgs,
};
use caliptra_api::SocManager;
use caliptra_builder::firmware::runtime_tests;

use caliptra_common::mailbox_api::{
    CommandId, ExtendPcrReq, GetPcrLogResp, IncrementPcrResetCounterReq, MailboxReq,
    MailboxReqHeader, QuotePcrsEcc384Req, QuotePcrsEcc384Resp, QuotePcrsMldsa87Req,
    QuotePcrsMldsa87Resp,
};
use caliptra_common::x509::{PCR_SIGNING_KEY_BINDING_FLAGS, PCR_SIGNING_KEY_BINDING_VERSION};
use caliptra_drivers::{PcrId, PcrLogArray};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, DeviceLifecycle, HwModel, ModelError, SecurityState};
use caliptra_test::x509::get_cert_extension;
use ml_dsa::signature::Verifier;
use ml_dsa::{MlDsa87, Signature, VerifyingKey};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::{Hasher, MessageDigest},
    nid::Nid,
    sha::Sha384,
    x509::X509,
};
use spki::DecodePublicKey;
use x509_cert::certificate::Certificate;
use x509_cert::der::{Decode, Encode};
use zerocopy::{FromBytes, IntoBytes};

fn extend_pcr(current: &[u8; 48], data: &[u8; 48]) -> [u8; 48] {
    let mut h = Hasher::new(MessageDigest::sha384()).unwrap();
    let _ = h.update(current);
    let _ = h.update(data);
    let res = h.finish().unwrap();
    res.as_bytes().try_into().unwrap()
}

const PCR_SIGNING_ECC384_DOMAIN: &[u8] = b"CALIPTRA_PCR_SIGNING_PUBLIC_KEY_ECC384";
const PCR_SIGNING_MLDSA87_DOMAIN: &[u8] = b"CALIPTRA_PCR_SIGNING_PUBLIC_KEY_MLDSA87";
const PCR_SIGNING_ECC384_PUB_KEY_DIGEST_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 42623, 2, 1);
const PCR_SIGNING_MLDSA87_PUB_KEY_DIGEST_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 42623, 2, 2);
const OPCODE_READ_PCR_SIGNING_KEY_LOCKS: u32 = 0xF200_0000;

// Recompute the published binding independently of firmware helpers to detect encoding drift.
fn pcr_signing_key_digest(
    domain: &[u8],
    version: u32,
    flags: u32,
    key_parts: &[&[u8]],
) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(domain);
    hasher.update(&version.to_be_bytes());
    hasher.update(&flags.to_be_bytes());
    for part in key_parts {
        hasher.update(part);
    }
    hasher.finish()
}

fn cert_pcr_signing_key_digest(cert_der: &[u8], oid: &asn1::ObjectIdentifier) -> [u8; 48] {
    let extension = get_cert_extension(cert_der, oid).unwrap().unwrap();
    // Unwrap the DER OCTET STRING inside extnValue before comparing the binding digest.
    asn1::parse_single::<&[u8]>(extension)
        .unwrap()
        .try_into()
        .unwrap()
}

fn get_pcr_signing_ecc384_pub_key(model: &mut DefaultHwModel) -> ([u8; 48], [u8; 48]) {
    let mut cmd = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0u8; 32],
    });
    cmd.populate_chksum().unwrap();
    let response = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_ECC384),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let response = QuotePcrsEcc384Resp::read_from_bytes(&response).unwrap();
    (response.pub_key_x, response.pub_key_y)
}

fn get_pcr_signing_mldsa87_pub_key(model: &mut DefaultHwModel) -> [u8; 2592] {
    let mut cmd = MailboxReq::QuotePcrsMldsa87(QuotePcrsMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0u8; 32],
    });
    cmd.populate_chksum().unwrap();
    let response = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_MLDSA87),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    QuotePcrsMldsa87Resp::read_from_bytes(&response)
        .unwrap()
        .pub_key
}

#[test]
fn test_pcr_signing_keys_are_write_and_use_locked() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);
    let test_fwid = if cfg!(feature = "fpga_subsystem") {
        &runtime_tests::MBOX_FPGA
    } else {
        &runtime_tests::MBOX
    };
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(test_fwid),
        security_state: Some(security_state),
        ..Default::default()
    });

    let assert_pcr_signing_keys_locked = |model: &mut DefaultHwModel| {
        let response = model
            .mailbox_execute(OPCODE_READ_PCR_SIGNING_KEY_LOCKS, &[])
            .unwrap()
            .unwrap();
        // Bits 0..3 represent KV7 write/use and KV8 write/use locks, respectively.
        assert_eq!(
            u32::from_le_bytes(response.as_slice().try_into().unwrap()),
            0b1111
        );
    };

    assert_pcr_signing_keys_locked(&mut model);

    // Reset releases locks; ROM must restore all four before Runtime starts again.
    model.warm_reset_flow().unwrap();
    model.step_until(|model| {
        model
            .soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_runtime()
    });
    assert_pcr_signing_keys_locked(&mut model);
}

#[test]
fn test_pcr_quote_ecc() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    const RESET_PCR: u32 = 7;

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    let mut cmd = MailboxReq::IncrementPcrResetCounter(IncrementPcrResetCounterReq {
        hdr: MailboxReqHeader { chksum: 0 },
        index: RESET_PCR,
    });
    cmd.populate_chksum().unwrap();

    let _ = model
        .mailbox_execute(
            u32::from(CommandId::INCREMENT_PCR_RESET_COUNTER),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let mut cmd = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0xf5; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_ECC384),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let resp = QuotePcrsEcc384Resp::read_from_bytes(resp.as_slice()).unwrap();

    // Compute the digest and compare to mailbox result
    let mut h = Hasher::new(MessageDigest::sha512()).unwrap();
    resp.pcrs.iter().for_each(|x| h.update(x).unwrap());
    h.update(&resp.nonce).unwrap();
    let res = h.finish().unwrap();
    let digest: [u8; 64] = res.as_bytes().try_into().unwrap();
    assert_eq!(resp.digest, &digest[..48]);

    let pcr7_reset_counter: u32 = resp.reset_ctrs[usize::try_from(RESET_PCR).unwrap()];
    // See if incrementing the reset counter worked
    assert_eq!(pcr7_reset_counter, 1);

    // Verify the certificate binding and quote signature with the dedicated key.
    let big_r = BigNum::from_slice(&resp.signature_r).unwrap();
    let big_s = BigNum::from_slice(&resp.signature_s).unwrap();
    let sig = EcdsaSig::from_private_components(big_r, big_s).unwrap();

    let fmc_resp = get_ecc_fmc_alias_cert(&mut model);
    let fmc_cert_der = &fmc_resp.data[..fmc_resp.data_size as usize];
    let fmc_cert: X509 = X509::from_der(fmc_cert_der).unwrap();
    let fmc_key = fmc_cert.public_key().unwrap().ec_key().unwrap();
    // Prove that the quote is no longer signed with the FMC Alias private key.
    assert!(!sig.verify(&resp.digest, &fmc_key).unwrap());

    // Authenticate the returned key through the signed digest before verifying the quote.
    assert_eq!(
        cert_pcr_signing_key_digest(fmc_cert_der, &PCR_SIGNING_ECC384_PUB_KEY_DIGEST_OID),
        pcr_signing_key_digest(
            PCR_SIGNING_ECC384_DOMAIN,
            PCR_SIGNING_KEY_BINDING_VERSION,
            PCR_SIGNING_KEY_BINDING_FLAGS,
            &[&resp.pub_key_x, &resp.pub_key_y],
        )
    );

    let pcr_signing_key = EcKey::from_public_key_affine_coordinates(
        &EcGroup::from_curve_name(Nid::SECP384R1).unwrap(),
        &BigNum::from_slice(&resp.pub_key_x).unwrap(),
        &BigNum::from_slice(&resp.pub_key_y).unwrap(),
    )
    .unwrap();
    assert!(sig.verify(&resp.digest, &pcr_signing_key).unwrap());
}

#[test]
fn test_pcr_quote_mldsa() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    const RESET_PCR: u32 = 7;

    model.step_until(|m| m.soc_mbox().status().read().mbox_fsm_ps().mbox_idle());

    let mut cmd = MailboxReq::IncrementPcrResetCounter(IncrementPcrResetCounterReq {
        hdr: MailboxReqHeader { chksum: 0 },
        index: RESET_PCR,
    });
    cmd.populate_chksum().unwrap();

    let _ = model
        .mailbox_execute(
            u32::from(CommandId::INCREMENT_PCR_RESET_COUNTER),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let mut cmd = MailboxReq::QuotePcrsMldsa87(QuotePcrsMldsa87Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0xf5; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_MLDSA87),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    let resp = QuotePcrsMldsa87Resp::read_from_bytes(resp.as_slice()).unwrap();

    // Compute the digest and compare to mailbox result
    let mut h = Hasher::new(MessageDigest::sha512()).unwrap();
    resp.pcrs.iter().for_each(|x| h.update(x).unwrap());
    h.update(&resp.nonce).unwrap();
    let res = h.finish().unwrap();
    let mut digest: [u8; 64] = res.as_bytes().try_into().unwrap();

    // Reverse the sequence of bytes in the digest.
    // This is the byte order Caliptra hardware uses for MLDSA signing the PCR digest.
    digest.reverse();
    assert_eq!(resp.digest, digest);

    let pcr7_reset_counter: u32 = resp.reset_ctrs[usize::try_from(RESET_PCR).unwrap()];
    // See if incrementing the reset counter worked
    assert_eq!(pcr7_reset_counter, 1);

    // Verify the certificate binding and quote signature with the dedicated key.
    let fmc_resp = get_mldsa_fmc_alias_cert(&mut model);
    let fmc_cert_der = &fmc_resp.data[..fmc_resp.data_size as usize];
    let cert = Certificate::from_der(fmc_cert_der).unwrap();
    let pk_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();
    let fmc_key = VerifyingKey::<MlDsa87>::from_public_key_der(&pk_bytes).unwrap();
    let signature_bytes: [u8; 4627] = resp.signature[..4627].try_into().unwrap();
    let signature = Signature::<MlDsa87>::decode((&signature_bytes).into()).unwrap();
    // The independent PCR key must not verify as the FMC Alias signing identity.
    assert!(fmc_key.verify(&resp.digest, &signature).is_err());

    // Authenticate the hardware-generated public key before checking its quote signature.
    assert_eq!(
        cert_pcr_signing_key_digest(fmc_cert_der, &PCR_SIGNING_MLDSA87_PUB_KEY_DIGEST_OID),
        pcr_signing_key_digest(
            PCR_SIGNING_MLDSA87_DOMAIN,
            PCR_SIGNING_KEY_BINDING_VERSION,
            PCR_SIGNING_KEY_BINDING_FLAGS,
            &[&resp.pub_key],
        )
    );

    let pcr_signing_key =
        VerifyingKey::<MlDsa87>::decode(resp.pub_key.as_slice().try_into().unwrap());
    pcr_signing_key.verify(&resp.digest, &signature).unwrap();
}

#[test]
fn test_pcr_signing_keys_persist_across_warm_reset() {
    let security_state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(DeviceLifecycle::Production);
    let mut model = run_rt_test(RuntimeTestArgs {
        security_state: Some(security_state),
        ..Default::default()
    });

    while !model.boot_complete() {
        model.step();
    }

    let ecc_before = get_pcr_signing_ecc384_pub_key(&mut model);
    let mldsa_before = get_pcr_signing_mldsa87_pub_key(&mut model);

    // Protected warm reset must preserve both certified PCR identities, not replace them.
    model.warm_reset_flow().unwrap();
    model.step_until(|model| {
        model
            .soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_runtime()
    });

    assert_eq!(get_pcr_signing_ecc384_pub_key(&mut model), ecc_before);
    assert_eq!(get_pcr_signing_mldsa87_pub_key(&mut model), mldsa_before);
}

// Exact key snapshots and CPU-bus fault injection are available only on the emulator.
#[cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]
mod fmc_key_lifecycle {
    use super::*;
    use crate::common::run_rt_test_return_fw;
    use crate::test_update_reset::update_fw;
    use caliptra_builder::{firmware::APP_WITH_UART, ImageOptions};
    use caliptra_common::RomBootStatus;
    use caliptra_drivers::{
        memory_layout::{BOOT_STATUS_ORG, DCCM_ORG, PERSISTENT_DATA_ORG},
        DataVault, PersistentData, RomPersistentData,
    };
    use caliptra_registers::kv::{regs::KvctrlWriteVal, KvReg};
    use std::mem::{offset_of, size_of};

    const KEY_SIZE: usize = 64;
    const FMC_RT_ALIAS_CERT_SIG_GENERATED: u32 = 0x405;

    // Debug-locked firmware reports boot status only in DCCM.
    fn boot_status(model: &DefaultHwModel) -> u32 {
        u32::from_le_bytes(
            model
                .dccm_read(BOOT_STATUS_ORG - DCCM_ORG, size_of::<u32>())
                .try_into()
                .unwrap(),
        )
    }

    fn start_at_boot_status(status: u32) -> DefaultHwModel {
        let security_state = *SecurityState::default()
            .set_debug_locked(true)
            .set_device_lifecycle(DeviceLifecycle::Production);
        let (mut model, image) = run_rt_test_return_fw(RuntimeTestArgs {
            test_image_options: Some(ImageOptions::default()),
            security_state: Some(security_state),
            stop_at_rom: true,
            successful_reach_rt: false,
            ..Default::default()
        });
        model
            .start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), &image.to_bytes().unwrap())
            .unwrap();
        // Finish the download handshake before stopping at the desired ROM/FMC boundary.
        let _ = model.finish_mailbox_execute().unwrap();
        model.step_until_or_timeout("FMC key lifecycle injection point", 30_000_000, |model| {
            assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
            boot_status(model) == status
        });
        model
    }

    fn write_key_control(model: &mut DefaultHwModel, slot: usize, value: KvctrlWriteVal) {
        let addr = u32::try_from(KvReg::PTR.addr()).unwrap()
            + u32::try_from(slot * size_of::<u32>()).unwrap();
        model.write_cpu_bus_word(addr, value.into()).unwrap();
    }

    fn assert_fmc_keys_erased(model: &DefaultHwModel) {
        let snapshot = model.key_vault_snapshot();
        // Inspect actual vault bytes; locking a slot or clearing a software handle is insufficient.
        for slot in [13, 14] {
            assert!(
                snapshot.keys[slot * KEY_SIZE..(slot + 1) * KEY_SIZE]
                    .iter()
                    .all(|byte| *byte == 0),
                "FMC Alias key slot {slot} was not erased"
            );
        }
    }

    // Snapshot FMC CDI and both PCR keys so reset tests detect any replacement of their contents.
    fn retained_keys(model: &DefaultHwModel) -> [Vec<u8>; 3] {
        let snapshot = model.key_vault_snapshot();
        [6, 7, 8].map(|slot| snapshot.keys[slot * KEY_SIZE..(slot + 1) * KEY_SIZE].to_vec())
    }

    fn assert_rt_key_state(model: &DefaultHwModel, expected: &[Vec<u8>; 3]) {
        assert_fmc_keys_erased(model);
        assert!(retained_keys(model) == *expected);
        let control = model.key_vault_snapshot().key_control;
        // Retained FMC CDI is use-locked; the PCR slots must retain both write and use locks.
        assert_ne!(control[6] & 0b10, 0);
        assert_eq!(control[7] & 0b11, 0b11);
        assert_eq!(control[8] & 0b11, 0b11);
    }

    fn pcr_key_bindings_match(model: &mut DefaultHwModel) -> [bool; 2] {
        let (x, y) = get_pcr_signing_ecc384_pub_key(model);
        let mldsa = get_pcr_signing_mldsa87_pub_key(model);
        let ecc_cert = get_ecc_fmc_alias_cert(model);
        let mldsa_cert = get_mldsa_fmc_alias_cert(model);
        [
            cert_pcr_signing_key_digest(
                &ecc_cert.data[..ecc_cert.data_size as usize],
                &PCR_SIGNING_ECC384_PUB_KEY_DIGEST_OID,
            ) == pcr_signing_key_digest(
                PCR_SIGNING_ECC384_DOMAIN,
                PCR_SIGNING_KEY_BINDING_VERSION,
                PCR_SIGNING_KEY_BINDING_FLAGS,
                &[&x, &y],
            ),
            cert_pcr_signing_key_digest(
                &mldsa_cert.data[..mldsa_cert.data_size as usize],
                &PCR_SIGNING_MLDSA87_PUB_KEY_DIGEST_OID,
            ) == pcr_signing_key_digest(
                PCR_SIGNING_MLDSA87_DOMAIN,
                PCR_SIGNING_KEY_BINDING_VERSION,
                PCR_SIGNING_KEY_BINDING_FLAGS,
                &[&mldsa],
            ),
        ]
    }

    fn wait_for_runtime(model: &mut DefaultHwModel) {
        // Flow status may still reflect the old image during update; also require the new RT status.
        model.step_until_or_timeout("runtime after FMC key recovery", 50_000_000, |model| {
            boot_status(model) == u32::from(caliptra_runtime::RtBootStatus::RtReadyForCommands)
                && model
                    .soc_ifc()
                    .cptra_flow_status()
                    .read()
                    .ready_for_runtime()
        });
    }

    fn assert_handoff_blocked(model: &mut DefaultHwModel, error: CaliptraError) {
        model.step_until_fatal_error(error.into(), 20_000_000);
        assert!(!model
            .soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_runtime());
    }

    #[test]
    fn test_fmc_key_erasure_and_recovery_across_resets() {
        // ROM hands off no FMC Alias secrets, but retains the CDI and certified PCR keys.
        let mut model = start_at_boot_status(RomBootStatus::FmcAliasDerivationComplete.into());
        assert_fmc_keys_erased(&model);
        let retained = retained_keys(&model);
        assert!(retained.iter().all(|key| key.iter().any(|byte| *byte != 0)));
        assert_eq!(model.key_vault_snapshot().key_control[6] & 0b10, 0);

        wait_for_runtime(&mut model);
        assert_rt_key_state(&model, &retained);
        let ecc_pub_key = get_pcr_signing_ecc384_pub_key(&mut model);
        let mldsa_pub_key = get_pcr_signing_mldsa87_pub_key(&mut model);

        // Repeat recovery to ensure it never depends on a surviving FMC Alias private key.
        for _ in 0..2 {
            while !model.boot_complete() {
                model.step();
            }
            model.warm_reset_flow().unwrap();
            wait_for_runtime(&mut model);
            assert_rt_key_state(&model, &retained);
        }

        // A changed RT measurement rotates Alias RT, while FMC CDI and the PCR keys stay fixed.
        let rt_key_before = model.key_vault_snapshot().keys[5 * KEY_SIZE..6 * KEY_SIZE].to_vec();
        update_fw(&mut model, &APP_WITH_UART, ImageOptions::default());
        wait_for_runtime(&mut model);
        assert_rt_key_state(&model, &retained);
        assert!(model.key_vault_snapshot().keys[5 * KEY_SIZE..6 * KEY_SIZE] != rt_key_before);
        assert_eq!(get_pcr_signing_ecc384_pub_key(&mut model), ecc_pub_key);
        assert_eq!(get_pcr_signing_mldsa87_pub_key(&mut model), mldsa_pub_key);
    }

    #[test]
    fn test_pcr_key_locks_after_debug_unlocked_update_reset() {
        let security_state = *SecurityState::default()
            .set_debug_locked(false)
            .set_device_lifecycle(DeviceLifecycle::Production);
        let mut model = run_rt_test(RuntimeTestArgs {
            security_state: Some(security_state),
            test_image_options: Some(ImageOptions::default()),
            ..Default::default()
        });
        let retained = retained_keys(&model);
        assert_rt_key_state(&model, &retained);
        assert_eq!(pcr_key_bindings_match(&mut model), [true, true]);

        // Update reset must restore both locks without changing either certified PCR identity.
        update_fw(&mut model, &APP_WITH_UART, ImageOptions::default());
        wait_for_runtime(&mut model);
        assert_rt_key_state(&model, &retained);
        assert_eq!(pcr_key_bindings_match(&mut model), [true, true]);
    }

    #[test]
    fn test_erased_fmc_cdi_blocks_handoff() {
        let mut model = start_at_boot_status(RomBootStatus::FmcAliasDerivationComplete.into());
        // Without retained CDI, FMC cannot recover its certified signing authority.
        write_key_control(&mut model, 6, KvctrlWriteVal::from(0).clear(true));
        assert_handoff_blocked(
            &mut model,
            CaliptraError::FMC_REGENERATE_FMC_ECC_KEY_PAIR_FAILED,
        );
    }

    #[test]
    fn test_fmc_public_key_mismatch_blocks_handoff() {
        for mldsa in [false, true] {
            let mut model = start_at_boot_status(RomBootStatus::FmcAliasDerivationComplete.into());
            let addr = PERSISTENT_DATA_ORG
                + u32::try_from(
                    offset_of!(PersistentData, rom) + offset_of!(RomPersistentData, data_vault),
                )
                .unwrap();
            let original = model.dccm_read(addr - DCCM_ORG, size_of::<DataVault>());
            let mut data_vault = DataVault::read_from_bytes(&original).unwrap();
            // Corrupt the certified comparison value, not the CDI, to isolate the mismatch checks.
            let error = if mldsa {
                let mut pub_key = data_vault.fmc_mldsa_pub_key();
                pub_key.0[0] ^= 1;
                data_vault.set_fmc_mldsa_pub_key(&pub_key);
                CaliptraError::FMC_REGENERATE_FMC_MLDSA_PUB_KEY_MISMATCH
            } else {
                let mut pub_key = data_vault.fmc_ecc_pub_key();
                pub_key.x.0[0] ^= 1;
                data_vault.set_fmc_ecc_pub_key(&pub_key);
                CaliptraError::FMC_REGENERATE_FMC_ECC_PUB_KEY_MISMATCH
            };
            // Change only the affected word, preserving every other retained boot-state field.
            for (index, (before, after)) in original
                .chunks_exact(4)
                .zip(data_vault.as_bytes().chunks_exact(4))
                .enumerate()
            {
                if before != after {
                    model
                        .write_cpu_bus_word(
                            addr + u32::try_from(index * 4).unwrap(),
                            u32::from_le_bytes(after.try_into().unwrap()),
                        )
                        .unwrap();
                }
            }
            assert_handoff_blocked(&mut model, error);
        }
    }

    #[test]
    fn test_fmc_alias_erase_failure_blocks_handoff() {
        // Inject after signing but before erasure at each of the ROM/FMC and FMC/RT boundaries.
        for status in [
            RomBootStatus::FmcAliasCertSigGenerationComplete.into(),
            FMC_RT_ALIAS_CERT_SIG_GENERATED,
        ] {
            for slot in [13, 14] {
                let mut model = start_at_boot_status(status);
                // A use-lock forces erase_key to fail; neither partial erasure may permit RT entry.
                write_key_control(&mut model, slot, KvctrlWriteVal::from(0).lock_use(true));
                assert_handoff_blocked(
                    &mut model,
                    CaliptraError::DRIVER_KV_ERASE_USE_LOCK_SET_FAILURE,
                );
            }
        }
    }
}

fn generate_mailbox_extend_pcr_req(idx: u32, pcr_extension_data: [u8; 48]) -> MailboxReq {
    let mut cmd = MailboxReq::ExtendPcr(ExtendPcrReq {
        hdr: MailboxReqHeader { chksum: 0 },
        pcr_idx: idx,
        data: pcr_extension_data,
    });
    cmd.populate_chksum().unwrap();

    cmd
}

pub fn get_model_pcrs(model: &mut DefaultHwModel) -> [[u8; 48]; 32] {
    let mut cmd = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0u8; 32],
    });
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(
            u32::from(CommandId::QUOTE_PCRS_ECC384),
            cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();

    QuotePcrsEcc384Resp::read_from_bytes(resp.as_slice())
        .unwrap()
        .pcrs
}

#[test]
fn test_extend_pcr_cmd_multiple_extensions() {
    // 0. Get fresh pcr state and verify
    let mut model = run_rt_test(RuntimeTestArgs::default());
    assert_eq!(get_model_pcrs(&mut model)[6], [0u8; 48]);

    // 1.0 Testing for extension_data [0,...,0]
    let extension_data = [0u8; 48];

    let cmd = generate_mailbox_extend_pcr_req(6, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());
    assert!(res.is_ok());

    // 1.1 Checking for PCR values using PCR_QUOTE
    let pcrs = get_model_pcrs(&mut model);
    let pcr = extend_pcr(&[0; 48], &extension_data);
    assert_eq!(pcrs[6], pcr);

    // 1.2 Extending PCR[6] with another [0,..,0] payload
    let cmd = generate_mailbox_extend_pcr_req(6, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());

    assert!(res.is_ok());

    // 1.3 Checking for PCR values using PCR_QUOTE
    let pcr = extend_pcr(&pcr, &extension_data);
    let pcrs = get_model_pcrs(&mut model);
    assert_eq!(pcrs[6], pcr);

    // 2.0 Testing for extension data with high entropy
    let extension_data: [u8; 48] = [
        225, 73, 188, 244, 110, 120, 121, 204, 185, 203, 86, 129, 104, 186, 33, 110, 125, 116, 216,
        80, 244, 199, 184, 21, 127, 187, 78, 122, 18, 26, 32, 48, 171, 251, 17, 20, 67, 224, 15,
        81, 144, 232, 190, 103, 213, 7, 199, 148,
    ];

    let cmd = generate_mailbox_extend_pcr_req(6, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());
    assert!(res.is_ok());

    // 2.1 Checking for PCR values using PCR_QUOTE
    let pcr = extend_pcr(&pcr, &extension_data);
    let pcrs = get_model_pcrs(&mut model);
    assert_eq!(pcrs[6], pcr);
}

#[test]
fn test_extend_pcr_cmd_invalid_pcr_index() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    let extension_data: [u8; 48] = [0u8; 48];

    // 3. Invalid PCR index
    let cmd = generate_mailbox_extend_pcr_req(33, extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());
    assert_eq!(
        res,
        Err(ModelError::MailboxCmdFailed(u32::from(
            CaliptraError::RUNTIME_PCR_INVALID_INDEX
        )))
    );
}

#[test]
fn test_extend_pcr_cmd_reserved_range() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    let extension_data: [u8; 48] = [0u8; 48];

    // 4. Ensure reserved PCR range
    let reserved_pcrs = [
        PcrId::PcrId0,
        PcrId::PcrId1,
        PcrId::PcrId2,
        PcrId::PcrId3,
        PcrId::PcrId4,
        PcrId::PcrId5,
    ];
    for test_pcr_index_reserved in reserved_pcrs {
        let cmd = generate_mailbox_extend_pcr_req(test_pcr_index_reserved.into(), extension_data);

        let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());
        assert_eq!(
            res,
            Err(ModelError::MailboxCmdFailed(u32::from(
                CaliptraError::RUNTIME_PCR_RESERVED
            )))
        );
    }
}

#[test]
fn test_extend_pcr31_from_pl0_for_mcu_soc_measurements() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    let extension_data = [0xa5; 48];
    let current_pcr = get_model_pcrs(&mut model)[PcrId::PcrId31 as usize];

    // The MCU uses its PL0 locality to extend SoC firmware measurements into PCR31.
    let cmd = generate_mailbox_extend_pcr_req(PcrId::PcrId31.into(), extension_data);
    let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());

    assert!(res.is_ok());
    assert_eq!(
        get_model_pcrs(&mut model)[PcrId::PcrId31 as usize],
        extend_pcr(&current_pcr, &extension_data)
    );
}

#[test]
fn test_extend_pcr_cmd_restricted_to_pl0() {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.set_axi_user(2);

    for pcr in [PcrId::PcrId4, PcrId::PcrId31] {
        let cmd = generate_mailbox_extend_pcr_req(pcr.into(), [0xa5; 48]);
        let res = model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap());

        assert_eq!(
            res,
            Err(ModelError::MailboxCmdFailed(u32::from(
                CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL
            )))
        );
    }
}

#[test]
fn test_extend_pcr_cmd_rejected_without_pl0_pauser() {
    let mut image_opts = caliptra_builder::ImageOptions::default();
    image_opts.vendor_config.pl0_pauser = None;

    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        test_image_options: Some(image_opts),
        ..Default::default()
    });
    let cmd = generate_mailbox_extend_pcr_req(PcrId::PcrId31.into(), [0xa5; 48]);

    assert_eq!(
        model.mailbox_execute(u32::from(CommandId::EXTEND_PCR), cmd.as_bytes().unwrap()),
        Err(ModelError::MailboxCmdFailed(u32::from(
            CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL
        )))
    );
}

#[test]
fn test_get_pcr_log() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let mut cmd = MailboxReq::GetPcrLog(MailboxReqHeader::default());
    cmd.populate_chksum().unwrap();

    let resp = model
        .mailbox_execute(u32::from(CommandId::GET_PCR_LOG), cmd.as_bytes().unwrap())
        .unwrap()
        .unwrap();

    let resp = GetPcrLogResp::read_from_bytes(resp.as_slice()).unwrap();
    let log = PcrLogArray::read_from_bytes(&resp.data[..resp.data_size as usize]);
    assert!(log.is_ok());
}
