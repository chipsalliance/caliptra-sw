// Licensed under the Apache-2.0 license

use crate::common::{
    execute_dpe_cmd, run_rt_test, verify_sign_and_certify_key, CertifyKeyCommandNoRef,
    CreateCertifyKeyCmdArgs, CreateSignCmdArgs, DpeResult, RuntimeTestArgs, SignCommandNoRef,
    TEST_SD_MU, TEST_SD_SHA384,
};
use caliptra_api::SocManager;
use caliptra_dpe::commands::{CertifyKeyCommand, Command};
use caliptra_hw_model::HwModel;
use caliptra_runtime::{CaliptraDpeProfile, RtBootStatus};

fn test_certify_chunks_helper(profile: CaliptraDpeProfile, max_chunk_size: Option<usize>) {
    let mut model = run_rt_test(RuntimeTestArgs {
        subsystem_mode: true,
        ..Default::default()
    });

    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let data = match profile {
        CaliptraDpeProfile::Ecc384 => TEST_SD_SHA384,
        CaliptraDpeProfile::Mldsa87 => TEST_SD_MU,
    };

    let sign_cmd = SignCommandNoRef::new(CreateSignCmdArgs {
        profile,
        data: data.clone(),
        ..Default::default()
    });

    let sign_resp = execute_dpe_cmd(
        &mut model,
        profile,
        &mut Command::from(&sign_cmd),
        DpeResult::Success,
    )
    .unwrap();

    let mut certify_key_cmd = CertifyKeyCommandNoRef::new(CreateCertifyKeyCmdArgs {
        profile,
        format: CertifyKeyCommand::FORMAT_X509,
        ..Default::default()
    });

    let certify_key_resp =
        crate::common::certify_key_chunks(&mut model, &mut certify_key_cmd, max_chunk_size)
            .unwrap();

    verify_sign_and_certify_key(
        &mut model,
        profile,
        &sign_resp,
        &certify_key_resp,
        data.as_slice(),
    );
}

#[test]
fn test_certify_key_chunks_ecdsa_helper_subsystem() {
    test_certify_chunks_helper(CaliptraDpeProfile::Ecc384, None);
}

#[test]
fn test_certify_key_chunks_ecdsa_helper_subsystem_max_chunk_size() {
    test_certify_chunks_helper(CaliptraDpeProfile::Ecc384, Some(512));
}

#[test]
fn test_certify_key_chunks_mldsa_helper_subsystem_max_chunk_size() {
    test_certify_chunks_helper(CaliptraDpeProfile::Mldsa87, Some(512));
}
