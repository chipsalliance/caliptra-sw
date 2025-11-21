/*++

Licensed under the Apache-2.0 license.

File Name:

    build.rs

Abstract:

    File contains the entry point for build time script used for generating various X509 artifacts
    used by Caliptra Firmware.

--*/

#[cfg(feature = "generate_templates")]
mod cert;
#[cfg(feature = "generate_templates")]
mod code_gen;
#[cfg(feature = "generate_templates")]
mod csr;
#[cfg(feature = "generate_templates")]
mod tbs;
#[cfg(feature = "generate_templates")]
mod x509;

#[cfg(feature = "generate_templates")]
use {
    code_gen::CodeGen,
    std::env,
    x509::{EcdsaSha384Algo, Fwid, FwidParam, KeyUsage, MlDsa87Algo},
};

// Main Entry point
fn main() {
    #[cfg(feature = "generate_templates")]
    {
        let out_dir_os_str = env::var_os("OUT_DIR").unwrap();
        let out_dir = out_dir_os_str.to_str().unwrap();

        gen_init_devid_csr(out_dir);
        gen_fmc_alias_csr(out_dir);
        gen_local_devid_cert(out_dir);
        gen_fmc_alias_cert(out_dir);
        gen_rt_alias_cert(out_dir);
        gen_ocp_lock_endorsement_cert(out_dir);
    }
}

/// Generate Initial DeviceId Cert Signing request Template
#[cfg(feature = "generate_templates")]
fn gen_init_devid_csr(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);

    let bldr = csr::CsrTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17]);
    let template = bldr.tbs_template("Caliptra 2.0 Ecc384 IDevID");
    CodeGen::gen_code("InitDevIdCsrTbsEcc384", template, out_dir);

    let bldr = csr::CsrTemplateBuilder::<MlDsa87Algo>::new()
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17]);
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 IDevID");
    CodeGen::gen_code("InitDevIdCsrTbsMlDsa87", template, out_dir);
}

#[cfg(feature = "generate_templates")]
fn gen_fmc_alias_csr(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = csr::CsrTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_fmc_dice_tcb_info_ext(
            /*device_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xEF; 48],
                },
            }],
            /*fmc_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_FMC_TCI",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xCD; 48],
                },
            }],
        );
    let template = bldr.tbs_template("Caliptra 2.0 FMC Alias");
    CodeGen::gen_code("FmcAliasCsrTbs", template, out_dir);

    let bldr = csr::CsrTemplateBuilder::<MlDsa87Algo>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_fmc_dice_tcb_info_ext(
            /*device_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xEF; 48],
                },
            }],
            /*fmc_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_FMC_TCI",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xCD; 48],
                },
            }],
        );
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 FMC Alias");
    CodeGen::gen_code("FmcAliasTbsMlDsa87", template, out_dir);
}

/// Generate Local DeviceId Certificate Template
#[cfg(feature = "generate_templates")]
fn gen_local_devid_cert(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo, EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 4)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17]);
    let template = bldr.tbs_template("Caliptra 2.0 Ecc384 LDevID", "Caliptra 2.0 Ecc384 IDevID");
    CodeGen::gen_code("LocalDevIdCertTbsEcc384", template, out_dir);

    let bldr = cert::CertTemplateBuilder::<MlDsa87Algo, MlDsa87Algo>::new()
        .add_basic_constraints_ext(true, 4)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17]);
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 LDevID", "Caliptra 2.0 MlDsa87 IDevID");
    CodeGen::gen_code("LocalDevIdCertTbsMlDsa87", template, out_dir);
}

/// Generate FMC Alias Certificate Template
#[cfg(feature = "generate_templates")]
fn gen_fmc_alias_cert(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo, EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_fmc_dice_tcb_info_ext(
            /*device_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xEF; 48],
                },
            }],
            /*fmc_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_FMC_TCI",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xCD; 48],
                },
            }],
        );
    let template = bldr.tbs_template(
        "Caliptra 2.0 Ecc384 FMC Alias",
        "Caliptra 2.0 Ecc384 LDevID",
    );
    CodeGen::gen_code("FmcAliasCertTbsEcc384", template, out_dir);

    let bldr = cert::CertTemplateBuilder::<MlDsa87Algo, MlDsa87Algo>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_fmc_dice_tcb_info_ext(
            /*device_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xEF; 48],
                },
            }],
            /*fmc_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_FMC_TCI",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xCD; 48],
                },
            }],
        );
    let template = bldr.tbs_template(
        "Caliptra 2.0 MlDsa87 FMC Alias",
        "Caliptra 2.0 MlDsa87 LDevID",
    );
    CodeGen::gen_code("FmcAliasCertTbsMlDsa87", template, out_dir);
}

/// Generate Runtime Alias Certificate Template
#[cfg(feature = "generate_templates")]
fn gen_rt_alias_cert(out_dir: &str) {
    let mut usage = KeyUsage::default();
    // Add KeyCertSign to allow signing of other certs
    usage.set_key_cert_sign(true);
    // Add DigitalSignature to allow signing of firmware
    usage.set_digital_signature(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo, EcdsaSha384Algo>::new()
        // Basic Constraints : CA = true, PathLen = 2
        .add_basic_constraints_ext(true, 2)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_rt_dice_tcb_info_ext(&[FwidParam {
            name: "TCB_INFO_RT_TCI",
            fwid: Fwid {
                hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                digest: &[0xCD; 48],
            },
        }]);
    let template = bldr.tbs_template(
        "Caliptra 2.0 Ecc384 Rt Alias",
        "Caliptra 2.0 Ecc384 FMC Alias",
    );
    CodeGen::gen_code("RtAliasCertTbsEcc384", template, out_dir);

    let bldr = cert::CertTemplateBuilder::<MlDsa87Algo, MlDsa87Algo>::new()
        // Basic Constraints : CA = true, PathLen = 2
        .add_basic_constraints_ext(true, 2)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_rt_dice_tcb_info_ext(&[FwidParam {
            name: "TCB_INFO_RT_TCI",
            fwid: Fwid {
                hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                digest: &[0xCD; 48],
            },
        }]);
    let template = bldr.tbs_template(
        "Caliptra 2.0 MlDsa87 Rt Alias",
        "Caliptra 2.0 MlDsa87 FMC Alias",
    );
    CodeGen::gen_code("RtAliasCertTbsMlDsa87", template, out_dir);
}

/// Generate OCP LOCK HPKE Endorsement Certificate Templates
#[cfg(feature = "generate_templates")]
fn gen_ocp_lock_endorsement_cert(out_dir: &str) {
    use x509::{HPKEIdentifiers, MlKem1024Algo};
    let mut usage = KeyUsage::default();
    // 4.2.2.1.3
    // In addition, the X.509 extended attributes SHALL:
    // * Indicate the key usage as keyEncipherment
    usage.set_key_encipherment(true);

    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo, MlKem1024Algo>::new()
        .add_basic_constraints_ext(false, 0)
        .add_key_usage_ext(usage)
        .add_hpke_identifiers_ext(&HPKEIdentifiers::new(
            HPKEIdentifiers::ML_KEM_1024_IANA_CODE_POINT,
            HPKEIdentifiers::HKDF_SHA384_IANA_CODE_POINT,
            HPKEIdentifiers::AES_256_GCM_IANA_CODE_POINT,
        ));
    let template = bldr.tbs_template(
        "OCP LOCK HPKE Endorsement ML-KEM 1024",
        "Caliptra 2.0 Ecc384 Rt Alias",
    );
    CodeGen::gen_code("OcpLockMlKemCertTbsEcc384", template, out_dir);

    let bldr = cert::CertTemplateBuilder::<MlDsa87Algo, MlKem1024Algo>::new()
        .add_basic_constraints_ext(false, 0)
        .add_key_usage_ext(usage)
        .add_hpke_identifiers_ext(&HPKEIdentifiers::new(
            HPKEIdentifiers::ML_KEM_1024_IANA_CODE_POINT,
            HPKEIdentifiers::HKDF_SHA384_IANA_CODE_POINT,
            HPKEIdentifiers::AES_256_GCM_IANA_CODE_POINT,
        ));
    let template = bldr.tbs_template(
        "OCP LOCK HPKE Endorsement ML-KEM 1024",
        "Caliptra 2.0 MlDsa87 Rt Alias",
    );
    CodeGen::gen_code("OcpLockMlKemCertTbsMlDsa87", template, out_dir);

    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo, EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(false, 0)
        .add_key_usage_ext(usage)
        .add_hpke_identifiers_ext(&HPKEIdentifiers::new(
            HPKEIdentifiers::ECDH_P384_IANA_CODE_POINT,
            HPKEIdentifiers::HKDF_SHA384_IANA_CODE_POINT,
            HPKEIdentifiers::AES_256_GCM_IANA_CODE_POINT,
        ));
    let template = bldr.tbs_template(
        "OCP LOCK HPKE Endorsement ECDH P-384",
        "Caliptra 2.0 Ecc384 Rt Alias",
    );
    CodeGen::gen_code("OcpLockEcdh384CertTbsEcc384", template, out_dir);

    let bldr = cert::CertTemplateBuilder::<MlDsa87Algo, EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(false, 0)
        .add_key_usage_ext(usage)
        .add_hpke_identifiers_ext(&HPKEIdentifiers::new(
            HPKEIdentifiers::ECDH_P384_IANA_CODE_POINT,
            HPKEIdentifiers::HKDF_SHA384_IANA_CODE_POINT,
            HPKEIdentifiers::AES_256_GCM_IANA_CODE_POINT,
        ));
    let template = bldr.tbs_template(
        "OCP LOCK HPKE Endorsement ECDH P-384",
        "Caliptra 2.0 MlDsa87 Rt Alias",
    );
    CodeGen::gen_code("OcpLockEcdh384CertTbsMlDsa87", template, out_dir);
}
