/*++

Licensed under the Apache-2.0 license.

File Name:

    main.rs

Abstract:

    Binary that generates X509 TBS templates used by Caliptra firmware.
    Outputs directly to x509/build/ and x509/src/.

    Usage: cargo run -p caliptra-x509-gen

--*/

mod cert;
mod code_gen;
mod csr;
mod tbs;
mod x509;
mod x509_cert;

#[allow(dead_code)]
#[path = "../../../builder/src/version.rs"]
mod version;

use code_gen::CodeGen;
use x509::{EcdsaSha384Algo, Fwid, FwidParam, KeyUsage, MlDsa87Algo};

/// Build certificate CN strings from the canonical version constants.
fn cert_cn_strings() -> CertCnStrings {
    let rom_ver = version::rom_version_string();
    let fmc_ver = version::fmc_version_string();
    let rt_ver = version::runtime_version_string();
    CertCnStrings {
        idevid_ecc384: format!("Caliptra ROM {rom_ver} Ecc384 IDevID"),
        idevid_mldsa87: format!("Caliptra ROM {rom_ver} MlDsa87 IDevID"),
        ldevid_ecc384: format!("Caliptra ROM {rom_ver} Ecc384 LDevID"),
        ldevid_mldsa87: format!("Caliptra ROM {rom_ver} MlDsa87 LDevID"),
        fmc_alias_ecc384: format!("Caliptra FW {fmc_ver} Ecc384 FMC Alias"),
        fmc_alias_mldsa87: format!("Caliptra FW {fmc_ver} MlDsa87 FMC Alias"),
        rt_alias_ecc384: format!("Caliptra FW {rt_ver} Ecc384 Rt Alias"),
        rt_alias_mldsa87: format!("Caliptra FW {rt_ver} MlDsa87 Rt Alias"),
    }
}

struct CertCnStrings {
    idevid_ecc384: String,
    idevid_mldsa87: String,
    ldevid_ecc384: String,
    ldevid_mldsa87: String,
    fmc_alias_ecc384: String,
    fmc_alias_mldsa87: String,
    rt_alias_ecc384: String,
    rt_alias_mldsa87: String,
}

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set; run via cargo");
    let x509_dir = std::path::Path::new(&manifest_dir).parent().unwrap();
    let build_dir = x509_dir.join("build");
    let src_dir = x509_dir.join("src");
    let build_dir = build_dir.to_str().unwrap();
    let src_dir = src_dir.to_str().unwrap();

    let cn = cert_cn_strings();

    gen_init_devid_csr(build_dir, &cn);
    gen_fmc_alias_csr(build_dir, &cn);
    gen_local_devid_cert(build_dir, &cn);
    gen_local_devid_csr(build_dir, &cn);
    gen_fmc_alias_cert(build_dir, &cn);
    gen_rt_alias_cert(build_dir, &cn);
    gen_rt_alias_csr(build_dir, &cn);
    gen_ocp_lock_endorsement_cert(build_dir, &cn);
    gen_ocp_lock_hybrid_endorsement_cert(build_dir, src_dir, &cn);

    eprintln!("Templates generated successfully in {build_dir}/ and {src_dir}/");
}

/// Generate Initial DeviceId Cert Signing request Template
fn gen_init_devid_csr(out_dir: &str, cn: &CertCnStrings) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);

    let bldr = csr::CsrTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 7)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_IDENTITY_INIT, x509::TCG_DICE_KP_ECA]);
    let template = bldr.tbs_template(&cn.idevid_ecc384);
    CodeGen::gen_code("InitDevIdCsrTbsEcc384", template, out_dir);

    let bldr = csr::CsrTemplateBuilder::<MlDsa87Algo>::new()
        .add_basic_constraints_ext(true, 7)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_IDENTITY_INIT, x509::TCG_DICE_KP_ECA]);
    let template = bldr.tbs_template(&cn.idevid_mldsa87);
    CodeGen::gen_code("InitDevIdCsrTbsMlDsa87", template, out_dir);
}

fn gen_fmc_alias_csr(out_dir: &str, cn: &CertCnStrings) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = csr::CsrTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_ECA, x509::TCG_DICE_KP_ATTEST_LOC])
        .add_fmc_dice_tcb_info_ext(
            /*owner_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_OWNER_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xEF; 48],
                },
            }],
            /*vendor_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_VENDOR_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xDE; 48],
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
    let template = bldr.tbs_template(&cn.fmc_alias_ecc384);
    CodeGen::gen_code("FmcAliasCsrTbsEcc384", template, out_dir);

    let bldr = csr::CsrTemplateBuilder::<MlDsa87Algo>::new()
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_ECA, x509::TCG_DICE_KP_ATTEST_LOC])
        .add_fmc_dice_tcb_info_ext(
            /*owner_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_OWNER_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xEF; 48],
                },
            }],
            /*vendor_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_VENDOR_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xDE; 48],
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
    let template = bldr.tbs_template(&cn.fmc_alias_mldsa87);
    CodeGen::gen_code("FmcAliasTbsMlDsa87", template, out_dir);
}

/// Generate Local DeviceId Certificate Template
fn gen_local_devid_cert(out_dir: &str, cn: &CertCnStrings) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo, EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 6)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_IDENTITY_LOC, x509::TCG_DICE_KP_ECA]);
    let template = bldr.tbs_template(&cn.ldevid_ecc384, &cn.idevid_ecc384);
    CodeGen::gen_code("LocalDevIdCertTbsEcc384", template, out_dir);

    let bldr = cert::CertTemplateBuilder::<MlDsa87Algo, MlDsa87Algo>::new()
        .add_basic_constraints_ext(true, 6)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_IDENTITY_LOC, x509::TCG_DICE_KP_ECA]);
    let template = bldr.tbs_template(&cn.ldevid_mldsa87, &cn.idevid_mldsa87);
    CodeGen::gen_code("LocalDevIdCertTbsMlDsa87", template, out_dir);
}

/// Generate Local DeviceId Certificate Template
fn gen_local_devid_csr(out_dir: &str, cn: &CertCnStrings) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = csr::CsrTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 6)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_IDENTITY_LOC, x509::TCG_DICE_KP_ECA]);
    let template = bldr.tbs_template(&cn.ldevid_ecc384);
    CodeGen::gen_code("LocalDevIdCsrTbsEcc384", template, out_dir);

    let bldr = csr::CsrTemplateBuilder::<MlDsa87Algo>::new()
        .add_basic_constraints_ext(true, 6)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_IDENTITY_LOC, x509::TCG_DICE_KP_ECA]);
    let template = bldr.tbs_template(&cn.ldevid_mldsa87);
    CodeGen::gen_code("LocalDevIdCsrTbsMlDsa87", template, out_dir);
}

/// Generate FMC Alias Certificate Template
fn gen_fmc_alias_cert(out_dir: &str, cn: &CertCnStrings) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo, EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_ECA, x509::TCG_DICE_KP_ATTEST_LOC])
        .add_fmc_dice_tcb_info_ext(
            /*owner_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_OWNER_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xEF; 48],
                },
            }],
            /*vendor_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_VENDOR_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xDE; 48],
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
    let template = bldr.tbs_template(&cn.fmc_alias_ecc384, &cn.ldevid_ecc384);
    CodeGen::gen_code("FmcAliasCertTbsEcc384", template, out_dir);

    let bldr = cert::CertTemplateBuilder::<MlDsa87Algo, MlDsa87Algo>::new()
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_ECA, x509::TCG_DICE_KP_ATTEST_LOC])
        .add_fmc_dice_tcb_info_ext(
            /*owner_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_OWNER_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xEF; 48],
                },
            }],
            /*vendor_fwids=*/
            &[FwidParam {
                name: "TCB_INFO_VENDOR_DEVICE_INFO_HASH",
                fwid: Fwid {
                    hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                    digest: &[0xDE; 48],
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
    let template = bldr.tbs_template(&cn.fmc_alias_mldsa87, &cn.ldevid_mldsa87);
    CodeGen::gen_code("FmcAliasCertTbsMlDsa87", template, out_dir);
}

/// Generate Runtime Alias Certificate Template
fn gen_rt_alias_cert(out_dir: &str, cn: &CertCnStrings) {
    let mut usage = KeyUsage::default();
    // Add KeyCertSign to allow signing of other certs
    usage.set_key_cert_sign(true);
    // Add DigitalSignature to allow signing of firmware
    usage.set_digital_signature(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo, EcdsaSha384Algo>::new()
        // Basic Constraints : CA = true, PathLen = 4
        .add_basic_constraints_ext(true, 4)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_ECA])
        .add_rt_dice_tcb_info_ext(&[FwidParam {
            name: "TCB_INFO_RT_TCI",
            fwid: Fwid {
                hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                digest: &[0xCD; 48],
            },
        }]);
    let template = bldr.tbs_template(&cn.rt_alias_ecc384, &cn.fmc_alias_ecc384);
    CodeGen::gen_code("RtAliasCertTbsEcc384", template, out_dir);

    let bldr = cert::CertTemplateBuilder::<MlDsa87Algo, MlDsa87Algo>::new()
        // Basic Constraints : CA = true, PathLen = 4
        .add_basic_constraints_ext(true, 4)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_ECA])
        .add_rt_dice_tcb_info_ext(&[FwidParam {
            name: "TCB_INFO_RT_TCI",
            fwid: Fwid {
                hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                digest: &[0xCD; 48],
            },
        }]);
    let template = bldr.tbs_template(&cn.rt_alias_mldsa87, &cn.fmc_alias_mldsa87);
    CodeGen::gen_code("RtAliasCertTbsMlDsa87", template, out_dir);
}

/// Generate Runtime alias Certificate Signing Request Template
fn gen_rt_alias_csr(out_dir: &str, cn: &CertCnStrings) {
    let mut usage = KeyUsage::default();
    // Add KeyCertSign to allow signing of other certs
    usage.set_key_cert_sign(true);
    // Add DigitalSignature to allow signing of firmware
    usage.set_digital_signature(true);
    let bldr = csr::CsrTemplateBuilder::<EcdsaSha384Algo>::new()
        // Basic Constraints : CA = true, PathLen = 4
        .add_basic_constraints_ext(true, 4)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_ECA])
        .add_rt_dice_tcb_info_ext(&[FwidParam {
            name: "TCB_INFO_RT_TCI",
            fwid: Fwid {
                hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                digest: &[0xCD; 48],
            },
        }]);
    let template = bldr.tbs_template(&cn.rt_alias_ecc384);
    CodeGen::gen_code("RtAliasCsrTbsEcc384", template, out_dir);

    let bldr = csr::CsrTemplateBuilder::<MlDsa87Algo>::new()
        // Basic Constraints : CA = true, PathLen = 4
        .add_basic_constraints_ext(true, 4)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_extended_key_usage_ext(&[x509::TCG_DICE_KP_ECA])
        .add_rt_dice_tcb_info_ext(&[FwidParam {
            name: "TCB_INFO_RT_TCI",
            fwid: Fwid {
                hash_alg: asn1::oid!(/*sha384*/ 2, 16, 840, 1, 101, 3, 4, 2, 2),
                digest: &[0xCD; 48],
            },
        }]);
    let template = bldr.tbs_template(&cn.rt_alias_mldsa87);
    CodeGen::gen_code("RtAliasCsrTbsMlDsa87", template, out_dir);
}

/// Generate OCP LOCK HPKE Endorsement Certificate Templates
fn gen_ocp_lock_endorsement_cert(out_dir: &str, cn: &CertCnStrings) {
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
    let template = bldr.tbs_template("OCP LOCK HPKE Endorsement ML-KEM 1024", &cn.rt_alias_ecc384);
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
        &cn.rt_alias_mldsa87,
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
    let template = bldr.tbs_template("OCP LOCK HPKE Endorsement ECDH P-384", &cn.rt_alias_ecc384);
    CodeGen::gen_code("OcpLockEcdh384CertTbsEcc384", template, out_dir);

    let bldr = cert::CertTemplateBuilder::<MlDsa87Algo, EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(false, 0)
        .add_key_usage_ext(usage)
        .add_hpke_identifiers_ext(&HPKEIdentifiers::new(
            HPKEIdentifiers::ECDH_P384_IANA_CODE_POINT,
            HPKEIdentifiers::HKDF_SHA384_IANA_CODE_POINT,
            HPKEIdentifiers::AES_256_GCM_IANA_CODE_POINT,
        ));
    let template = bldr.tbs_template("OCP LOCK HPKE Endorsement ECDH P-384", &cn.rt_alias_mldsa87);
    CodeGen::gen_code("OcpLockEcdh384CertTbsMlDsa87", template, out_dir);
}

/// Generate OCP LOCK HPKE Endorsement Certificate Templates with Hybrid Keys
/// This is built with the "x509-cert" crate because OpenSSL does not yet support the ML-KEM &
/// P-384 hybrid key type.
fn gen_ocp_lock_hybrid_endorsement_cert(build_dir: &str, src_dir: &str, cn: &CertCnStrings) {
    use x509::{HPKEIdentifiers, HybridP384MlKem1024Algo};
    use x509_cert::X509CertTemplateBuilder;
    // 4.2.2.1.3
    // In addition, the X.509 extended attributes SHALL:
    // * Indicate the key usage as keyEncipherment
    let mut usage = KeyUsage::default();
    usage.set_key_encipherment(true);

    let bldr = X509CertTemplateBuilder::<EcdsaSha384Algo, HybridP384MlKem1024Algo>::new()
        .add_basic_constraints_ext(false, 0)
        .add_key_usage_ext(usage)
        .add_hpke_identifiers_ext(&HPKEIdentifiers::new(
            HPKEIdentifiers::ML_KEM_1024_ECDH_P384_IANA_CODE_POINT,
            HPKEIdentifiers::HKDF_SHA384_IANA_CODE_POINT,
            HPKEIdentifiers::AES_256_GCM_IANA_CODE_POINT,
        ));
    let template = bldr.tbs_template(
        "OCP LOCK HPKE Endorsement ML-KEM-1024-ECDH-P384",
        &cn.rt_alias_ecc384,
    );
    // Hybrid templates go to both build/ (for OUT_DIR path) and src/ (for include! path)
    CodeGen::gen_code("OcpLockHybridCertTbsEcc384", template, build_dir);
    std::fs::copy(
        std::path::Path::new(build_dir).join("ocp_lock_hybrid_cert_tbs_ecc_384.rs"),
        std::path::Path::new(src_dir).join("ocp_lock_hybrid_cert_tbs_ecc_384.rs"),
    )
    .unwrap();

    let bldr = X509CertTemplateBuilder::<MlDsa87Algo, HybridP384MlKem1024Algo>::new()
        .add_basic_constraints_ext(false, 0)
        .add_key_usage_ext(usage)
        .add_hpke_identifiers_ext(&HPKEIdentifiers::new(
            HPKEIdentifiers::ML_KEM_1024_ECDH_P384_IANA_CODE_POINT,
            HPKEIdentifiers::HKDF_SHA384_IANA_CODE_POINT,
            HPKEIdentifiers::AES_256_GCM_IANA_CODE_POINT,
        ));
    let template = bldr.tbs_template(
        "OCP LOCK HPKE Endorsement ML-KEM-1024-ECDH-P384",
        &cn.rt_alias_mldsa87,
    );
    CodeGen::gen_code("OcpLockHybridCertTbsMlDsa87", template, build_dir);
    std::fs::copy(
        std::path::Path::new(build_dir).join("ocp_lock_hybrid_cert_tbs_ml_dsa_87.rs"),
        std::path::Path::new(src_dir).join("ocp_lock_hybrid_cert_tbs_ml_dsa_87.rs"),
    )
    .unwrap();
}
