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
mod cert_rustcrypto;
#[cfg(feature = "generate_templates")]
mod code_gen;
#[cfg(feature = "generate_templates")]
mod csr;
#[cfg(feature = "generate_templates")]
mod csr_rustcrypto;
#[cfg(feature = "generate_templates")]
mod tbs;
#[cfg(feature = "generate_templates")]
mod x509;

#[cfg(feature = "generate_templates")]
use {
    code_gen::CodeGen,
    const_oid::ObjectIdentifier,
    ml_dsa::MlDsa87,
    std::env,
    x509::{EcdsaSha384Algo, Fwid, FwidParam, KeyUsage},
    x509_cert::ext::pkix::{KeyUsage as KeyUsageRustCrypto, KeyUsages},
};

// Main Entry point
fn main() {
    #[cfg(feature = "generate_templates")]
    {
        let out_dir_os_str = env::var_os("OUT_DIR").unwrap();
        let out_dir = out_dir_os_str.to_str().unwrap();

        gen_init_devid_csr_ecc384(out_dir);
        gen_fmc_alias_csr(out_dir);
        gen_local_devid_cert_ecc384(out_dir);
        gen_fmc_alias_cert_ecc384(out_dir);
        gen_rt_alias_cert_ecc384(out_dir);

        // Generate all ML-DSA-87 certificate and CSR templates
        gen_init_devid_csr_mldsa87(out_dir);
        gen_fmc_alias_csr_mldsa87(out_dir);
        gen_local_devid_cert_mldsa87(out_dir);
        gen_fmc_alias_cert_mldsa87(out_dir);
        gen_rt_alias_cert_mldsa87(out_dir);
    }
}

/// Generated Initial DeviceId Cert Signing request Template
#[cfg(feature = "generate_templates")]
fn gen_init_devid_csr_ecc384(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = csr::CsrTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17]);
    let template = bldr.tbs_template("Caliptra 1.0 IDevID");
    CodeGen::gen_code("InitDevIdCsrTbsEcc384", template, out_dir);
}

#[cfg(feature = "generate_templates")]
fn gen_fmc_alias_csr(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = csr::CsrTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17]);
    let template = bldr.tbs_template("Caliptra 1.0 FMC Alias");
    CodeGen::gen_code("FmcAliasCsrTbs", template, out_dir);
}

/// Generate Local DeviceId Certificate Template
#[cfg(feature = "generate_templates")]
fn gen_local_devid_cert_ecc384(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo>::new()
        .add_basic_constraints_ext(true, 4)
        .add_key_usage_ext(usage)
        .add_ueid_ext(&[0xFF; 17]);
    let template = bldr.tbs_template("Caliptra 1.0 LDevID", "Caliptra 1.0 IDevID");
    CodeGen::gen_code("LocalDevIdCertTbsEcc384", template, out_dir);
}

/// Generate FMC Alias Certificate Template
#[cfg(feature = "generate_templates")]
fn gen_fmc_alias_cert_ecc384(out_dir: &str) {
    let mut usage = KeyUsage::default();
    usage.set_key_cert_sign(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo>::new()
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
    let template = bldr.tbs_template("Caliptra 1.0 FMC Alias", "Caliptra 1.0 LDevID");
    CodeGen::gen_code("FmcAliasCertTbsEcc384", template, out_dir);
}

/// Generate FMC Alias Certificate Template
#[cfg(feature = "generate_templates")]
fn gen_rt_alias_cert_ecc384(out_dir: &str) {
    let mut usage = KeyUsage::default();
    // Add KeyCertSign to allow signing of other certs
    usage.set_key_cert_sign(true);
    // Add DigitalSignature to allow signing of firmware
    usage.set_digital_signature(true);
    let bldr = cert::CertTemplateBuilder::<EcdsaSha384Algo>::new()
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
    let template = bldr.tbs_template("Caliptra 1.0 Rt Alias", "Caliptra 1.0 FMC Alias");
    CodeGen::gen_code("RtAliasCertTbsEcc384", template, out_dir);
}

/// Generated Initial DeviceId Cert Signing request Template
#[cfg(feature = "generate_templates")]
fn gen_init_devid_csr_mldsa87(out_dir: &str) {
    // Set up key usage for certificate signing
    let key_usage = KeyUsageRustCrypto(KeyUsages::KeyCertSign.into());

    // Create the CSR template builder with ML-DSA-87
    let bldr = csr_rustcrypto::CsrTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_ueid_ext(&[0xFF; 17])
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(key_usage);

    // Generate the template with a subject name
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 IDevID");

    // Generate code from the template
    CodeGen::gen_code("InitDevIdCsrTbsMlDsa87", template, out_dir);
}

/// Generate FMC Alias CSR Template
#[cfg(feature = "generate_templates")]
fn gen_fmc_alias_csr_mldsa87(out_dir: &str) {
    // Set up key usage for certificate signing
    let key_usage = KeyUsageRustCrypto(KeyUsages::KeyCertSign.into());

    // Create the CSR template builder with ML-DSA-87
    let bldr = csr_rustcrypto::CsrTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_ueid_ext(&[0xFF; 17])
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(key_usage);

    // Generate the template with a subject name
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 FMC Alias");

    // Generate code from the template
    CodeGen::gen_code("FmcAliasTbsMlDsa87", template, out_dir);
}

/// Generate Local DeviceId Certificate Template
#[cfg(feature = "generate_templates")]
fn gen_local_devid_cert_mldsa87(out_dir: &str) {
    // Create KeyUsage with key_cert_sign set to true
    let key_usage = KeyUsageRustCrypto(KeyUsages::KeyCertSign.into());

    // Build the FMC Alias certificate template
    let bldr = cert_rustcrypto::CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(key_usage)
        .add_ueid_ext(&[0xFF; 17]);

    // Generate the template with subject and issuer CN
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 LDevID", "Caliptra 2.0 MlDsa87 IDevID");

    // Generate the code
    CodeGen::gen_code("LocalDevIdCertTbsMlDsa87", template, out_dir);
}

/// Generate FMC Alias Certificate Template
#[cfg(feature = "generate_templates")]
fn gen_fmc_alias_cert_mldsa87(out_dir: &str) {
    // Create KeyUsage with key_cert_sign set to true
    let key_usage = KeyUsageRustCrypto(KeyUsages::KeyCertSign.into());

    // SHA-384 OID
    let sha384_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

    // Create long-lived FWID parameters
    let device_fwids = [cert_rustcrypto::FwidParam {
        name: "TCB_INFO_DEVICE_INFO_HASH",
        fwid: cert_rustcrypto::Fwid {
            hash_alg: sha384_oid,
            digest: &[0xEF; 48],
        },
    }];

    let fmc_fwids = [cert_rustcrypto::FwidParam {
        name: "TCB_INFO_FMC_TCI",
        fwid: cert_rustcrypto::Fwid {
            hash_alg: sha384_oid,
            digest: &[0xCD; 48],
        },
    }];

    // Build the FMC Alias certificate template with TCB info
    let bldr = cert_rustcrypto::CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(key_usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_fmc_dice_tcb_info_ext(
            /*device_fwids=*/
            &device_fwids,
            /*fmc_fwids=*/
            &fmc_fwids,
        );

    // Generate the template with subject and issuer CN
    let template = bldr.tbs_template(
        "Caliptra 2.0 MlDsa87 FMC Alias",
        "Caliptra 2.0 MlDsa87 LDevID",
    );

    // Generate the code
    CodeGen::gen_code("FmcAliasCertTbsMlDsa87", template, out_dir);
}

/// Generate RT Alias Certificate Template
#[cfg(feature = "generate_templates")]
fn gen_rt_alias_cert_mldsa87(out_dir: &str) {
    // Create KeyUsage with key_cert_sign set to true and digital_signature set to true
    let key_usage = KeyUsageRustCrypto(KeyUsages::KeyCertSign | KeyUsages::DigitalSignature);

    // SHA-384 OID
    let sha384_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

    // Create RT FWID parameter
    let rt_fwids = [cert_rustcrypto::FwidParam {
        name: "TCB_INFO_RT_TCI",
        fwid: cert_rustcrypto::Fwid {
            hash_alg: sha384_oid,
            digest: &[0xCD; 48],
        },
    }];

    // Build the RT Alias certificate template with TCB info
    let bldr = cert_rustcrypto::CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_basic_constraints_ext(true, 2)
        .add_key_usage_ext(key_usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_rt_dice_tcb_info_ext(0xC4, &rt_fwids);
    // Generate the template with subject and issuer CN
    let template = bldr.tbs_template(
        "Caliptra 2.0 MlDsa87 RT Alias",
        "Caliptra 2.0 MlDsa87 FMC Alias",
    );

    // Generate the code
    CodeGen::gen_code("RtAliasCertTbsMlDsa87", template, out_dir);
}
