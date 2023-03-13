/*++

Licensed under the Apache-2.0 license.

File Name:

    csr.rs

Abstract:

    File contains generation of X509 Certificate Signing Request (CSR) To Be Singed (TBS)
    template that can be substituted at firmware runtime.

--*/

use crate::tbs::{TbsParam, TbsTemplate};
use crate::x509::{self, AsymKey, KeyUsage, SigningAlgorithm};
use openssl::stack::Stack;
use openssl::x509::{X509Extension, X509NameBuilder, X509ReqBuilder};

/// CSR Template Parameter
struct CsrTemplateParam {
    tbs_param: TbsParam,
    needle: Vec<u8>,
}

/// CSR Template Builder
pub struct CsrTemplateBuilder<Algo: SigningAlgorithm> {
    algo: Algo,
    builder: X509ReqBuilder,
    exts: Stack<X509Extension>,
    params: Vec<CsrTemplateParam>,
}

impl<Algo: SigningAlgorithm> CsrTemplateBuilder<Algo> {
    // Create an instance of `CertificateTemplateBuilder`
    pub fn new() -> Self {
        Self {
            algo: Algo::default(),
            builder: X509ReqBuilder::new().unwrap(),
            exts: Stack::new().unwrap(),
            params: vec![],
        }
    }
    /// Add X509 Basic Constraints Extension
    ///
    /// # Arguments
    ///
    /// * `ca`       - Flag indicating if the certificate is a Certificate Authority
    /// * `path_len` - Certificate path length

    pub fn add_basic_constraints_ext(mut self, ca: bool, path_len: u32) -> Self {
        self.exts
            .push(x509::make_basic_constraints_ext(ca, path_len))
            .unwrap();
        self
    }

    /// Add X509 Key Usage Extension
    ///
    /// # Arguments
    ///
    /// * `usage` - Key Usage
    pub fn add_key_usage_ext(mut self, usage: KeyUsage) -> Self {
        self.exts.push(x509::make_key_usage_ext(usage)).unwrap();
        self
    }

    /// Add TCG UEID extension
    ///
    /// # Arguments
    ///
    /// * `ueid` - Unique Endpoint Identifier
    pub fn add_ueid_ext(mut self, ueid: &[u8]) -> Self {
        self.exts.push(x509::make_tcg_ueid_ext(ueid)).unwrap();

        let param = CsrTemplateParam {
            tbs_param: TbsParam::new("UEID", 0, ueid.len()),
            needle: ueid.to_vec(),
        };
        self.params.push(param);

        self
    }

    /// Generate To Be Signed (TBS) Template
    pub fn tbs_template(mut self, subject_cn: &str) -> TbsTemplate {
        // Generate key pair
        let key = self.algo.gen_key();

        // Set Version
        self.builder.set_version(0).unwrap();

        // Set Public Key
        self.builder.set_pubkey(key.priv_key()).unwrap();
        let param = CsrTemplateParam {
            tbs_param: TbsParam::new("PUBLIC_KEY", 0, key.pub_key().len()),
            needle: key.pub_key().to_vec(),
        };
        self.params.push(param);

        // Set the subject name
        let mut subject_name = X509NameBuilder::new().unwrap();
        subject_name.append_entry_by_text("CN", subject_cn).unwrap();
        subject_name
            .append_entry_by_text("serialNumber", &key.hex_str())
            .unwrap();
        let subject_name = subject_name.build();
        self.builder.set_subject_name(&subject_name).unwrap();
        let param = CsrTemplateParam {
            tbs_param: TbsParam::new("SUBJECT_SN", 0, key.hex_str().len()),
            needle: key.hex_str().into_bytes(),
        };
        self.params.push(param);

        // Add the requested extensions
        self.builder.add_extensions(&self.exts).unwrap();

        // Sign the CSR
        self.builder
            .sign(key.priv_key(), self.algo.digest())
            .unwrap();

        // Generate the CSR
        let csr = self.builder.build();

        // Serialize the CSR to DER
        let der = csr.to_der().unwrap();

        // Retrieve the To be signed portion from the CSR
        let mut tbs = x509::get_tbs(der);

        // Calculate the offset of parameters and sanitize the TBS section
        let params = self
            .params
            .iter()
            .map(|p| x509::sanitize(x509::init_param(&p.needle, &tbs, p.tbs_param), &mut tbs))
            .collect();
        // Create the template
        TbsTemplate::new(tbs, params)
    }
}
