/*++

Licensed under the Apache-2.0 license.

File Name:

    code_gen.rs

Abstract:

    File contains code generation routines for X509 Templates

--*/

use crate::tbs::TbsTemplate;
use caliptra_x509::lzss;
use convert_case::{Case, Casing};
use quote::{__private::TokenStream, format_ident, quote};
use std::{path::Path, process::Command};

// Code Generator
pub struct CodeGen {}

impl CodeGen {
    /// Generate code
    ///
    /// # Arguments
    ///
    /// * `type_name` - Type Name,
    /// * `template` - To Be Signed template
    /// * `out_path` - Output Path
    pub fn gen_code(type_name: &str, template: TbsTemplate, out_path: &str) {
        let file_name = format!("{}.rs", type_name.to_case(Case::Snake));
        let file_path = Path::new(out_path).join(file_name);
        std::fs::write(&file_path, Self::code(type_name, template)).unwrap();
        let _ = Command::new("rustfmt")
            .arg("--emit=files")
            .arg("--edition=2024")
            .arg(file_path)
            .status();
    }

    fn code(type_name: &str, template: TbsTemplate) -> String {
        let type_name = format_ident!("{}", type_name);
        let param_name = format_ident!("{}Params", type_name);

        let param_vars = template.params().iter().map(|p| {
            let name = format_ident!("{}", p.name.to_case(Case::Snake));
            let value = p.len;
            quote! {
               #name: &'a[u8; #value],
            }
        });

        let offset_consts = template.params().iter().map(|p| {
            let name = format_ident!("{}_OFFSET", p.name.to_uppercase());
            let value = p.offset;
            quote! {
               const #name: usize = #value;
            }
        });

        let len_consts: Vec<TokenStream> = template
            .params()
            .iter()
            .map(|p| {
                let name = format_ident!("{}_LEN", p.name.to_uppercase());
                let value = p.len;
                quote! {
                   const #name: usize = #value;
                }
            })
            .collect();

        let apply_calls = template.params().iter().map(|p| {
            let name = format_ident!("{}", p.name.to_case(Case::Snake));
            let len = format_ident!("{}_LEN", p.name.to_uppercase());
            let offset = format_ident!("{}_OFFSET", p.name.to_uppercase());
            quote!(
                 apply_slice::<{Self::#offset}, {Self::#len}>(&mut self.tbs, params.#name);
            )
        });

        let tbs_len = template.tbs().len();
        let tbs_len_const = quote!(
            pub const TBS_TEMPLATE_LEN: usize = #tbs_len;
        );

        // Generate chunked template constants, new() body, and verification tests
        let (template_consts, new_body, verification_test) = if let (
            Some(before_key),
            Some(after_key),
        ) =
            (template.tbs_before_key(), template.tbs_after_key())
        {
            let compressed_before = lzss::compress(before_key);
            let compressed_after = lzss::compress(after_key);

            // Build-time verification
            {
                let mut decompressed_before = vec![0u8; before_key.len()];
                assert!(lzss::decompress(
                    &compressed_before,
                    &mut decompressed_before
                ));
                assert_eq!(before_key, decompressed_before);

                let mut decompressed_after = vec![0u8; after_key.len()];
                assert!(lzss::decompress(&compressed_after, &mut decompressed_after));
                assert_eq!(after_key, decompressed_after);
            }

            let compressed_before_len = compressed_before.len();
            let compressed_after_len = compressed_after.len();

            let template_consts = quote!(
                const COMPRESSED_TBS_TEMPLATE_BEFORE_KEY: [u8; #compressed_before_len] = [#(#compressed_before,)*];
                const COMPRESSED_TBS_TEMPLATE_AFTER_KEY: [u8; #compressed_after_len] = [#(#compressed_after,)*];
                const TBS_TEMPLATE_BEFORE_KEY_LEN: usize = Self::PUBLIC_KEY_OFFSET;
                const TBS_TEMPLATE_AFTER_KEY_LEN: usize = Self::TBS_TEMPLATE_LEN - Self::PUBLIC_KEY_OFFSET - Self::PUBLIC_KEY_LEN;

                #[cfg(test)]
                const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = {
                    let mut result = [0x5F_u8; Self::TBS_TEMPLATE_LEN];
                    let before = [#(#before_key,)*];
                    let after = [#(#after_key,)*];
                    let mut i = 0;
                    while i < before.len() {
                        result[i] = before[i];
                        i += 1;
                    }
                    i = 0;
                    while i < after.len() {
                        result[Self::PUBLIC_KEY_OFFSET + Self::PUBLIC_KEY_LEN + i] = after[i];
                        i += 1;
                    }
                    result
                };
            );

            let new_body = quote!(
                pub fn new(params: &#param_name) -> caliptra_error::CaliptraResult<Self> {
                    let mut tbs = [0x5F_u8; Self::TBS_TEMPLATE_LEN];

                    let mut before_key = [0u8; Self::TBS_TEMPLATE_BEFORE_KEY_LEN];
                    if !crate::lzss::decompress(&Self::COMPRESSED_TBS_TEMPLATE_BEFORE_KEY, &mut before_key) {
                        return Err(caliptra_error::CaliptraError::X509_TEMPLATE_DECOMPRESSION_FAILED);
                    }
                    tbs[..Self::PUBLIC_KEY_OFFSET].copy_from_slice(&before_key);

                    let mut after_key = [0u8; Self::TBS_TEMPLATE_AFTER_KEY_LEN];
                    if !crate::lzss::decompress(&Self::COMPRESSED_TBS_TEMPLATE_AFTER_KEY, &mut after_key) {
                        return Err(caliptra_error::CaliptraError::X509_TEMPLATE_DECOMPRESSION_FAILED);
                    }
                    tbs[Self::PUBLIC_KEY_OFFSET + Self::PUBLIC_KEY_LEN..].copy_from_slice(&after_key);

                    let mut template = Self { tbs };
                    template.apply(params);
                    Ok(template)
                }
            );

            let verification_test = quote!(
                #[cfg(test)]
                mod lzss_tests {
                    use super::*;
                    #[test]
                    fn test_template_decompression() {
                        let mut before_key = [0u8; #type_name::TBS_TEMPLATE_BEFORE_KEY_LEN];
                        assert!(crate::lzss::decompress(&#type_name::COMPRESSED_TBS_TEMPLATE_BEFORE_KEY, &mut before_key));
                        assert_eq!(before_key, #type_name::TBS_TEMPLATE[..#type_name::PUBLIC_KEY_OFFSET]);

                        let mut after_key = [0u8; #type_name::TBS_TEMPLATE_AFTER_KEY_LEN];
                        assert!(crate::lzss::decompress(&#type_name::COMPRESSED_TBS_TEMPLATE_AFTER_KEY, &mut after_key));
                        assert_eq!(after_key, #type_name::TBS_TEMPLATE[#type_name::PUBLIC_KEY_OFFSET + #type_name::PUBLIC_KEY_LEN..]);
                    }
                }
            );

            (template_consts, new_body, verification_test)
        } else {
            let tbs = template.tbs();
            let compressed_tbs = lzss::compress(tbs);
            let compressed_tbs_len = compressed_tbs.len();

            // Build-time verification
            {
                let mut decompressed_tbs = vec![0u8; tbs.len()];
                assert!(lzss::decompress(&compressed_tbs, &mut decompressed_tbs));
                assert_eq!(tbs, decompressed_tbs);
            }

            let template_consts = quote!(
                const COMPRESSED_TBS_TEMPLATE: [u8; #compressed_tbs_len] = [#(#compressed_tbs,)*];

                #[cfg(test)]
                const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = [#(#tbs,)*];
            );

            let new_body = quote!(
                pub fn new(params: &#param_name) -> caliptra_error::CaliptraResult<Self> {
                    let mut tbs = [0u8; Self::TBS_TEMPLATE_LEN];
                    if !crate::lzss::decompress(&Self::COMPRESSED_TBS_TEMPLATE, &mut tbs) {
                        return Err(caliptra_error::CaliptraError::X509_TEMPLATE_DECOMPRESSION_FAILED);
                    }
                    let mut template = Self { tbs };
                    template.apply(params);
                    Ok(template)
                }
            );

            let verification_test = quote!(
                #[cfg(test)]
                mod lzss_tests {
                    use super::*;
                    #[test]
                    fn test_template_decompression() {
                        let mut tbs = [0u8; #type_name::TBS_TEMPLATE_LEN];
                        assert!(crate::lzss::decompress(&#type_name::COMPRESSED_TBS_TEMPLATE, &mut tbs));
                        assert_eq!(tbs, #type_name::TBS_TEMPLATE);
                    }
                }
            );

            (template_consts, new_body, verification_test)
        };

        quote!(
            #[doc = "++

Licensed under the Apache-2.0 license.

Abstract:

    Regenerate the template with: cargo run -p caliptra-x509-gen

--"]
            #[allow(clippy::needless_lifetimes)]
            pub struct #param_name<'a> {
                #(pub #param_vars)*
            }

            impl #param_name<'_>{
                #(pub #len_consts)*
            }

            pub struct #type_name {
                tbs: [u8; Self::TBS_TEMPLATE_LEN],
            }

            impl #type_name {
                #(#offset_consts)*
                #(#len_consts)*
                #tbs_len_const
                #template_consts

                #new_body

                pub fn sign<Sig, Error>(
                    &self,
                    sign_fn: impl Fn(&[u8]) -> Result<Sig, Error>,
                ) -> Result<Sig, Error> {
                    sign_fn(&self.tbs)
                }

                pub fn tbs(&self) -> &[u8] {
                    &self.tbs
                }

                fn apply(&mut self, params: &#param_name) {
                    #[inline(always)]
                    fn apply_slice<const OFFSET: usize, const LEN: usize>(buf: &mut [u8; #tbs_len], val: &[u8; LEN]) {
                        buf[OFFSET..OFFSET + LEN].copy_from_slice(val);
                    }

                    #(#apply_calls)*
                }
            }

            #verification_test
        )
        .to_string()
    }
}
