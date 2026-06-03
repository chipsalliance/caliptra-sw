/*++

Licensed under the Apache-2.0 license.

File Name:

    code_gen.rs

Abstract:

    File contains code generation routines for X509 Templates

--*/

use crate::tbs::TbsTemplate;
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
            let before_len = before_key.len();
            let after_len = after_key.len();

            let template_consts = quote!(
                const TBS_TEMPLATE_BEFORE_KEY: [u8; #before_len] = [#(#before_key,)*];
                const TBS_TEMPLATE_AFTER_KEY: [u8; #after_len] = [#(#after_key,)*];

                #[cfg(test)]
                pub const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = {
                    let mut result = [0x5F_u8; Self::TBS_TEMPLATE_LEN];
                    let mut i = 0;
                    while i < Self::TBS_TEMPLATE_BEFORE_KEY.len() {
                        result[i] = Self::TBS_TEMPLATE_BEFORE_KEY[i];
                        i += 1;
                    }
                    i = 0;
                    while i < Self::TBS_TEMPLATE_AFTER_KEY.len() {
                        result[Self::PUBLIC_KEY_OFFSET + Self::PUBLIC_KEY_LEN + i] = Self::TBS_TEMPLATE_AFTER_KEY[i];
                        i += 1;
                    }
                    result
                };
            );

            let new_body = quote!(
                pub fn new(params: &#param_name) -> Self {
                    let mut tbs = [0x5F_u8; Self::TBS_TEMPLATE_LEN];
                    tbs[..Self::PUBLIC_KEY_OFFSET].copy_from_slice(&Self::TBS_TEMPLATE_BEFORE_KEY);
                    tbs[Self::PUBLIC_KEY_OFFSET + Self::PUBLIC_KEY_LEN..].copy_from_slice(&Self::TBS_TEMPLATE_AFTER_KEY);
                    let mut template = Self { tbs };
                    template.apply(params);
                    template
                }
            );

            let verification_test = quote!(
                #[cfg(test)]
                mod template_tests {
                    use super::*;
                    #[test]
                    fn test_template_construction() {
                        let mut before_key = [0u8; #type_name::PUBLIC_KEY_OFFSET];
                        before_key.copy_from_slice(&#type_name::TBS_TEMPLATE_BEFORE_KEY);
                        assert_eq!(before_key, #type_name::TBS_TEMPLATE[..#type_name::PUBLIC_KEY_OFFSET]);

                        let mut after_key = [0u8; #type_name::TBS_TEMPLATE_LEN - #type_name::PUBLIC_KEY_OFFSET - #type_name::PUBLIC_KEY_LEN];
                        after_key.copy_from_slice(&#type_name::TBS_TEMPLATE_AFTER_KEY);
                        assert_eq!(after_key, #type_name::TBS_TEMPLATE[#type_name::PUBLIC_KEY_OFFSET + #type_name::PUBLIC_KEY_LEN..]);
                    }
                }
            );

            (template_consts, new_body, verification_test)
        } else {
            let tbs = template.tbs();

            let template_consts = quote!(
                pub const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = [#(#tbs,)*];
            );

            let new_body = quote!(
                pub fn new(params: &#param_name) -> Self {
                    let mut tbs = Self::TBS_TEMPLATE;
                    let mut template = Self { tbs };
                    template.apply(params);
                    template
                }
            );

            let verification_test = quote!();

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
