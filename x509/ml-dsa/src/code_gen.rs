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
        if Command::new("rustfmt")
            .arg("--emit=files")
            .arg("--edition=2021")
            .arg(file_path)
            .spawn()
            .is_ok()
        {}
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

        let tbs = template.tbs();

        quote!(
            #[doc = "++

Licensed under the Apache-2.0 license.

Abstract:

    Regenerate the template by building caliptra-x509-build with the generate-templates flag.

--"]

            pub struct #param_name<'a> {
                #(pub #param_vars)*
            }

            impl<'a> #param_name<'a>{
                #(pub #len_consts)*
            }

            pub struct #type_name {
                tbs: [u8; Self::TBS_TEMPLATE_LEN],
            }

            impl #type_name {
                #(#offset_consts)*
                #(#len_consts)*
                #tbs_len_const
                const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = [#(#tbs,)*];

                pub fn new(params: &#param_name) -> Self {
                    let mut template = Self {
                        tbs: Self::TBS_TEMPLATE,
                    };
                    template.apply(params);
                    template
                }

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
        )
        .to_string()
    }
}
