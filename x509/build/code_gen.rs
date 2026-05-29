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

/// Templates whose largest placeholder run is at least this many bytes are emitted
/// as a BEFORE/AFTER split rather than a single inline TBS_TEMPLATE const, to avoid
/// inlining large stretches of `0x5F` filler into `.rodata`. Below this threshold,
/// the savings don't justify the extra indirection.
const SPLIT_THRESHOLD: usize = 512;

/// Locate the longest contiguous run of `0x5F` placeholder bytes in a TBS template.
/// Returns `Some((offset, len))` of the longest run, or `None` if there are none.
fn longest_placeholder_run(tbs: &[u8]) -> Option<(usize, usize)> {
    let mut best: (usize, usize) = (0, 0);
    let mut cur_start = 0;
    let mut cur_len = 0;
    for (i, &b) in tbs.iter().enumerate() {
        if b == 0x5F {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
        } else {
            if cur_len > best.1 {
                best = (cur_start, cur_len);
            }
            cur_len = 0;
        }
    }
    if cur_len > best.1 {
        best = (cur_start, cur_len);
    }
    (best.1 > 0).then_some(best)
}

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

        let (template_consts, new_body) = match longest_placeholder_run(tbs)
            .filter(|(_, len)| *len >= SPLIT_THRESHOLD)
        {
            Some((split_offset, split_len)) => {
                let before = &tbs[..split_offset];
                let after = &tbs[split_offset + split_len..];
                let before_len = before.len();
                let after_len = after.len();
                let placeholder_end = split_offset + split_len;

                let consts = quote!(
                    const TBS_TEMPLATE_BEFORE_PLACEHOLDER: [u8; #before_len] = [#(#before,)*];
                    const TBS_TEMPLATE_AFTER_PLACEHOLDER: [u8; #after_len] = [#(#after,)*];

                    #[cfg(test)]
                    const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = {
                        let mut result = [0x5F_u8; Self::TBS_TEMPLATE_LEN];
                        let before = Self::TBS_TEMPLATE_BEFORE_PLACEHOLDER;
                        let after = Self::TBS_TEMPLATE_AFTER_PLACEHOLDER;
                        let mut i = 0;
                        while i < before.len() {
                            result[i] = before[i];
                            i += 1;
                        }
                        let mut i = 0;
                        while i < after.len() {
                            result[#placeholder_end + i] = after[i];
                            i += 1;
                        }
                        result
                    };
                );

                let body = quote!(
                    let mut tbs = [0x5F_u8; Self::TBS_TEMPLATE_LEN];
                    tbs[..#before_len].copy_from_slice(&Self::TBS_TEMPLATE_BEFORE_PLACEHOLDER);
                    tbs[#placeholder_end..].copy_from_slice(&Self::TBS_TEMPLATE_AFTER_PLACEHOLDER);
                    let mut template = Self { tbs };
                    template.apply(params);
                    template
                );

                (consts, body)
            }
            None => {
                let consts = quote!(
                    const TBS_TEMPLATE: [u8; Self::TBS_TEMPLATE_LEN] = [#(#tbs,)*];
                );
                let body = quote!(
                    let mut template = Self {
                        tbs: Self::TBS_TEMPLATE,
                    };
                    template.apply(params);
                    template
                );
                (consts, body)
            }
        };

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
                #template_consts

                pub fn new(params: &#param_name) -> Self {
                    #new_body
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
