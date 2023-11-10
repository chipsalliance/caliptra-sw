/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    File contains CFI procedural macro.

References:
    https://tf-m-user-guide.trustedfirmware.org/design_docs/tfm_physical_attack_mitigation.html
    https://github.com/rust-embedded/riscv/blob/master/src/asm.rs

--*/

use proc_macro::TokenStream;
use proc_macro2::{Ident, TokenTree};
use quote::quote;
use quote::TokenStreamExt;
use syn::parse_macro_input;
use syn::parse_quote;
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::visit_mut::VisitMut;
use syn::FnArg;
use syn::ItemFn;
use syn::Macro;
use syn::{ExprPath, Pat};

#[proc_macro_attribute]
pub fn cfi_mod_fn(_args: TokenStream, input: TokenStream) -> TokenStream {
    cfi_fn(true, input)
}

#[proc_macro_attribute]
pub fn cfi_impl_fn(_args: TokenStream, input: TokenStream) -> TokenStream {
    cfi_fn(false, input)
}

struct SelfRenamer;

impl VisitMut for SelfRenamer {
    fn visit_macro_mut(&mut self, m: &mut Macro) {
        for token in std::mem::take(&mut m.tokens).into_iter() {
            m.tokens.append(match token {
                TokenTree::Ident(ident) => {
                    if ident == "self" {
                        TokenTree::Ident(Ident::new("__cfi_self", ident.span()))
                    } else {
                        TokenTree::Ident(ident)
                    }
                }
                other => other,
            });
        }
    }
    fn visit_expr_path_mut(&mut self, p: &mut ExprPath) {
        if p.path.is_ident("self") {
            *p = parse_quote!(__cfi_self);
        }
    }
}

fn cfi_fn(_mod_fn: bool, input: TokenStream) -> TokenStream {
    let mut func: ItemFn = parse_macro_input!(input as ItemFn);

    let inline_attr = func
        .attrs
        .iter()
        .find(|a| a.path.is_ident("inline"))
        .cloned();

    // Remove the inline attribute from the wrapper function; we'll put this on
    // the closure instead.
    func.attrs.retain(|a| !a.path.is_ident("inline"));

    // For some silly reason, LLVM doesn't optimize as well if we let the
    // closure capture the arguments. So pass them in manually instead.
    let params: Punctuated<FnArg, Comma> = func
        .sig
        .inputs
        .iter()
        .map(|p| match p {
            FnArg::Receiver(r) => {
                let mutability = r.mutability;
                match &r.reference {
                    Some((and, lifetime)) => {
                        parse_quote!(__cfi_self: #and #lifetime #mutability Self)
                    }
                    None => parse_quote!(#mutability __cfi_self: Self),
                }
            }
            FnArg::Typed(t) => FnArg::Typed(t.clone()),
        })
        .collect();

    let args: Punctuated<Box<Pat>, Comma> = func
        .sig
        .inputs
        .iter()
        .map(|p| match p {
            FnArg::Receiver(_) => parse_quote!(self),
            FnArg::Typed(t) => t.pat.clone(),
        })
        .collect();

    let mut orig_block = std::mem::replace(&mut func.block, parse_quote!({}));
    SelfRenamer.visit_block_mut(&mut orig_block);

    func.block.stmts = parse_quote!(
        // This is necessary to allow the inline attribute to be placed on the
        // closure
        fn __cfi_move<R>(r: R) -> R {
            r
        }
        let __cfi_saved_ctr = caliptra_cfi_lib::CfiCounter::read();
        caliptra_cfi_lib::CfiCounter::delay();
        let __cfi_ret = __cfi_move(#inline_attr move |#params| {
            caliptra_cfi_lib::CfiCounter::increment();
            #orig_block
        })(#args);
        caliptra_cfi_lib::CfiCounter::delay();
        let __cfi_new_ctr = caliptra_cfi_lib::CfiCounter::decrement();
        caliptra_cfi_lib::CfiCounter::assert_eq(__cfi_saved_ctr, __cfi_new_ctr);
        __cfi_ret
    );

    quote! {
        #[inline(always)]
        #func
    }
    .into()
}
