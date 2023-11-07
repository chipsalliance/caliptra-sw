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
use quote::{format_ident, quote, ToTokens};
use syn::__private::TokenStream2;
use syn::parse_macro_input;
use syn::parse_quote;
use syn::FnArg;
use syn::ItemFn;

#[proc_macro_attribute]
pub fn cfi_mod_fn(_args: TokenStream, input: TokenStream) -> TokenStream {
    cfi_fn(true, input)
}

#[proc_macro_attribute]
pub fn cfi_impl_fn(_args: TokenStream, input: TokenStream) -> TokenStream {
    cfi_fn(false, input)
}

fn cfi_fn(mod_fn: bool, input: TokenStream) -> TokenStream {
    let mut wrapper_fn: ItemFn = parse_macro_input!(input as ItemFn);
    let mut orig_fn = wrapper_fn.clone();
    orig_fn.sig.ident = format_ident!("__cfi_{}", wrapper_fn.sig.ident);
    orig_fn.attrs.clear();
    orig_fn.vis = syn::Visibility::Inherited;

    let fn_name = format_ident!("{}", orig_fn.sig.ident);

    let param_names: Vec<TokenStream2> = orig_fn
        .sig
        .inputs
        .iter()
        .map(|input| match input {
            FnArg::Receiver(r) => r.self_token.to_token_stream(),
            FnArg::Typed(p) => p.pat.to_token_stream(),
        })
        .collect();

    let fn_call = if mod_fn {
        quote!(#fn_name( #(#param_names,)* ))
    } else {
        quote!(Self::#fn_name( #(#param_names,)* ))
    };

    wrapper_fn.block.stmts.clear();
    wrapper_fn.block.stmts = parse_quote!(
        let saved_ctr = caliptra_cfi_lib::CfiCounter::read();
        caliptra_cfi_lib::CfiCounter::delay();
        let ret = #fn_call;
        caliptra_cfi_lib::CfiCounter::delay();
        let new_ctr = caliptra_cfi_lib::CfiCounter::decrement();
        caliptra_cfi_lib::CfiCounter::assert_eq(saved_ctr, new_ctr);
        ret
    );

    // Add inline attribute to the wrapper function.
    let inline_attr = parse_quote! {
    #[inline(always)]
     };

    wrapper_fn.attrs.insert(wrapper_fn.attrs.len(), inline_attr);

    // Add CFI counter increment statement to the beginning of the original function.
    orig_fn.block.stmts.insert(
        0,
        parse_quote!(
            caliptra_cfi_lib::CfiCounter::increment();
        ),
    );

    let code = quote! {
            #wrapper_fn
            #orig_fn
    };

    code.into()
}
