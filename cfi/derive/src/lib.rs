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
use quote::quote;
use syn::parse_macro_input;
use syn::parse_quote;
use syn::ItemFn;

#[proc_macro_attribute]
pub fn cfi_mod_fn(_args: TokenStream, input: TokenStream) -> TokenStream {
    cfi_fn(true, input)
}

#[proc_macro_attribute]
pub fn cfi_impl_fn(_args: TokenStream, input: TokenStream) -> TokenStream {
    cfi_fn(false, input)
}

fn cfi_fn(_mod_fn: bool, input: TokenStream) -> TokenStream {
    let mut f: ItemFn = parse_macro_input!(input as ItemFn);

    let inline_attr = f.attrs.iter().find(|a| a.path.is_ident("inline")).cloned();

    // Remove the inline attribute from the wrapper function; we'll put this on
    // the closure instead.
    f.attrs.retain(|a| !a.path.is_ident("inline"));

    let orig_block = std::mem::replace(&mut f.block, parse_quote!({}));
    f.block.stmts = parse_quote!(
        // This is necessary to allow the inline attribute to be placed on the
        // closure
        fn __cfi_move<R>(r: R) -> R {
            r
        }
        let __cfi_saved_ctr = caliptra_cfi_lib::CfiCounter::read();
        caliptra_cfi_lib::CfiCounter::delay();
        let __cfi_ret = __cfi_move(#inline_attr move || {
            caliptra_cfi_lib::CfiCounter::increment();
            #orig_block
        })();
        caliptra_cfi_lib::CfiCounter::delay();
        let __cfi_new_ctr = caliptra_cfi_lib::CfiCounter::decrement();
        caliptra_cfi_lib::CfiCounter::assert_eq(__cfi_saved_ctr, __cfi_new_ctr);
        __cfi_ret
    );

    quote! {
        #[inline(always)]
        #f
    }
    .into()
}
