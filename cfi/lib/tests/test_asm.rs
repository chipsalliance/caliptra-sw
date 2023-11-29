// Licensed under the Apache-2.0 license

#![cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]

// This test only runs on risc-v.
// To test, run "cargo install cross", then "cross test --target
// riscv64gc-unknown-linux-gnu"

use std::cell::RefCell;
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use caliptra_error::CaliptraError;

thread_local! {
    static CFI_PANIC_CALLED: RefCell<Arc<AtomicU32>> = RefCell::new(Arc::new(0.into()));
}

#[no_mangle]
extern "C" fn cfi_panic_handler(code: u32) -> ! {
    // This function cannot return or panic, so the only way we have to detect
    // this call is to set a thread-local variable that can be checked from
    // another thread before hanging this thread forever.
    CFI_PANIC_CALLED.with(|c| c.borrow_mut().store(code, Relaxed));

    #[allow(clippy::empty_loop)]
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
pub fn test_assert_eq_12words_success() {
    CFI_PANIC_CALLED.with(|c| c.borrow_mut().store(0, Relaxed));
    use caliptra_cfi_lib::cfi_assert_eq_12_words;
    let a = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let b = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    // Make sure these are separate memory addresses
    assert_ne!(a.as_ptr(), b.as_ptr());
    cfi_assert_eq_12_words(&a, &b);
    assert_eq!(CFI_PANIC_CALLED.with(|c| c.borrow_mut().load(Relaxed)), 0);
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[test]
pub fn test_assert_eq_12words_failure() {
    use caliptra_cfi_lib::cfi_assert_eq_12_words;

    let cfi_panic_called = Arc::new(AtomicU32::new(0));
    let cfi_panic_called2 = cfi_panic_called.clone();

    std::thread::spawn(|| {
        CFI_PANIC_CALLED.with(|c| c.replace(cfi_panic_called2));
        cfi_assert_eq_12_words(
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12],
        );
    });
    let val = loop {
        let val = cfi_panic_called.load(Relaxed);
        if val != 0 {
            break val;
        }
    };
    assert_eq!(val, CaliptraError::ROM_CFI_PANIC_ASSERT_EQ_FAILURE.into());

    // Leak thread in infinite loop...
}

#[test]
pub fn test_assert_eq_6words_success() {
    CFI_PANIC_CALLED.with(|c| c.borrow_mut().store(0, Relaxed));
    use caliptra_cfi_lib::cfi_assert_eq_6_words;
    let a = [0, 1, 2, 3, 4, 5];
    let b = [0, 1, 2, 3, 4, 5];
    // Make sure these are separate memory addresses
    assert_ne!(a.as_ptr(), b.as_ptr());
    cfi_assert_eq_6_words(&a, &b);
    assert_eq!(CFI_PANIC_CALLED.with(|c| c.borrow_mut().load(Relaxed)), 0);
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[test]
pub fn test_assert_eq_6words_failure() {
    use caliptra_cfi_lib::cfi_assert_eq_6_words;

    let cfi_panic_called = Arc::new(AtomicU32::new(0));
    let cfi_panic_called2 = cfi_panic_called.clone();

    std::thread::spawn(|| {
        CFI_PANIC_CALLED.with(|c| c.replace(cfi_panic_called2));
        cfi_assert_eq_6_words(&[0, 1, 2, 3, 4, 0x8000_0005], &[0, 1, 2, 3, 4, 5]);
    });
    let val = loop {
        let val = cfi_panic_called.load(Relaxed);
        if val != 0 {
            break val;
        }
    };
    assert_eq!(val, CaliptraError::ROM_CFI_PANIC_ASSERT_EQ_FAILURE.into());

    // Leak thread in infinite loop...
}
