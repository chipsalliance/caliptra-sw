/*++

Licensed under the Apache-2.0 license.

File Name:

    wait.rs

Abstract:

    File contains common functions and macros to implement wait routines.

--*/

pub fn until<F>(predicate: F)
where
    F: Fn() -> bool,
{
    while !predicate() {}
}
