/*++

Licensed under the Apache-2.0 license.

File Name:

    macros.rs

Abstract:

    Macros used by the project

--*/

#[macro_export]
macro_rules! trace_instr {
    ($tracer:expr, $pc:expr, $instr:expr) => {
        if let Some(tracer) = $tracer {
            tracer($pc, $instr);
        }
    };
}
