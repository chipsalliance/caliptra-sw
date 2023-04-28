# Caliptra - Error Handling and Reporting Specification (RFC)

## Version History

| Date       | Version | Description                                                                        |
| :--------- | :------ | :----------------------------------------------------------------------------------|
| 04/28/2023 | 0.1     | Document Created

The purpose the error handling crate is to provide a common error handling
and reporting mechanisms and type definitions for all Caliptra components.

Caliptra components are entities that can generate errors. Examples of
Caliptra components are the Driver, ROM, FMC, RT, and FIPS.Each Caliptra 
component has a unique identifier that is used to identify the component 
when reporting errors.

The error handling module shall reside in the common crate of the Caliptra
project. The error handling module shall be used by all Caliptra components.

Error handling and reporting is done by raising an error. Caliptra uses the
idiomatic Rust approach of returning a Result type from functions that can
fail. The Caliptra error type should use the newtype pattern and defined 
as follows:

```
struct CaliptraError(pub NonZeroU32)
```

Caliptra Result is an alias of the core::Result type.

```
type CaliptraResult = Result<(), CaliptraError>
```

Caliptra error policy shall partition the 32-bit name error space into three parts:
1. Caliptra component identifier (8 bits)
2. Caliptra sub-component identifier (8 bits)
3. Caliptra error code (16 bits)

See the diagram below for the error space partitioning:                                      

component[31:24]-sub-comp[23:16]-code[15:0]
                                        
The Caliptra sub-component identifier is Caliptra component specific.
The Caliptra error code is Caliptra sub-component specific.

Non fatal error flow propagates all the way to the topmost module of the Caliptra
component. The topmost module is the one that is responsible for reporting
the errors to the system in which the Caliptra .

Error reporting is done via SoC interface registers, more specifically the
fatal and non-fatal error register via the API defined in 
caliptra::drivers::error reporter.

Fatal errors are errors which trigger exceptions and NMI. Fatal errors are
reported via fatal error registers.

Non-fatal errors are errors which are encountered in the course of normal operation and
reported to the user via the non-fatal SoC interface registers.
