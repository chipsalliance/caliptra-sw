/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_idev.rs

Abstract:

    File contains PopulateIdev mailbox command.

--*/

use caliptra_common::mailbox_api::{PopulateIdevEcc384CertReq, PopulateIdevMldsa87CertReq};
use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::FromBytes;

use crate::{Drivers, PL0_PAUSER_FLAG};

pub struct PopulateIDevIdEcc384CertCmd;
impl PopulateIDevIdEcc384CertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
        // To avoid placing Req on the stack do a rw zerocopy on the mailbox content
        // This is ok as we check the size of the input and cert_size
        let mbox_raw = &drivers
            .mbox
            .raw_mailbox_contents()
            .get(..core::mem::size_of::<PopulateIdevEcc384CertReq>())
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)?;
        let cmd = PopulateIdevEcc384CertReq::read_from_bytes(mbox_raw)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)?;

        if cmd_args.len() > core::mem::size_of::<PopulateIdevEcc384CertReq>() {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }

        let cert_size = cmd.cert_size as usize;
        if cert_size > cmd.cert.len() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        let flags = drivers.persistent_data.get().manifest1.header.flags;
        // PL1 cannot call this mailbox command
        if flags & PL0_PAUSER_FLAG == 0 {
            return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
        }

        // Avoid stack allocation by reusing the existing ArrayVec in-place.
        // Instead of creating a temporary ArrayVec, we shift existing content
        // down and insert the new certificate at the beginning.
        // Check if we have enough capacity for the new cert plus existing content
        let current_len = drivers.ecc_cert_chain.len();
        if cert_size + current_len > drivers.ecc_cert_chain.capacity() {
            return Err(CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED);
        }

        // Move existing content down by cert_size bytes and copy new cert
        if current_len > 0 {
            // Append zeros to make room for the new cert
            for _ in 0..cert_size {
                drivers
                    .ecc_cert_chain
                    .try_push(0)
                    .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
            }

            // Move existing content down (reverse iteration to avoid overwriting)
            for i in (0..current_len).rev() {
                let src_idx = i;
                let dst_idx = i + cert_size;
                if let Some(src_val) = drivers.ecc_cert_chain.get(src_idx).copied() {
                    if let Some(dst) = drivers.ecc_cert_chain.get_mut(dst_idx) {
                        *dst = src_val;
                    } else {
                        return Err(CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED);
                    }
                } else {
                    return Err(CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED);
                }
            }
        } else {
            // No existing content, just append zeros
            for _ in 0..cert_size {
                drivers
                    .ecc_cert_chain
                    .try_push(0)
                    .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
            }
        }

        // Copy new cert data to the beginning
        drivers
            .ecc_cert_chain
            .as_mut_slice()
            .get_mut(..cert_size)
            .ok_or(CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?
            .copy_from_slice(&cmd.cert[..cert_size]);

        Ok(0)
    }
}

pub struct PopulateIDevIdMldsa87CertCmd;
impl PopulateIDevIdMldsa87CertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
        // To avoid placing Req on the stack do a rw zerocopy on the mailbox content
        let mbox_raw = &drivers
            .mbox
            .raw_mailbox_contents()
            .get(..core::mem::size_of::<PopulateIdevMldsa87CertReq>())
            .ok_or(CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)?;
        let cmd = PopulateIdevMldsa87CertReq::read_from_bytes(mbox_raw)
            .map_err(|_| CaliptraError::RUNTIME_MAILBOX_API_REQUEST_DATA_LEN_TOO_LARGE)?;

        if cmd_args.len() > core::mem::size_of::<PopulateIdevMldsa87CertReq>() {
            return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
        }

        let cert_size = cmd.cert_size as usize;
        if cert_size > cmd.cert.len() {
            return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
        }

        let flags = drivers.persistent_data.get().manifest1.header.flags;
        // PL1 cannot call this mailbox command
        if flags & PL0_PAUSER_FLAG == 0 {
            return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
        }

        // Avoid stack allocation by reusing the existing ArrayVec in-place.
        // Instead of creating a temporary ArrayVec, we shift existing content
        // down and insert the new certificate at the beginning.
        // Check if we have enough capacity for the new cert plus existing content
        let current_len = drivers.mldsa_cert_chain.len();
        if cert_size + current_len > drivers.mldsa_cert_chain.capacity() {
            return Err(CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED);
        }

        // Move existing content down by cert_size bytes and copy new cert
        if current_len > 0 {
            // Append zeros to make room for the new cert
            for _ in 0..cert_size {
                drivers
                    .mldsa_cert_chain
                    .try_push(0)
                    .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
            }

            // Move existing content down (reverse iteration to avoid overwriting)
            for i in (0..current_len).rev() {
                let src_idx = i;
                let dst_idx = i + cert_size;
                if let Some(src_val) = drivers.mldsa_cert_chain.get(src_idx).copied() {
                    if let Some(dst) = drivers.mldsa_cert_chain.get_mut(dst_idx) {
                        *dst = src_val;
                    } else {
                        return Err(CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED);
                    }
                } else {
                    return Err(CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED);
                }
            }
        } else {
            // No existing content, just append zeros
            for _ in 0..cert_size {
                drivers
                    .mldsa_cert_chain
                    .try_push(0)
                    .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
            }
        }

        // Copy new cert data to the beginning
        drivers
            .mldsa_cert_chain
            .as_mut_slice()
            .get_mut(..cert_size)
            .ok_or(CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?
            .copy_from_slice(&cmd.cert[..cert_size]);

        Ok(0)
    }
}
