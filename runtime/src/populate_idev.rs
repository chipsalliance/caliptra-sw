/*++

Licensed under the Apache-2.0 license.

File Name:

    populate_idev.rs

Abstract:

    File contains PopulateIdev mailbox command.

--*/

use arrayvec::ArrayVec;
use caliptra_common::mailbox_api::{PopulateIdevEcc384CertReq, PopulateIdevMldsa87CertReq};
use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::IntoBytes;

use crate::{Drivers, MAX_ECC_CERT_CHAIN_SIZE, MAX_MLDSA_CERT_CHAIN_SIZE, PL0_PAUSER_FLAG};

pub struct PopulateIDevIdEcc384CertCmd;
impl PopulateIDevIdEcc384CertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
        if cmd_args.len() <= core::mem::size_of::<PopulateIdevEcc384CertReq>() {
            let mut cmd = PopulateIdevEcc384CertReq::default();
            cmd.as_mut_bytes()[..cmd_args.len()].copy_from_slice(cmd_args);

            let cert_size = cmd.cert_size as usize;
            if cert_size > cmd.cert.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            let flags = drivers.persistent_data.get().manifest1.header.flags;
            // PL1 cannot call this mailbox command
            if flags & PL0_PAUSER_FLAG == 0 {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }

            let mut tmp_chain = ArrayVec::<u8, MAX_ECC_CERT_CHAIN_SIZE>::new();
            tmp_chain
                .try_extend_from_slice(&cmd.cert[..cert_size])
                .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
            tmp_chain
                .try_extend_from_slice(drivers.ecc_cert_chain.as_slice())
                .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
            drivers.ecc_cert_chain = tmp_chain;

            Ok(0)
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}

pub struct PopulateIDevIdMldsa87CertCmd;
impl PopulateIDevIdMldsa87CertCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers, cmd_args: &[u8]) -> CaliptraResult<usize> {
        if cmd_args.len() <= core::mem::size_of::<PopulateIdevMldsa87CertReq>() {
            let mut cmd = PopulateIdevMldsa87CertReq::default();
            cmd.as_mut_bytes()[..cmd_args.len()].copy_from_slice(cmd_args);

            let cert_size = cmd.cert_size as usize;
            if cert_size > cmd.cert.len() {
                return Err(CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS);
            }

            let flags = drivers.persistent_data.get().manifest1.header.flags;
            // PL1 cannot call this mailbox command
            if flags & PL0_PAUSER_FLAG == 0 {
                return Err(CaliptraError::RUNTIME_INCORRECT_PAUSER_PRIVILEGE_LEVEL);
            }

            let mut tmp_chain = ArrayVec::<u8, MAX_MLDSA_CERT_CHAIN_SIZE>::new();
            tmp_chain
                .try_extend_from_slice(&cmd.cert[..cert_size])
                .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
            tmp_chain
                .try_extend_from_slice(drivers.mldsa_cert_chain.as_slice())
                .map_err(|_| CaliptraError::RUNTIME_IDEV_CERT_POPULATION_FAILED)?;
            drivers.mldsa_cert_chain = tmp_chain;

            Ok(0)
        } else {
            Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)
        }
    }
}
