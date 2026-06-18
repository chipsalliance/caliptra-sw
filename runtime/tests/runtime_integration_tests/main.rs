// Licensed under the Apache-2.0 license

#![allow(dead_code, unused_imports)]

mod common;
#[cfg(any())]
mod test_activate_firmware;
mod test_attested_csr;
#[cfg(any())]
mod test_authorize_and_stash;
#[cfg(any())]
mod test_boot;
#[cfg(any())]
mod test_cap_warmreset;
#[cfg(any())]
mod test_capabilities;
#[cfg(any())]
mod test_certify_key_chunks;
#[cfg(any())]
mod test_certify_key_extended;
#[cfg(any())]
mod test_certs;
#[cfg(any())]
mod test_certs_384_warmreset;
mod test_cryptographic_mailbox;
#[cfg(any())]
mod test_debug_unlock;
#[cfg(any())]
mod test_disable;
#[cfg(any())]
mod test_ecdsa;
#[cfg(any())]
mod test_encrypted_firmware;
#[cfg(any())]
mod test_fe_programming;
mod test_fips;
#[cfg(any())]
mod test_firmware_verify;
#[cfg(any())]
mod test_get_fmc_alias_csr;
#[cfg(any())]
mod test_get_idev_csr;
#[cfg(any())]
mod test_get_image_info;
#[cfg(any())]
mod test_info;
#[cfg(any())]
mod test_invoke_dpe;
#[cfg(any())]
mod test_lms;
#[cfg(any())]
mod test_mailbox;
mod test_mldsa;
#[cfg(any())]
mod test_ocp_lock;
#[cfg(any())]
mod test_panic_missing;
#[cfg(any())]
mod test_pauser_privilege_levels;
mod test_pcr;
#[cfg(any())]
mod test_populate_idev;
#[cfg(any())]
mod test_reallocate_dpe_context_limits;
#[cfg(any())]
mod test_recovery_flow;
#[cfg(any())]
mod test_revoke_exported_cdi_handle;
#[cfg(any())]
mod test_set_auth_manifest;
#[cfg(any())]
mod test_sign_with_export_ecdsa;
#[cfg(any())]
mod test_sign_with_export_mldsa;
#[cfg(any())]
mod test_stash_measurement;
#[cfg(any())]
mod test_tagging;
#[cfg(any())]
mod test_update_reset;
#[cfg(any())]
mod test_warm_reset;
