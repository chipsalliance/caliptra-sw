// Licensed under the Apache-2.0 license

mod common;
mod test_authorize_and_stash;
mod test_boot;
mod test_certify_key_extended;
#[cfg(feature = "mldsa_attestation")]
mod test_certify_key_extended_mldsa;
mod test_certs;
mod test_command_timing;
mod test_disable;
mod test_ecdsa;
mod test_fips;
mod test_get_fmc_alias_csr;
mod test_get_idev_csr;
#[cfg(feature = "mldsa_attestation")]
mod test_get_pq_cert;
#[cfg(feature = "mldsa_attestation")]
mod test_get_pq_csr;
mod test_info;
mod test_invoke_dpe;
#[cfg(feature = "mldsa_attestation")]
mod test_invoke_dpe_mldsa;
mod test_lms;
mod test_mailbox;
mod test_measurements_common;
#[cfg(feature = "mldsa_attestation")]
mod test_mldsa_verify;
mod test_panic_missing;
mod test_pauser_privilege_levels;
mod test_pcr;
mod test_populate_idev;
mod test_reallocate_dpe_context_limits;
mod test_revoke_exported_cdi_handle;
#[cfg(feature = "mldsa_attestation")]
mod test_revoke_exported_cdi_handle_mldsa;
mod test_set_auth_manifest;
#[cfg(feature = "mldsa_attestation")]
mod test_set_pq_seed;
mod test_sign_with_export_ecdsa;
mod test_stack_usage;
mod test_stash_measurement;
mod test_tagging;
mod test_update_reset;
mod test_warm_reset;
