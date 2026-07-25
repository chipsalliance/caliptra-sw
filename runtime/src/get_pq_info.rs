/*++

Licensed under the Apache-2.0 license.

File Name:

    get_pq_info.rs

Abstract:

    File contains the GET_PQ_INFO mailbox command, which returns the PQ.DevID
    ML-DSA-87 public key -- the post-quantum sibling of GET_IDEV_INFO.

    Unlike the ECDSA IDevID public key (cached in the FHT), the ML-DSA-87 public
    key is re-derived on demand from the persisted PQ.DevID CDI: the seed is
    reconstructed, the public key is computed from it, and the transient seed is
    zeroized.

--*/

use crate::packet::{copy_from_mbox, copy_to_mbox};
use crate::Drivers;
use caliptra_common::mailbox_api::{GetPqInfoReq, GetPqInfoResp};
use caliptra_drivers::{CaliptraResult, Mldsa87, Mldsa87PubKey, Mldsa87Seed};
use zerocopy::{FromZeros, IntoBytes};

pub struct GetPqInfoCmd;

impl GetPqInfoCmd {
    #[inline(never)]
    pub(crate) fn execute(drivers: &mut Drivers) -> CaliptraResult<()> {
        copy_from_mbox(drivers, GetPqInfoReq::new_zeroed().as_mut_bytes())?;

        let mut seed = Mldsa87Seed::default();
        drivers.derive_devid_seed(&mut seed)?;

        let mut pub_key = Mldsa87PubKey::default();
        Mldsa87::pub_from_seed(&seed, &mut pub_key, None)?;
        drop(seed);

        let mut resp = GetPqInfoResp::new_zeroed();
        resp.pq_pub_key.copy_from_slice(pub_key.as_slice());
        copy_to_mbox(drivers, resp.as_mut_bytes())
    }
}
