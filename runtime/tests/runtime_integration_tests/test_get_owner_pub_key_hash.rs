// Licensed under the Apache-2.0 license

use caliptra_api::mailbox::GetOwnerPubKeyHashResp;
use caliptra_common::mailbox_api::{CommandId, MailboxReqHeader};
use caliptra_hw_model::HwModel;
use zerocopy::{AsBytes, FromBytes};

use crate::common::{run_rt_test, RuntimeTestArgs};

#[test]
fn test_get_owner_pub_key_hash() {
    let mut model = run_rt_test(RuntimeTestArgs::default());

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::GET_OWNER_PUB_KEY_HASH),
            &[],
        ),
    };

    let result =
        model.mailbox_execute(CommandId::GET_OWNER_PUB_KEY_HASH.into(), payload.as_bytes());

    let response = result.unwrap().unwrap();

    let get_owner_pub_key_hash_resp =
        GetOwnerPubKeyHashResp::read_from(response.as_bytes()).unwrap();

    // Check against our fake owner public key hash
    let mut exp_pub_key_hash =
        openssl::sha::sha384(caliptra_image_fake_keys::OWNER_PUBLIC_KEYS.as_bytes());
    // FLip endianness by each dword for the hash
    for dword in exp_pub_key_hash.chunks_exact_mut(4) {
        dword.reverse();
    }
    assert_eq!(exp_pub_key_hash, get_owner_pub_key_hash_resp.key_hash);
}
