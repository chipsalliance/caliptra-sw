// Licensed under the Apache-2.0 license

use crate::common::run_rt_test_lms;
use crate::test_set_auth_manifest::generate_auth_manifest;
use crate::test_set_image_metadata::{
    generate_image_metadata, get_ims_actual_size, send_auth_manifest_cmd, IMAGE_DIGEST1,
    IMAGE_DIGEST2,
};
use caliptra_auth_man_types::AuthManifestFlags;
use caliptra_common::mailbox_api::{AuthAndStashFlags, SetImageMetadataReq};
use caliptra_common::mailbox_api::{
    AuthorizeAndStashReq, AuthorizeAndStashResp, CommandId, ImageHashSource, MailboxReq,
    MailboxReqHeader,
};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{DefaultHwModel, HwModel};
use caliptra_runtime::RtBootStatus;
use caliptra_runtime::{IMAGE_AUTHORIZED, IMAGE_HASH_NOT_FOUND, IMAGE_NOT_AUTHORIZED};
use zerocopy::{AsBytes, FromBytes};

fn send_image_metadata_cmd(payload: &[u8], model: &mut DefaultHwModel) {
    let mut ims_slice = [0u8; SetImageMetadataReq::MAX_SIZE];
    ims_slice[..payload.len()].copy_from_slice(payload);

    let mut set_image_metadata_cmd = MailboxReq::SetImageMetadata(SetImageMetadataReq {
        hdr: MailboxReqHeader { chksum: 0 },
        metadata_size: payload.len() as u32,
        metadata: ims_slice,
    });
    set_image_metadata_cmd.populate_chksum().unwrap();

    model
        .mailbox_execute(
            u32::from(CommandId::SET_IMAGE_METADATA),
            set_image_metadata_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .expect("We should have received a response");
}

fn test_authorization(
    payload: &[u8],
    _expected_err: Option<CaliptraError>,
    model: Option<&mut DefaultHwModel>,
    auth_result: u32,
) {
    let mut model_instance: Option<DefaultHwModel>;

    let model = if model.is_none() {
        model_instance = Some(run_rt_test_lms(None, None, None, true));

        if let Some(ref mut instance) = model_instance {
            instance.step_until(|m| {
                m.soc_ifc().cptra_boot_status().read()
                    == u32::from(RtBootStatus::RtReadyForCommands)
            });
        }
        model_instance.as_mut()
    } else {
        model
    };
    let model = model.unwrap();

    let resp = model
        .mailbox_execute(u32::from(CommandId::AUTHORIZE_AND_STASH), payload)
        .unwrap()
        .expect("We should have received a response");

    let authorize_and_stash_resp = AuthorizeAndStashResp::read_from(resp.as_slice()).unwrap();
    assert_eq!(authorize_and_stash_resp.auth_req_result, auth_result);
}

#[test]
fn test_authorization_allowed() {
    let flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED;
    let auth_man = generate_auth_manifest(flags);
    let mut model = send_auth_manifest_cmd(auth_man.as_bytes());

    let ims = generate_image_metadata(flags);
    send_image_metadata_cmd(
        ims.as_bytes()[..get_ims_actual_size(&ims)].as_ref(),
        &mut model,
    );

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: 1,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: AuthAndStashFlags::SKIP_STASH.bits(),
        ..Default::default()
    });
    authorize_and_stash_cmd.populate_chksum().unwrap();

    test_authorization(
        authorize_and_stash_cmd.as_bytes().unwrap(),
        None,
        Some(&mut model),
        IMAGE_AUTHORIZED,
    );
}

#[test]
fn test_authorization_denied() {
    let flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED;
    let auth_man = generate_auth_manifest(flags);
    let mut model = send_auth_manifest_cmd(auth_man.as_bytes());

    let ims = generate_image_metadata(flags);
    send_image_metadata_cmd(
        ims.as_bytes()[..get_ims_actual_size(&ims)].as_ref(),
        &mut model,
    );

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: u32::MAX,
        measurement: IMAGE_DIGEST1,
        source: ImageHashSource::InRequest as u32,
        flags: AuthAndStashFlags::SKIP_STASH.bits(),
        ..Default::default()
    });
    authorize_and_stash_cmd.populate_chksum().unwrap();

    test_authorization(
        authorize_and_stash_cmd.as_bytes().unwrap(),
        None,
        Some(&mut model),
        IMAGE_NOT_AUTHORIZED,
    );
}

#[test]
fn test_authorization_fwid_present_image_digest_absent() {
    let flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED;
    let auth_man = generate_auth_manifest(flags);
    let mut model = send_auth_manifest_cmd(auth_man.as_bytes());

    let ims = generate_image_metadata(flags);
    send_image_metadata_cmd(
        ims.as_bytes()[..get_ims_actual_size(&ims)].as_ref(),
        &mut model,
    );

    let mut authorize_and_stash_cmd = MailboxReq::AuthorizeAndStash(AuthorizeAndStashReq {
        hdr: MailboxReqHeader { chksum: 0 },
        fw_id: 1,
        measurement: IMAGE_DIGEST2,
        source: ImageHashSource::InRequest as u32,
        flags: AuthAndStashFlags::SKIP_STASH.bits(),
        ..Default::default()
    });
    authorize_and_stash_cmd.populate_chksum().unwrap();

    test_authorization(
        authorize_and_stash_cmd.as_bytes().unwrap(),
        None,
        Some(&mut model),
        IMAGE_HASH_NOT_FOUND,
    );
}
