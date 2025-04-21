// Licensed under the Apache-2.0 license

use ghac::v1::{
    self as ghac_types, CreateCacheEntryResponse, FinalizeCacheEntryUploadResponse,
    GetCacheEntryDownloadUrlResponse,
};
use prost::Message;

use crate::{
    http::{self, Content, HttpResponse},
    util::{hex, other_err},
    Cache,
};

const VERSION: &str = "caliptra-size-history-cache1";

pub struct GithubActionCache {
    prefix: String,
}
impl GithubActionCache {
    pub fn new() -> std::io::Result<Self> {
        let wrap_err =
            |_| other_err("ACTIONS_RESULTS_URL environment variable not set".to_string());
        let prefix = format!(
            "{}/twirp/github.actions.results.api.v1.CacheService",
            std::env::var("ACTIONS_RESULTS_URL").map_err(wrap_err)?
        );
        Ok(Self { prefix })
    }
}
impl Cache for GithubActionCache {
    fn set(&self, key: &str, val: &[u8]) -> std::io::Result<()> {
        let url_key = format_key(key);
        let request = ghac_types::CreateCacheEntryRequest {
            key: url_key.clone(),
            version: VERSION.into(),
            metadata: None,
        };
        let content = Content::protobuf(request.encode_to_vec());
        let body = Some(&content);
        let response = http::api_post(&format!("{}/CreateCacheEntry", self.prefix), body)?;
        let response: ghac_types::CreateCacheEntryResponse =
            CreateCacheEntryResponse::decode(response.data.as_ref())?;
        if !response.ok {
            return Err(other_err(format!(
                "Unable to create cache entry for {url_key:?}"
            )));
        }
        let cache_url = response.signed_upload_url;
        empty_response(http::api_patch(&cache_url, 0, &Content::octet_stream(val))?)?;
        let request = ghac_types::FinalizeCacheEntryUploadRequest {
            key: url_key.clone(),
            version: VERSION.into(),
            size_bytes: val.len() as i64,
            metadata: None,
        };
        let content = Content::protobuf(request.encode_to_vec());
        let body = Some(&content);
        let response = http::api_post(&format!("{}/FinalizeCacheEntryUpload", self.prefix), body)?;
        let response: ghac_types::FinalizeCacheEntryUploadResponse =
            FinalizeCacheEntryUploadResponse::decode(response.data.as_ref())?;
        if !response.ok {
            return Err(other_err(format!(
                "Unable to finalize cache upload for {url_key:?}"
            )));
        }
        Ok(())
    }

    fn get(&self, key: &str) -> std::io::Result<Option<Vec<u8>>> {
        let url_key = format_key(key);
        let request = ghac_types::GetCacheEntryDownloadUrlRequest {
            key: url_key.clone(),
            version: VERSION.into(),
            metadata: None,
            restore_keys: vec![],
        };
        let content = Content::protobuf(request.encode_to_vec());
        let body = Some(&content);
        let response = http::api_post(&format!("{}/GetCacheEntryDownloadURL", self.prefix), body)?;
        let response: GetCacheEntryDownloadUrlResponse =
            GetCacheEntryDownloadUrlResponse::decode(response.data.as_ref())?;
        if !response.ok {
            return Ok(None);
        }
        if response.matched_key != url_key {
            return Err(other_err(format!(
                "Expected key {url_key:?}, was {:?}",
                response.matched_key
            )));
        }
        let response = http::raw_get(&response.signed_download_url)?;
        Ok(Some(response.data))
    }
}

fn empty_response(response: HttpResponse) -> std::io::Result<()> {
    if !(200..300).contains(&response.status) {
        return Err(other_err(format!(
            "Unexpected response from server {response:?}"
        )));
    }
    Ok(())
}

fn format_key(key: &str) -> String {
    format!("size-history-{}", hex(key.as_bytes()))
}
