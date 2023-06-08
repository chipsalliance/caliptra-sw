// Licensed under the Apache-2.0 license

use serde::{Deserialize, Serialize};

use crate::{
    http::{self, Content, HttpResponse},
    util::{hex, other_err},
    Cache,
};

const VERSION: &str = "caliptra-size-history-cache0";

pub struct GithubActionCache {
    prefix: String,
}
impl GithubActionCache {
    pub fn new() -> std::io::Result<Self> {
        let wrap_err = |_| other_err("ACTIONS_CACHE_URL environment variable not set".to_string());
        let prefix = format!(
            "{}/_apis/artifactcache",
            std::env::var("ACTIONS_CACHE_URL").map_err(wrap_err)?
        );
        Ok(Self { prefix })
    }
}
impl Cache for GithubActionCache {
    fn set(&self, key: &str, val: &[u8]) -> std::io::Result<()> {
        let response = http::api_post(
            &format!("{}/caches", self.prefix),
            Some(&Content::json(&CacheReserveRequest {
                key: format_key(key),
                version: VERSION.into(),
            })),
        )?;
        let response: CacheReserveResponse = json_response(&response)?;
        let cache_url = &format!("{}/caches/{}", self.prefix, response.cache_id);
        empty_response(http::api_patch(cache_url, 0, &Content::octet_stream(val))?)?;
        empty_response(http::api_post(
            cache_url,
            Some(&Content::json(&CacheFinalize {
                size: val.len() as u64,
            })),
        )?)?;
        Ok(())
    }

    fn get(&self, key: &str) -> std::io::Result<Option<Vec<u8>>> {
        let url_key = format_key(key);
        let response = http::api_get(&format!(
            "{}/cache?keys={url_key}&version={VERSION}",
            self.prefix
        ))?;
        if response.status == 204 {
            return Ok(None);
        }
        let response: CacheResponse = json_response(&response)?;
        if response.cache_key != url_key {
            return Err(other_err(format!(
                "Expected key {url_key:?}, was {:?}",
                response.cache_key
            )));
        }
        let response = http::raw_get(&response.archive_location)?;
        Ok(Some(response.data))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CacheResponse {
    cache_key: String,
    #[allow(dead_code)]
    scope: String,
    archive_location: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CacheReserveRequest {
    key: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CacheReserveResponse {
    cache_id: u64,
}

#[derive(Serialize)]
struct CacheFinalize {
    size: u64,
}

fn empty_response(response: HttpResponse) -> std::io::Result<()> {
    if !(200..300).contains(&response.status) {
        return Err(other_err(format!(
            "Unexpected response from server {response:?}"
        )));
    }
    Ok(())
}

fn json_response<'a, T: Deserialize<'a>>(response: &'a HttpResponse) -> std::io::Result<T> {
    if !(200..300).contains(&response.status) {
        return Err(other_err(format!(
            "Unexpected response from server {response:?}"
        )));
    }
    serde_json::from_slice(&response.data)
        .map_err(|_| other_err(format!("Unable to parse response {response:?}")))
}

fn format_key(key: &str) -> String {
    format!("size-history-{}", hex(key.as_bytes()))
}
