// Licensed under the Apache-2.0 license

use std::{borrow::Cow, io, process::Command};

use serde::Serialize;
use std::str::FromStr;

use crate::{
    process::run_cmd_stdout,
    util::{expect_line_with_prefix, other_err},
};

pub struct Content<'a> {
    mime_type: Cow<'a, str>,
    data: Cow<'a, [u8]>,
}

impl<'a> Content<'a> {
    pub fn octet_stream(val: impl Into<Cow<'a, [u8]>>) -> Self {
        Self {
            mime_type: "application/octet-stream".into(),
            data: val.into(),
        }
    }
    pub fn json(val: &impl Serialize) -> Content {
        Content {
            mime_type: "application/json".into(),
            data: serde_json::to_string(val).unwrap().into_bytes().into(),
        }
    }
}

pub struct HttpResponse {
    pub status: u32,
    pub content_type: String,
    pub data: Vec<u8>,
}

impl HttpResponse {
    fn parse(raw: Vec<u8>) -> io::Result<Self> {
        use std::io::BufRead;
        let mut raw = &raw[..];
        let mut line = String::new();
        raw.read_line(&mut line)?;
        let status_str = expect_line_with_prefix("HTTP/1.1 ", Some(&line))
            .or_else(|_| expect_line_with_prefix("HTTP/2 ", Some(&line)))?;
        if status_str.len() < 3 {
            return Err(other_err(format!("HTTP line too short: {line:?}")));
        }
        let status = u32::from_str(&status_str[..3])
            .map_err(|_| other_err(format!("Bad HTTP status code: {line:?}")))?;
        let mut content_type = String::new();
        loop {
            let mut line = String::new();
            raw.read_line(&mut line)?;
            if line == "\r\n" {
                break;
            }
            if let Ok(header_val) = expect_line_with_prefix("Content-Type: ", Some(&line)) {
                content_type = header_val.trim().into();
            }
        }
        Ok(HttpResponse {
            status,
            content_type,
            data: raw.into(),
        })
    }
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("data", &String::from_utf8_lossy(&self.data))
            .finish()
    }
}

fn auth_header() -> io::Result<String> {
    let token = std::env::var("ACTIONS_RUNTIME_TOKEN")
        .map_err(|_| other_err("env-var ACTIONS_RUNTIME_TOKEN must be set"))?;
    Ok(format!("Authorization: Bearer {token}"))
}

pub fn raw_get(url: &str) -> io::Result<HttpResponse> {
    HttpResponse::parse(run_cmd_stdout(
        Command::new("curl").arg("-sSi").arg(url),
        None,
    )?)
}

pub fn api_get(url: &str) -> io::Result<HttpResponse> {
    HttpResponse::parse(run_cmd_stdout(
        Command::new("curl")
            .arg("-sSi")
            .arg(url)
            .arg("-H")
            .arg(auth_header()?)
            .arg("-H")
            .arg("Accept: application/json;api-version=6.0-preview.1"),
        None,
    )?)
}

pub fn api_post(url: &str, content: Option<&Content>) -> io::Result<HttpResponse> {
    let mut cmd = Command::new("curl");
    cmd.arg("-sSi");
    cmd.arg("-X").arg("POST");
    cmd.arg("-H").arg(auth_header()?);
    cmd.arg("-H")
        .arg("Accept: application/json;api-version=6.0-preview.1");
    if let Some(content) = content {
        cmd.arg("-H")
            .arg(format!("Content-Type: {}", content.mime_type));
        cmd.arg("--data-binary").arg("@-");
        cmd.arg(url);
        HttpResponse::parse(run_cmd_stdout(&mut cmd, Some(&content.data))?)
    } else {
        cmd.arg(url);
        HttpResponse::parse(run_cmd_stdout(&mut cmd, None)?)
    }
}

pub fn api_patch(url: &str, offset: u64, content: &Content) -> io::Result<HttpResponse> {
    HttpResponse::parse(run_cmd_stdout(
        Command::new("curl")
            .arg("-sSi")
            .arg("-H")
            .arg(format!("Content-Type: {}", content.mime_type))
            .arg("-H")
            .arg(format!(
                "Content-Range: bytes {offset}-{}/*",
                offset + (content.data.len() as u64)
            ))
            .arg("-H")
            .arg("Accept: application/json;api-version=6.0-preview.1")
            .arg("-H")
            .arg(auth_header()?)
            .arg("-X")
            .arg("PATCH")
            .arg("--data-binary")
            .arg("@-")
            .arg(url),
        Some(&content.data),
    )?)
}
