use anyhow::{anyhow, bail, Result};
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt::Debug;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Version {
    acv_version: String,
}

impl Default for Version {
    fn default() -> Self {
        Version {
            acv_version: "1.0".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AlgorithmAesCbc {
    algorithm: String,
    revision: String,
    direction: Vec<String>,
    key_len: Vec<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewTestSessionResponse {
    acvp_version: String,
    url: String,
    created_on: String,
    expires_on: String,
    encrypt_at_rest: bool,
    vector_set_urls: Vec<String>,
    publishable: bool,
    passed: bool,
    is_sample: bool,
    access_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    access_token: String,
    large_endpoint_required: bool,
    size_constraint: i32,
}

fn login(server_url: &str, cert_file: &str, key_file: &str, totp64: &str) -> Result<String> {
    use base64::prelude::*;
    let version = Version::default();
    let mut totp_secret = vec![0u8; totp64.len()];
    let len = BASE64_STANDARD_NO_PAD
        .decode_slice(totp64.trim(), &mut totp_secret)
        .map_err(|e| anyhow!("Error decoding base64 TOTP secret"))?;
    totp_secret.truncate(len);
    let totp = totp_rs::TOTP::new(totp_rs::Algorithm::SHA256, 8, 0, 30, totp_secret)?;
    let totp = totp.generate_current()?;
    let req_json = json!([
        version,
        {
            "password": totp,
        }
    ]);

    Ok(req_json.to_string())
}

/// Parses the login response and returns the access token.
fn parse_login_resp(resp: &str) -> Result<String> {
    let v: Value = serde_json::from_str(resp)?;
    if let Value::Array(ref arr) = v {
        if arr.len() == 2 {
            let resp: LoginResponse = serde_json::from_value(arr[1].clone())?;
            return Ok(resp.access_token);
        }
    }
    bail!("Unexpected response format: {:?}", v)
}

fn register(server_url: &str) -> Result<()> {
    let version = Version::default();
    let alg = AlgorithmAesCbc {
        algorithm: "ACVP-AES-CBC".to_string(),
        revision: "1.0".to_string(),
        direction: vec!["encrypt".to_string()],
        key_len: vec![256],
    };
    let new_session_request = json!([version,
    {
        "isSample": true,
        "algorithms": [alg]
    }]);

    println!("Request to register: {}", new_session_request);
    let resp = r#"
    [
        {"acvVersion": "1.0"},
        {
            "url": "/acvp/v1/testSessions/2",
            "acvpVersion": "1.0",
            "createdOn": "2018-05-31T12:03:43Z",
            "expiresOn": "2018-06-30T12:03:43Z",
            "encryptAtRest": false,
            "vectorSetUrls": [
                "/acvp/v1/testSessions/2/vectorSets/10",
                "/acvp/v1/testSessions/2/vectorSets/11",
                "/acvp/v1/testSessions/2/vectorSets/12"
            ],
            "publishable": false,
            "passed": true,
            "isSample": true,
            "accessToken" : "eyJhbGciOiJIUzI1NiIsInR5cCI6Ik"
        }
    ]
    "#;

    let v: Value = serde_json::from_str(resp)?;

    match v {
        Value::Array(arr) if arr.len() == 2 => {
            let session_resp: NewTestSessionResponse = serde_json::from_value(arr[1].clone())?;
            println!("Session resp: {:?}", session_resp);
        }
        _ => {
            eprintln!("Unexpected response format: {:?}", v);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_response_parse() {
        // this is a fake token that resembles the real JWT the demo server sends
        let jwt = r#"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJFPWFAZXhhbXBsZS5jb20sIENOPUFCLCBPVT1Tb2Z0d2FyZSwgTz1DYWxpcHRyYSwgUz1PcmVnb24sIEM9VVMiLCJuYmYiOjE3NDgzODIyOTEsImV4cCI6MTc0ODM4NDA5MSwiaWF0IjoxNzQ4MzgyMjkxLCJpc3MiOiJOSVNUIEFDVlAgREVNTyJ9.E2NBJqUmh2IXW2rwM4DRVtBmf2w10Oz0JP1QsUF31qQ"#;
        let resp = json!([
            {
                "acvVersion": "1.0"
            },
            {
                "accessToken": jwt,
                "largeEndpointRequired": false,
                "sizeConstraint": -1
            }
        ])
        .to_string();
        assert_eq!(jwt, parse_login_resp(&resp).unwrap());
    }
    #[test]
    fn test_register() {
        let server_url = "http://example.com";
        register(server_url);
        // Here you would typically assert the expected behavior, such as checking the request format.
        // For this example, we just print the request.

        // this secret is all 0x01s.
        let secret64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB";
        println!("{:?}", login("", "", "", secret64,));
    }
}
