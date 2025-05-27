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

fn register(server_url: &str) {
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

    let v: Value = serde_json::from_str(resp).unwrap();

    match v {
        Value::Array(arr) if arr.len() == 2 => {
            let session_resp: NewTestSessionResponse =
                serde_json::from_value(arr[1].clone()).unwrap();
            println!("Session resp: {:?}", session_resp);
        }
        _ => {
            eprintln!("Unexpected response format: {:?}", v);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_register() {
        let server_url = "http://example.com";
        register(server_url);
        // Here you would typically assert the expected behavior, such as checking the request format.
        // For this example, we just print the request.
    }
}
