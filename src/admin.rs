#![deny(warnings)]

use reqwest::header::{HeaderValue, CONTENT_TYPE};



pub fn payload_bearer_request(path: &str, payload: serde_json::Value ,token: &str) -> reqwest::Response {
    
    let client = reqwest::Client::new();
    let k_res = client.post(path)
                    .bearer_auth(token.to_string())
                    .header(CONTENT_TYPE,HeaderValue::from_static("application/json"))
                    .json(&payload)
                    .send().unwrap();

    return k_res
}

pub fn payload_bearer_request_status(path: &str, payload: serde_json::Value ,token: &str) -> reqwest::StatusCode {
    
    let client = reqwest::Client::new();
    let k_res = client.post(path)
                    .bearer_auth(token.to_string())
                    .header(CONTENT_TYPE,HeaderValue::from_static("application/json"))
                    .json(&payload)
                    .send().unwrap().status();

    return k_res
}

pub fn bearer_post_request(path: &str ,token: &str) -> reqwest::Response {
    
    let client = reqwest::Client::new();
    let k_res = client.post(path)
                    .bearer_auth(token.to_string())
                    .send().unwrap();

    return k_res
}

pub fn bearer_get_request(path: &str ,token: &str) -> reqwest::Response {
    
    let client = reqwest::Client::new();
    let k_res = client.get(path)
                    .bearer_auth(token.to_string())
                    .send().unwrap();

    return k_res
}
