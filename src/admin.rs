use reqwest::header::{HeaderValue, CONTENT_TYPE};

pub async fn payload_bearer_request(
    path: &str,
    payload: serde_json::Value,
    token: &str,
) -> Result<reqwest::Response, reqwest::Error> {
    let client = reqwest::Client::new();
    client
        .post(path)
        .bearer_auth(token.to_string())
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .json(&payload)
        .send()
        .await
}

pub async fn payload_bearer_request_status(
    path: &str,
    payload: serde_json::Value,
    token: &str,
) -> Result<reqwest::StatusCode, reqwest::Error> {
    let client = reqwest::Client::new();
    client
        .post(path)
        .bearer_auth(token.to_string())
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .json(&payload)
        .send()
        .await
        .map(|response| response.status())
}

pub async fn bearer_post_request(
    path: &str,
    token: &str,
) -> Result<reqwest::Response, reqwest::Error> {
    let client = reqwest::Client::new();
    client
        .post(path)
        .bearer_auth(token.to_string())
        .send()
        .await
}

pub async fn bearer_get_request(
    path: &str,
    token: &str,
) -> Result<reqwest::Response, reqwest::Error> {
    let client = reqwest::Client::new();
    client.get(path).bearer_auth(token.to_string()).send().await
}
