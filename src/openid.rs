use reqwest::header::{HeaderValue, CONTENT_TYPE};

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    pub access_token: String,
    pub token_type: String,
    pub session_state: String,
    pub scope: String,
}

pub async fn get_token(path: &str, payload: serde_json::Value) -> Result<Token, reqwest::Error> {
    let client = reqwest::Client::new();
    let k_res = client
        .post(path)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .form(&payload)
        .send()
        .await?;
    k_res.json().await
}

pub async fn introspect_token(
    path: &str,
    payload: serde_json::Value,
) -> Result<String, reqwest::Error> {
    let client = reqwest::Client::new();
    let k_res = client
        .post(path)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .form(&payload)
        .send()
        .await?;
    k_res.text().await
}
