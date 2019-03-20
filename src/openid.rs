#![deny(warnings)]

use reqwest::header::{HeaderValue, CONTENT_TYPE};

#[derive(Debug,Serialize, Deserialize)]
pub struct Token {
    pub access_token:       String,
    pub token_type:         String,
    pub session_state:      String,
    pub scope:              String
}


pub fn get_token (path: &str, payload: serde_json::Value ) -> Token {
    
    let client = reqwest::Client::new();
    let k_res: Token = client.post(path)
                    .header(CONTENT_TYPE,HeaderValue::from_static("application/json"))
                    .form(&payload)
                    .send().unwrap().json().unwrap();
    return k_res
}

pub fn introspect_token (path: &str, payload: serde_json::Value ) -> String {
    
    let client = reqwest::Client::new();
    let k_res = client.post(path)
                    .header(CONTENT_TYPE,HeaderValue::from_static("application/json"))
                    .form(&payload)
                    .send().unwrap().text().unwrap();
    return k_res
}

