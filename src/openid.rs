#![deny(warnings)]

use reqwest::header::{HeaderValue, CONTENT_TYPE};

#[derive(Debug,Serialize, Deserialize)]
pub struct Token {
    pub access_token:       String,
    pub token_type:         String,
    pub session_state:      String,
    pub scope:              String
}


pub fn get_token (path: &str, payload: serde_json::Value ) -> Result<Token,String> {
    
    let client = reqwest::Client::new();
    if let Ok(mut k_res) = client.post(path)
                    .header(CONTENT_TYPE,HeaderValue::from_static("application/json"))
                    .form(&payload)
                    .send() {
                        if let Ok(kk) = k_res.json() {
                            let k: Token = kk;
                            return Ok(k)
                        }else{
                            return Err("".to_string())
                        }
                    }else{
                        return Err("".to_string())
                    };
}

pub fn introspect_token (path: &str, payload: serde_json::Value ) -> String {
    
    let client = reqwest::Client::new();
    let k_res = client.post(path)
                    .header(CONTENT_TYPE,HeaderValue::from_static("application/json"))
                    .form(&payload)
                    .send().unwrap().text().unwrap();
    return k_res
}

 