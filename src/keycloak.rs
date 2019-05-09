#![deny(warnings)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

use urls;
use openid;
use admin;
use std::mem;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use jwt::{decode_header};

pub struct Admin {
    
}

pub struct OpenId {
    
}


impl OpenId {

        pub fn well_known (base_url: &str,realm: &str) -> String {

            let url = urls::OPENID_URLS.url_well_known.replace("{realm-name}",realm);
            let client = reqwest::Client::new();

            let path = base_url.to_owned()+&url.to_owned();
            let k_res = client.post(&path)
                .send().unwrap().text().unwrap();

            return k_res
        }

        pub fn token (base_url: &str, data: serde_json::Value , realm: &str) -> Result<String,String> {
            let url = urls::OPENID_URLS.url_token.replace("{realm-name}",realm);

            let payload = json!({
                "username":data["username"],
                "password":data["password"],
                "client_id":data["client_id"],
                "grant_type":data["grant_type"],
                "code":data["code"],
                "redirect_uri":data["redirect_uri"],
            });

            let path = base_url.to_owned()+&url.to_owned();
            if let Ok(res) = openid::get_token(&path,payload) {
                let token = res.access_token;
                return Ok(token)
            }else{
                return Err("".to_string())
            };
            
        }

        pub fn introspect (base_url: &str, realm: &str, data: serde_json::Value ) -> String {
            let url = urls::OPENID_URLS.url_introspect.replace("{realm-name}",realm);

            let payload = json!({
                "client_id":data["client_id"],
                "client_secret":data["client_secret"],
                "token":data["token"],
            });

            let path = base_url.to_owned()+&url.to_owned();
            let res  = openid::introspect_token(&path,payload);

            return res
        }

        pub fn jwt_decode (token: String) -> jwt::Header {
            let tok = decode_header(&token).unwrap();
            return tok
        }

        pub fn refresh_token (base_url: &str, data: serde_json::Value , realm: &str) -> Result<String,String> {
            let url = urls::OPENID_URLS.url_token.replace("{realm-name}",realm);

            let payload = json!({
                "refresh_token":data["token"],
                "grant_type":data["grant_type"],
                "client_id":data["client_id"]
            });
            
            let path = base_url.to_owned()+&url.to_owned();

            if let Ok(res) = openid::get_token(&path,payload) {
                let d = json!(res);
                let token = d["access_token"].to_string();
                return Ok(token)
            }else{
                return Err("".to_string())
            };

            
            
        }
}

impl Admin {

    pub fn create_user(base_url: &str, data: serde_json::Value , realm: &str,token: &str) -> String {
        let url = urls::ADMIN_URLS.url_admin_users.replace("{realm-name}",realm);
        let payload = json!({
                        "email": data["email"].to_string(),
                        "username": data["username"],
                        "enabled": data["enabled"],
                        "firstName": data["firstName"],
                        "lastName": data["lastName"],
                        "credentials": [{"value": data["password"],"type": "password"}],
                        "realmRoles": [data["realmRole"]]
                    });

        let path = base_url.to_owned()+&url.to_owned();
        let res = admin::payload_bearer_request_status(&path,payload,token);

        let user_created = res.to_string();
        return "Creation of user: ".to_string() +&user_created

    }

    pub fn users_count(base_url: &str, realm: &str, bearer: &str) -> String {
        let url = urls::ADMIN_URLS.url_admin_users_count.replace("{realm-name}",realm);

        let path = base_url.to_owned()+&url.to_owned();
        let mut res = admin::bearer_get_request(&path,bearer);
    
        let u_count = res.text().unwrap();
        return u_count
    }

    pub fn user_info (base_url: &str, realm: &str, bearer: &str) -> String {
        let url = urls::OPENID_URLS.url_userinfo.replace("{realm-name}",realm);
        let client = reqwest::Client::new();

        let path = base_url.to_owned()+&url.to_owned();
        let k_res = client.post(&path)
            .bearer_auth(bearer)
            .send().unwrap().text().unwrap();
        
        return k_res
    }

}



pub fn string_to_static_str(s: String) -> &'static str {
    unsafe {
        let ret = mem::transmute(&s as &str);
        mem::forget(s);
        ret
    }
}


