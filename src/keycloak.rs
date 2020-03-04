use crate::admin;
use crate::openid;
use crate::urls;
use jwt::{decode_header, errors::Error as JwtError};

pub struct Admin();

pub struct OpenId();

impl OpenId {
    pub async fn well_known(base_url: &str, realm: &str) -> Result<String, reqwest::Error> {
        let url = urls::OPENID_URLS
            .url_well_known
            .replace("{realm-name}", realm);
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let res = client.post(&path).send().await?;
        res.text().await
    }

    pub async fn token(
        base_url: &str,
        data: serde_json::Value,
        realm: &str,
    ) -> Result<String, reqwest::Error> {
        let url = urls::OPENID_URLS.url_token.replace("{realm-name}", realm);

        let payload = json!({
            "username":data["username"],
            "password":data["password"],
            "client_id":data["client_id"],
            "grant_type":data["grant_type"],
            "code":data["code"],
            "redirect_uri":data["redirect_uri"],
        });

        let path = base_url.to_owned() + &url.to_owned();
        openid::get_token(&path, payload)
            .await
            .map(|res| res.access_token)
    }

    pub async fn introspect(
        base_url: &str,
        realm: &str,
        data: serde_json::Value,
    ) -> Result<String, reqwest::Error> {
        let url = urls::OPENID_URLS
            .url_introspect
            .replace("{realm-name}", realm);

        let payload = json!({
            "client_id":data["client_id"],
            "client_secret":data["client_secret"],
            "token":data["token"],
        });

        let path = base_url.to_owned() + &url.to_owned();
        openid::introspect_token(&path, payload).await
    }

    pub fn jwt_decode(token: String) -> Result<jwt::Header, JwtError> {
        decode_header(&token)
    }

    pub async fn refresh_token(
        base_url: &str,
        data: serde_json::Value,
        realm: &str,
    ) -> Result<String, reqwest::Error> {
        let url = urls::OPENID_URLS.url_token.replace("{realm-name}", realm);

        let payload = json!({
            "refresh_token":data["token"],
            "grant_type":data["grant_type"],
            "client_id":data["client_id"]
        });

        let path = base_url.to_owned() + &url.to_owned();

        let res = openid::get_token(&path, payload).await?;
        let d = json!(res);
        let token = d["access_token"].to_string();
        Ok(token)
    }
}

impl Admin {
    pub async fn create_user(
        base_url: &str,
        data: serde_json::Value,
        realm: &str,
        token: &str,
    ) -> Result<reqwest::StatusCode, reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_users
            .replace("{realm-name}", realm);
        let payload = json!({
            "email": data["email"].to_string(),
            "username": data["username"],
            "enabled": data["enabled"],
            "firstName": data["firstName"],
            "lastName": data["lastName"],
            "credentials": [{"value": data["password"],"type": "password"}],
            "realmRoles": [data["realmRole"]]
        });

        let path = base_url.to_owned() + &url.to_owned();
        admin::payload_bearer_request_status(&path, payload, token).await
    }

    pub async fn users_count(
        base_url: &str,
        realm: &str,
        bearer: &str,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let url = urls::ADMIN_URLS
            .url_admin_users_count
            .replace("{realm-name}", realm);

        let path = base_url.to_owned() + &url.to_owned();
        let res = admin::bearer_get_request(&path, bearer).await?;
        if let serde_json::Value::Number(count) = res.json().await? {
            count
                .as_u64()
                .ok_or_else(|| "Response is not a positive number".into())
        } else {
            Err("Response is not a number".into())
        }
    }

    pub async fn user_info(
        base_url: &str,
        realm: &str,
        bearer: &str,
    ) -> Result<serde_json::Value, reqwest::Error> {
        let url = urls::OPENID_URLS
            .url_userinfo
            .replace("{realm-name}", realm);
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.post(&path).bearer_auth(bearer).send().await?;
        Ok(json!(k_res.json().await?))
    }
}
