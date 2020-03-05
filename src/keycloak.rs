use std::collections::HashMap;
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

    pub async fn token_client(
        base_url: &str,
        realm: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<String, reqwest::Error> {
        let url = urls::OPENID_URLS.url_token.replace("{realm-name}", realm);

        let payload = json!({
            "client_id": client_id.to_owned(),
            "client_secret": client_secret.to_owned(),
            "grant_type": "client_credentials".to_owned(),
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
        let k_res = client.post(&path).bearer_auth(bearer).send().await?.error_for_status()?;
        Ok(json!(k_res.json().await?))
    }

    pub async fn add_user_group<'a>(
        base_url: &'a str,
        realm: &'a str,
        user_id: &'a str,
        group_id: &'a str,
        bearer: &'a str,
    ) -> Result<(), reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_user_group
            .replace("{realm-name}", realm)
            .replace("{id}", user_id)
            .replace("{group-id}", group_id);
        
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.put(&path).bearer_auth(bearer)
            .json(&json!({
                "realm": realm.to_owned(),
                "userId": user_id.to_owned(),
                "groupId": group_id.to_owned(),
            }))
            .send().await?.error_for_status()?;
        k_res.text().await?;
        Ok(())
    }

    pub async fn remove_user_group<'a>(
        base_url: &'a str,
        realm: &'a str,
        user_id: &'a str,
        group_id: &'a str,
        bearer: &'a str,
    ) -> Result<(), reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_user_group
            .replace("{realm-name}", realm)
            .replace("{id}", user_id)
            .replace("{group-id}", group_id);
        
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.delete(&path).bearer_auth(bearer)
            .json(&json!({
                "realm": realm.to_owned(),
                "userId": user_id.to_owned(),
                "groupId": group_id.to_owned(),
            }))
            .send().await?.error_for_status()?;
        k_res.text().await?;
        Ok(())
    }

    pub async fn user_representation(
        base_url: &str,
        realm: &str,
        id: &str,
        bearer: &str,
    ) -> Result<Option<UserRepresentation>, reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_user
            .replace("{realm-name}", realm)
            .replace("{id}", id);
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.get(&path).bearer_auth(bearer).send().await?.error_for_status()?;
        Ok(serde_json::from_value(k_res.json().await?).ok())
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all="camelCase")]
pub struct UserConsentRepresentation {
    client_id: Option<String>,
    created_date: Option<i64>,
    granted_client_scopes: Option<Vec<String>>,
    last_update_date: Option<i64>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all="camelCase")]
pub struct CredentialRepresentation {
    algorithm: Option<String>,
    config: serde_json::Value,
    counter: Option<i32>,
    created_date: Option<i64>,
    device: Option<String>,
    digits: Option<i32>,
    hash_iterations: Option<i32>,
    hashed_salted_value: Option<String>,
    period: Option<i32>,
    salt: Option<String>,
    temporary: Option<bool>,
    r#type: Option<String>,
    value: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all="camelCase")]
pub struct FederatedIdentityRepresentation {
    identity_provider: Option<String>,
    user_id: Option<String>,
    user_name: Option<String>,
}

#[derive(Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct UserRepresentation {
    access: Option<HashMap<String, bool>>,
    attributes: Option<HashMap<String, Vec<String>>>,
    client_consents: Option<Vec<UserConsentRepresentation>>,
    created_timestamp: Option<i64>,
    credentials: Option<Vec<CredentialRepresentation>>,
    disableable_credential_types: Option<Vec<String>>,
    email: Option<String>,
    email_verified: Option<bool>,
    enabled: Option<bool>,
    federated_identities: Option<Vec<FederatedIdentityRepresentation>>,
    federation_link: Option<String>,
    first_name: Option<String>,
    groups: Option<Vec<String>>,
    id: Option<String>,
    last_name: Option<String>,
    not_before: Option<i32>,
    origin: Option<String>,
    realm_roles: Option<Vec<String>>,
    required_actions: Option<Vec<String>>,
    #[serde(rename="self")]
    self_: Option<String>,
    service_account_client_id: Option<String>,
    username: Option<String>,
}
