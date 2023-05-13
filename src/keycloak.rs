use std::collections::HashMap;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
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
        data: &UserRepresentation,
        realm: &str,
        token: &str,
    ) -> Result<Option<String>, reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_users
            .replace("{realm-name}", realm);
        let payload =  serde_json::to_value(data).unwrap();

        let path = base_url.to_owned() + &url.to_owned();
        let response = admin::payload_bearer_request(&path, payload, token).await?;

        if let Some(location) = response.headers().get("location").and_then(|location| location.to_str().ok()) {
            Ok(location.rsplitn(2, '/').next().map(|id| id.to_owned()))
        } else {
            Ok(None)
        }
    }

    pub async fn update_user(
        base_url: &str,
        data: &UserRepresentation,
        realm: &str,
        token: &str,
    ) -> Result<(), reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_user
            .replace("{realm-name}", realm)
            .replace("{id}", data.id.as_ref().unwrap());
        let payload =  serde_json::to_value(data).unwrap();

        let path = base_url.to_owned() + &url.to_owned();
        let client = reqwest::Client::new();
        client
            .put(&path)
            .bearer_auth(token.to_string())
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .json(&payload)
            .send()
            .await?.error_for_status()
            .map(|_| {})
    }

    pub async fn get_user(
        base_url: &str,
        realm: &str,
        user_id: &str,
        token: &str,
    ) -> Result<Option<UserRepresentation>, reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_user
            .replace("{realm-name}", realm)
            .replace("{id}", user_id);
        
        let path = base_url.to_owned() + &url.to_owned();
        let client = reqwest::Client::new();
        let response = client
            .get(&path)
            .bearer_auth(token.to_string())
            .send()
            .await?.error_for_status()?;
        let json = response.json().await?;

        if let Ok(user) = serde_json::from_value(json) {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    pub async fn get_users(
        base_url: &str,
        realm: &str,
        query: &UserQuery,
        token: &str,
    ) -> Result<Vec<UserRepresentation>, reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_users
            .replace("{realm-name}", realm);
        
        let path = base_url.to_owned() + &url.to_owned();
        let client = reqwest::Client::new();
        let response = client
            .get(&path)
            .bearer_auth(token.to_string())
            .query(&query)
            .send()
            .await?.error_for_status()?;
        let json = response.json().await?;

        if let Ok(users) = serde_json::from_value(json) {
            Ok(users)
        } else {
            Ok(Vec::new())
        }
    }

    pub async fn delete_user(
        base_url: &str,
        user_id: &str,
        realm: &str,
        token: &str,
    ) -> Result<(), reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_user
            .replace("{realm-name}", realm)
            .replace("{id}", user_id);

        let path = base_url.to_owned() + &url.to_owned();
        let client = reqwest::Client::new();
        client
            .delete(&path)
            .bearer_auth(token.to_string())
            .send()
            .await?.error_for_status()?;
        Ok(())
    }

    pub async fn users_count(
        base_url: &str,
        realm: &str,
        bearer: &str,
    ) -> Result<Option<u64>, reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_users_count
            .replace("{realm-name}", realm);

        let path = base_url.to_owned() + &url.to_owned();
        let res = admin::bearer_get_request(&path, bearer).await?;
        if let serde_json::Value::Number(count) = res.json().await? {
            Ok(count.as_u64())
        } else {
            Ok(None)
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

    pub async fn user_groups(
        base_url: &str,
        realm: &str,
        id: &str,
        query: Option<UserGroupsQuery<'_>>,
        bearer: &str,
    ) -> Result<Option<Vec<GroupRepresentation>>, reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_user_groups
            .replace("{realm-name}", realm)
            .replace("{id}", id);
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let request = client.get(&path).bearer_auth(bearer);
        let request = if let Some(query) = query {
            request.query(&query)
        } else {
            request
        };
        let k_res = request.send().await?.error_for_status()?;
        Ok(serde_json::from_value(k_res.json().await?).ok())
    }

    pub async fn add_realm_roles_to_user(
        base_url: &str,
        realm: &str,
        user_id: &str,
        roles: &[RoleRepresentation],
        bearer: &str,
    ) -> Result<(), reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_user_realm_roles
            .replace("{realm-name}", realm)
            .replace("{id}", user_id);
        
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.post(&path).bearer_auth(bearer)
            .json(roles)
            .send().await?.error_for_status()?;
        k_res.text().await?;
        Ok(())
    }

    pub async fn add_client_roles_to_user(
        base_url: &str,
        realm: &str,
        user_id: &str,
        client_id: &str,
        roles: &[RoleRepresentation],
        bearer: &str,
    ) -> Result<(), reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_user_client_roles
            .replace("{realm-name}", realm)
            .replace("{id}", user_id)
            .replace("{client-id}", client_id);
        
        let client = reqwest::Client::new();

        let path = base_url.to_owned() + &url.to_owned();
        let k_res = client.post(&path).bearer_auth(bearer)
            .json(roles)
            .send().await?.error_for_status()?;
        k_res.text().await?;
        Ok(())
    }

    pub async fn delete_realm(
        base_url: &str,
        realm: &str,
        bearer: &str,
    ) -> Result<(), reqwest::Error> {
        let url = urls::ADMIN_URLS.url_admin_realm
            .replace("{realm-name}", realm);


        let client = reqwest::Client::new();
        let path = base_url.to_owned() + &url.to_owned();

        let response = client.delete(&path).bearer_auth(bearer)
            .send().await?.error_for_status()?;

        response.text().await?;
        Ok(())
    }

    pub async fn create_realm(
        base_url: &str,
        realm: &RealmRepresentation,
        bearer: &str,
    ) -> Result<Option<String>, reqwest::Error> {
        let url = urls::ADMIN_URLS.url_admin_realm_import;

        let client = reqwest::Client::new();
        let path = base_url.to_owned() + &url.to_owned();

        let response = client.post(&path)
            .bearer_auth(bearer)
            .json(realm)
            .send().await?.error_for_status()?;

        if let Some(location) = response.headers().get("location").and_then(|location| location.to_str().ok()) {
            Ok(location.rsplitn(2, '/').next().map(|id| id.to_owned()))
        } else {
            Ok(None)
        }
    }

    pub async fn create_client(
        base_url: &str,
        realm: &str,
        client_representation: &ClientRepresentation,
        bearer: &str,
    ) -> Result<Option<String>, reqwest::Error> {
        let url = urls::ADMIN_URLS.url_admin_clients
            .replace("{realm-name}", realm);

        let client = reqwest::Client::new();
        let path = base_url.to_owned() + &url.to_owned();

        let response = client.post(&path)
            .bearer_auth(bearer)
            .json(client_representation)
            .send().await?.error_for_status()?;

        if let Some(location) = response.headers().get("location").and_then(|location| location.to_str().ok()) {
            Ok(location.rsplitn(2, '/').next().map(|id| id.to_owned()))
        } else {
            Ok(None)
        }
    }

    pub async fn create_identity_provider(
        base_url: &str,
        realm: &str,
        identity_provider_representation: &IdentityProviderRepresentation,
        bearer: &str,
    ) -> Result<Option<String>, reqwest::Error> {
        let url = urls::ADMIN_URLS.url_admin_identity_provider_instances
            .replace("{realm-name}", realm);

        let client = reqwest::Client::new();
        let path = base_url.to_owned() + &url.to_owned();

        let response = client.post(&path)
            .bearer_auth(bearer)
            .json(identity_provider_representation)
            .send().await?.error_for_status()?;

        if let Some(location) = response.headers().get("location").and_then(|location| location.to_str().ok()) {
            Ok(location.rsplitn(2, '/').next().map(|id| id.to_owned()))
        } else {
            Ok(None)
        }
    }



    pub async fn send_update_account(
        base_url: &str,
        realm: &str,
        user_id: &str,
        actions: &[&str],
        lifespan: i32,
        client_id: Option<&str>,
        redirect_uri: Option<&str>,
        bearer: &str,
    ) -> Result<(), reqwest::Error> {
        let url = urls::ADMIN_URLS
            .url_admin_send_update_account
            .replace("{realm-name}", realm)
            .replace("{id}", user_id);
        
        let client = reqwest::Client::new();
        let query = ExecuteActionsEmailQuery {
            lifespan, client_id, redirect_uri,
        };

        let path = base_url.to_owned() + &url.to_owned();
        client.put(&path).bearer_auth(bearer)
            .query(&query)
            .json(&actions)
            .send().await?.error_for_status()?;
        Ok(())
    }

}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="camelCase")]
pub struct UserConsentRepresentation {
    pub client_id: Option<String>,
    pub created_date: Option<i64>,
    pub granted_client_scopes: Option<Vec<String>>,
    pub last_update_date: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="camelCase")]
pub struct CredentialRepresentation {
    pub algorithm: Option<String>,
    pub config: serde_json::Value,
    pub counter: Option<i32>,
    pub created_date: Option<i64>,
    pub device: Option<String>,
    pub digits: Option<i32>,
    pub hash_iterations: Option<i32>,
    pub hashed_salted_value: Option<String>,
    pub period: Option<i32>,
    pub salt: Option<String>,
    pub temporary: Option<bool>,
    pub r#type: Option<String>,
    pub value: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all="camelCase")]
pub struct FederatedIdentityRepresentation {
    pub identity_provider: Option<String>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct UserRepresentation {
    pub access: Option<HashMap<String, bool>>,
    pub attributes: Option<HashMap<String, Vec<String>>>,
    pub client_consents: Option<Vec<UserConsentRepresentation>>,
    pub created_timestamp: Option<i64>,
    pub credentials: Option<Vec<CredentialRepresentation>>,
    pub disableable_credential_types: Option<Vec<String>>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub enabled: Option<bool>,
    pub federated_identities: Option<Vec<FederatedIdentityRepresentation>>,
    pub federation_link: Option<String>,
    pub first_name: Option<String>,
    pub groups: Option<Vec<String>>,
    pub id: Option<String>,
    pub last_name: Option<String>,
    pub not_before: Option<i32>,
    pub origin: Option<String>,
    pub realm_roles: Option<Vec<String>>,
    pub required_actions: Option<Vec<String>>,
    #[serde(rename="self")]
    pub self_: Option<String>,
    pub service_account_client_id: Option<String>,
    pub username: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RoleRepresentationComposites {
    pub client: Option<HashMap<String, String>>,
    pub realm: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct RoleRepresentation {
    pub attributes: Option<HashMap<String, String>>,
    pub client_role: Option<bool>,
    pub composite: Option<bool>,
    pub composites: Option<RoleRepresentationComposites>,
    pub container_id: Option<String>,
    pub description: Option<String>,
    pub id: Option<String>,
    pub name: Option<String>,
}

impl RoleRepresentation {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: Some(id.to_owned()),
            name: Some(name.to_owned()),
            ..Default::default()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct ProviderConfigRepresentation {
    pub use_jwks_url: Option<bool>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct IdentityProviderRepresentation {
    pub enabled: Option<bool>,
    pub alias: Option<String>,
    pub provider_id: Option<String>,
    pub config: Option<ProviderConfigRepresentation>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct ClientRepresentation {
    pub client_id: Option<String>,
    pub public_client: Option<bool>,
    pub redirect_uris: Option<Vec<String>>,
    pub web_origins: Option<Vec<String>>,
    pub direct_access_grants_enabled: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct RealmRepresentation {
    pub realm: Option<String>,
    pub enabled: Option<bool>,
    pub registration_allowed: Option<bool>,
    pub registration_email_as_username: Option<bool>,
    pub login_theme: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all="camelCase")]
pub struct UserQuery {
    pub brief_representation: Option<bool>,
    pub email: Option<String>,
    pub first: Option<i32>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub max: Option<i32>,
    pub search: Option<String>,
    pub username: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct ExecuteActionsEmailQuery<'a> {
    lifespan: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<&'a str>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct UserGroupsQuery<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<&'a str>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct GroupRepresentation {
    pub id: String,
    pub name: String,
    pub path: String,
}
