extern crate rust_keycloak;
use tokio;

struct UniqueUserConfig {
    realm_name: String,
    base_url: String,
    admin_user: String,
    admin_password: String,

    project_realm_name: String,
    project_client_id: String,

    identity_provider_name: String,
    identity_provider_client_id: String,
    identity_provider_client_secret: String,
}

async fn configure_keycloak() {
    let key_cfg = UniqueUserConfig {
        realm_name: String::from("master"),
        base_url: String::from("http://localhost:8080/"), // tested with keycloak 21.1.1 https://www.keycloak.org/docs-api/21.1.1/rest-api/index.html
        admin_user: String::from("admin"),
        admin_password: String::from("admin"),
        project_realm_name: String::from("myRealm"),
        project_client_id: String::from("yourClientId"),
        identity_provider_client_id: String::from("ssoClientId"), // generated from cloud.google.com in the case of sign in with google
        identity_provider_client_secret: String::from("ssoClientSecret"), // generated from cloud.google.com in the case of sign in with google
        identity_provider_name: String::from("google") // google for example
    };

    let token_request = rust_keycloak::serde_json::json!({
        "grant_type": "password".to_string(),
        "username": key_cfg.admin_user,
        "password": key_cfg.admin_password,
        "realm": key_cfg.realm_name, 
        "client_id": "admin-cli".to_string(), 
        "redirect_uri":"".to_string(), 
        "code":"".to_string(),
    });

    let tok = rust_keycloak::keycloak::OpenId::token(&key_cfg.base_url,
        token_request,
        &key_cfg.realm_name,
    );
    let admin_token = match tok.await {
        Ok(strg) => strg,
        Err(error) => panic!("Failed to make the request: {:?}", error),
    };
    println!("got admin token");

    let ds_realm = rust_keycloak::keycloak::RealmRepresentation{
        realm: Some(key_cfg.project_realm_name.clone()),
        enabled: Some(true),
        registration_allowed: Some(true),
        registration_email_as_username: Some(true),
        login_theme: None,
    };

    let crt_rlm_ok = rust_keycloak::keycloak::Admin::create_realm(&key_cfg.base_url, &ds_realm, &admin_token);
    let realm_id = match crt_rlm_ok.await {
        Ok(strg) => strg,
        Err(error) => panic!("Failed to make the request: {:?}", error),
    };
    println!("[Realm ID] {}", realm_id.unwrap());

    let ds_client = rust_keycloak::keycloak::ClientRepresentation{
        client_id: Some(key_cfg.project_client_id),
        direct_access_grants_enabled: Some(true),
        public_client: Some(true),
        redirect_uris: Some(vec![String::from("*")]), // set to actual uri(s) in production
        web_origins: Some(vec![String::from("*")]), // set to actual uri(s) in production
    };

    let crt_clnt_ok = rust_keycloak::keycloak::Admin::create_client(&key_cfg.base_url, &key_cfg.project_realm_name, &ds_client, &admin_token);
    let clnt_id = match crt_clnt_ok.await {
        Ok(strg) => strg,
        Err(error) => panic!("Failed to make the request: {:?}", error),
    };
    println!("[Client ID] {}", clnt_id.unwrap());

    let id_prov_rep = rust_keycloak::keycloak::IdentityProviderRepresentation{
        enabled: Some(true),
        alias: Some(key_cfg.identity_provider_name.clone()),
        provider_id: Some(key_cfg.identity_provider_name),
        config: Some(rust_keycloak::keycloak::ProviderConfigRepresentation{
            use_jwks_url: Some(true),
            client_id: Some(key_cfg.identity_provider_client_id),
            client_secret: Some(key_cfg.identity_provider_client_secret),
        })
    };

    let id_prov_res = rust_keycloak::keycloak::Admin::create_identity_provider(
        &key_cfg.base_url,
        &key_cfg.project_realm_name,
        &id_prov_rep,
        &admin_token,
    );
    let id_prov_id = match id_prov_res.await {
        Ok(strg) => strg,
        Err(error) => panic!("Failed to make the request: {:?}", error),
    };

    println!("[Provider ID] {}", id_prov_id.unwrap());

    let del_rlm_ok = rust_keycloak::keycloak::Admin::delete_realm(
        &key_cfg.base_url,
        &key_cfg.project_realm_name,
        &admin_token,
    );
    let _del_rlm_msg = match del_rlm_ok.await {
        Ok(strg) => strg,
        Err(error) => println!("Couldn't delete realm: {:?}", error),
    };
}

#[tokio::main]
async fn main() {
    configure_keycloak().await;
}
