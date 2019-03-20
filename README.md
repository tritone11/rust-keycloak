# Rust Keycloak
rust-keycloak is a Rust crate providing access to the Keycloak API.  

<p align="center">
  <h2 align="center">Rust Keycloak</a></h3>
  <a href="https://crates.io/crates/rust-keycloak"><img src="https://img.shields.io/badge/crates.io-v0.0.2-orange.svg?longCache=true" alt="0.0.2" title="rust-keycloak’s current version badge"></a>
  <p align="center">rust-keycloak is a Rust crate providing access to the Keycloak API.</a></p>
</p>


## Features

### OpenId

* [x] well_known
* [x] token
* [x] refresh_token
* [x] jwt_decode

### Admin

* [x] create_user
* [x] users_count
* [x] user_info
* [x] introspect

## Example usage

```
    let token_request = rust_keycloak::serde_json::json!({
        "grant_type":"password".to_string(),
        "username":"admin".to_string(),
        "password":"password".to_string(),
        "realm":"realm_name".to_string(), 
        "client_id":"client_id".to_string(), 
        "redirect_uri":"".to_string(), 
        "code":"".to_string()});

    let tok = rust_keycloak::keycloak::OpenId::token("http://localhost/auth/",token_request,"realm_name");
```
