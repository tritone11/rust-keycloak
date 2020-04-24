# Rust Keycloak
rust-keycloak is a Rust crate providing access to the Keycloak API.  

<p align="center">
  <h2 align="center">Rust Keycloak</a></h3>
  <a href="https://crates.io/crates/rust-keycloak"><img src="https://img.shields.io/badge/crates.io-v0.0.6-orange.svg?longCache=true" alt="0.0.6" title="rust-keycloak’s current version badge"></a>
  <p align="center">rust-keycloak is a Rust crate providing access to the Keycloak API.</a></p>
</p>


## Features

### OpenId

* [x] well_known
* [x] token
* [x] refresh_token
* [x] jwt_decode
* [x] service_account

### Admin

* [x] Create user
* [x] Delete user
* [x] Update user
* [x] Count users
* [x] user_info
* [x] introspect
* [x] Add user to grup
* [x] Remove user from group
* [x] Add realm and client roles to users

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
