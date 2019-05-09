extern crate rust_keycloak;

fn main() {
    let well = rust_keycloak::keycloak::OpenId::well_known("http://localhost/auth/","realm_name");
    println!("{:?}",well);

    let token_request = rust_keycloak::serde_json::json!({
        "grant_type":"password".to_string(),
        "username":"admin".to_string(),
        "password":"password".to_string(),
        "realm":"realm_name".to_string(), 
        "client_id":"client_id".to_string(), 
        "redirect_uri":"".to_string(), 
        "code":"".to_string()});

    let tok = rust_keycloak::keycloak::OpenId::token("http://localhost/auth/",token_request,"realm_name");
    println!("AUTH TOKEN {:?}",tok);

    let u_info = rust_keycloak::keycloak::Admin::user_info("http://localhost/auth/","realm_name",&tok);
    println!("USER INFO {:?}",u_info);

    let u_count = rust_keycloak::keycloak::Admin::users_count("http://localhost/auth/","realm_name",&tok);
    println!("USERS COUNT {:?}",u_count);

    let payload = rust_keycloak::serde_json::json!({
        "client_id":"client_id", 
        "client_secret":"client_secret",
        "token":tok.to_string()});

    let introspect = rust_keycloak::keycloak::OpenId::introspect("http://localhost/auth/","realm_name",payload);
    println!("INTROSPECT {:?}",introspect);

    let payload = rust_keycloak::serde_json::json!({"email": "info@example.com".to_string(),
                        "username": "username".to_string(),
                        "firstName": "firstName".to_string(),
                        "lastName": "lastName".to_string(),
                        "enabled":"True".to_string(),
                        "password":"password".to_string(),
                        "realmRole": "client_id".to_string()
                        });
    
    let creation = rust_keycloak::keycloak::Admin::create_user("http://localhost/auth/",payload,"realm_name",&tok);
    println!("{:?}",creation);
}
