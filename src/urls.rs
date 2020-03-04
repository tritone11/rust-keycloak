#[derive(Debug)]
pub struct Urls {
    pub url_well_known: &'static str,
    pub url_token: &'static str,
    pub url_userinfo: &'static str,
    pub url_introspect: &'static str,
    /*url_logout : &'static str,
    url_certs : &'static str,
    url_introspect : &'static str,
    url_entitlement : &'static str,
    url_auth : &'static str,*/
}

#[derive(Debug)]
pub struct AdminUrls {
    pub url_admin_users: &'static str,
    pub url_admin_users_count: &'static str,
    /*url_admin_user : &'static str,
    url_admin_user_consents : &'static str,
    url_admin_send_update_account : &'static str,
    url_admin_send_verify_email : &'static str,
    url_admin_reset_password : &'static str,
    url_admin_get_sessions : &'static str,
    url_admin_user_client_roles : &'static str,
    url_admin_user_client_roles_available : &'static str,
    url_admin_user_client_roles_composite : &'static str,
    url_admin_user_group : &'static str,
    url_admin_user_groups : &'static str,
    url_admin_user_password : &'static str,
    url_admin_user_storage : &'static str,

    url_admin_server_info : &'static str,

    url_admin_groups : &'static str,
    url_admin_group : &'static str,
    url_admin_group_child : &'static str,
    url_admin_group_permissions : &'static str,
    url_admin_group_members : &'static str,

    url_admin_clients : &'static str,
    url_admin_client : &'static str,
    url_admin_client_roles : &'static str,
    url_admin_client_role : &'static str,
    url_admin_client_authz_settings : &'static str,
    url_admin_client_authz_resources : &'static str,
    url_admin_client_certs : &'static str,

    url_admin_realm_roles : &'static str,
    url_admin_realm_import : &'static str,
    url_admin_idps : &'static str,

    url_admin_flows : &'static str,
    url_admin_flows_executions : &'static str,*/
}

pub const OPENID_URLS: Urls = Urls {
    url_well_known: "realms/{realm-name}/.well-known/openid-configuration",
    url_token: "realms/{realm-name}/protocol/openid-connect/token",
    url_userinfo: "realms/{realm-name}/protocol/openid-connect/userinfo",
    url_introspect: "realms/{realm-name}/protocol/openid-connect/token/introspect",
    /*url_logout : "realms/{realm-name}/protocol/openid-connect/logout",
    url_certs : "realms/{realm-name}/protocol/openid-connect/certs",

    url_entitlement : "realms/{realm-name}/authz/entitlement/{resource-server-id}",
    url_auth : "{authorization-endpoint}?client_id={client-id}&response_type=code&redirect_uri={redirect-uri}",*/
};

pub const ADMIN_URLS: AdminUrls = AdminUrls {
    url_admin_users: "admin/realms/{realm-name}/users",
    url_admin_users_count: "admin/realms/{realm-name}/users/count",
    /*url_admin_user : "admin/realms/{realm-name}/users/{id}",
    url_admin_user_consents : "admin/realms/{realm-name}/users/{id}/consents",
    url_admin_send_update_account : "admin/realms/{realm-name}/users/{id}/execute-actions-email",
    url_admin_send_verify_email : "admin/realms/{realm-name}/users/{id}/send-verify-email",
    url_admin_reset_password : "admin/realms/{realm-name}/users/{id}/reset-password",
    url_admin_get_sessions : "admin/realms/{realm-name}/users/{id}/sessions",
    url_admin_user_client_roles : "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}",
    url_admin_user_client_roles_available : "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}/available",
    url_admin_user_client_roles_composite : "admin/realms/{realm-name}/users/{id}/role-mappings/clients/{client-id}/composite",
    url_admin_user_group : "admin/realms/{realm-name}/users/{id}/groups/{group-id}",
    url_admin_user_groups : "admin/realms/{realm-name}/users/{id}/groups",
    url_admin_user_password : "admin/realms/{realm-name}/users/{id}/reset-password",
    url_admin_user_storage : "admin/realms/{realm-name}/user-storage/{id}/sync",

    url_admin_server_info : "admin/serverinfo",

    url_admin_groups : "admin/realms/{realm-name}/groups",
    url_admin_group : "admin/realms/{realm-name}/groups/{id}",
    url_admin_group_child : "admin/realms/{realm-name}/groups/{id}/children",
    url_admin_group_permissions : "admin/realms/{realm-name}/groups/{id}/management/permissions",
    url_admin_group_members : "admin/realms/{realm-name}/groups/{id}/members",

    url_admin_clients : "admin/realms/{realm-name}/clients",
    url_admin_client : "admin/realms/{realm-name}/clients/{id}",
    url_admin_client_roles : "admin/realms/{realm-name}/clients/{id}/roles",
    url_admin_client_role : "admin/realms/{realm-name}/clients/{id}/roles/{role-name}",
    url_admin_client_authz_settings : "admin/realms/{realm-name}/clients/{id}/authz/resource-server/settings",
    url_admin_client_authz_resources : "admin/realms/{realm-name}/clients/{id}/authz/resource-server/resource",
    url_admin_client_certs : "admin/realms/{realm-name}/clients/{id}/certificates/{attr}",

    url_admin_realm_roles : "admin/realms/{realm-name}/roles",
    url_admin_realm_import : "admin/realms",
    url_admin_idps : "admin/realms/{realm-name}/identity-provider/instances",

    url_admin_flows : "admin/realms/{realm-name}/authentication/flows",
    url_admin_flows_executions : "admin/realms/{realm-name}/authentication/flows/{flow-alias}/executions",
    */
};
