#[macro_use]
pub extern crate serde_json;
#[macro_use]
pub extern crate serde_derive;
pub extern crate jsonwebtoken as jwt;
pub extern crate reqwest;
pub extern crate serde;

pub mod admin;
pub mod keycloak;
pub mod openid;
pub mod urls;
