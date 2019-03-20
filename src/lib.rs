#![deny(warnings)]

#[macro_use] pub extern crate serde_json;
#[macro_use] pub extern crate serde_derive;
pub extern crate serde;
pub extern crate reqwest;
pub extern crate jsonwebtoken as jwt;

pub mod urls;
pub mod keycloak;
pub mod openid;
pub mod admin;
