use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Router {
    pub(crate) rule: String,
    pub(crate) service: String,
    pub(crate) entryPoints: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LoadBalancerServer {
    pub(crate) url: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LoadBalancer {
    pub(crate) servers: Vec<LoadBalancerServer>,
    pub(crate) passHostHeader: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Service {
    pub(crate) loadBalancer: LoadBalancer,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct HttpConfig {
    pub(crate) routers: HashMap<String, Router>,
    pub(crate) services: HashMap<String, Service>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct DynamicConfig {
    pub(crate) http: HttpConfig,
}
