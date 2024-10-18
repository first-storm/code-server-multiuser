use std::env;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref DATADIR: String = env::var("DATADIR").expect("Environment variable 'DATADIR' not set");

    pub static ref USERDB: String = env::var("USERDB").expect("Environment variable 'USERDB' not set");

    pub static ref TRAEFIK_CONFIG: String = env::var("TRAEFIK_CONFIG").expect("Environment variable 'TRAEFIK_CONFIG' not set");

    pub static ref TEMPLATES: String = env::var("TEMPLATES").expect("Environment variable 'DATADIR' not set");

    pub static ref UID_WHITELIST: String = env::var("UID_WHITELIST").expect("Environment variable 'UID_WHITELIST' not set");

    pub static ref DOMAIN: String = env::var("DOMAIN").expect("Environment variable 'DOMAIN' not set");

    pub static ref DOCKER_IMAGE: String = env::var("DOCKER_IMAGE").expect("Environment variable 'DOCKER_IMAGE' not set.");

    pub static ref SAVE_INTERVAL: u64 = env::var("SAVE_INTERVAL").expect("Environment variable 'SAVE_INTERVAL' not set.").parse::<u64>().expect("Environment variable 'SAVE_INTERVAL' not a number.");
    
    // pub static ref GITHUB_TOKEN: String = env::var("GITHUB_TOKEN").expect("Environment variable 'GITHUB_TOKEN' not set");
}
