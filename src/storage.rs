use once_cell::sync::Lazy;
use std::env;

pub static DATADIR: Lazy<String> = Lazy::new(|| {
    env::var("DATADIR").expect("Environment variable 'DATADIR' not set")
});

pub static USERDB: Lazy<String> = Lazy::new(|| {
    env::var("USERDB").expect("Environment variable 'USERDB' not set")
});

pub static TRAEFIK_CONFIG: Lazy<String> = Lazy::new(|| {
    env::var("TRAEFIK_CONFIG").expect("Environment variable 'TRAEFIK_CONFIG' not set")
});

pub static TEMPLATES: Lazy<String> = Lazy::new(|| {
    env::var("TEMPLATES").expect("Environment variable 'DATADIR' not set")
});

pub static UID_WHITELIST: Lazy<String> = Lazy::new(|| {
    env::var("UID_WHITELIST").expect("Environment variable 'UID_WHITELIST' not set")
});

pub static DOMAIN: Lazy<String> = Lazy::new(|| {
    env::var("DOMAIN").expect("Environment variable 'DOMAIN' not set")
});

pub static DOCKER_IMAGE: Lazy<String> = Lazy::new(|| {
    env::var("DOCKER_IMAGE").expect("Environment variable 'DOCKER_IMAGE' not set.")
});

// pub static GITHUB_TOKEN: Lazy<String> = Lazy::new(|| {
//     env::var("GITHUB_TOKEN").expect("Environment variable 'GITHUB_TOKEN' not set")
// });