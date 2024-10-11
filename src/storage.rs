use once_cell::sync::Lazy;
use std::env;

pub static DATADIR: Lazy<String> = Lazy::new(|| {
    env::var("DATADIR").expect("Environment variable 'DATADIR' not set")
});

pub static USERDB: Lazy<String> = Lazy::new(|| {
    env::var("USERDB").expect("Environment variable 'USERDB' not set")
});

// pub static CONFIG: Lazy<String> = Lazy::new(|| {
//     env::var("CONFIG").expect("Environment variable 'CONFIG' not set")
// });

pub static TEMPLATES: Lazy<String> = Lazy::new(|| {
    env::var("TEMPLATES").expect("Environment variable 'DATADIR' not set")
});