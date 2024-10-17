use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, io};

use indexmap::IndexMap;

mod traefik_config_dynamic;

use super::storage;
use traefik_config_dynamic::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Instance {
    pub(crate) name: String,
    pub(crate) token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Instances {
    pub(crate) instances: IndexMap<String, Instance>, // Map instance name to Instance
    token_to_name: HashMap<String, String>,           // Map token to instance name
    config_path: String,                              // Traefik dynamic configuration file path
}

impl Instances {
    // Initialize Instances with the configuration path
    pub fn new() -> Self {
        Instances {
            instances: IndexMap::new(),
            token_to_name: HashMap::new(),
            config_path: storage::TRAEFIK_CONFIG.clone(),
        }
    }

    pub fn add(&mut self, instance: Instance) -> Result<(), io::Error> {
        // Insert or update the instance
        self.instances.insert(instance.name.clone(), instance.clone());
        // Update the token_to_name mapping
        self.token_to_name
            .insert(instance.token.clone(), instance.name.clone());
        // Save the updated configuration
        self.save_config()
    }

    pub fn remove(&mut self, instance_token: &str) -> Result<(), io::Error> {
        if let Some(instance_name) = self.token_to_name.remove(instance_token) {
            self.instances.swap_remove(&instance_name);
        }
        self.save_config()
    }

    fn save_config(&self) -> Result<(), io::Error> {
        // Generate and save the Traefik configuration
        let new_config = self.generate_traefik_config();
        fs::write(&self.config_path, new_config)
    }

    pub fn shutdown(&mut self) -> Result<(), io::Error> {
        self.instances.clear();      // Clear instances
        self.token_to_name.clear();  // Clear token mappings
        self.save_config()?;         // Save the empty configuration
        Ok(())
    }

    fn generate_traefik_config(&self) -> String {
        // Generate the Traefik dynamic configuration based on current instances
        let mut config = DynamicConfig {
            http: HttpConfig {
                routers: HashMap::new(),   // Use HashMap instead of IndexMap
                services: HashMap::new(),  // Use HashMap instead of IndexMap
            },
        };

        for (instance_name, instance) in &self.instances {
            let router = Router {
                rule: format!("HeaderRegexp(`Cookie`, `auth_token={}`)", instance.token),
                service: format!("{}-service", instance_name),
                entryPoints: vec![String::from("web")],
            };
            let service = Service {
                loadBalancer: LoadBalancer {
                    servers: vec![LoadBalancerServer {
                        url: format!("http://{}:8080", instance_name),
                    }],
                    passHostHeader: true,
                },
            };
            config.http.services.insert(format!("{}-service", instance_name), service);
            config.http.routers.insert(format!("{}-router", instance_name), router);
        }

        // Serialize to a YAML string and return
        serde_yml::to_string(&config).unwrap_or_else(|_| String::new())
    }
}