use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::fs;

mod traefik_config_dynamic;

use traefik_config_dynamic::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct Instance {
    pub(crate) name: String,
    pub(crate) token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Instances {
    pub(crate) instances: Vec<Instance>,
    config_path: String, // Unified Traefik dynamic configuration file path
}

impl Instances {
    // Pass in the configuration path when initializing an instance
    pub fn new(config_path: String) -> Self {
        Instances {
            instances: Vec::new(),
            config_path,
        }
    }

    pub fn add(&mut self, instance: Instance) {
        self.instances.push(instance);
        self.save_config();
    }

    pub fn remove(&mut self, instance_token: &str) {
        self.instances.retain(|i| i.token != instance_token);
        self.save_config();
    }

    fn save_config(&self) {
        // Save the configuration to the instance-level config_path
        let new_config = self.generate_traefik_config();
        fs::write(&self.config_path, new_config).expect("Unable to write config to Traefik");
    }

    fn shutdown(&mut self){
        self.instances = Vec::new(); // Clear instances
        self.save_config(); // Save file, shut down all reverse proxies
    }

    fn generate_traefik_config(&self) -> String {
        // Generate the content of the Traefik dynamic configuration file based on the current instances
        let mut config = DynamicConfig {
            http: HttpConfig {
                routers: HashMap::new(), // Add router configurations
                services: HashMap::new(), // Add service configurations
            },
        };
        for instance in &self.instances {
            let router = Router {
                rule: format!("HeadersRegexp(`Cookie`, `auth_token={}`)", instance.token),
                service: format!("{}-service", instance.name),
                entryPoints: vec![String::from("web")],
            };
            let service = Service {
                loadBalancer: LoadBalancer {
                    servers: vec![LoadBalancerServer {
                        url: format!("http://{}:8080", instance.name),
                    }],
                    passHostHeader: true,
                },
            };
            config.http.services.insert(format!("{}-service", instance.name), service);
            config.http.routers.insert(format!("{}-router", instance.name), router);
        }
        // Serialize to a string and return
        serde_json::to_string(&config).unwrap_or_else(|_| String::new())
    }
}
