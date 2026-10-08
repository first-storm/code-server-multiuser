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
        Self::with_config_path(storage::TRAEFIK_CONFIG.clone())
    }

    pub fn with_config_path(config_path: String) -> Self {
        Instances {
            instances: IndexMap::new(),
            token_to_name: HashMap::new(),
            config_path,
        }
    }

    pub fn add(&mut self, instance: Instance) -> Result<(), io::Error> {
        // If an instance with the same name already exists (e.g. the user
        // logged in again and got a fresh token), drop the stale token
        // mapping first so the old token stops resolving.
        if let Some(old) = self.instances.get(&instance.name) {
            self.token_to_name.remove(&old.token);
        }
        // Insert or update the instance
        self.instances.insert(instance.name.clone(), instance.clone());
        // Update the token_to_name mapping
        self.token_to_name
            .insert(instance.token.clone(), instance.name.clone());
        // Save the updated configuration
        self.save_config()
    }

    /// Remove an instance by instance name, dropping every token mapping
    /// that points at it. Callers pass the container name
    /// (`<uid>.codeserver`), which is the instance name.
    pub fn remove(&mut self, instance_name: &str) -> Result<(), io::Error> {
        if self.instances.swap_remove(instance_name).is_some() {
            self.token_to_name
                .retain(|_, name| name != instance_name);
        }
        self.save_config()
    }

    fn save_config(&self) -> Result<(), io::Error> {
        // Serialize first: if serialization fails, keep the old file
        // untouched instead of wiping the live Traefik configuration.
        let new_config = self.generate_traefik_config().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize Traefik config: {}", e),
            )
        })?;
        // Atomic write so the Traefik file watcher never reads a partial file.
        let tmp_path = format!("{}.tmp", self.config_path);
        fs::write(&tmp_path, new_config)?;
        fs::rename(&tmp_path, &self.config_path)
    }

    pub fn shutdown(&mut self) -> Result<(), io::Error> {
        self.instances.clear();      // Clear instances
        self.token_to_name.clear();  // Clear token mappings
        self.save_config()?;         // Save the empty configuration
        Ok(())
    }

    fn generate_traefik_config(&self) -> Result<String, serde_yml::Error> {
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
        serde_yml::to_string(&config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_instances() -> (Instances, String) {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "traefik-instances-test-{}-{}.yml",
            std::process::id(),
            id
        ));
        let path_str = path.to_string_lossy().to_string();
        (Instances::with_config_path(path_str.clone()), path_str)
    }

    fn read_config(path: &str) -> String {
        fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn remove_by_instance_name_drops_instance_and_token_mapping() {
        let (mut instances, config_path) = test_instances();
        instances
            .add(Instance {
                name: "123.codeserver".to_string(),
                token: "token-aaa".to_string(),
            })
            .unwrap();
        assert!(read_config(&config_path).contains("token-aaa"));

        // Callers pass the container/instance name (see stop_container).
        instances.remove("123.codeserver").unwrap();

        assert!(
            !instances.instances.contains_key("123.codeserver"),
            "instance must be gone after remove()"
        );
        assert!(
            !instances.token_to_name.contains_key("token-aaa"),
            "stale token mapping must be gone after remove()"
        );
        assert!(
            !read_config(&config_path).contains("token-aaa"),
            "regenerated config must not route the removed instance"
        );
        let _ = fs::remove_file(&config_path);
    }

    #[test]
    fn add_same_name_twice_replaces_stale_token_mapping() {
        let (mut instances, config_path) = test_instances();
        instances
            .add(Instance {
                name: "123.codeserver".to_string(),
                token: "token-old".to_string(),
            })
            .unwrap();
        // User logs in again and gets a fresh token for the same container.
        instances
            .add(Instance {
                name: "123.codeserver".to_string(),
                token: "token-new".to_string(),
            })
            .unwrap();

        assert_eq!(instances.instances.len(), 1);
        assert!(
            !instances.token_to_name.contains_key("token-old"),
            "old token mapping must be dropped when instance is overwritten"
        );
        assert_eq!(
            instances.token_to_name.get("token-new").unwrap(),
            "123.codeserver"
        );
        let config = read_config(&config_path);
        assert!(config.contains("token-new"));
        assert!(!config.contains("token-old"));
        let _ = fs::remove_file(&config_path);
    }

    #[test]
    fn generated_config_routes_token_to_container() {
        let (mut instances, config_path) = test_instances();
        instances
            .add(Instance {
                name: "42.codeserver".to_string(),
                token: "secret-token".to_string(),
            })
            .unwrap();

        let config = read_config(&config_path);
        assert!(config.contains("42.codeserver-router"));
        assert!(config.contains("42.codeserver-service"));
        assert!(config.contains("http://42.codeserver:8080"));
        assert!(config.contains("secret-token"));
        let _ = fs::remove_file(&config_path);
    }
}