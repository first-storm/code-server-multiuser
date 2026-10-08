use std::{
    env, fs,
    io::{self, ErrorKind},
    process::Command,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use crate::storage::DOCKER_IMAGE;
use lazy_static::lazy_static;
use log::{error, info};
use regex::Regex;
use serde::Deserialize;
use users::{get_current_gid, get_current_uid};

lazy_static! {
    static ref UID: u32 = get_current_uid();
    static ref GID: u32 = get_current_gid();
    static ref USERNAME: String = env::var("USER").unwrap_or_else(|_| "default_user".to_string());
    static ref VERSION_REGEX: Regex = Regex::new(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$").unwrap();
    static ref CACHE_MUTEX: Mutex<()> = Mutex::new(());
}

pub struct ContainerManager;

impl ContainerManager {
    /// Create a new Docker container
    pub fn create_container(uid: &str) -> io::Result<()> {
        Self::run_docker_create_command(uid)
    }

    /// Start a Docker container and run the first-boot setup commands
    /// inside it. Blocking: callers on async runtimes must run this in
    /// `spawn_blocking`. This only touches Docker; Traefik bookkeeping is
    /// done separately by the caller under a short database lock.
    pub fn start_container_docker(container_id: &str) -> io::Result<()> {
        let output = Command::new("docker")
            .arg("start")
            .arg(container_id)
            .output()?;

        if output.status.success() {
            info!("Successfully started container: {}", container_id);

            // Execute commands inside the container
            let exec_commands = r#"
                mkdir -p /home/coder/.local/share/code-server/User/;
                if [ ! -e /home/coder/.local/share/code-server/extensions ]; then
                    ln -s /home/defaultconfig/.local/share/code-server/extensions /home/coder/.local/share/code-server/extensions;
                fi;
                if [ ! -e /home/coder/.local/share/code-server/User/settings.json ]; then
                    cp /home/defaultconfig/.local/share/code-server/User/settings.json /home/coder/.local/share/code-server/User/settings.json;
                fi
            "#;

            let exec_output = Command::new("docker")
                .arg("exec")
                .arg(container_id)
                .arg("sh")
                .arg("-c")
                .arg(exec_commands)
                .output()?;

            if exec_output.status.success() {
                info!("Executed command inside container: {}", container_id);
            } else {
                let exec_error = String::from_utf8_lossy(&exec_output.stderr);
                error!(
                    "Failed to execute command inside container: {}. Error: {}",
                    container_id, exec_error
                );
                return Err(io::Error::new(ErrorKind::Other, exec_error.to_string()));
            }

            Ok(())
        } else {
            let error_message = format!(
                "Failed to start container: {}. Error: {}",
                container_id,
                String::from_utf8_lossy(&output.stderr)
            );
            error!("{}", error_message);
            Err(io::Error::new(ErrorKind::Other, error_message))
        }
    }

    /// Stop a Docker container. Blocking: callers on async runtimes must
    /// run this in `spawn_blocking`. This only touches Docker; Traefik
    /// bookkeeping is done separately by the caller under a short lock.
    pub fn stop_container_docker(container_id: &str) -> io::Result<()> {
        let output = Command::new("docker")
            .arg("stop")
            .arg(container_id)
            .output()?;

        if output.status.success() {
            info!("Successfully stopped container: {}", container_id);
            Ok(())
        } else {
            let error_message = format!(
                "Failed to stop container: {}. Error: {}",
                container_id,
                String::from_utf8_lossy(&output.stderr)
            );
            error!("{}", error_message);
            Err(io::Error::new(ErrorKind::Other, error_message))
        }
    }

    /// Check if a container is running
    pub fn is_container_running(uid: &str) -> io::Result<bool> {
        let container_id = format!("{}.codeserver", uid);
        let output = Command::new("docker")
            .arg("inspect")
            .arg("--format")
            .arg("{{.State.Running}}")
            .arg(&container_id)
            .output()?;

        if output.status.success() {
            let is_running = String::from_utf8_lossy(&output.stdout).trim() == "true";
            Ok(is_running)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(io::Error::new(
                ErrorKind::Other,
                format!("Docker error: {}", stderr),
            ))
        }
    }

    /// Private function to build Docker create command
    fn build_docker_create_command(uid: &str) -> io::Result<Command> {
        let image_with_tag = format!(
            "{}:{}",
            DOCKER_IMAGE.as_str(),
            Self::get_latest_image_tag()?
        );

        let mut command = Command::new("docker");
        command
            .arg("create")
            .arg("--name")
            .arg(format!("{}.codeserver", uid))
            .arg("-v")
            .arg(format!("/mnt/code-data/{}.data/home:/home/coder", uid))
            .arg("-u")
            .arg(format!("{}:{}", *UID, *GID))
            .arg("-e")
            .arg(format!("DOCKER_USER={}", *USERNAME))
            .arg("-e")
            .arg(
                r#"EXTENSIONS_GALLERY={"serviceUrl": "https://marketplace.visualstudio.com/_apis/public/gallery"}"#,
            )
            .arg("-e")
            .arg("XDG_DATA_HOME=/home/coder/.local/share")
            .arg("--storage-opt")
            .arg("size=1G")
            .arg("--network")
            .arg("traefik-network")
            .arg(image_with_tag)
            .arg("--auth")
            .arg("none")
            .arg("--bind-addr")
            .arg("0.0.0.0:8080")
            .arg("--user-data-dir")
            .arg("/home/coder/.local/share/code-server");
        Ok(command)
    }

    /// Private function to execute Docker create command
    fn run_docker_create_command(uid: &str) -> io::Result<()> {
        let mut command = Self::build_docker_create_command(uid)?;
        let output = command.output()?;

        if output.status.success() {
            info!("Successfully created container for UID: {}", uid);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                "Failed to create container for UID: {}. Error: {}",
                uid, stderr
            );
            Err(io::Error::new(
                ErrorKind::Other,
                format!("Docker create command failed: {}", stderr),
            ))
        }
    }

    /// Remove a Docker container. Blocking: callers on async runtimes
    /// must run this in `spawn_blocking`.
    pub fn remove_container(container_id: &str) -> io::Result<()> {
        let output = Command::new("docker")
            .arg("rm")
            .arg(container_id)
            .output()?;

        if output.status.success() {
            info!("Successfully removed container '{}'", container_id);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                "Failed to remove container '{}'. Error: {}",
                container_id, stderr
            );
            Err(io::Error::new(
                ErrorKind::Other,
                format!("Docker rm command failed: {}", stderr),
            ))
        }
    }

    /// Pull the latest Docker image. Blocking: callers on async runtimes
    /// must run this in `spawn_blocking`.
    pub fn pull_latest_image() -> io::Result<()> {
        let latest_tag = Self::get_latest_image_tag()?;
        let image_with_tag = format!("{}:{}", DOCKER_IMAGE.as_str(), latest_tag);

        let output = Command::new("docker")
            .arg("pull")
            .arg(&image_with_tag)
            .output()?;

        if output.status.success() {
            info!("Successfully pulled the latest image '{}'", image_with_tag);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                "Failed to pull the latest image '{}'. Error: {}",
                image_with_tag, stderr
            );
            Err(io::Error::new(
                ErrorKind::Other,
                format!("Docker pull command failed: {}", stderr),
            ))
        }
    }

    /// Get the tag of a container given its ID
    pub fn get_container_tag(container_id: &str) -> io::Result<String> {
        let output = Command::new("docker")
            .arg("inspect")
            .arg("--format")
            .arg("{{.Config.Image}}")
            .arg(container_id)
            .output()?;

        if output.status.success() {
            let image_full_name = String::from_utf8_lossy(&output.stdout);
            Ok(parse_image_tag(image_full_name.trim()).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(io::Error::new(
                ErrorKind::Other,
                format!("Failed to get container tag: {}", stderr),
            ))
        }
    }

    /// Get the latest tag version of the image, with a one-hour cache
    pub fn get_latest_image_tag() -> io::Result<String> {
        let cache_file = "/tmp/docker_image_latest_tag.cache";
        let _cache_lock = CACHE_MUTEX.lock().unwrap();

        // Check if the cache file exists and is within one hour
        if let Ok(metadata) = fs::metadata(cache_file) {
            if let Ok(modified_time) = metadata.modified() {
                if let Ok(duration) = SystemTime::now().duration_since(modified_time) {
                    if duration < Duration::from_secs(3600) {
                        // Cache is valid
                        if let Ok(cached_tag) = fs::read_to_string(cache_file) {
                            return Ok(cached_tag.trim().to_string());
                        }
                    }
                }
            }
        }

        // Parse DOCKER_IMAGE
        let docker_image = DOCKER_IMAGE.as_str();
        let parts: Vec<&str> = docker_image.split('/').collect();
        if parts.len() != 3 {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Invalid DOCKER_IMAGE format. Expected format: registry/user/image",
            ));
        }
        let registry = parts[0];
        let user = parts[1];
        let image = parts[2];

        if registry != "ghcr.io" {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Registry not supported. Only 'ghcr.io' is supported.",
            ));
        }

        // Create HTTP client
        let client = reqwest::blocking::Client::new();

        // Get token (for public images, a fake NOOP token is sufficient)
        let token_url = format!(
            "https://ghcr.io/token?scope=repository:{}%2F{}:pull",
            user, image
        );
        #[derive(Deserialize)]
        struct TokenResponse {
            token: String,
        }
        let token_resp: TokenResponse = client
            .get(&token_url)
            .send()
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?
            .json()
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        // Get list of tags
        let tags_url = format!("https://ghcr.io/v2/{}/{}/tags/list", user, image);
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct TagsResponse {
            name: String,
            tags: Vec<String>,
        }
        let tags_resp: TagsResponse = client
            .get(&tags_url)
            .header("Authorization", format!("Bearer {}", token_resp.token))
            .send()
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?
            .json()
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        let latest_tag = select_latest_tag(tags_resp.tags)
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "No valid version tags found"))?;

        // Cache the latest tag
        fs::write(cache_file, &latest_tag)?;

        Ok(latest_tag)
    }

    /// Check if a container is using the latest version
    #[allow(dead_code)]
    pub fn is_container_latest_version(container_id: &str) -> io::Result<bool> {
        let container_tag = Self::get_container_tag(container_id)?;
        let latest_tag = Self::get_latest_image_tag()?;
        Ok(container_tag == latest_tag)
    }
}

/// Extract the tag from a `docker inspect` image reference.
/// Uses the last `:` so registries with a port (e.g.
/// `localhost:5000/user/image:1.0.0.0`) parse correctly.
fn parse_image_tag(image_full_name: &str) -> &str {
    image_full_name
        .rsplit_once(':')
        .map(|(_, tag)| tag)
        .unwrap_or("latest")
}

/// Pick the highest `x.y.z.w` version tag, ignoring anything else.
fn select_latest_tag(tags: Vec<String>) -> Option<String> {
    let mut version_tags: Vec<((u64, u64, u64, u64), String)> = tags
        .into_iter()
        .filter_map(|tag| {
            let version = VERSION_REGEX.captures(&tag).and_then(|caps| {
                Some((
                    caps.get(1)?.as_str().parse().ok()?,
                    caps.get(2)?.as_str().parse().ok()?,
                    caps.get(3)?.as_str().parse().ok()?,
                    caps.get(4)?.as_str().parse().ok()?,
                ))
            })?;
            Some((version, tag))
        })
        .collect();

    version_tags.sort_by_key(|(version, _)| std::cmp::Reverse(*version));
    version_tags.into_iter().next().map(|(_, tag)| tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_image_tag_handles_registries_with_ports() {
        assert_eq!(parse_image_tag("ghcr.io/user/image:1.2.3.4"), "1.2.3.4");
        assert_eq!(
            parse_image_tag("localhost:5000/user/image:2.0.0.0"),
            "2.0.0.0"
        );
        assert_eq!(parse_image_tag("image"), "latest");
    }

    #[test]
    fn select_latest_tag_picks_highest_version() {
        let tags = vec![
            "1.2.3.4".to_string(),
            "latest".to_string(),
            "1.10.0.0".to_string(),
            "not-a-version".to_string(),
            "1.2.3.10".to_string(),
        ];
        assert_eq!(select_latest_tag(tags).as_deref(), Some("1.10.0.0"));
    }

    #[test]
    fn select_latest_tag_returns_none_without_valid_tags() {
        assert_eq!(select_latest_tag(vec![]), None);
        assert_eq!(
            select_latest_tag(vec!["latest".to_string(), "v1".to_string()]),
            None
        );
    }
}
