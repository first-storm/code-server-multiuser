use std::{
    collections::HashMap,
    env,
    fs,
    io::{self, ErrorKind},
    path::Path,
    process::Command,
    time::SystemTime,
};

use crate::{
    storage::{DATADIR, DOCKER_IMAGE},
    traefik::{self, Instance},
};

use log::{error, info};
use regex::Regex;
use semver::Version;
use serde::Deserialize;
use users::{get_current_gid, get_current_uid};

pub struct ContainerManager;

impl ContainerManager {
    /// Create a new Docker container
    pub fn create_container(uid: &str) -> io::Result<()> {
        Self::run_docker_create_command(uid)
    }

    /// Update an existing Docker container
    pub fn update_container(uid: &str) -> io::Result<()> {
        let container_id = format!("{}.codeserver", uid);

        // Check if the container is running, if so, stop it
        if Self::is_container_running(uid)? {
            Self::stop_container(&container_id, &mut traefik::Instances::new())?;
        }

        // Remove the existing container
        Self::remove_container(&container_id)?;

        // Pull the latest image
        Self::pull_latest_image()?;

        // Recreate the container
        Self::run_docker_create_command(uid)
    }

    /// Start Docker container
    pub fn start_container(
        container_id: &str,
        token: &str,
        traefik_instances: &mut traefik::Instances,
    ) -> io::Result<()> {
        let output = Command::new("docker").arg("start").arg(container_id).output()?;

        if output.status.success() {
            info!("Successfully started container: {}", container_id);

            if let Err(e) = traefik_instances.add(Instance {
                name: container_id.to_string(),
                token: token.to_string(),
            }) {
                let error_message = format!("Failed to add traefik instance: {}", e);
                error!("{}", error_message);
                return Err(io::Error::new(ErrorKind::Other, error_message));
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

    /// Stop Docker container
    pub fn stop_container(
        container_id: &str,
        traefik_instances: &mut traefik::Instances,
    ) -> io::Result<()> {
        let output = Command::new("docker").arg("stop").arg(container_id).output()?;

        if output.status.success() {
            info!("Successfully stopped container: {}", container_id);
            if let Err(e) = traefik_instances.remove(container_id) {
                error!(
                    "Failed to remove traefik instance for container {}: {}",
                    container_id, e
                );
            }
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
        let output = Command::new("docker").arg("inspect").arg("--format").arg("{{.State.Running}}").arg(&container_id).output()?;

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

    /// Check and stop expired containers
    pub fn check_expiration(
        users: &mut Vec<crate::user::User>,
        traefik_instances: &mut traefik::Instances,
    ) {
        for user in users.iter_mut() {
            let heartbeat_path = format!(
                "{}/{}.data/.local/share/code-server/heartbeat",
                *DATADIR, user.uid
            );

            let is_expired = match fs::metadata(&heartbeat_path).and_then(|metadata| metadata.modified()).and_then(|modified_time| {
                SystemTime::now().duration_since(modified_time).map_err(|e| io::Error::new(ErrorKind::Other, e))
            }) {
                Ok(duration) => duration.as_secs() > 1200,
                Err(_) => false,
            };

            if is_expired {
                info!(
                    "User '{}' has been idle for too long. Logging out.",
                    user.username
                );
                if let Err(e) = Self::logout_user(user, traefik_instances) {
                    error!("Failed to log out user '{}': {}", user.username, e);
                } else {
                    info!("Successfully logged out user '{}'", user.username);
                }
            }
        }
    }

    /// Log out a user
    pub fn logout_user(
        user: &mut crate::user::User,
        traefik_instances: &mut traefik::Instances,
    ) -> io::Result<()> {
        let container_id = format!("{}.codeserver", user.uid);

        // Stop the container if it's running
        if Self::is_container_running(&user.uid.to_string())? {
            Self::stop_container(&container_id, traefik_instances)?;
        }

        // Clear the user's token
        user.token = None;
        info!("Cleared token for user: {}", user.username);

        Ok(())
    }

    /// Log out all users
    pub fn logout_all_users(
        users: &mut Vec<crate::user::User>,
        traefik_instances: &mut traefik::Instances,
    ) -> io::Result<()> {
        for user in users.iter_mut() {
            if let Err(e) = Self::logout_user(user, traefik_instances) {
                error!("Failed to log out user '{}': {}", user.username, e);
            } else {
                info!("Successfully logged out user '{}'", user.username);
            }
        }
        Ok(())
    }

    /// Private function to build Docker create command
    fn build_docker_create_command(uid: &str) -> io::Result<Command> {
        // Prepare environment variables and paths
        let home = dirs::home_dir().ok_or_else(|| io::Error::new(ErrorKind::Other, "Cannot determine home directory"))?;
        let home_str = home.to_str().ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid home directory"))?;

        let pwd = env::current_dir()?;
        let pwd_str = pwd.to_str().ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid current directory"))?;

        let user = env::var("USER").map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        // Get the numeric UID and GID without spawning a process
        let uid_num = get_current_uid();
        let gid_num = get_current_gid();
        let uid_str = uid_num.to_string();
        let gid_str = gid_num.to_string();

        // Get the latest image tag
        let latest_tag = Self::get_latest_image_tag()?;
        let image_with_tag = format!("{}:{}", DOCKER_IMAGE.as_str(), latest_tag);

        // Build Docker create command
        let mut command = Command::new("docker");
        command.arg("create").arg("--name").arg(format!("{}.codeserver", uid)).arg("-v").arg(format!(
            "{}/{}.data/.local:{}/.local",
            DATADIR.as_str(),
            uid,
            home_str
        )).arg("-v").arg(format!(
            "{}/{}.data/.config:{}/.config",
            DATADIR.as_str(),
            uid,
            home_str
        )).arg("-v").arg(format!(
            "{}/{}.data/project:{}",
            DATADIR.as_str(),
            uid,
            pwd_str
        )).arg("-u").arg(format!("{}:{}", uid_str, gid_str)).arg("-e").arg(format!("DOCKER_USER={}", user))
            // .arg("-e")
            // .arg(format!("PASSWORD={}", password))
            .arg("-e").arg(r#"EXTENSIONS_GALLERY={"serviceUrl": "https://marketplace.visualstudio.com/_apis/public/gallery"}"#).arg("--storage-opt").arg("size=1G").arg("--network").arg("traefik-network").arg(image_with_tag).arg("--auth").arg("none");

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

    /// Private function to remove Docker container
    fn remove_container(container_id: &str) -> io::Result<()> {
        let output = Command::new("docker").arg("rm").arg(container_id).output()?;

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

    /// Private function to pull the latest Docker image
    fn pull_latest_image() -> io::Result<()> {
        let latest_tag = Self::get_latest_image_tag()?;
        let image_with_tag = format!("{}:{}", DOCKER_IMAGE.as_str(), latest_tag);

        let output = Command::new("docker").arg("pull").arg(&image_with_tag).output()?;

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
        let output = Command::new("docker").arg("inspect").arg("--format").arg("{{.Config.Image}}").arg(container_id).output()?;

        if output.status.success() {
            let image_full_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // Extract the tag part
            if let Some(tag) = image_full_name.split(':').nth(1) {
                Ok(tag.to_string())
            } else {
                // Default tag is 'latest' if not specified
                Ok("latest".to_string())
            }
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

        // Check if the cache file exists and is within one hour
        if Path::new(cache_file).exists() {
            let metadata = fs::metadata(cache_file)?;
            let modified_time = metadata.modified()?;
            if let Ok(duration) = SystemTime::now().duration_since(modified_time) {
                if duration.as_secs() < 3600 {
                    // Cache is valid
                    let cached_tag = fs::read_to_string(cache_file)?;
                    return Ok(cached_tag.trim().to_string());
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
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?
            .json()
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        // Iterate over tags and extract versions
        fn extract_version(tag: &str) -> Option<Version> {
            // Match tags that are exactly x.y.z
            let re = Regex::new(r"^(\d+\.\d+\.\d+)$").unwrap();
            if let Some(caps) = re.captures(tag) {
                let version_str = caps.get(1).unwrap().as_str();
                if let Ok(version) = Version::parse(version_str) {
                    return Some(version);
                }
            }
            None
        }

        // Collect all valid versions and corresponding tags
        let mut version_tags: HashMap<Version, String> = HashMap::new();

        for tag in tags_resp.tags {
            if let Some(version) = extract_version(&tag) {
                version_tags.insert(version, tag);
            }
        }

        if version_tags.is_empty() {
            return Err(io::Error::new(
                ErrorKind::Other,
                "No valid version tags found",
            ));
        }

        // Find the highest version
        let latest_version = version_tags.keys().max().unwrap();
        let latest_tag = version_tags.get(latest_version).unwrap().clone();

        // Cache the latest tag
        fs::write(cache_file, &latest_tag)?;

        Ok(latest_tag)
    }

    /// Check if a container is using the latest version
    pub fn is_container_latest_version(container_id: &str) -> io::Result<bool> {
        let container_tag = Self::get_container_tag(container_id)?;
        let latest_tag = Self::get_latest_image_tag()?;
        Ok(container_tag == latest_tag)
    }
}
