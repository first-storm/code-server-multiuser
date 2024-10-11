use crate::storage::{DATADIR, USERDB};
use bcrypt::{hash, verify};
use log::{error, info, warn};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::{env, fmt, io};
use tokio::sync::Mutex;
use tokio::time::sleep;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub(crate) uid: isize,
    pub(crate) username: String,
    pub(crate) email: String,
    pub(crate) password: String,
    pub(crate) token: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct UserDB {
    users: Vec<User>,
    file_path: String,
}

type SharedUserDB = Arc<Mutex<UserDB>>;

#[derive(Debug)]
pub enum LoginError {
    UserNotFound,
    IncorrectPassword,
    ContainerError(String),
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::UserNotFound => write!(f, "User not found"),
            LoginError::IncorrectPassword => write!(f, "Incorrect password"),
            LoginError::ContainerError(msg) => write!(f, "Container error: {}", msg),
        }
    }
}

impl Error for LoginError {}

impl UserDB {
    /// A func to generate token, which is used to verify user's identity.
    fn generate_unique_token(&self) -> String {
        loop {
            // Generate a 16-character random combination of letters and numbers
            let token: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();

            // Check if there are any duplicate tokens
            if !self.users.iter().any(|u| u.token.as_deref() == Some(&token)) {
                return token;
            }
        }
    }


    /// Creates a new `UserDB` instance with the given file path and writes the empty database to the file.
    pub fn new(file_path: &str) -> UserDB {
        info!("Creating a new user database with file path: {}", file_path);
        let udb = UserDB {
            users: Vec::new(),
            file_path: file_path.to_string(),
        };
        udb.write_to_file();  // Write the initial empty database to file
        udb
    }

    /// Adds a new user to the database and writes the updated database to file.
    pub fn add_user(&mut self, mut user: User) -> Result<(), Box<dyn Error>> {
        let hashed_password = hash(&user.password, bcrypt::DEFAULT_COST)?;  // Hash the user's password
        user.password = hashed_password;
        info!("Added new user: {:?}", user.username);
        self.users.push(user);  // Add user to the user list
        self.write_to_file()?;  // Write updated database to file
        Ok(())
    }

    /// Handles user login, container validation, and startup.
    pub fn login(&mut self, username: String, password: String) -> Result<String, LoginError> {
        // Find the user; to avoid mutable borrowing, first use an immutable borrow to search for the user
        let user_exists = self
            .users
            .iter()
            .find(|u| u.username == username)
            .ok_or_else(|| {
                warn!("User '{}' not found", username);
                LoginError::UserNotFound
            })?;

        // Validate the password
        if !verify(password, &user_exists.password).map_err(|_| LoginError::IncorrectPassword)? {
            warn!("Incorrect password for user: {}", username);
            return Err(LoginError::IncorrectPassword);
        }

        // Generate a unique token; at this point, we haven't mutably borrowed `self`
        let token = self.generate_unique_token();

        // Now find the user with a mutable borrow and update the token
        let user = self
            .users
            .iter_mut()
            .find(|u| u.username == username)
            .expect("User should exist after the previous check");

        user.token = Some(token.clone()); // Set the user's token

        // Docker container logic
        let container_id = format!("{}.codeserver", user.uid);
        let output = Command::new("docker")
            .arg("ps")
            .arg("-a")
            .arg("--filter")
            .arg(format!("name={}", container_id))
            .arg("--format")
            .arg("{{.Names}}")
            .output()
            .map_err(|e| {
                error!("Failed to list containers: {}", e);
                LoginError::ContainerError(format!("Failed to list containers: {}", e))
            })?;

        let container_exists = !String::from_utf8_lossy(&output.stdout).trim().is_empty();

        if container_exists {
            let running_output = Command::new("docker")
                .arg("inspect")
                .arg("--format")
                .arg("{{.State.Running}}")
                .arg(&container_id)
                .output()
                .map_err(|e| {
                    error!("Failed to check container status: {}", e);
                    LoginError::ContainerError(format!("Failed to check container status: {}", e))
                })?;

            let is_running = String::from_utf8_lossy(&running_output.stdout).trim() == "true";

            if is_running {
                info!("Container {} is already running.", container_id);
            } else {
                info!("Container {} exists but is not running. Starting it.", container_id);
                Self::start_container(&container_id);
            }
        } else {
            info!("Container {} does not exist. Creating and starting it.", container_id);
            if let Err(e) = Self::create_container(&user.uid.to_string(), &user.password) {
                error!("Failed to create container for user {}: {}", username, e);
                return Err(LoginError::ContainerError("Failed to create container".to_string()));
            }
        }

        info!("Login successful for user: {}", username);
        Ok(token) // Return the generated token
    }


    /// Check if a username exists in the database.
    pub fn username_exists(&self, username: &str) -> bool {
        self.users.iter().any(|u| u.username == username)
    }

    /// Check if an email exists in the database.
    pub fn email_exists(&self, email: &str) -> bool {
        self.users.iter().any(|u| u.email == email)
    }

    /// Check if a UID exists in the database.
    pub fn uid_exists(&self, uid: isize) -> bool {
        self.users.iter().any(|u| u.uid == uid)
    }

    /// Retrieve a user by their username.
    pub fn get_user_by_username(&self, username: &str) -> Option<User> {
        info!("Searching for user: {}", username);
        for user in &self.users {
            if user.username == username {
                return Some(user.clone());
            }
        }
        warn!("User '{}' not found", username);
        None
    }

    /// Create a new Docker container for the user.
    fn create_container(uid: &str, password: &str) -> io::Result<()> {
        // Prepare environment variables and paths for Docker
        let home = env::var("HOME").map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let pwd = env::current_dir()?;
        let pwd_str = pwd
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid current directory"))?;
        let user = env::var("USER").map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let uid_output = Command::new("id").arg("-u").output()?;
        let uid_str = String::from_utf8_lossy(&uid_output.stdout).trim().to_string();

        let gid_output = Command::new("id").arg("-g").output()?;
        let gid_str = String::from_utf8_lossy(&gid_output.stdout).trim().to_string();

        // Run Docker command to create the container
        let output = Command::new("docker")
            .arg("run")
            .arg("-d")
            .arg("--name")
            .arg("code-server")
            .arg("-v")
            .arg(format!("{}/{}.data/.local:{}/.local", DATADIR.as_str(), uid, home))
            .arg("-v")
            .arg(format!("{}/{}.data/.config:{}/.config", DATADIR.as_str(), uid, home))
            .arg("-v")
            .arg(format!("{}/{}.data/project:{}", DATADIR.as_str(), uid, pwd_str))
            .arg("-u")
            .arg(format!("{}:{}", uid_str, gid_str))
            .arg("-e")
            .arg(format!("DOCKER_USER={}", user))
            .arg("-e")
            .arg(format!("PASSWORD={}", password))
            .arg("--storage-opt")
            .arg("size=1G")
            .arg("codercom/code-server:latest")
            .output()?;

        if output.status.success() {
            info!("Successfully created container for UID: {}", uid);
            Ok(())
        } else {
            error!("Failed to create container for UID: {}. Error: {}", uid, String::from_utf8_lossy(&output.stderr));
            Err(io::Error::new(io::ErrorKind::Other, "Docker run command failed"))
        }
    }

    /// Stops a Docker container by its container ID.
    fn stop_container(container_id: &str) {
        let output = Command::new("docker")
            .arg("stop")
            .arg(container_id)
            .output()
            .expect("Failed to execute process");

        if output.status.success() {
            info!("Successfully stopped container: {}", container_id);
        } else {
            error!(
                "Failed to stop container: {}. Error: {}",
                container_id,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// Starts a Docker container by its container ID.
    fn start_container(container_id: &str) {
        let output = Command::new("docker")
            .arg("start")
            .arg(container_id)
            .output()
            .expect("Failed to execute process");

        if output.status.success() {
            info!("Successfully started container: {}", container_id);
        } else {
            error!(
                "Failed to start container: {}. Error: {}",
                container_id,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// Checks and stops containers that have been idle for more than 1200 seconds.
    pub fn check_expiration(&mut self) {
        self.users.iter_mut().for_each(|user| {
            let heartbeat_path = format!(
                "{}{}.data/.local/share/code-server/heartbeat",
                *USERDB,
                user.uid
            );

            if let Ok(metadata) = std::fs::metadata(&heartbeat_path) {
                if let Ok(modified_time) = metadata.modified() {
                    let now = SystemTime::now();

                    if let Ok(duration) = now.duration_since(modified_time) {
                        let elapsed_secs = duration.as_secs();
                        if elapsed_secs > 1200 {
                            info!("Stopping expired container for user: {}", user.username);
                            Self::stop_container(&format!("{}.codeserver", user.uid));
                            user.token = None; // 清空过期用户的 Token
                            info!("Cleared token for user: {}", user.username);
                        }
                    }
                }
            }
        });
    }

    /// Writes the current user database to a file in JSON format.
    pub fn write_to_file(&self) -> Result<(), Box<dyn Error>> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.file_path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, &self)?;
        info!("User database written to file: {}", self.file_path);
        Ok(())
    }

    /// Reads the user database from a file and returns a `UserDB` instance.
    pub fn read_from_file(file_path: &str) -> Result<UserDB, Box<dyn Error>> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let mut userdb: UserDB = serde_json::from_reader(reader)?;
        userdb.file_path = file_path.to_string();
        info!("User database loaded from file: {}", file_path);
        Ok(userdb)
    }

    /// Prints the details of all users for debugging purposes.
    pub fn print_users(&self) {
        for user in &self.users {
            info!("{:?}", user);
        }
    }
}
