use super::traefik;
use crate::storage::{DATADIR, USERDB};
use crate::traefik::Instance;
use bcrypt::{hash, verify};
use log::{error, info, warn};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind};
use std::process::Command;
use std::time::SystemTime;
use std::{env, fmt, io};

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
    pub(crate) traefik_instances: traefik::Instances,
    users: Vec<User>,
    file_path: String,
}

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
            traefik_instances: traefik::Instances::new(),
            users: Vec::new(),
            file_path: file_path.to_string(),
        };
        udb.write_to_file().expect("Database is not writeable! Please check permission.");  // Write the initial empty database to file
        udb
    }

    /// Adds a new user to the database and writes the updated database to file.
    pub fn add_user(&mut self, mut user: User) -> Result<(), Box<dyn Error>> {
        let hashed_password = hash(&user.password, bcrypt::DEFAULT_COST)?;  // Hash the user's password
        user.password = hashed_password;
        info!("Added new user: {:?}", user.username);

        // Create and start Docker container for the new user
        if let Err(e) = Self::create_container(&user.uid.to_string(), &user.password) {
            error!("Failed to create container for user {}: {}", user.username, e);
            return Err(Box::new(e));
        } else {
            info!("Successfully created container for user: {}", user.username);
        }

        // Add user to the user list
        self.users.push(user);
        self.write_to_file()?;  // Write updated database to file
        Ok(())
    }

    #[allow(dead_code)]
    pub fn logout(&mut self, uid: isize) -> Result<(), Box<dyn Error>> {
        // Variables to store user information and container status
        let container_id;
        let username;
        let is_running;

        // Limit the scope of the mutable borrow
        {
            // Find the user mutably
            if let Some(user) = self.users.iter_mut().find(|u| u.uid == uid) {
                // Collect necessary data
                container_id = format!("{}.codeserver", user.uid);
                username = user.username.clone(); // Clone to avoid borrowing after this scope

                // Check if the container is running
                is_running = match Self::is_container_running(&user.uid.to_string()) {
                    Ok(val) => val,
                    Err(e) => {
                        error!(
                        "Failed to check if container is running for user {}: {}",
                        user.username, e
                    );
                        return Err(Box::new(e));
                    }
                };

                // Clear the user's token
                user.token = None;
                info!("Cleared token for user: {}", user.username);
            } else {
                error!("User with UID {} not found for logout", uid);
                return Err(Box::new(LoginError::UserNotFound));
            }
        } // The mutable borrow of 'self.users' ends here

        // Now, you can safely call methods that require mutable borrow of 'self'
        if is_running {
            info!("Stopping container for user: {}", username);
            match self.stop_container(&container_id) {
                Ok(()) => info!("Successfully stopped container for user: {}", username),
                Err(e) => { error!("Failed to stop container for user {}: {}", username, e); },
            }
            match self.traefik_instances.remove(&container_id) {
                Ok(_) => { info!("Successfully stopped traefik proxy for user: {}", username); },
                Err(e) => { error!("Failed to stop traefik proxy {}: {}", username, e); }
            }
        } else {
            info!("Container is not running for user: {}", username);
        }

        // Write changes to file
        self.write_to_file()?;

        Ok(())
    }




    pub fn login(&mut self, username: String, password: String) -> Result<String, LoginError> {
        // Find user: use an immutable borrow first to avoid conflicts
        let user_exists = self
            .users
            .iter()
            .find(|u| u.username == username)
            .ok_or_else(|| {
                warn!("User '{}' not found", username);
                LoginError::UserNotFound
            })?;

        // Verify password
        if !verify(password, &user_exists.password).map_err(|_| LoginError::IncorrectPassword)? {
            warn!("Incorrect password for user: {}", username);
            return Err(LoginError::IncorrectPassword);
        }

        // Generate a unique token
        let token = self.generate_unique_token();

        // Record user UID to avoid mutable borrow conflict
        let uid = user_exists.uid.clone();

        // Find user with a mutable borrow and update the token
        {
            let user = self
                .users
                .iter_mut()
                .find(|u| u.username == username)
                .expect("User should exist after the previous check");

            user.token = Some(token.clone()); // Set the user's token
        } // End of mutable borrow

        // Check if the container is running
        match Self::is_container_running(&uid.to_string()) {
            Ok(true) => {
                info!("Container is already running for user: {}", username);

                // Ensure to add a Traefik instance even if the container is running
                if let Err(e) = self.traefik_instances.add(Instance {
                    name: format!("{}.codeserver", uid),
                    token: token.clone(),
                }) {
                    let error_message = format!("Failed to add traefik instance: {}", e);
                    error!("{}", error_message);
                    return Err(LoginError::ContainerError(error_message));
                }
            }
            Ok(false) => {
                // If the container is not running, start the container
                info!("Starting container for user: {}", username);
                match self.start_container(&format!("{}.codeserver", uid), &token) {
                    Ok(()) => info!("Successfully started container for user: {}", username),
                    Err(e) => {
                        error!("Failed to start container for user {}: {}", username, e);
                        return Err(LoginError::ContainerError(e.to_string()));
                    }
                }
            }
            Err(e) => {
                error!("Failed to check container status for user {}: {}", username, e);
                return Err(LoginError::ContainerError(e.to_string()));
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
    #[allow(dead_code)]
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
        let home = env::var("HOME").map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        let pwd = env::current_dir()?;
        let pwd_str = pwd
            .to_str()
            .ok_or_else(|| io::Error::new(ErrorKind::Other, "Invalid current directory"))?;
        let user = env::var("USER").map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        let uid_output = Command::new("id").arg("-u").output()?;
        let uid_str = String::from_utf8_lossy(&uid_output.stdout).trim().to_string();

        let gid_output = Command::new("id").arg("-g").output()?;
        let gid_str = String::from_utf8_lossy(&gid_output.stdout).trim().to_string();

        // Run Docker command to create the container without starting it
        let output = Command::new("docker")
            .arg("create")
            .arg("--name")
            .arg(format!("{}.codeserver", uid))
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
            .arg("-e")
            .arg(r#"EXTENSIONS_GALLERY={"serviceUrl": "https://marketplace.visualstudio.com/_apis/public/gallery"}"#)
            .arg("--storage-opt")
            .arg("size=1G")
            .arg("--network")
            .arg("traefik-network")
            .arg("codercom/code-server:latest")
            .arg("--auth")
            .arg("none")
            .output()?;


        if output.status.success() {
            info!("Successfully created container for UID: {}", uid);
            Ok(())
        } else {
            error!("Failed to create container for UID: {}. Error: {}", uid, String::from_utf8_lossy(&output.stderr));
            Err(io::Error::new(ErrorKind::Other, "Docker create command failed"))
        }
    }


    /// Stops a Docker container by its container ID.
    /// Stops a Docker container by its container ID.
    fn stop_container(&mut self, container_id: &str) -> io::Result<()> {
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

    /// Starts a Docker container by its container ID.
    fn start_container(&mut self, container_id: &str, token: &str) -> io::Result<()> {
        let output = Command::new("docker")
            .arg("start")
            .arg(container_id)
            .output()?;

        if output.status.success() {
            info!("Successfully started container: {}", container_id);

            if let Err(e) = self.traefik_instances.add(Instance {
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

    pub fn is_container_running(uid: &str) -> io::Result<bool> {
        // Construct the container ID/name based on the UID
        let container_id = format!("{}.codeserver", uid);

        // Run Docker inspect command to check if the container is running
        let output = Command::new("docker")
            .arg("inspect")
            .arg("--format")
            .arg("{{.State.Running}}")
            .arg(&container_id)
            .output()?;

        // Check if the command succeeded
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(ErrorKind::Other, format!("Docker error: {}", stderr)));
        }

        // Get the output and check if it's "true" (container is running)
        let is_running = String::from_utf8_lossy(&output.stdout).trim() == "true";

        Ok(is_running)
    }


    /// Checks and stops containers that have been idle for more than 1200 seconds.
    pub fn check_expiration(&mut self) {
        // Collect a list of user UIDs to log out to avoid mutable/immutable borrow conflicts
        let expired_user_uids: Vec<isize> = self
            .users
            .iter()
            .filter_map(|user| {
                let heartbeat_path = format!(
                    "{}{}.data/.local/share/code-server/heartbeat",
                    *USERDB,
                    user.uid
                );

                if let Ok(metadata) = std::fs::metadata(&heartbeat_path) {
                    if let Ok(modified_time) = metadata.modified() {
                        if let Ok(duration) = SystemTime::now().duration_since(modified_time) {
                            if duration.as_secs() > 1200 {
                                info!(
                                "User '{}' has been idle for too long. Marking for logout.",
                                user.username
                            );
                                return Some(user.uid); // Collect UID for logout
                            }
                        }
                    }
                }
                None
            })
            .collect();

        // Log out the expired users in a second loop to avoid borrowing conflicts
        for uid in expired_user_uids {
            if let Err(e) = self.logout(uid) {
                error!("Failed to log out user with UID {}: {}", uid, e);
            } else {
                info!("Successfully logged out user with UID {}", uid);
            }
        }
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
    #[allow(dead_code)]
    pub fn print_users(&self) {
        for user in &self.users {
            info!("{:?}", user);
        }
    }

    /// Logs out all users by stopping their containers and clearing their tokens.
    pub fn logout_all_users(&mut self) -> Result<(), Box<dyn Error>> {
        let mut container_ids = Vec::new();

        // Iterate over all users, collect container IDs, and clear tokens
        for user in self.users.iter_mut() {
            let container_id = format!("{}.codeserver", user.uid);
            container_ids.push(container_id.clone());

            // Clear the user's token
            user.token = None;
            info!("Logged out user: {}", user.username);
        }

        // Now, stop all containers
        for container_id in container_ids {
            info!("Stopping container: {}", container_id);
            match self.stop_container(&container_id) {
                Ok(()) => info!("Successfully stopped container id: {}", container_id),
                Err(e) => { error!("Failed to stop container {}: {}", container_id, e); },
            }
        }

        // Write the updated database to file
        self.write_to_file()?;

        Ok(())
    }

    pub fn find_user_by_token(&self, token: &str) -> Option<&User> {
        self.users.iter().find(|user| user.token.as_deref() == Some(token))
    }
}
