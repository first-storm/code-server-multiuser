use super::traefik;
use crate::traefik::Instance;
use bcrypt::{hash, verify};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::{fmt, io};
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, ErrorKind};
use std::time::{SystemTime, Duration, Instant};
use filetime::{set_file_mtime, FileTime};
use uuid::Uuid;
use super::container::ContainerManager;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub uid: isize,
    pub username: String,
    pub email: String,
    pub password: String,
    pub token: Option<String>,
    pub is_updating: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserDB {
    pub traefik_instances: traefik::Instances,
    users: HashMap<isize, User>,
    #[serde(skip)]
    username_to_uid: HashMap<String, isize>,
    #[serde(skip)]
    email_to_uid: HashMap<String, isize>,
    file_path: String,
    #[serde(skip)]
    last_write_time: Option<Instant>, // Add this field
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
    /// Generates a unique token for user authentication.
    fn generate_unique_token() -> String {
        Uuid::new_v4().to_string()
    }

    /// Creates a new `UserDB` instance with the given file path and writes the empty database to the file.
    pub fn new(file_path: &str) -> UserDB {
        info!("Creating a new user database with file path: {}", file_path);
        let mut udb = UserDB {
            traefik_instances: traefik::Instances::new(),
            users: HashMap::new(),
            username_to_uid: HashMap::new(),
            email_to_uid: HashMap::new(),
            file_path: file_path.to_string(),
            last_write_time: None, // Initialize last_write_time
        };
        if let Err(e) = udb.write_to_file() {
            error!(
                "Database is not writable! Please check permissions. Error: {}",
                e
            );
        }
        udb
    }

    /// Adds a new user to the database and writes the updated database to file.
    pub fn add_user(&mut self, mut user: User) -> Result<(), Box<dyn Error>> {
        if self.username_exists(&user.username) {
            return Err("Username already exists".into());
        }
        if self.email_exists(&user.email) {
            return Err("Email already exists".into());
        }

        user.password = hash(&user.password, bcrypt::DEFAULT_COST)?; // Hash the user's password
        info!("Adding new user: {}", user.username);

        // Create and start Docker container for the new user
        ContainerManager::create_container(&user.uid.to_string()).map_err(|e| {
            error!("Failed to create container for user {}: {}", user.username, e);
            e
        })?;

        info!("Successfully created container for user: {}", user.username);

        // Add user to the users HashMap and update mappings
        let uid = user.uid;
        self.users.insert(uid, user.clone());
        self.username_to_uid.insert(user.username.clone(), uid);
        self.email_to_uid.insert(user.email.clone(), uid);

        self.write_to_file()?; // Write updated database to file
        Ok(())
    }

    fn update_file_mtime(file_path: &str) -> io::Result<()> {
        // Get current time
        let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        let mtime = FileTime::from_unix_time(now.as_secs() as i64, now.subsec_nanos());

        // Set file mtime
        set_file_mtime(file_path, mtime)?;

        Ok(())
    }

    pub fn login(&mut self, username: &str, password: &str) -> Result<String, LoginError> {
        // First, get user UID from username_to_uid
        let uid = self.username_to_uid.get(username).ok_or_else(|| {
            warn!("User '{}' not found", username);
            LoginError::UserNotFound
        })?;
        // Borrow the user mutably
        let user = self.users.get_mut(uid).ok_or_else(|| {
            warn!("User '{}' not found in users HashMap", username);
            LoginError::UserNotFound
        })?;
        // Verify password
        if !verify(password, &user.password).map_err(|_| LoginError::IncorrectPassword)? {
            warn!("Incorrect password for user: {}", username);
            return Err(LoginError::IncorrectPassword);
        }

        // Generate a unique token
        let token = UserDB::generate_unique_token();
        user.token = Some(token.clone());
        let uid = *uid;

        let refresh_heartbeat = || {
            // Update heartbeat file
            match Self::update_file_mtime(&format!(
                "{}/{}.data/home/.local/share/code-server/heartbeat",
                *crate::storage::DATADIR, uid
            )) {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to update heartbeat file: {}", e);
                }
            }
        };

        // Proceed with other operations
        match ContainerManager::is_container_running(&uid.to_string()) {
            Ok(true) => {
                // Update heartbeat file
                refresh_heartbeat();
                info!("Container is already running for user: {}", username);

                // Ensure to add a Traefik instance even if the container is running
                self.traefik_instances.add(Instance {
                    name: format!("{}.codeserver", uid),
                    token: token.clone(),
                }).map_err(|e| {
                    let error_message = format!("Failed to add traefik instance: {}", e);
                    error!("{}", error_message);
                    LoginError::ContainerError(error_message)
                })?;
            }
            Ok(false) => {
                // Update heartbeat file
                refresh_heartbeat();
                // If the container is not running, start the container
                info!("Starting container for user: {}", username);
                ContainerManager::start_container(
                    &format!("{}.codeserver", uid),
                    &token,
                    &mut self.traefik_instances,
                ).map_err(|e| {
                    error!("Failed to start container for user {}: {}", username, e);
                    LoginError::ContainerError(e.to_string())
                })?;
                info!("Successfully started container for user: {}", username);
            }
            Err(e) => {
                error!("Failed to check container status for user {}: {}", username, e);
                return Err(LoginError::ContainerError(e.to_string()));
            }
        }

        info!("Login successful for user: {}", username);
        Ok(token) // Return the generated token
    }

    pub fn logout(&mut self, uid: isize) -> Result<(), Box<dyn Error>> {
        // Find the user mutably
        if let Some(user) = self.users.get_mut(&uid) {
            // Logout the user
            ContainerManager::logout_user(user, &mut self.traefik_instances)?;
            info!("User '{}' logged out successfully", user.username);
            // Clear the user's token
            user.token = None;
        } else {
            error!("User with UID {} not found for logout", uid);
            return Err(Box::new(LoginError::UserNotFound));
        }

        // Write changes to file
        self.write_to_file()?;

        Ok(())
    }

    /// Checks and stops containers that have been idle for more than 1200 seconds.
    pub fn check_expiration(&mut self) {
        ContainerManager::check_expiration(&mut self.users.values_mut().collect::<Vec<_>>(), &mut self.traefik_instances);
    }

    /// Logs out all users by stopping their containers and clearing their tokens.
    pub fn logout_all_users(&mut self) -> Result<(), Box<dyn Error>> {
        ContainerManager::logout_all_users(&mut self.users.values_mut().collect::<Vec<_>>(), &mut self.traefik_instances)?;

        // Clear tokens for all users
        for user in self.users.values_mut() {
            user.token = None;
        }

        // Write the updated database to file
        self.write_to_file()?;

        Ok(())
    }

    /// Check if a username exists in the database.
    pub fn username_exists(&self, username: &str) -> bool {
        self.username_to_uid.contains_key(username)
    }

    /// Check if an email exists in the database.
    pub fn email_exists(&self, email: &str) -> bool {
        self.email_to_uid.contains_key(email)
    }

    /// Check if a UID exists in the database.
    pub fn uid_exists(&self, uid: isize) -> bool {
        self.users.contains_key(&uid)
    }

    /// Retrieve a user by their username.
    #[allow(dead_code)]
    pub fn get_user_by_username(&self, username: &str) -> Option<&User> {
        if let Some(uid) = self.username_to_uid.get(username) {
            self.users.get(uid)
        } else {
            None
        }
    }

    /// Writes the current user database to a file in JSON format.
    pub fn write_to_file(&mut self) -> Result<(), Box<dyn Error>> {
        let now = Instant::now();
        // Check if it's time to write to the file
        if self.last_write_time.is_none() || now.duration_since(self.last_write_time.unwrap()) >= Duration::from_secs(600) {
            let file = OpenOptions::new().write(true).create(true).truncate(true).open(&self.file_path)?;
            let writer = BufWriter::new(file);
            serde_json::to_writer_pretty(writer, &self)?;
            info!("User database written to file: {}", self.file_path);
            self.last_write_time = Some(now); // Update the last write time
        } else {
            info!("Skipping write_to_file; less than 10 minutes since last write");
        }
        Ok(())
    }

    /// Reads the user database from a file and returns a `UserDB` instance.
    pub fn read_from_file(file_path: &str) -> Result<UserDB, Box<dyn Error>> {
        let file = OpenOptions::new().read(true).open(file_path)?;
        let reader = BufReader::new(file);
        let mut userdb: UserDB = serde_json::from_reader(reader)?;
        userdb.file_path = file_path.to_string();
        userdb.last_write_time = Some(Instant::now()); // Initialize last_write_time
        info!("User database loaded from file: {}", file_path);

        // Rebuild username_to_uid and email_to_uid mappings
        userdb.username_to_uid = HashMap::new();
        userdb.email_to_uid = HashMap::new();
        for (uid, user) in &userdb.users {
            userdb.username_to_uid.insert(user.username.clone(), *uid);
            userdb.email_to_uid.insert(user.email.clone(), *uid);
        }

        Ok(userdb)
    }

    /// Finds a user by their token.
    pub fn find_user_by_token(&self, token: &str) -> Option<&User> {
        self.users.values().find(|user| user.token.as_deref() == Some(token))
    }

    pub fn find_user_by_token_mut(&mut self, token: &str) -> Option<&mut User> {
        self.users.values_mut().find(|user| user.token.as_deref() == Some(token))
    }

    /// Finds a user by their UID.
    #[allow(dead_code)]
    pub fn find_user_by_uid(&self, uid: isize) -> Option<&User> {
        self.users.get(&uid)
    }

    /// Finds a user by their UID with a mutable reference.
    pub fn find_user_by_uid_mut(&mut self, uid: isize) -> Option<&mut User> {
        self.users.get_mut(&uid)
    }

    pub fn update_user_container(&mut self, uid: isize) -> io::Result<()> {
        // First, find the user and clone the token if it exists
        let token = if let Some(user) = self.users.get(&uid) {
            user.token.clone()
        } else {
            return Err(io::Error::new(ErrorKind::NotFound, "User not found"));
        };

        // Now, perform the mutable operation on traefik_instances
        if let Some(token) = token {
            ContainerManager::update_container(&uid.to_string(), &token, &mut self.traefik_instances)?;
            Ok(())
        } else {
            Err(io::Error::new(ErrorKind::Other, "User not logged in"))
        }
    }
}

// Implement Drop to ensure data is written when the program exits
impl Drop for UserDB {
    fn drop(&mut self) {
        // Force write to file on drop
        let now = Instant::now();
        match OpenOptions::new().write(true).create(true).truncate(true).open(&self.file_path) {
            Ok(file) => {
                let writer = BufWriter::new(file);
                if let Err(e) = serde_json::to_writer_pretty(writer, &self) {
                    error!("Failed to write user database on drop: {}", e);
                } else {
                    info!("User database written to file on drop: {}", self.file_path);
                    self.last_write_time = Some(now);
                }
            },
            Err(e) => {
                error!("Failed to open file for writing on drop: {}", e);
            }
        }
    }
}
