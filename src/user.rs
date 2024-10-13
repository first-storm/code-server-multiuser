use super::traefik;
use crate::traefik::Instance;
use bcrypt::{hash, verify};
use log::{error, info, warn};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter};

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
    /// Generates a unique token for user authentication.
    fn generate_unique_token(&self) -> String {
        let mut rng = rand::thread_rng();
        loop {
            // Generate a 16-character random combination of letters and numbers
            let token: String = (&mut rng).sample_iter(&Alphanumeric).take(16).map(char::from).collect();

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
        user.password = hash(&user.password, bcrypt::DEFAULT_COST)?; // Hash the user's password
        info!("Adding new user: {}", user.username);

        // Create and start Docker container for the new user
        ContainerManager::create_container(&user.uid.to_string()).map_err(|e| {
            error!("Failed to create container for user {}: {}", user.username, e);
            e
        })?;

        info!("Successfully created container for user: {}", user.username);

        // Add user to the user list
        self.users.push(user);
        self.write_to_file()?; // Write updated database to file
        Ok(())
    }

    /// Updated login method to fix borrowing issue
    pub fn login(&mut self, username: &str, password: &str) -> Result<String, LoginError> {
        // First, find user index with an immutable borrow
        let user_idx = self.users.iter().position(|u| u.username == username).ok_or_else(|| {
            warn!("User '{}' not found", username);
            LoginError::UserNotFound
        })?;

        // Verify password using an immutable borrow
        if !verify(password, &self.users[user_idx].password).map_err(|_| LoginError::IncorrectPassword)? {
            warn!("Incorrect password for user: {}", username);
            return Err(LoginError::IncorrectPassword);
        }

        // Generate a unique token (immutable borrow of self)
        let token = self.generate_unique_token();

        let uid;
        // Now borrow the user mutably in a new scope to set the token
        {
            let user = &mut self.users[user_idx];
            user.token = Some(token.clone());
            uid = user.uid;
        } // Mutable borrow ends here

        // Proceed with other operations that may borrow self immutably or mutably
        // Check if the container is running
        match ContainerManager::is_container_running(&uid.to_string()) {
            Ok(true) => {
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
        if let Some(user) = self.users.iter_mut().find(|u| u.uid == uid) {
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
        ContainerManager::check_expiration(&mut self.users, &mut self.traefik_instances);
    }

    /// Logs out all users by stopping their containers and clearing their tokens.
    pub fn logout_all_users(&mut self) -> Result<(), Box<dyn Error>> {
        ContainerManager::logout_all_users(&mut self.users, &mut self.traefik_instances)?;

        // Clear tokens for all users
        for user in &mut self.users {
            user.token = None;
        }

        // Write the updated database to file
        self.write_to_file()?;

        Ok(())
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
    pub fn get_user_by_username(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == username)
    }

    /// Writes the current user database to a file in JSON format.
    pub fn write_to_file(&self) -> Result<(), Box<dyn Error>> {
        let file = OpenOptions::new().write(true).create(true).truncate(true).open(&self.file_path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, &self)?;
        info!("User database written to file: {}", self.file_path);
        Ok(())
    }

    /// Reads the user database from a file and returns a `UserDB` instance.
    pub fn read_from_file(file_path: &str) -> Result<UserDB, Box<dyn Error>> {
        let file = OpenOptions::new().read(true).open(file_path)?;
        let reader = BufReader::new(file);
        let mut userdb: UserDB = serde_json::from_reader(reader)?;
        userdb.file_path = file_path.to_string();
        info!("User database loaded from file: {}", file_path);
        Ok(userdb)
    }

    /// Finds a user by their token.
    pub fn find_user_by_token(&self, token: &str) -> Option<&User> {
        self.users.iter().find(|user| user.token.as_deref() == Some(token))
    }

    pub fn find_user_by_token_mut(&mut self, token: &str) -> Option<&mut User> {
        self.users.iter_mut().find(|user| user.token.as_deref() == Some(token))
    }

    /// Finds a user by their UID.
    #[allow(dead_code)]
    pub fn find_user_by_uid(&self, uid: isize) -> Option<&User> {
        self.users.iter().find(|user| user.uid == uid)
    }

    /// Finds a user by their UID with a mutable reference.
    pub fn find_user_by_uid_mut(&mut self, uid: isize) -> Option<&mut User> {
        self.users.iter_mut().find(|user| user.uid == uid)
    }
}
