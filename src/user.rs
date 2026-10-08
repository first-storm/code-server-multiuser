use super::traefik;
use crate::traefik::Instance;
use filetime::{set_file_mtime, FileTime};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::time::SystemTime;
use std::{fs, io};
use uuid::Uuid;

/// Seconds of heartbeat silence after which a session is considered idle
/// and its container is stopped.
pub const IDLE_TIMEOUT_SECS: u64 = 1200;

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
    #[serde(skip)]
    token_to_uid: HashMap<String, isize>,
    file_path: String,
}

impl UserDB {
    /// Generates a unique token for user authentication.
    fn generate_unique_token() -> String {
        Uuid::now_v7().to_string()
    }

    /// Build an empty UserDB for tests without touching docker or
    /// environment variables.
    #[cfg(test)]
    pub(crate) fn empty_for_test(file_path: &str) -> UserDB {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let traefik_path = std::env::temp_dir()
            .join(format!(
                "userdb-test-traefik-{}-{}.yml",
                std::process::id(),
                id
            ))
            .to_string_lossy()
            .to_string();
        UserDB {
            traefik_instances: traefik::Instances::with_config_path(traefik_path),
            users: HashMap::new(),
            username_to_uid: HashMap::new(),
            email_to_uid: HashMap::new(),
            token_to_uid: HashMap::new(),
            file_path: file_path.to_string(),
        }
    }

    /// Insert a user record for tests without creating any container.
    /// The password is stored as given (tests pass a pre-hashed value).
    #[cfg(test)]
    pub(crate) fn insert_for_test(&mut self, user: User) {
        let uid = user.uid;
        self.username_to_uid.insert(user.username.clone(), uid);
        self.email_to_uid.insert(user.email.clone(), uid);
        self.users.insert(uid, user);
    }

    /// Clears the token for a user and updates the token_to_uid map
    pub fn clear_user_token(&mut self, uid: isize) {
        if let Some(user) = self.users.get_mut(&uid) {
            if let Some(token) = &user.token {
                self.token_to_uid.remove(token);
            }
            user.token = None;
        }
    }

    /// Assigns a new token to a user, dropping the previous token mapping
    /// so stale tokens stop authenticating (e.g. after a re-login).
    pub fn set_user_token(&mut self, uid: isize, token: String) {
        if let Some(user) = self.users.get_mut(&uid) {
            if let Some(old_token) = user.token.replace(token.clone()) {
                self.token_to_uid.remove(&old_token);
            }
            self.token_to_uid.insert(token, uid);
        }
    }

    /// Creates a new `UserDB` instance with the given file path and writes the empty database to the file.
    pub fn new(file_path: &str) -> UserDB {
        info!("Creating a new user database with file path: {}", file_path);
        let udb = UserDB {
            traefik_instances: traefik::Instances::new(),
            users: HashMap::new(),
            username_to_uid: HashMap::new(),
            email_to_uid: HashMap::new(),
            token_to_uid: HashMap::new(),
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

    /// Inserts a user record with all index mappings. The password must
    /// already be hashed by the caller (hashing is CPU-bound and runs in
    /// a blocking thread). Does not touch Docker; the caller creates the
    /// container outside the database lock and rolls back with
    /// `remove_user_record` on failure.
    pub fn add_user_record(&mut self, user: User) -> Result<(), Box<dyn Error>> {
        if self.username_exists(&user.username) {
            return Err("Username already exists".into());
        }
        if self.email_exists(&user.email) {
            return Err("Email already exists".into());
        }
        if self.uid_exists(user.uid) {
            return Err("UID already exists".into());
        }

        info!("Adding new user: {}", user.username);

        let uid = user.uid;
        let username = user.username.clone();
        let email = user.email.clone();
        self.users.insert(uid, user);
        self.username_to_uid.insert(username, uid);
        self.email_to_uid.insert(email, uid);
        Ok(())
    }

    /// Removes a user record and all of its index mappings. Used to roll
    /// back a registration whose container creation failed.
    pub fn remove_user_record(&mut self, uid: isize) {
        if let Some(user) = self.users.remove(&uid) {
            self.username_to_uid.remove(&user.username);
            self.email_to_uid.remove(&user.email);
            if let Some(token) = &user.token {
                self.token_to_uid.remove(token);
            }
            info!("Removed user record for UID {}", uid);
        }
    }

    fn update_file_mtime(file_path: &str) -> io::Result<()> {
        let mtime = FileTime::now();
        set_file_mtime(file_path, mtime)?;
        Ok(())
    }

    pub(crate) fn refresh_heartbeat(uid: isize) {
        match Self::update_file_mtime(&format!(
            "{}/{}.data/home/.local/share/code-server/heartbeat",
            *crate::storage::DATADIR,
            uid
        )) {
            Ok(_) => (),
            Err(e) => {
                error!("Failed to update heartbeat file: {}", e);
            }
        }
    }

    /// Returns the uid and stored password hash for a username, if it exists.
    /// Read-only so handlers can verify the password in a blocking thread
    /// without holding any lock.
    pub fn credential_for(&self, username: &str) -> Option<(isize, String)> {
        let uid = *self.username_to_uid.get(username)?;
        let user = self.users.get(&uid)?;
        Some((uid, user.password.clone()))
    }

    /// Mints a fresh session token for a user, invalidating the previous one.
    pub fn publish_session(&mut self, uid: isize) -> String {
        let token = UserDB::generate_unique_token();
        self.set_user_token(uid, token.clone());
        token
    }

    /// Routes a user's container in Traefik under the given session token.
    pub fn register_traefik_instance(&mut self, uid: isize, token: &str) -> io::Result<()> {
        self.traefik_instances
            .add(Instance {
                name: format!("{}.codeserver", uid),
                token: token.to_string(),
            })
            .map_err(|e| {
                let error_message = format!("Failed to add traefik instance: {}", e);
                error!("{}", error_message);
                io::Error::new(ErrorKind::Other, error_message)
            })
    }

    /// Finishes a logout: removes the Traefik route and clears the session
    /// token. The caller stops the Docker container beforehand, outside
    /// the database lock.
    pub fn finish_logout(&mut self, uid: isize) -> Result<(), Box<dyn Error>> {
        if let Some(user) = self.users.get(&uid) {
            let container_id = format!("{}.codeserver", uid);
            let username = user.username.clone();
            if let Err(e) = self.traefik_instances.remove(&container_id) {
                error!(
                    "Failed to remove Traefik instance for container {}: {}",
                    container_id, e
                );
            }
            self.clear_user_token(uid);
            info!("User '{}' logged out successfully", username);
        } else {
            error!("User with UID {} not found for logout", uid);
            return Err(Box::new(io::Error::new(
                ErrorKind::NotFound,
                format!("User with UID {} not found", uid),
            )));
        }
        Ok(())
    }

    /// Returns the uids of logged-in users whose heartbeat has been silent
    /// for at least `IDLE_TIMEOUT_SECS`. Read-only; the caller stops each
    /// container outside the lock and then calls `finish_logout`.
    pub fn expired_uids(&self) -> Vec<isize> {
        let mut expired = Vec::new();

        for user in self.users.values() {
            if user.token.is_none() {
                continue;
            }

            let heartbeat_path = format!(
                "{}/{}.data/home/.local/share/code-server/heartbeat",
                *crate::storage::DATADIR,
                user.uid
            );

            match fs::metadata(&heartbeat_path)
                .and_then(|metadata| metadata.modified())
                .and_then(|modified_time| {
                    SystemTime::now()
                        .duration_since(modified_time)
                        .map_err(|e| io::Error::new(ErrorKind::Other, e))
                }) {
                Ok(duration) if duration.as_secs() >= IDLE_TIMEOUT_SECS => {
                    expired.push(user.uid);
                }
                Ok(duration) => {
                    info!(
                        "User '{}' has been idle for {} seconds.",
                        user.username,
                        duration.as_secs()
                    );
                }
                Err(e) => {
                    error!("Failed to check user status '{}': {}", user.username, e);
                }
            }
        }

        expired
    }

    /// Clears every session token and empties the Traefik routing table.
    /// The caller stops the Docker containers beforehand, outside the lock.
    pub fn clear_all_sessions(&mut self) -> Result<(), Box<dyn Error>> {
        for uid in self.users.keys().cloned().collect::<Vec<_>>() {
            self.clear_user_token(uid);
        }
        self.traefik_instances.shutdown()?;
        Ok(())
    }

    /// Container names (`<uid>.codeserver`) of all known users, for
    /// shutdown handling.
    pub fn container_names(&self) -> Vec<String> {
        self.users
            .keys()
            .map(|uid| format!("{}.codeserver", uid))
            .collect()
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
    /// Takes `&self` so periodic saves only need a read lock. The write
    /// is atomic (tmp file + rename) so a crash never leaves a truncated
    /// database, and the file is restricted to owner-only access because
    /// it contains password hashes and session tokens.
    pub fn write_to_file(&self) -> Result<(), Box<dyn Error>> {
        let tmp_path = format!("{}.tmp", self.file_path);
        {
            let mut options = OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            options.mode(0o600);
            let file = options.open(&tmp_path)?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(writer.by_ref(), self)?;
            writer.flush()?;
        }
        fs::rename(&tmp_path, &self.file_path)?;
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

        // Rebuild username_to_uid and email_to_uid mappings
        userdb.username_to_uid = HashMap::with_capacity(userdb.users.len());
        userdb.email_to_uid = HashMap::with_capacity(userdb.users.len());
        userdb.token_to_uid = HashMap::new(); // Initialize the token_to_uid map

        for (uid, user) in &userdb.users {
            userdb.username_to_uid.insert(user.username.clone(), *uid);
            userdb.email_to_uid.insert(user.email.clone(), *uid);
            if let Some(token) = &user.token {
                userdb.token_to_uid.insert(token.clone(), *uid); // Populate token_to_uid
            }
        }

        Ok(userdb)
    }

    /// Finds a user by their token.
    pub fn find_user_by_token(&self, token: &str) -> Option<&User> {
        self.token_to_uid
            .get(token)
            .and_then(|uid| self.users.get(uid))
    }

    #[allow(dead_code)]
    pub fn find_user_by_token_mut(&mut self, token: &str) -> Option<&mut User> {
        self.token_to_uid
            .get(token)
            .and_then(|uid| self.users.get_mut(uid))
    }

    /// Finds a user by their UID.
    pub fn find_user_by_uid(&self, uid: isize) -> Option<&User> {
        self.users.get(&uid)
    }

    /// Finds a user by their UID with a mutable reference.
    pub fn find_user_by_uid_mut(&mut self, uid: isize) -> Option<&mut User> {
        self.users.get_mut(&uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path(prefix: &str) -> String {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir()
            .join(format!(
                "userdb-test-{}-{}-{}.json",
                prefix,
                std::process::id(),
                id
            ))
            .to_string_lossy()
            .to_string()
    }

    fn test_user(uid: isize) -> User {
        User {
            uid,
            username: format!("user{}", uid),
            email: format!("user{}@example.com", uid),
            password: "hashed".to_string(),
            token: None,
            is_updating: false,
        }
    }

    #[test]
    fn set_user_token_drops_old_token_mapping() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);

        db.insert_for_test(test_user(7));
        db.set_user_token(7, "tok-first".to_string());
        assert!(db.find_user_by_token("tok-first").is_some());

        // Re-login rotates the token: the old one must stop resolving.
        db.set_user_token(7, "tok-second".to_string());
        assert!(
            db.find_user_by_token("tok-first").is_none(),
            "stale token must not authenticate after rotation"
        );
        assert_eq!(db.find_user_by_token("tok-second").unwrap().uid, 7);
        assert!(!db.token_to_uid.contains_key("tok-first"));
        drop(db);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn clear_user_token_removes_token_mapping() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);

        db.insert_for_test(test_user(7));
        db.set_user_token(7, "tok".to_string());
        db.clear_user_token(7);

        assert!(db.find_user_by_token("tok").is_none());
        assert!(db.users.get(&7).unwrap().token.is_none());
        drop(db);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn write_then_read_roundtrip_rebuilds_indexes() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);

        db.insert_for_test(test_user(7));
        db.set_user_token(7, "tok-persist".to_string());
        db.write_to_file().unwrap();
        drop(db);

        let loaded = UserDB::read_from_file(&path).unwrap();
        assert!(loaded.username_exists("user7"));
        assert!(loaded.email_exists("user7@example.com"));
        assert!(loaded.uid_exists(7));
        assert_eq!(loaded.find_user_by_token("tok-persist").unwrap().uid, 7);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn write_to_file_is_atomic_and_owner_only() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);
        db.insert_for_test(test_user(7));
        db.write_to_file().unwrap();

        // No tmp file may be left behind after the atomic rename.
        assert!(
            fs::metadata(format!("{}.tmp", path)).is_err(),
            "tmp file must be renamed away"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "db file must be owner-only");
        }

        drop(db);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn add_user_record_rejects_duplicates() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);
        db.insert_for_test(test_user(7));

        let mut dup_name = test_user(8);
        dup_name.username = "user7".to_string();
        assert!(db.add_user_record(dup_name).is_err());

        let mut dup_email = test_user(8);
        dup_email.email = "user7@example.com".to_string();
        assert!(db.add_user_record(dup_email).is_err());

        let mut dup_uid = test_user(7);
        dup_uid.username = "other".to_string();
        dup_uid.email = "other@example.com".to_string();
        assert!(db.add_user_record(dup_uid).is_err());

        assert!(db.add_user_record(test_user(9)).is_ok());
        assert!(db.uid_exists(9));

        drop(db);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn remove_user_record_clears_all_mappings() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);
        db.insert_for_test(test_user(7));
        db.set_user_token(7, "tok".to_string());

        db.remove_user_record(7);

        assert!(!db.uid_exists(7));
        assert!(!db.username_exists("user7"));
        assert!(!db.email_exists("user7@example.com"));
        assert!(db.find_user_by_token("tok").is_none());
        // Removing an unknown uid is a no-op, not a panic.
        db.remove_user_record(7);

        drop(db);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn credential_for_returns_uid_and_hash() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);
        db.insert_for_test(test_user(7));

        assert_eq!(db.credential_for("user7"), Some((7, "hashed".to_string())));
        assert_eq!(db.credential_for("nobody"), None);

        drop(db);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn publish_session_rotates_token() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);
        db.insert_for_test(test_user(7));

        let first = db.publish_session(7);
        assert!(db.find_user_by_token(&first).is_some());
        let second = db.publish_session(7);

        assert_ne!(first, second);
        assert!(db.find_user_by_token(&first).is_none());
        assert_eq!(db.find_user_by_token(&second).unwrap().uid, 7);

        drop(db);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn register_and_finish_logout_manage_traefik_route() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);
        db.insert_for_test(test_user(7));
        let token = db.publish_session(7);

        db.register_traefik_instance(7, &token).unwrap();
        let config_path = test_traefik_config_path(&db);
        let config = fs::read_to_string(&config_path).unwrap();
        assert!(config.contains("7.codeserver-router"));
        assert!(config.contains(&token));

        db.finish_logout(7).unwrap();
        assert!(db.find_user_by_token(&token).is_none());
        let config = fs::read_to_string(&config_path).unwrap();
        assert!(
            !config.contains(&token),
            "logout must remove the traefik route"
        );

        assert!(db.finish_logout(999).is_err());
        drop(db);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&config_path);
    }

    #[test]
    fn expired_uids_flags_only_idle_sessions() {
        let datadir = std::env::temp_dir().join(format!("userdb-datadir-{}", std::process::id()));
        std::env::set_var("DATADIR", &datadir);

        // uid 21: heartbeat went silent long ago -> expired.
        // uid 22: fresh heartbeat -> active.
        // uid 23: logged out (no token) -> skipped.
        for (uid, age_secs) in [(21isize, 7200u64), (22, 0)] {
            let dir = datadir.join(format!("{}.data/home/.local/share/code-server", uid));
            fs::create_dir_all(&dir).unwrap();
            let heartbeat = dir.join("heartbeat");
            fs::write(&heartbeat, b"beat").unwrap();
            let mtime = FileTime::from_system_time(
                SystemTime::now() - std::time::Duration::from_secs(age_secs),
            );
            filetime::set_file_mtime(&heartbeat, mtime).unwrap();
        }

        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);
        for uid in [21, 22, 23] {
            db.insert_for_test(test_user(uid));
        }
        db.set_user_token(21, "tok-21".to_string());
        db.set_user_token(22, "tok-22".to_string());

        assert_eq!(db.expired_uids(), vec![21]);

        drop(db);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&datadir);
    }

    #[test]
    fn clear_all_sessions_empties_tokens_and_routes() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);
        db.insert_for_test(test_user(7));
        let token = db.publish_session(7);
        db.register_traefik_instance(7, &token).unwrap();

        db.clear_all_sessions().unwrap();

        assert!(db.find_user_by_token(&token).is_none());
        let config = fs::read_to_string(test_traefik_config_path(&db)).unwrap();
        assert!(!config.contains("codeserver-router"));

        let config_path = test_traefik_config_path(&db);
        drop(db);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&config_path);
    }

    #[test]
    fn dropping_db_does_not_rewrite_the_file() {
        let path = temp_path("db");
        let mut db = UserDB::empty_for_test(&path);
        db.insert_for_test(test_user(7));
        db.write_to_file().unwrap();

        // External edit on disk; this is what /reloaddb loads.
        let raw = fs::read_to_string(&path).unwrap();
        fs::write(&path, raw.replace("user7@example.com", "edited@example.com")).unwrap();

        // Replacing the live db drops the old one; that must not write
        // the old in-memory state back over the file.
        drop(db);

        let loaded = UserDB::read_from_file(&path).unwrap();
        assert_eq!(
            loaded.find_user_by_uid(7).unwrap().email,
            "edited@example.com"
        );
        drop(loaded);
        let _ = fs::remove_file(&path);
    }

    fn test_traefik_config_path(db: &UserDB) -> String {
        db.traefik_instances.config_path().to_string()
    }
}
