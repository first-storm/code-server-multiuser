mod user;
mod storage;
mod traefik;
mod container;

use actix_web::{
    cookie::{self, CookieBuilder},
    web, App, HttpResponse, HttpServer, Result as ActixResult,
};
use std::path::Path;
use std::{fs, fs::File, io::{self, BufRead}, process::exit, sync::Arc, time::Duration};

use crate::{
    container::ContainerManager,
    user::UserDB,
};

use log::{error, info, warn};
use serde::Deserialize;
use tera::{Context, Tera};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::RwLock,
    time::sleep,
};


async fn reload_db(db: web::Data<SharedUserDB>) -> Result<HttpResponse, actix_web::Error> {
    let db_file_path = storage::USERDB.as_str();

    info!("Reloading database from file: {}", db_file_path);

    let new_db = match UserDB::read_from_file(db_file_path) {
        Ok(db) => db,
        Err(_) => {
            error!("Failed to reload database from file: {}", db_file_path);
            return Ok(HttpResponse::InternalServerError().body("Failed to reload database."));
        }
    };

    // Replace the current database with the reloaded one
    {
        let mut db_write = db.write().await;
        *db_write = new_db;
    }

    info!("Database reloaded successfully from file: {}", db_file_path);
    Ok(HttpResponse::Ok().body("Database reloaded successfully."))
}

/// Renders the login page. If there is a message (e.g., login failed), it will be passed to the template.
async fn login_page(
    tera: web::Data<Tera>,
    msg: Option<String>,
) -> Result<HttpResponse, actix_web::Error> {
    let mut context = Context::new();

    // Insert any message into the template context
    if let Some(message) = msg {
        context.insert("message", &message);
    }

    let rendered = tera.render("login.html", &context).map_err(|e| {
        error!("Template rendering error: {}", e);
        actix_web::error::ErrorInternalServerError("Template error")
    })?;

    info!("Rendering login page.");
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Renders the registration page. If there is a message or success message, they will be passed to the template.
async fn register_page(
    tera: web::Data<Tera>,
    msg: Option<String>,
    success_msg: Option<String>,
) -> Result<HttpResponse, actix_web::Error> {
    let mut context = Context::new();

    // Insert any error message into the template context
    if let Some(message) = msg {
        context.insert("message", &message);
    }
    // Insert any success message into the template context
    if let Some(message) = success_msg {
        context.insert("success_message", &message);
    }

    let rendered = tera.render("register.html", &context).map_err(|e| {
        error!("Template rendering error: {}", e);
        actix_web::error::ErrorInternalServerError("Template error")
    })?;

    info!("Rendering registration page.");
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Renders a custom 404 page when a route is not found.
async fn page_404(tera: web::Data<Tera>) -> Result<HttpResponse, actix_web::Error> {
    let context = Context::new();
    let rendered = tera.render("404.html", &context).map_err(|e| {
        error!("Template rendering error: {}", e);
        actix_web::error::ErrorInternalServerError("Template error")
    })?;

    warn!("Page not found, returning 404.");
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

type SharedUserDB = Arc<RwLock<UserDB>>;

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterForm {
    username: String,
    password: String,
    email: String,
    password2: String,
    uid: isize,
}

/// Check if the given UID is in the whitelist
async fn is_uid_allowed(uid: isize) -> Result<bool, io::Error> {
    let whitelist_path = storage::UID_WHITELIST.as_str();

    // Open the file and check each line
    if let Ok(file) = File::open(whitelist_path) {
        let reader = io::BufReader::new(file);

        // Iterate through each line in the file
        for line in reader.lines() {
            if let Ok(line_content) = line {
                if let Ok(whitelist_uid) = line_content.trim().parse::<isize>() {
                    // If UID matches, allow registration
                    if whitelist_uid == uid {
                        return Ok(true);
                    }
                }
            }
        }
    }

    // If no matching UID is found, registration is not allowed
    Ok(false)
}

/// Handles the user registration logic, both GET (render page) and POST (process registration).
async fn register(
    form: Option<web::Form<RegisterForm>>,
    tera: web::Data<Tera>,
    db: web::Data<SharedUserDB>,
) -> Result<HttpResponse, actix_web::Error> {
    if let Some(form) = form {
        info!(
            "Received registration request: username: {}, email: {}",
            form.username, form.email
        );

        let RegisterForm {
            username,
            password,
            email,
            password2,
            uid,
        } = form.into_inner();

        // Check if the UID is in the whitelist
        if let Ok(is_allowed) = is_uid_allowed(uid).await {
            if !is_allowed {
                let msg = format!("UID {} 无法注册。", uid);
                warn!("UID {} is not in the whitelist.", uid);
                return register_page(tera, Some(msg), None).await;
            }
        } else {
            let msg = "检查 UID 白名单时出错。".to_string();
            error!("Error checking UID whitelist for UID: {}", uid);
            return register_page(tera, Some(msg), None).await;
        }

        // Check if passwords match
        if password != password2 {
            let msg = "两次输入的密码不一致，请重试。".to_string();
            warn!("Password mismatch for user: {}", username);
            return register_page(tera, Some(msg), None).await;
        }

        // Lock the database
        let mut db = db.write().await;

        // Check if the username already exists
        if db.username_exists(&username) {
            let msg = format!("用户名 {} 已经存在，请选择其他用户名。", username);
            warn!("Username {} already exists.", username);
            return register_page(tera, Some(msg), None).await;
        }

        // Check if the email already exists
        if db.email_exists(&email) {
            let msg = format!("邮箱 {} 已经存在，请选择其他邮箱。", email);
            warn!("Email {} already exists.", email);
            return register_page(tera, Some(msg), None).await;
        }

        // Check if the UID already exists
        if db.uid_exists(uid) {
            let msg = format!("UID {} 已经存在，请选择其他 UID。", uid);
            warn!("UID {} already exists.", uid);
            return register_page(tera, Some(msg), None).await;
        }

        // Create a new user
        let new_user = user::User {
            uid,
            username: username.clone(),
            email: email.clone(),
            password: password.clone(),
            token: None,
            is_updating: false,
        };

        // Try to add the user to the database
        match db.add_user(new_user) {
            Ok(_) => {
                let msg = "注册成功！请继续登录。".to_string();
                info!("User {} registered successfully.", username);
                register_page(tera, None, Some(msg)).await
            }
            Err(e) => {
                error!("Failed to add user {} to the database: {}", username, e);
                let msg = "注册失败，请联系管理员。".to_string();
                register_page(tera, Some(msg), None).await
            }
        }
    } else {
        info!("Displaying registration page.");
        // Render the registration page
        register_page(tera, None, None).await
    }
}

async fn logout(db: web::Data<SharedUserDB>, req: actix_web::HttpRequest) -> Result<HttpResponse, actix_web::Error> {
    if let Some(token_cookie) = req.cookie("auth_token") {
        let token = token_cookie.value().to_string();

        // Lock the db to find the user associated with the token
        let uid_option = {
            let db_read = db.read().await;
            db_read.find_user_by_token(&token).map(|user| user.uid)
        };

        return if let Some(uid) = uid_option {
            let mut db_write = db.write().await;
            db_write.logout(uid).expect("Failed to logout. Maybe it is because of permission problem");
            Ok(HttpResponse::Found() // Use Found for 302 redirect
                .append_header(("LOCATION", "/login")).finish())
        } else {
            // If the token is invalid, redirect to the login page
            warn!("Invalid token, redirecting to login page.");
            Ok(HttpResponse::Found().append_header(("LOCATION", "/login")).finish())
        };
    }

    // If no auth_token is found, redirect to the login page
    warn!("auth_token not found, redirecting to login page.");
    Ok(HttpResponse::Found().append_header(("LOCATION", "/login")).finish())
}

/// Handles user login logic for both GET (render page) and POST (process login).
async fn login(
    form: Option<web::Form<LoginForm>>,
    tera: web::Data<Tera>,
    db: web::Data<SharedUserDB>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    // Check if there is a valid auth_token
    if let Some(auth_cookie) = req.cookie("auth_token") {
        let token = auth_cookie.value();

        // Lock the database and find the user
        let db_read = db.read().await;
        if let Some(user) = db_read.find_user_by_token(token) {
            // If user is found, redirect to dashboard
            info!("User {} already logged in, redirecting to dashboard.", user.username);
            return Ok(HttpResponse::Found().append_header(("LOCATION", "/dashboard")).finish());
        }
    }

    // If there is no valid token or processing a form request
    if let Some(form) = form {
        let LoginForm { username, password } = form.into_inner();

        let mut db_write = db.write().await;
        return if let Ok(token) = db_write.login(&username, &password) {
            info!("User {} logged in successfully.", username);

            let cookie = CookieBuilder::new("auth_token", token).domain(&*storage::DOMAIN).path("/").http_only(true).secure(true).max_age(cookie::time::Duration::days(30)).finish();

            Ok(HttpResponse::Found().append_header(("LOCATION", "/dashboard")).cookie(cookie).finish())
        } else {
            warn!("Failed login attempt for user: {}", username);
            let msg = "Invalid username or password.".to_string();
            login_page(tera, Some(msg)).await
        };
    }

    info!("Displaying login page.");
    login_page(tera, None).await
}

async fn update_container(
    db: web::Data<SharedUserDB>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    // Check if there is a valid auth_token
    if let Some(auth_cookie) = req.cookie("auth_token") {
        let token = auth_cookie.value().to_string();

        // Lock the database and find the user
        let uid_option = {
            let db_read = db.read().await;
            db_read.find_user_by_token(&token).map(|user| user.uid)
        };

        return if let Some(uid) = uid_option {
            // Clone the db and move it into the closure
            let db_clone = db.clone();

            // Spawn an asynchronous task
            actix_web::rt::spawn(async move {
                // Lock the Mutex to get a mutable reference to UserDB
                let mut db_write = db_clone.write().await;

                // Call the method on the locked UserDB instance
                match db_write.update_user_container(uid) {
                    Ok(_) => {
                        // Set is_updating to false after the update
                        if let Some(user_mut) = db_write.find_user_by_uid_mut(uid) {
                            user_mut.is_updating = false;
                        }
                        info!("Container for user {} updated successfully.", uid);
                    }
                    Err(e) => {
                        error!("Failed to update container for user {}: {}", uid, e);
                    }
                }
            });

            Ok(HttpResponse::Found().append_header(("LOCATION", "/dashboard")).finish())
        } else {
            // If the user is not found, redirect to the dashboard
            info!("User not found, redirecting to dashboard.");
            Ok(HttpResponse::Found().append_header(("LOCATION", "/dashboard")).finish())
        };
    }

    info!("Redirect to dashboard.");
    Ok(HttpResponse::Found().append_header(("LOCATION", "/dashboard")).finish())
}

/// Renders the dashboard page for logged-in users.
async fn dashboard(
    tera: web::Data<Tera>,              // Instance of the Tera template engine
    db: web::Data<SharedUserDB>,        // Shared user database
    req: actix_web::HttpRequest,        // Request object, used to retrieve the Cookie
) -> Result<HttpResponse, actix_web::Error> {
    // Attempt to get "auth_token" from the request's cookies
    if let Some(auth_cookie) = req.cookie("auth_token") {
        let token = auth_cookie.value();

        // Lock the database to find the user by token
        let db_read = db.read().await;

        // Try to find the user by token
        return if let Some(user) = db_read.find_user_by_token(token) {
            // If the user is found, prepare to render the dashboard page
            let mut context = Context::new();
            context.insert("username", &user.username);  // Insert username into the context
            context.insert("email", &user.email);        // Insert email into the context

            // Check if the container is running and update the context accordingly
            match ContainerManager::is_container_running(&user.uid.to_string()) {
                Ok(true) => context.insert("container_stat", "on"),
                Ok(false) => context.insert("container_stat", "off"),
                Err(e) => {
                    context.insert("warning", format!("Container status error. Please contact the administrator.\nError: {}", e).as_str());
                    context.insert("container_stat", "off");
                }
            };

            // Get the latest image tag
            let latest_tag_result = ContainerManager::get_latest_image_tag();

            // Get the current container's image tag
            let container_name = format!("{}.codeserver", user.uid);
            let current_tag_result = ContainerManager::get_container_tag(&container_name);

            // Variables to hold the tags if they are successfully retrieved
            let mut latest_tag_opt = None;
            let mut current_tag_opt = None;

            // Handle the latest tag result
            match latest_tag_result {
                Ok(tag) => {
                    latest_tag_opt = Some(tag);
                }
                Err(e) => {
                    context.insert("warning", format!("Failed to get latest image tag: {}", e).as_str());
                }
            }

            // Handle the current tag result and insert container version into context
            match current_tag_result {
                Ok(ref tag) => {
                    context.insert("container_version", tag);  // Insert current container version into context
                    current_tag_opt = Some(tag.clone());
                }
                Err(e) => {
                    context.insert("container_version", format!("Failed to get container version: {}", e).as_str());
                    context.insert("warning", format!("Failed to get current container image tag: {}", e).as_str());
                }
            }

            // Compare the tags if both are available
            if let (Some(latest_tag), Some(current_tag)) = (&latest_tag_opt, &current_tag_opt) {
                if latest_tag != current_tag {
                    // An update is available, insert into context
                    context.insert("update_available", latest_tag);
                }
                // Else, no update is available
            }

            // Render the dashboard.html template
            let rendered = tera.render("dashboard.html", &context).map_err(|e| {
                error!("Template rendering error: {}", e);
                actix_web::error::ErrorInternalServerError("Template rendering error")
            })?;

            info!("Rendered dashboard page, user: {}", user.username);
            Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
        } else {
            // If the token is invalid, redirect to the login page
            warn!("Invalid token, redirecting to login page.");
            Ok(HttpResponse::Found().append_header(("LOCATION", "/login")).finish())
        };
    }

    // If no auth_token is found, redirect to the login page
    warn!("auth_token not found, redirecting to login page.");
    Ok(HttpResponse::Found().append_header(("LOCATION", "/login")).finish())
}

async fn index_page(
    tera: web::Data<Tera>,
    req: actix_web::HttpRequest,
    db: web::Data<SharedUserDB>,
) -> ActixResult<HttpResponse> {
    let mut context = Context::new();

    // Check if the user is logged in
    let logged_in = if let Some(auth_cookie) = req.cookie("auth_token") {
        let token = auth_cookie.value();
        let db_read = db.read().await;
        db_read.find_user_by_token(token).is_some()
    } else {
        false
    };
    context.insert("logged_in", &logged_in);

    // Render the index.html template
    let rendered = tera.render("index.html", &context).map_err(|e| {
        error!("Template rendering error: {}", e);
        actix_web::error::ErrorInternalServerError("Template rendering error")
    })?;

    info!("Rendered homepage index.html");
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Periodically checks and stops expired containers for users.
async fn expiration_checker(db: SharedUserDB) {
    loop {
        {
            // Lock the database and check for expired containers
            let mut db_write = db.write().await;
            db_write.check_expiration();  // Check expiration of containers
        }
        info!("The expired users have already been checked.");
        sleep(Duration::from_secs(60)).await; // Sleep for 60 seconds before re-checking
    }
}

// Periodically save userdb
async fn db_saver(db: SharedUserDB) {
    loop {
        // Lock the database and save the database
        let mut db_write = db.write().await;
        match db_write.write_to_file() {
            Ok(_) => info!("The user database saved successfully"),
            Err(e) => error!("Error writing database to file periodically: {}", e),
        }
        info!("The database has been saved.");
        sleep(Duration::from_secs(*storage::SAVE_INTERVAL)).await; // Sleep for 60 seconds before re-checking
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    info!("Starting server...");

    let tera = Tera::new(format!("{}/**/*", storage::TEMPLATES.as_str()).as_str()).unwrap_or_else(|e| {
        error!("Error initializing Tera templates: {}", e);
        exit(1);
    });

    // Initialize shared database
    let shared_database = if !Path::new(storage::USERDB.as_str()).exists() {
        info!("Database not found: {}. Creating new database...", storage::USERDB.as_str());
        Arc::new(RwLock::new(UserDB::new(storage::USERDB.as_str())))
    } else {
        info!("Database exists: {}", &*storage::USERDB);
        Arc::new(RwLock::new(match UserDB::read_from_file(storage::USERDB.as_str()) {
            Ok(db) => db,
            Err(_) => {
                error!("Cannot read from database: {}. Please check access permissions.", storage::USERDB.as_str());
                exit(1);
            }
        }))
    };

    // Spawn a background task for container expiration checking
    tokio::spawn(expiration_checker(shared_database.clone()));
    
    // Spawn a background task for saving database.
    tokio::spawn(db_saver(shared_database.clone()));

    // Handle the server shutdown signal
    let shared_db_clone = shared_database.clone(); // Clone shared database for shutdown handler
    tokio::spawn(async move {
        // For Unix platforms, set up signal handlers for SIGINT and SIGTERM
        #[cfg(unix)]
        {
            let mut sigint = signal(SignalKind::interrupt()).expect("Failed to listen to SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to listen to SIGTERM");

            tokio::select! {
                _ = sigint.recv() => {
                    info!("Received SIGINT signal.");
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM signal.");
                }
            }
        }
        // For non-Unix platforms, use ctrl_c()
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        }

        // Perform the shutdown procedure (save the database, etc.)
        shutdown_procedure(shared_db_clone).await;

        // Gracefully exit after shutdown tasks are done
        info!("Server is shutting down.");
        exit(0);  // Exit after completing the shutdown
    });

    // Start the HTTP server and share the database
    let srv = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(tera.clone())) // Add Tera template engine to app state
            .app_data(web::Data::new(shared_database.clone())) // Share the database
            .wrap(actix_web::middleware::Logger::default()) // Enable logger middleware
            .route("/login", web::get().to(login)) // Handle GET requests for login page
            .route("/login", web::post().to(login)) // Handle POST requests for login form
            .route("/register", web::get().to(register)) // Handle GET requests for registration page
            .route("/register", web::post().to(register)) // Handle POST requests for registration form
            .route("/dashboard", web::get().to(dashboard))
            .route("/logout", web::get().to(logout))
            .route("/", web::get().to(index_page))
            .route("/reloaddb", web::get().to(reload_db))
            .route("/upgrade", web::get().to(update_container))
            .default_service(web::route().to(page_404)) // Default handler for 404 pages
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await;

    srv
}

/// Gracefully shuts down the server and saves the database before exit.
async fn shutdown_procedure(shared_db: SharedUserDB) {
    info!("Shutting down the server...");

    // Lock the database to save it
    let mut db = shared_db.write().await;
    match &db.logout_all_users() {
        Ok(()) => info!("All users have been successfully logged out."),
        Err(e) => error!("Error logging out users during shutdown: {}", e),
    }

    match &db.traefik_instances.shutdown() {
        Ok(()) => info!("Traefik instances have been successfully shut down."),
        Err(e) => error!("Error shutting down Traefik instances: {}", e),
    }

    match &db.write_to_file() {
        Ok(()) => info!("Successfully saved the database."),
        Err(e) => error!("Error saving the database: {}", e),
    }

    // Delete /tmp/docker_image_latest_tag.cache
    let cache_file = "/tmp/docker_image_latest_tag.cache";
    if Path::new(cache_file).exists() {
        match fs::remove_file(cache_file) {
            Ok(_) => info!("Successfully deleted cache file: {}", cache_file),
            Err(e) => error!("Failed to delete cache file {}: {}", cache_file, e),
        }
    } else {
        info!("Cache file does not exist: {}", cache_file);
    }

    info!("Shutdown complete.");
}