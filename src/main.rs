mod user;
mod storage;
mod traefik;

use crate::user::UserDB;
use actix_web::cookie::CookieBuilder;
use actix_web::rt::signal;
use actix_web::{cookie, web, App, HttpResponse, HttpServer};
use log::{error, info, warn};
use serde::Deserialize;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use tera::{Context, Tera};
use tokio::sync::Mutex;
use tokio::time::sleep;
use crate::storage::DOMAIN;

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

    // Lock the current database and replace it with the reloaded one
    {
        let mut db_lock = db.lock().await;
        *db_lock = new_db;
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

    let rendered = tera
        .render("login.html", &context)
        .map_err(|e| {
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

    let rendered = tera
        .render("register.html", &context)
        .map_err(|e| {
            error!("Template rendering error: {}", e);
            actix_web::error::ErrorInternalServerError("Template error")
        })?;

    info!("Rendering registration page.");
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Renders a custom 404 page when a route is not found.
async fn page_404(tera: web::Data<Tera>) -> Result<HttpResponse, actix_web::Error> {
    let context = Context::new();
    let rendered = tera
        .render("404.html", &context)
        .map_err(|e| {
            error!("Template rendering error: {}", e);
            actix_web::error::ErrorInternalServerError("Template error")
        })?;

    warn!("Page not found, returning 404.");
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

type SharedUserDB = Arc<Mutex<UserDB>>;

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
        let mut db = db.lock().await;

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
        let user;
        {
            let db = db.lock().await;
            user = db.find_user_by_token(&token).cloned();  // Clone the user out of the lock scope
        }

        return if let Some(user) = user {
            // Now that the user has been cloned, we can lock the db mutably
            let mut db = db.lock().await;
            db.logout(user.uid).expect("Failed to logout. Maybe it is because permission problem");
            Ok(HttpResponse::Found() // Use Found for 302 redirect
                .append_header(("LOCATION", "/login"))
                .finish())
        } else {
            // If the token is invalid, redirect to the login page
            warn!("Invalid token, redirecting to login page.");
            Ok(HttpResponse::Found().append_header(("LOCATION", "/login")).finish())
        }
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
    req: actix_web::HttpRequest, // Include request object to get cookies
) -> Result<HttpResponse, actix_web::Error> {
    // Check if there is a valid auth_token
    if let Some(auth_cookie) = req.cookie("auth_token") {
        let token = auth_cookie.value();

        // Lock the database and find the user
        let db = db.lock().await;
        if let Some(user) = db.find_user_by_token(token) {
            // If user is found, redirect to dashboard
            info!("User {} already logged in, redirecting to dashboard.", user.username);
            return Ok(HttpResponse::Found()
                .append_header(("LOCATION", "/dashboard"))
                .finish());
        }
    }

    // If there is no valid token or processing a form request
    if let Some(form) = form {
        let LoginForm { username, password } = form.into_inner();

        let mut db = db.lock().await;
        return if let Ok(token) = db.login(username.clone(), password) {
            info!("User {} logged in successfully.", username);

            let cookie = CookieBuilder::new("auth_token", token)
                .domain(DOMAIN.to_string())
                .path("/")
                .http_only(true)
                .secure(true)
                .max_age(cookie::time::Duration::days(30))
                .finish();

            Ok(HttpResponse::Found()
                .append_header(("LOCATION", "/dashboard"))
                .cookie(cookie)
                .finish())
        } else {
            warn!("Failed login attempt for user: {}", username);
            let msg = "Invalid username or password.".to_string();
            login_page(tera, Some(msg)).await
        };
    }

    info!("Displaying login page.");
    login_page(tera, None).await
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
        let db = db.lock().await;

        // Try to find the user by token
        return if let Some(user) = db.find_user_by_token(token) {
            // If the user is found, prepare to render the dashboard page
            let mut context = Context::new();
            context.insert("username", &user.username);  // Insert username into the context
            context.insert("email", &user.email);        // Insert email into the context
            match UserDB::is_container_running(format!("{}", user.uid).as_str()) {
                Ok(true) => context.insert("container_stat", "on"),
                Ok(false) => context.insert("container_stat", "off"),
                Err(e) => {
                    context.insert("warning", format!("容器状态异常。请联系管理员。\n错误信息：{}", e).as_str());
                    context.insert("container_stat", "off");
                },
            };

            // Render the dashboard.html template
            let rendered = tera
                .render("dashboard.html", &context)
                .map_err(|e| {
                    error!("Template rendering error: {}", e);
                    actix_web::error::ErrorInternalServerError("Template rendering error")
                })?;

            info!("Rendered dashboard page, user: {}", user.username);
            Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
        } else {
            // If the token is invalid, redirect to the login page
            warn!("Invalid token, redirecting to login page.");
            Ok(HttpResponse::Found().append_header(("LOCATION", "/login")).finish())
        }
    }

    // If no auth_token is found, redirect to the login page
    warn!("auth_token not found, redirecting to login page.");
    Ok(HttpResponse::Found().append_header(("LOCATION", "/login")).finish())
}




/// Periodically checks and stops expired containers for users.
async fn expiration_checker(db: SharedUserDB) {
    loop {
        {
            // Lock the database and check for expired containers
            let mut db_guard = db.lock().await;
            db_guard.check_expiration();  // Check expiration of containers
        }
        info!("The expired users have already been checked.");
        sleep(Duration::from_secs(60)).await; // Sleep for 60 seconds before re-checking
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    info!("Starting server...");

    let tera = Tera::new(format!("{}/**/*", storage::TEMPLATES.as_str()).as_str())
        .unwrap_or_else(|e| {
            error!("Error initializing Tera templates: {}", e);
            exit(1);
        });

    // Initialize shared database
    let shared_database = if !std::path::Path::new(storage::USERDB.as_str()).exists() {
        info!("Database not found: {}. Creating new database...", storage::USERDB.as_str());
        Arc::new(Mutex::new(UserDB::new(storage::USERDB.as_str())))
    } else {
        info!("Database exists: {}", &*storage::USERDB);
        Arc::new(Mutex::new(match UserDB::read_from_file(storage::USERDB.as_str()) {
            Ok(db) => db,
            Err(_) => {
                error!("Cannot read from database: {}. Please check access permissions.", storage::USERDB.as_str());
                exit(1);
            }
        }))
    };

    // Spawn a background task for container expiration checking
    tokio::spawn(expiration_checker(shared_database.clone()));

    // Handle the server shutdown signal
    let shared_db_clone = shared_database.clone(); // Clone shared database for shutdown handler
    tokio::spawn(async move {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");

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
            .route("/login", web::get().to(login)) // Handle GET requests for login page
            .route("/login", web::post().to(login)) // Handle POST requests for login form
            .route("/register", web::get().to(register)) // Handle GET requests for registration page
            .route("/register", web::post().to(register)) // Handle POST requests for registration form
            .route("/dashboard", web::get().to(dashboard))
            .route("/logout", web::get().to(logout))
            .route("/reloaddb", web::get().to(reload_db))
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
    let mut db = shared_db.lock().await;
    let db_file_path = storage::USERDB.as_str();
    match &db.logout_all_users() {
        Ok(()) => info!("All users have been successfully logged out."),
        Err(e) => error!("Error logging out users during shutdown: {}", e),
    }

    match &db.write_to_file() {
        Ok(_) => info!("Database has been successfully saved to {}", db_file_path),
        Err(e) => error!("Error occurred while saving the database: {}", e),
    }

    match &db.traefik_instances.shutdown() {
        Ok(()) => info!("Traefik instances have been successfully shut down."),
        Err(e) => error!("Error shutting down Traefik instances: {}", e),
    }


    info!("Shutdown complete.");
}
