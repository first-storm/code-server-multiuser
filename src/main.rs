mod user;
mod storage;

use crate::user::UserDB;
use actix_web::cookie::{Cookie, CookieBuilder};
use actix_web::{cookie, web, App, HttpResponse, HttpServer};
use log::{error, info, warn};
use serde::Deserialize;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use tera::{Context, Tera};
use tokio::sync::Mutex;
use tokio::time::sleep;

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

        // Check if the passwords match
        if password != password2 {
            let msg = "Passwords do not match, please try again.".to_string();
            warn!("Password mismatch for user: {}", username);
            return register_page(tera, Some(msg), None).await;
        }

        // Lock the database
        let mut db = db.lock().await;

        // Check if the username already exists
        if db.username_exists(&username) {
            let msg = format!("Username {} already exists, please choose another.", username);
            warn!("Username {} already exists.", username);
            return register_page(tera, Some(msg), None).await;
        }

        // Create new user
        let new_user = user::User {
            uid,
            username: username.clone(),
            email: email.clone(),
            password: password.clone(),
            token: None,
        };

        // Attempt to add user to the database
        match db.add_user(new_user) {
            Ok(_) => {
                let msg = "Registration successful! Please proceed to login.".to_string();
                info!("User {} registered successfully.", username);
                register_page(tera, None, Some(msg)).await
            }
            Err(e) => {
                error!("Failed to add user {} to the database: {}", username, e);
                let msg = "Registration failed, please contact the administrator.".to_string();
                register_page(tera, Some(msg), None).await
            }
        }
    } else {
        info!("Displaying registration page.");
        // Render registration page for GET requests
        register_page(tera, None, None).await
    }
}

/// Handles user login logic for both GET (render page) and POST (process login).
async fn login(
    form: Option<web::Form<LoginForm>>, // Option indicates whether it's a POST request with data
    tera: web::Data<Tera>,
    db: web::Data<SharedUserDB>,
) -> Result<HttpResponse, actix_web::Error> {
    if let Some(form) = form {
        // Process POST request, handle login logic
        let LoginForm { username, password } = form.into_inner();
        let mut msg = String::new();

        // Lock the database and check user credentials
        let mut db = db.lock().await;

        if let Ok(token) = db.login(username.clone(), password) {
            // On successful login, generate a cookie and set the token
            msg = "Login successful.".to_string();
            info!("User {} logged in successfully.", username);

            // Create a Cookie, set Domain to *.code.cocoabrew.cc, and mark as HttpOnly and Secure
            let cookie = CookieBuilder::new("auth_token", token)
                .domain(".code.cocoabrew.cc") // Set the domain to *.code.cocoabrew.cc
                .path("/") // Accessible on all paths
                .http_only(true) // Restrict to HTTP access, preventing JavaScript access
                .secure(true) // Only transmit in HTTPS requests
                .max_age(cookie::time::Duration::days(30)) // Set the cookie expiration to 30 days
                .finish();

            // Set the cookie in the response
            return Ok(HttpResponse::Ok()
                .content_type("text/html")
                .cookie(cookie) // Add the cookie to the response
                .body(msg));
        } else {
            msg = "Invalid username or password.".to_string();
            warn!("Failed login attempt for user: {}", username);
        }

        // Render the login page with the result message
        login_page(tera, Some(msg)).await
    } else {
        // Render login page for GET requests
        info!("Displaying login page.");
        login_page(tera, None).await
    }
}


/// Periodically checks and stops expired containers for users.
async fn expiration_checker(db: SharedUserDB) {
    loop {
        {
            // Lock the database and check for expired containers
            let mut db_guard = db.lock().await;
            info!("Checking for expired containers...");
            db_guard.check_expiration();  // Check expiration of containers
        }
        sleep(Duration::from_secs(60)).await; // Sleep for 60 seconds before re-checking
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
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

    // Start the HTTP server and share the database
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(tera.clone())) // Add Tera template engine to app state
            .app_data(web::Data::new(shared_database.clone())) // Share the database
            .route("/login", web::get().to(login)) // Handle GET requests for login page
            .route("/login", web::post().to(login)) // Handle POST requests for login form
            .route("/register", web::get().to(register)) // Handle GET requests for registration page
            .route("/register", web::post().to(register)) // Handle POST requests for registration form
            .default_service(web::route().to(page_404)) // Default handler for 404 pages
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
