mod user;
mod storage;
mod traefik;

use crate::user::UserDB;
use actix_web::cookie::{CookieBuilder};
use actix_web::{cookie, web, App, HttpResponse, HttpServer};
use log::{error, info, warn};
use serde::Deserialize;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use actix_web::rt::signal;
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

        if db.email_exists(&email) {
            let msg = format!("Email {} already exists, please choose another.", email);
            warn!("Email {} already exists.", email);
            return register_page(tera, Some(msg), None).await;
        }

        if db.uid_exists(uid) {
            let msg = format!("UID {} already exists, please choose another.", uid);
            warn!("UID {} already exists.", uid);
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
) -> Result<HttpResponse, actix_web::Error> {
    if let Some(form) = form {
        // Process POST request, handle login logic
        let LoginForm { username, password } = form.into_inner();

        // Lock the database and check user credentials
        let mut db = db.lock().await;

        return if let Ok(token) = db.login(username.clone(), password) {
            // On successful login, generate a cookie and set the token
            info!("User {} logged in successfully.", username);

            // Create a Cookie, set Domain to *.code.cocoabrew.cc, and mark as HttpOnly and Secure
            let cookie = CookieBuilder::new("auth_token", token)
                .domain(".code.cocoabrew.cc")
                .path("/")
                .http_only(true)
                .secure(true)
                .max_age(cookie::time::Duration::days(30))
                .finish();

            // Set the cookie in the response and redirect to /dashboard
            Ok(HttpResponse::Found()
                .append_header(("LOCATION", "/dashboard"))
                .cookie(cookie)
                .finish())
        } else {
            warn!("Failed login attempt for user: {}", username);
            let msg = "Invalid username or password.".to_string();

            // Render the login page with the result message
            login_page(tera, Some(msg)).await
        }
    }

    // Render login page for GET requests or when form is None
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
async fn main() -> std::io::Result<()> {
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
