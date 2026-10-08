mod container;
mod storage;
mod traefik;
mod user;

use actix_web::{
    cookie::{self, CookieBuilder},
    web, App, HttpResponse, HttpServer, Result as ActixResult,
};
use std::path::Path;
use std::{
    fs,
    fs::File,
    io::{self, BufRead},
    process::exit,
    sync::Arc,
    time::Duration,
};

use crate::{container::ContainerManager, user::UserDB};

use bcrypt::{hash, verify};
use log::{error, info, warn};
use serde::Deserialize;
use tera::{Context, Tera};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::RwLock,
    time::sleep,
};

/// Resolve the logged-in user's uid from the request's auth cookie.
/// Returns `None` when there is no cookie or the token is unknown.
async fn authenticated_uid(
    db: &web::Data<SharedUserDB>,
    req: &actix_web::HttpRequest,
) -> Option<isize> {
    let token = req.cookie("auth_token")?;
    let db_read = db.read().await;
    db_read
        .find_user_by_token(token.value())
        .map(|user| user.uid)
}

async fn reload_db(
    db: web::Data<SharedUserDB>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    // This endpoint replaces the live database; never serve it anonymously.
    let Some(uid) = authenticated_uid(&db, &req).await else {
        warn!("Rejected unauthenticated /reloaddb request.");
        return Ok(HttpResponse::Unauthorized().body("Authentication required."));
    };

    let db_file_path = storage::USERDB.as_str();

    info!(
        "Reloading database from file: {} (requested by uid {})",
        db_file_path, uid
    );

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
    Ok(HttpResponse::NotFound()
        .content_type("text/html")
        .body(rendered))
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

/// Check if the given UID is in the whitelist. Blocking file IO:
/// callers on async runtimes must run this in `spawn_blocking`.
fn is_uid_allowed_sync(uid: isize) -> bool {
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
                        return true;
                    }
                }
            }
        }
    }

    // If no matching UID is found, registration is not allowed
    false
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

        // Check if the UID is in the whitelist (blocking file IO).
        let whitelist_ok = tokio::task::spawn_blocking(move || is_uid_allowed_sync(uid)).await;
        match whitelist_ok {
            Ok(true) => {}
            Ok(false) => {
                let msg = format!("UID {} 无法注册。", uid);
                warn!("UID {} is not in the whitelist.", uid);
                return register_page(tera, Some(msg), None).await;
            }
            Err(e) => {
                let msg = "检查 UID 白名单时出错。".to_string();
                error!("Error checking UID whitelist for UID {}: {}", uid, e);
                return register_page(tera, Some(msg), None).await;
            }
        }

        // Check if passwords match
        if password != password2 {
            let msg = "两次输入的密码不一致，请重试。".to_string();
            warn!("Password mismatch for user: {}", username);
            return register_page(tera, Some(msg), None).await;
        }

        // Hash the password in the blocking pool (CPU-bound), outside any lock.
        let hashed =
            match tokio::task::spawn_blocking(move || hash(password, bcrypt::DEFAULT_COST)).await {
                Ok(Ok(hashed)) => hashed,
                Ok(Err(e)) => {
                    error!("Password hashing failed for user {}: {}", username, e);
                    let msg = "注册失败，请联系管理员。".to_string();
                    return register_page(tera, Some(msg), None).await;
                }
                Err(e) => {
                    error!("Password hashing task failed for user {}: {}", username, e);
                    let msg = "注册失败，请联系管理员。".to_string();
                    return register_page(tera, Some(msg), None).await;
                }
            };

        // Insert the record under a short write lock (checks + insert are atomic).
        let inserted: Result<(), String> = {
            let mut db_write = db.write().await;
            if db_write.username_exists(&username) {
                warn!("Username {} already exists.", username);
                Err(format!("用户名 {} 已经存在，请选择其他用户名。", username))
            } else if db_write.email_exists(&email) {
                warn!("Email {} already exists.", email);
                Err(format!("邮箱 {} 已经存在，请选择其他邮箱。", email))
            } else if db_write.uid_exists(uid) {
                warn!("UID {} already exists.", uid);
                Err(format!("UID {} 已经存在，请选择其他 UID。", uid))
            } else {
                let new_user = user::User {
                    uid,
                    username: username.clone(),
                    email: email.clone(),
                    password: hashed,
                    token: None,
                    is_updating: false,
                };
                match db_write.add_user_record(new_user) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        error!("Failed to add user {} to the database: {}", username, e);
                        Err("注册失败，请联系管理员。".to_string())
                    }
                }
            }
        };
        if let Err(msg) = inserted {
            return register_page(tera, Some(msg), None).await;
        }

        // Create the container outside the lock; roll back the record on failure.
        let uid_string = uid.to_string();
        let created =
            tokio::task::spawn_blocking(move || ContainerManager::create_container(&uid_string))
                .await;
        match created {
            Ok(Ok(())) => {
                let msg = "注册成功！请继续登录。".to_string();
                info!("User {} registered successfully.", username);
                register_page(tera, None, Some(msg)).await
            }
            Ok(Err(e)) => {
                error!("Failed to create container for user {}: {}", username, e);
                rollback_failed_registration(&db, uid).await;
                let msg = "注册失败，请联系管理员。".to_string();
                register_page(tera, Some(msg), None).await
            }
            Err(e) => {
                error!(
                    "Container creation task failed for user {}: {}",
                    username, e
                );
                rollback_failed_registration(&db, uid).await;
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

/// Removes a just-inserted user record after its container creation
/// failed, plus best-effort cleanup of a half-created container, so the
/// username/email/uid can be registered again.
async fn rollback_failed_registration(db: &web::Data<SharedUserDB>, uid: isize) {
    {
        let mut db_write = db.write().await;
        db_write.remove_user_record(uid);
    }
    let container_id = format!("{}.codeserver", uid);
    let _ = tokio::task::spawn_blocking(move || {
        let _ = ContainerManager::remove_container(&container_id);
    })
    .await;
}

async fn logout(
    db: web::Data<SharedUserDB>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(uid) = authenticated_uid(&db, &req).await else {
        warn!("auth_token missing or invalid, redirecting to login page.");
        return Ok(HttpResponse::Found()
            .append_header(("LOCATION", "/login"))
            .finish());
    };

    // Stop the container outside the lock. The logout proceeds even if
    // Docker fails: a stuck container must not trap the session.
    let stopped = tokio::task::spawn_blocking(move || -> io::Result<()> {
        let uid_string = uid.to_string();
        if ContainerManager::is_container_running(&uid_string)? {
            ContainerManager::stop_container_docker(&format!("{}.codeserver", uid))?;
            info!("Container stopped for UID: {}", uid);
        }
        Ok(())
    })
    .await;
    match stopped {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!("Failed to stop container for UID {}: {}", uid, e),
        Err(e) => error!("Container stop task failed for UID {}: {}", uid, e),
    }

    {
        let mut db_write = db.write().await;
        if let Err(e) = db_write.finish_logout(uid) {
            error!("Failed to finish logout for UID {}: {}", uid, e);
        }
    }

    Ok(HttpResponse::Found()
        .append_header(("LOCATION", "/login"))
        .finish())
}

/// Handles user login logic for both GET (render page) and POST (process login).
async fn login(
    form: Option<web::Form<LoginForm>>,
    tera: web::Data<Tera>,
    db: web::Data<SharedUserDB>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    // Check if there is a valid auth_token (short read, no lock held afterwards)
    if let Some(auth_cookie) = req.cookie("auth_token") {
        let token = auth_cookie.value().to_string();
        let logged_in_as = {
            let db_read = db.read().await;
            db_read
                .find_user_by_token(&token)
                .map(|user| user.username.clone())
        };
        if let Some(username) = logged_in_as {
            // If user is found, redirect to dashboard
            info!(
                "User {} already logged in, redirecting to dashboard.",
                username
            );
            return Ok(HttpResponse::Found()
                .append_header(("LOCATION", "/dashboard"))
                .finish());
        }
    }

    // If there is no valid token or processing a form request
    if let Some(form) = form {
        let LoginForm { username, password } = form.into_inner();

        // 1. Fetch the credential under a short read lock.
        let credential = {
            let db_read = db.read().await;
            db_read.credential_for(&username)
        };
        let Some((uid, password_hash)) = credential else {
            warn!("User '{}' not found", username);
            let msg = "用户名或密码错误。".to_string();
            return login_page(tera, Some(msg)).await;
        };

        // 2. Verify the password in the blocking pool (CPU-bound), lock-free.
        let verified =
            tokio::task::spawn_blocking(move || verify(&password, &password_hash).unwrap_or(false))
                .await;
        match verified {
            Ok(true) => {}
            Ok(false) => {
                warn!("Incorrect password for user: {}", username);
                let msg = "用户名或密码错误。".to_string();
                return login_page(tera, Some(msg)).await;
            }
            Err(e) => {
                error!("Password verify task failed for user {}: {}", username, e);
                return Ok(HttpResponse::InternalServerError().body("登录失败，请稍后重试。"));
            }
        }

        // 3. Ensure the container is running, outside any lock.
        let username_for_task = username.clone();
        let ensure_running = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let uid_string = uid.to_string();
            if ContainerManager::is_container_running(&uid_string)? {
                info!(
                    "Container is already running for user: {}",
                    username_for_task
                );
            } else {
                info!("Starting container for user: {}", username_for_task);
                ContainerManager::start_container_docker(&format!("{}.codeserver", uid))?;
                info!(
                    "Successfully started container for user: {}",
                    username_for_task
                );
            }
            UserDB::refresh_heartbeat(uid);
            Ok(())
        })
        .await;
        match ensure_running {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                error!("Failed to start container for user {}: {}", username, e);
                return Ok(HttpResponse::InternalServerError().body("IDE 启动失败，请联系管理员。"));
            }
            Err(e) => {
                error!("Container start task failed for user {}: {}", username, e);
                return Ok(HttpResponse::InternalServerError().body("IDE 启动失败，请联系管理员。"));
            }
        }

        // 4. Publish the session and route under a short write lock.
        let token = {
            let mut db_write = db.write().await;
            let token = db_write.publish_session(uid);
            if let Err(e) = db_write.register_traefik_instance(uid, &token) {
                error!(
                    "Failed to register traefik instance for user {}: {}",
                    username, e
                );
                return Ok(HttpResponse::InternalServerError()
                    .body("登录失败：路由配置错误，请联系管理员。"));
            }
            token
        };

        info!("User {} logged in successfully.", username);

        let cookie = CookieBuilder::new("auth_token", token)
            .domain(&*storage::DOMAIN)
            .path("/")
            .http_only(true)
            .secure(true)
            .max_age(cookie::time::Duration::days(30))
            .finish();

        return Ok(HttpResponse::Found()
            .append_header(("LOCATION", "/dashboard"))
            .cookie(cookie)
            .finish());
    }

    info!("Displaying login page.");
    login_page(tera, None).await
}

async fn update_container(
    db: web::Data<SharedUserDB>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    let Some(uid) = authenticated_uid(&db, &req).await else {
        info!("Unauthenticated /upgrade request, redirecting to dashboard.");
        return Ok(HttpResponse::Found()
            .append_header(("LOCATION", "/dashboard"))
            .finish());
    };

    // Mark the user as updating under a short write lock.
    let already_updating = {
        let mut db_write = db.write().await;
        match db_write.find_user_by_uid_mut(uid) {
            Some(user) if user.is_updating => true,
            Some(user) => {
                user.is_updating = true;
                false
            }
            None => {
                return Ok(HttpResponse::Found()
                    .append_header(("LOCATION", "/dashboard"))
                    .finish())
            }
        }
    };
    if already_updating {
        info!(
            "Update already in progress for UID {}, redirecting to dashboard.",
            uid
        );
        return Ok(HttpResponse::Found()
            .append_header(("LOCATION", "/dashboard"))
            .finish());
    }

    // Clone the db and move it into the background task. All Docker and
    // network work runs in the blocking pool without holding any lock.
    let db_clone = db.clone();
    actix_web::rt::spawn(async move {
        let docker_result = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let uid_string = uid.to_string();
            let container_id = format!("{}.codeserver", uid);
            if ContainerManager::is_container_running(&uid_string)? {
                ContainerManager::stop_container_docker(&container_id)?;
            }
            ContainerManager::remove_container(&container_id)?;
            ContainerManager::pull_latest_image()?;
            ContainerManager::create_container(&uid_string)?;
            ContainerManager::start_container_docker(&container_id)?;
            Ok(())
        })
        .await;

        // Finalize under a short write lock, using the live session token
        // (it may have rotated while the update was running).
        let mut db_write = db_clone.write().await;
        let live_token = db_write
            .find_user_by_uid(uid)
            .and_then(|user| user.token.clone());
        match docker_result {
            Ok(Ok(())) => match live_token {
                Some(token) => {
                    if let Err(e) = db_write.register_traefik_instance(uid, &token) {
                        error!("Update finished but failed to register traefik instance for UID {}: {}", uid, e);
                    } else {
                        info!("Container for user {} updated successfully.", uid);
                    }
                }
                None => {
                    warn!(
                        "User {} logged out during update; container left without a route.",
                        uid
                    );
                }
            },
            Ok(Err(e)) => {
                error!("Failed to update container for user {}: {}", uid, e);
            }
            Err(e) => {
                error!("Container update task failed for user {}: {}", uid, e);
            }
        }
        if let Some(user) = db_write.find_user_by_uid_mut(uid) {
            user.is_updating = false;
        }
    });

    Ok(HttpResponse::Found()
        .append_header(("LOCATION", "/dashboard"))
        .finish())
}

/// Renders the dashboard page for logged-in users.
async fn dashboard(
    tera: web::Data<Tera>,       // Instance of the Tera template engine
    db: web::Data<SharedUserDB>, // Shared user database
    req: actix_web::HttpRequest, // Request object, used to retrieve the Cookie
) -> Result<HttpResponse, actix_web::Error> {
    let Some(uid) = authenticated_uid(&db, &req).await else {
        warn!("auth_token missing or invalid, redirecting to login page.");
        return Ok(HttpResponse::Found()
            .append_header(("LOCATION", "/login"))
            .finish());
    };

    // Snapshot the user record under a short read lock. Everything below
    // (Docker subprocesses, registry network calls) runs in the blocking
    // pool without holding any lock.
    let snapshot = {
        let db_read = db.read().await;
        db_read
            .find_user_by_uid(uid)
            .map(|user| (user.username.clone(), user.email.clone(), user.is_updating))
    };
    let Some((username, email, is_updating)) = snapshot else {
        warn!(
            "User with UID {} not found, redirecting to login page.",
            uid
        );
        return Ok(HttpResponse::Found()
            .append_header(("LOCATION", "/login"))
            .finish());
    };

    let mut context = Context::new();
    context.insert("username", &username);
    context.insert("email", &email);
    context.insert("is_updating", &is_updating);

    if !is_updating {
        let running_uid = uid.to_string();
        let tag_container = format!("{}.codeserver", uid);
        let (running_result, latest_result, current_result) = tokio::join!(
            tokio::task::spawn_blocking(move || ContainerManager::is_container_running(
                &running_uid
            )),
            tokio::task::spawn_blocking(ContainerManager::get_latest_image_tag),
            tokio::task::spawn_blocking(move || ContainerManager::get_container_tag(
                &tag_container
            )),
        );
        let running_result: io::Result<bool> = flatten_blocking(running_result);
        let latest_tag_result: io::Result<String> = flatten_blocking(latest_result);
        let current_tag_result: io::Result<String> = flatten_blocking(current_result);

        // Check if the container is running and update the context accordingly
        match running_result {
            Ok(true) => context.insert("container_stat", "on"),
            Ok(false) => context.insert("container_stat", "off"),
            Err(e) => {
                context.insert(
                    "warning",
                    format!(
                        "Container status error. Please contact the administrator.\nError: {}",
                        e
                    )
                    .as_str(),
                );
                context.insert("container_stat", "off");
            }
        };

        // Variables to hold the tags if they are successfully retrieved
        let mut latest_tag_opt = None;
        let mut current_tag_opt = None;

        // Handle the latest tag result
        match latest_tag_result {
            Ok(tag) => {
                latest_tag_opt = Some(tag);
            }
            Err(e) => {
                context.insert(
                    "warning",
                    format!("Failed to get latest image tag: {}", e).as_str(),
                );
            }
        }

        // Handle the current tag result and insert container version into context
        match current_tag_result {
            Ok(ref tag) => {
                context.insert("container_version", tag); // Insert current container version into context
                current_tag_opt = Some(tag.clone());
            }
            Err(e) => {
                context.insert(
                    "container_version",
                    format!("Failed to get container version: {}", e).as_str(),
                );
                context.insert(
                    "warning",
                    format!("Failed to get current container image tag: {}", e).as_str(),
                );
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
    }

    // Render the dashboard.html template
    let rendered = tera.render("dashboard.html", &context).map_err(|e| {
        error!("Template rendering error: {}", e);
        actix_web::error::ErrorInternalServerError("Template rendering error")
    })?;

    info!("Rendered dashboard page, user: {}", username);
    Ok(HttpResponse::Ok().content_type("text/html").body(rendered))
}

/// Collapse a `spawn_blocking` join result and its inner `io::Result`
/// into one, turning a panicked/cancelled task into an `io::Error`.
fn flatten_blocking<T>(result: Result<io::Result<T>, tokio::task::JoinError>) -> io::Result<T> {
    match result {
        Ok(inner) => inner,
        Err(e) => Err(io::Error::other(e.to_string())),
    }
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
        // Collect expired uids under a short read lock; Docker stops and
        // per-user finalization happen afterwards without a held lock.
        let expired = { db.read().await.expired_uids() };
        for uid in expired {
            let stopped = tokio::task::spawn_blocking(move || -> io::Result<()> {
                let uid_string = uid.to_string();
                if ContainerManager::is_container_running(&uid_string)? {
                    ContainerManager::stop_container_docker(&format!("{}.codeserver", uid))?;
                }
                Ok(())
            })
            .await;
            match stopped {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!("Failed to stop idle container for UID {}: {}", uid, e),
                Err(e) => error!("Idle container stop task failed for UID {}: {}", uid, e),
            }
            let mut db_write = db.write().await;
            let username = db_write
                .find_user_by_uid(uid)
                .map(|user| user.username.clone());
            if let Err(e) = db_write.finish_logout(uid) {
                error!("Failed to log out idle user with UID {}: {}", uid, e);
            } else {
                info!(
                    "User '{}' has been idle for more than {} seconds and logged out.",
                    username.as_deref().unwrap_or("?"),
                    crate::user::IDLE_TIMEOUT_SECS,
                );
            }
        }
        info!("The expired users have already been checked.");
        sleep(Duration::from_secs(60)).await; // Sleep for 60 seconds before re-checking
    }
}

// Periodically save userdb
async fn db_saver(db: SharedUserDB) {
    loop {
        {
            // Saving only needs a read lock; writers are never blocked.
            let db_read = db.read().await;
            match db_read.write_to_file() {
                Ok(_) => info!("The user database saved successfully"),
                Err(e) => error!("Error writing database to file periodically: {}", e),
            }
        }
        sleep(Duration::from_secs(*storage::SAVE_INTERVAL)).await;
    }
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    info!("Starting server...");

    let tera =
        Tera::new(format!("{}/**/*", storage::TEMPLATES.as_str()).as_str()).unwrap_or_else(|e| {
            error!("Error initializing Tera templates: {}", e);
            exit(1);
        });

    // Initialize shared database
    let shared_database = if !Path::new(storage::USERDB.as_str()).exists() {
        info!(
            "Database not found: {}. Creating new database...",
            storage::USERDB.as_str()
        );
        Arc::new(RwLock::new(UserDB::new(storage::USERDB.as_str())))
    } else {
        info!("Database exists: {}", &*storage::USERDB);
        Arc::new(RwLock::new(
            match UserDB::read_from_file(storage::USERDB.as_str()) {
                Ok(db) => db,
                Err(_) => {
                    error!(
                        "Cannot read from database: {}. Please check access permissions.",
                        storage::USERDB.as_str()
                    );
                    exit(1);
                }
            },
        ))
    };

    // Update tasks that died with the previous process leave stale
    // `is_updating` flags persisted in the database; clear them so those
    // users are not stuck in the updating state forever.
    shared_database.write().await.clear_updating_flags();

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
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to listen for Ctrl+C");
        }

        // Perform the shutdown procedure (save the database, etc.)
        shutdown_procedure(shared_db_clone).await;

        // Gracefully exit after shutdown tasks are done
        info!("Server is shutting down.");
        exit(0); // Exit after completing the shutdown
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

    // Stop every container outside the lock (`docker stop` is idempotent,
    // so already-stopped containers are harmless).
    let container_names = { shared_db.read().await.container_names() };
    let stops = tokio::task::spawn_blocking(move || {
        for name in container_names {
            if let Err(e) = ContainerManager::stop_container_docker(&name) {
                error!("Error stopping container {} during shutdown: {}", name, e);
            }
        }
    })
    .await;
    if let Err(e) = stops {
        error!("Container shutdown task failed: {}", e);
    }

    // Clear sessions and routes, then persist, under a short write lock.
    {
        let mut db = shared_db.write().await;
        match db.clear_all_sessions() {
            Ok(()) => info!("All users have been successfully logged out."),
            Err(e) => error!("Error logging out users during shutdown: {}", e),
        }

        match db.write_to_file() {
            Ok(()) => info!("Successfully saved the database."),
            Err(e) => error!("Error saving the database: {}", e),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::User;
    use actix_web::{http::StatusCode, test::TestRequest};

    fn test_user_with_token(uid: isize, token: &str) -> (UserDB, String) {
        let file_path = std::env::temp_dir()
            .join(format!("reloaddb-test-{}-{}.json", std::process::id(), uid))
            .to_string_lossy()
            .to_string();
        let mut db = UserDB::empty_for_test(&file_path);
        db.insert_for_test(User {
            uid,
            username: format!("user{}", uid),
            email: format!("user{}@example.com", uid),
            password: "hashed".to_string(),
            token: None,
            is_updating: false,
        });
        db.set_user_token(uid, token.to_string());
        (db, file_path)
    }

    #[actix_web::test]
    async fn authenticated_uid_resolves_valid_token_only() {
        let (db, file_path) = test_user_with_token(11, "valid-token");
        let data = web::Data::new(Arc::new(RwLock::new(db)));

        let authed = TestRequest::default()
            .cookie(CookieBuilder::new("auth_token", "valid-token").finish())
            .to_http_request();
        assert_eq!(authenticated_uid(&data, &authed).await, Some(11));

        let anonymous = TestRequest::default().to_http_request();
        assert_eq!(authenticated_uid(&data, &anonymous).await, None);

        let forged = TestRequest::default()
            .cookie(CookieBuilder::new("auth_token", "no-such-token").finish())
            .to_http_request();
        assert_eq!(authenticated_uid(&data, &forged).await, None);

        drop(data);
        let _ = fs::remove_file(&file_path);
    }

    #[actix_web::test]
    async fn reload_db_rejects_unauthenticated_request() {
        let (db, file_path) = test_user_with_token(12, "valid-token");
        let data = web::Data::new(Arc::new(RwLock::new(db)));

        let req = TestRequest::default().to_http_request();
        let resp = reload_db(data.clone(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        drop(data);
        let _ = fs::remove_file(&file_path);
    }

    #[actix_web::test]
    async fn reload_db_accepts_authenticated_request() {
        // Seed the on-disk database that /reloaddb loads.
        let (seed_db, file_path) = test_user_with_token(13, "valid-token");
        seed_db.write_to_file().unwrap();
        drop(seed_db);
        std::env::set_var("USERDB", &file_path);

        let (db, _) = test_user_with_token(13, "valid-token");
        let data = web::Data::new(Arc::new(RwLock::new(db)));

        let req = TestRequest::default()
            .cookie(CookieBuilder::new("auth_token", "valid-token").finish())
            .to_http_request();
        let resp = reload_db(data.clone(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The live db was replaced with the file content.
        let db_read = data.read().await;
        assert!(db_read.username_exists("user13"));
        drop(db_read);

        drop(data);
        let _ = fs::remove_file(&file_path);
    }
}
