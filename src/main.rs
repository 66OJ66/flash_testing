use axum::{
    extract::Extension,
    http::StatusCode,
    response::Html,
    routing::{get, get_service, post},
    Router,
};
use axum_extra::{extract::cookie::Key, routing::RouterExt};
use std::net::SocketAddr;
use axum::extract::Form;
use axum::response::{IntoResponse, Redirect};
use axum_extra::extract::cookie::{Cookie, Expiration, SameSite};
use axum_extra::extract::PrivateCookieJar;
use axum_flash::{Flash, IncomingFlashes};
use tera::Tera;
use serde::{Deserialize};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    // Enable debug tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "example_static_file_server=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let secret_key: Key = Key::generate();

    let tera: Tera = Tera::new("templates/**/*").unwrap();

    let app = Router::new()
        .route("/login", get(get_login).post(post_login))
        .route("/do/a/thing", get(get_do).post(post_do))
        .nest(
            "/assets",
            get_service(ServeDir::new("./assets")).handle_error(
                |error: std::io::Error| async move {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Unhandled internal error: {}", error),
                    )
                },
            ),
        )
        .layer(TraceLayer::new_for_http())
        .layer(Extension(secret_key.clone()))
        .layer(Extension(tera))
        .layer(axum_flash::layer(secret_key).with_cookie_manager())
        .into_make_service_with_connect_info::<SocketAddr>();

    let address = SocketAddr::from(([127,0,0,1], 8000));

    println!("Application starting on {}", address);
    // Start the server
    match axum::Server::bind(&address).serve(app).await {
        Ok(_) => {}
        Err(e) => eprintln!("Error: {}", e.to_string()),
    }
}

pub const AUTH_COOKIE_NAME: &str = "id";

async fn get_login(
    jar: PrivateCookieJar,
    flash: IncomingFlashes,
    Extension(tera): Extension<Tera>,
) -> impl IntoResponse {
    let mut context = tera::Context::new();
    if flash.len() == 1{
        context.insert("message", flash.iter().nth(0).unwrap().1);
    }

    Html(tera.render("login.html.tera", &context).unwrap()).into_response()
}

async fn post_login(
    form: Form<Login>,
    jar: PrivateCookieJar,
    mut flash: Flash,
) -> impl IntoResponse {

    if form.user == "admin" && form.password == "admin"{
        let cookie: Cookie = Cookie::build(AUTH_COOKIE_NAME, 0.to_string())
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax)
            .expires(Expiration::Session)
            .finish();

        let updated_jar: PrivateCookieJar = jar.add(cookie);

        (updated_jar, Redirect::to("/do/a/thing")).into_response()
    }

    else {
        flash.error("Incorrect email address or password");
        Redirect::to("/login").into_response()
    }
}

async fn get_do(flash: IncomingFlashes, Extension(tera): Extension<Tera>) -> impl IntoResponse{
    let mut context = tera::Context::new();
    if flash.len() == 1{
        context.insert("message", flash.iter().nth(0).unwrap().1);
    }

    Html(tera.render("do_a_thing.html.tera", &context).unwrap()).into_response()
}

async fn post_do(mut flash: Flash) -> impl IntoResponse{
    flash.error("Error: Cannot create this item");
    Redirect::to("/do/a/thing").into_response()
}

#[derive(Deserialize)]
pub struct Login {
    user: String,
    password: String,
}

#[derive(Deserialize)]
pub struct PostedData {
    name: String,
    description: String,
}