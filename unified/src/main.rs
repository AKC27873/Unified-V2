use axum::{Router, routing::{get, post}};
use std::{net::SocketAddr, sync::Arc};
use tracing_subscriber::FmtSubscriber;


mod routes;
mod collectors;
mod db;


#[derive(Clone)]
pub struct AppState {
    pub neo4_url: String,
    pub neo4_user: String,
    pub neo4_pass: String,
}


#[tokio::main]
async fn main(){
    //Init logging
    let subscriber = FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    // Config

    let state = Arc::new(AppState{

        neo4_url: std::env::var("NEO4J_URL").unwrap_or("http://127.0.0.1:7474".into()),
        neo4_url: std::env::var("NEO4J_USER").unwrap_or("neo4j".into()),
        neo4_url: std::env::var("NEO4J_PASS").unwrap_or("password".into()),
    });   

    // Router setup 
    let app = Router::new()
        .route("/api/status", get(routes::api::status))
        .route("/api/collect", get(routes::api::trigger_collect))
        .route("/api/updates", get(routes::ws::ws_handler))
        .with_state(state);
    let addr = SocketAddr::from(([0,0,0,0], 8080));
    tracing::info!("Unified-RS running on http://{}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}