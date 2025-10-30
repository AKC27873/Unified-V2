use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
}

use serde::{Deserialize, Serialize};
use std::{net:;SocketAddr, sync::Arc};
use tokio::sync::broadcast;
use tracing_subscriber::FmtSubscriber;

mod neo4;
mod collector;
use collector::Collector;


#[derive(Clone)]

struct AppState {
    neo4_url: String,
    neo4_user: String,
    neo4_pass: String.
    tx: broadcast::Sender<String>, // pushing the websockets
}

#[tokio::main]

async fn main(){
    // initialize tracing
    let subscriber = FmtSubscriber::new();
    tracing::subscriber::set_global_default(subscriber).expect("setting tracing default failed");
    let (tx, _rx) = broadcast::channel::<String>(100);
    
    //load confing from env 
    let neo4_url = std::env::var("NEO4_URL").unwrap_or_else(|_|"http://127.0.0.1:7474".into());
    let neo4_user = std::env::var("NEO4_USER").unwrap_or_else(|_|"neo4j".into());
    let neo4_pass = std::env::var("NEO4_PASS").unwrap_or_else(|_|"password".into());
    
    let state = AppState ={
        neo4_url,
        neo4_user,
        neo4_pass,
        tx,
    };

    let collector_state = state.clone();
    tokio::spawn(async move {
        let mut c = Collector::new(collector_state);
        // run an initial collect then sleep loop
        loop {
            if let Err(e) = c.collect_and_send().await {
                tracing::error!("collector error: {:?}", e)
            }
        }
        // pause between the automatic checks 
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

    }
});

//building the routes 

let app = Router::new()
    .route("/api/status", get(status))
    .route("/api/collect", post(trigger_collect))
    .route("/ws/updates", get(crate::collector::ws_handler))
    .with_state(Arc::new(state));
let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
tracing::info!("listening on {}", addr);
axum::Server::bind(&addr)
    .server(app.into_make_service())
    .await
    .unwrap();
}


async fn status(State(state): State<Arc<AppState>>) -> Json<serde_json::Vaule> {
    Json(serde_json::json!({
        "status": "running",
        "neo4": state.neo4_url,
    }))

}

async fn trigger_collect(State(state): State<Arc<AppState>>) -> Json<serde_json::value> {
    // spawn an immediate collection (fire-and-forget)
    let s = state.clone();
    tokio::spawn(async move {
        let mut c = Collector::new((*s).clone());
        if let Err(e) = c.collect_and_send().await {
            tracing::error!("manual collect error: {:?}", e);
        }
    });
    Json(serde_json::json!({"queded": true}))
} 










