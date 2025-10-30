use axum::extract::State;
use futures::{SinkExt, StreamExt};
use reqwest::Client;
use serde_json::json;
use std::{sync::Arc};
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;

use crate::neo4::Neo4jClient;

#[derive(Clone)]
pub struct Collector {
    state: Arc<crate::AppState>,
}

impl Collector {
    pub fn new(state: Arc<crate::AppState>) -> Self {
        Self { state }
    }

    /// Example collector: builds 1 user node and 1 computer node and a relationship, then sends to Neo4j
    pub async fn collect_and_send(&mut self) -> Result<(), anyhow::Error> {
        // 1) Gather - (stubbed) -> Replace with real collectors (LDAP, procfs, SMB, WinRM, etc.)
        let user = json!({"label":"User","props":{"name":"alice","domain":"ACME","lastSeen":"2025-10-08T00:00:00Z"}});
        let computer = json!({"label":"Computer","props":{"name":"HOST-1","ip":"192.168.1.10","os":"Linux","lastSeen":"2025-10-08T00:00:00Z"}});
        let rel = json!({"from":"alice","to":"HOST-1","type":"HasSession","props":{ "since":"2025-10-08T00:00:00Z"}});

        // 2) Convert to Cypher statements and POST to neo4j
        let neo = Neo4jClient::new(&self.state.neo4_url, &self.state.neo4_user, &self.state.neo4_pass);
        // create/merge user
        let stmt1 = "MERGE (u:User {name:$name, domain:$domain}) SET u.lastSeen = $lastSeen RETURN u";
        let params1 = json!({"name":"alice","domain":"ACME","lastSeen":"2025-10-08T00:00:00Z"});
        neo.run_statement(stmt1, params1).await?;

        // create/merge computer
        let stmt2 = "MERGE (c:Computer {name:$name}) SET c.ip=$ip, c.os=$os, c.lastSeen=$lastSeen RETURN c";
        let params2 = json!({"name":"HOST-1","ip":"192.168.1.10","os":"Linux","lastSeen":"2025-10-08T00:00:00Z"});
        neo.run_statement(stmt2, params2).await?;

        // create relationship
        let stmt3 = "MATCH (u:User {name:$user}), (c:Computer {name:$host}) MERGE (u)-[r:HasSession]->(c) SET r.since=$since RETURN r";
        let params3 = json!({"user":"alice","host":"HOST-1","since":"2025-10-08T00:00:00Z"});
        neo.run_statement(stmt3, params3).await?;

        // 3) broadcast an update
        let _ = self.state.tx.send("collected: alice -> HOST-1".to_string());
        Ok(())
    }
}

/// WebSocket handler to stream update messages to clients
pub async fn ws_handler(
    ws: axum::extract::WebSocketUpgrade,
    State(state): State<Arc<crate::AppState>>,
) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut socket: axum::extract::WebSocket, state: Arc<crate::AppState>) {
    let mut rx = state.tx.subscribe();
    // spawn a task to forward broadcast messages to the websocket
    loop {
        let msg = rx.recv().await;
        match msg {
            Ok(text) => {
                if socket.send(axum::extract::ws::Message::Text(text)).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}
