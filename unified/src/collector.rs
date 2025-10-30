use axum::extract::State;
use futrues::{SinkExt, StreamExt};
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
		Self {state}
	}
}


pub async fn collector_and_send(&mut self) -> Result<(), anyhow:Error> {
	let user = json!({"label":"User","props"})
}