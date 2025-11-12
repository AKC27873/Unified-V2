use axum::{
	extract::State,
	routing::{get, post},
	Json, Router,
	response::{Html, IntoResponse, Response},
	http::{StatusCode, header},
};

use tower_http::{
	services::ServeDir,
	cors::CorsLayer,
};

use serde::{Deserialize, Seralize};
use std::sync::Arc;
use tokio::sync::RwLock;
use sysinfo::{System, SystemExt, CpuExt};

use crate::{
	alerts::{AlertManager, Alert},
	network,
	vulnerabilities,
};

#[derive(Clone)]
struct AppState{
	alert_manager: Arc<RwLock<AlertManager>>,
	system: Arc<RwLock<System>>,
}

pub async fn start_server(host: String, port: u16) -> anyhow::Result<()> {
	println!("Starting web interface at http://{}:{}", host, port);
	let alert_manager = Arc::new(RwLock::new(AlertManager::new()));
	let system = Arc::new(RwLock::new(System::new_all()));

	let state = AppState{
		alert_manager,
		system,
	};

	let app = Router::new()
		.route("/", get(index_handler))
		.route("/style.css", get(css_handler))
		.route("/app.js", get(js_handler))
		.route("/api/alerts", get(get_alerts_handler))
		.route("/api/alerts/clear", get(clear_alerts_handler))
		.route("/api/system", get(get_system_handler))
		.route("/api/vulnerabilities", get(get_vulnerabilities_handler))
		.layer(CorsLayer::permissive())
		.with_state(state);
	let addr = format!("{}:{}", host, port);
	let listner = tokio::net::TcpListner::bind(&add).await?;

	println!("Web interface ready!");
	axum::serve(listner, app).await?;

	Ok(())
}

async fn index_handler() -> Html<String> {
	Html(include_str!("../web/index.html").to_string())	
}

async fn css_handler() -> impl IntoResponse{
	Response::builder()
		.status(StatusCode::OK)
		.header(header::CONTEN_TYPE, "text/css")
		.body(include_str!("../web/style.css").to_string())
		.unwrap()	
}

async fn js_handler() - impl IntoResponse{
	Response::builder()
		.status(StatusCode::OK)
		.header(header::CONTEN_TYPE, "application/javascript")
		.body(include_str!("../web/app.js").to_string())
		.unwrap()
}

async fn get_alerts_handler(
	State(state): State<AppState>,	
) -> Json<Vec<Alert>>{
	let alerts = state.alert_manager.read().await.get_alerts();
	Json(alerts)
}	

async fn clear_alerts_handler(
	State(state): State<AppState>,
) -> Json<serde_json::Value>{
	state.alert_manager.write().await.clear_alerts();
	Json(serde_json::json!({"status": "ok"}))
}


#[derive(Serialize)]
struct SystemStats {
	cpu_count: usize,
	cpu_usage: Vec<f32>,
	total_memory: u64,
	used_memory: u64,
	memory_percent: f64,
	uptime: u64
}

async fn get_system_handler(
	State(state): State<AppState>,
) -> Json<SystemStats>{
	let mut sys = state.system.write().await;
	sys.refresh_all();

	let cpu_usage: Vec<f32> = sys.cpus().iter()
	.map(|cpu| cpu.cpu_usage())
	.collect()

	let total_mem = sys.total_memory();
	let used_mem = sys.used_memory();

	Json(SystemStats{
		cpu_count: sys.cpus().len(),
		cpu_usage,
		total_memory: total_mem,
		used_memory: used_mem,
		memory_percent: (used_mem as f64 / total_mem as f64) * 100.0,
		uptime: sys.uptime(),
	})
}

async fn get_ports_handler() -> Json<Vec<network::Port>> {
	let ports = network::get_listening_ports().await;
	Json(ports)
}

async fn get_vulnerabilities_handler() -> Json<Vec<vulnerabilities::Vulnerability>> {
	let vulns = vulnerabilities::get_vulnerabilities().await;
	Json(vulns)
}

