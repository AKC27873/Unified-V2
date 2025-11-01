use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::sync::RwLock;

mod monitoring;
mod alerts;
mod plugins;
mod vulnerabilities;
mod network;
mod config;
mod web;

use monitoring::{ProcessMonitor, LogMonitor};
use alerts::AlertManager;
use config::Config;

#[derive(Parser)]
#[command(name="unified")]
#[command(about="A real-time security monitoring tool.", long_about = None)]

struct Cli {
	#[command(subcommand)]
	command: Commands,
}

#[derive(Subcommand)]

enum Commands {
	/// Start the monitoring daemon
	Monitor {
		/// Path to configuration file goes here 
		#[arg(short, long, default_value = "config.toml")]
		config: String,	
	},
	/// Start the Web Interface
	Web {
		// Port to bind to
		#[arg(short, long, default_value= "8080")]
		port: u16,
		/// Host to bind to
		#[arg(long, default_value= "127.0.0.1")]
		host: String,
	},
	/// Run a vulnerability scan 
	Scan {
		/// Scan type: all, ports, packages, permissions
		#[arg(short, long, default_value= "all")]
		scan_type: String,
	},
	/// list all Listening Ports
	Ports,
}


#[tokio::main]
async fn main() -> anyhow::Result<()>{
	env_logger::init();
	let cli = Cli::parse();

	match cli.command {
		Commands::Monitor {config} => {
			run_monitor(config).await?;
		}
		Commands::Web {port, host} => {
			web::start_server(host, port).await?;
		}
		Commands::Scan {scan_type} => {
			run_scan(&scan_type).await?;
		}
		Commands::Ports => {
			list_ports().await?;
		}
	}

	Ok(())
}

async fn run_monitor(config_path: String) -> anyhow::Result<()> {
	println!("Starting Unified Security Monitor...");

	let config = Config::load(&config_path)?;
	let alert_manager = Arc::new(RwLock::new(AlertManager::new()));

	// Spawn process Monitor
	let process_monitor = LogMonitor::new(config.log_paths.clone(), alert_manager.clone());
	let lm_handle = tokio::spawn(async move {
		log_monitor.start().await
	});

	println!("All monitors started. Press Ctrl+c to stop.")

	tokio::select! {
		_ = tokio::signal::ctrl_c() => {
			println!("\n Shutting down...");
		}
	_ = pm_handle => {}
	_ = lm_handle => {}

	}

	Ok(())
}

async fn run_scan(scan_type: &str) -> anyhow::Result<()>{
	println!("Running {} scan...", scan_type);

	match scan_type {
		"all" => {
			vulnerabilities::scan_packages().await?;
			vulnerabilities::scan_permissions().await?;
			network::scan_ports().await?;
		}
		"ports" => network::scan_ports().await?,
		"packages" => vulnerabilities::scan_packages().await?,
		"permissions" => vulnerabilities::scan_permissions().await?,
		_ => println!("Unknow scan type: {}", scan_type),
	}
	Ok(())
}

asyn fn list_ports() -> anyhow::Result<()>{
	network::list_listening_ports().await?;
	Ok(())
}
