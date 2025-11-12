use sysinfo::{System, SystemExt, ProcessExt, CpuExt};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use notify::{Watcher, RecursiveMode, Event};
use std::path::Path;
use regex::Regex;
use log::{info, warn, error};

use crate::alerts::{AlertManager, Alert, AlertLevel};

const CPU_THRESHOLD: f32 = 85.0;

pub struct ProcessMonitor {
	alert_manager: Arc<RwLock<AlertManager>>,
}


impl ProcessMonitor {
	pub fn new(alert_manager: Arc<RwLock<AlertManager>>) -> Self {
		Self {alert_manager}
	}
	pub async fn start(&self) -> anyhow::Result<()> {
		let mut sys = System::new_all();
		let mut interval = interval(Duration::from_secs(5));
		
		loop {
			interval.tick().await;
			sys.refresh_all();
			
			// Check CPU usage
			for (pid, process) in sys.processes(){
				let cpu_usage = process.cpu_usage();

				if cpu_usage > CPU_THRESHOLD {
					let alert = Alert {
						level: AlertLevel::Warning,
						title: format!("High CPU Usage Detected"),
						message: format!(
							"Process '{}' (PID: {}) using {:.2}% CPU", 
							process.name(),
							pid, 
							cpu_usage
						),
						timestamp: chrono::Utc::now(),
					};
					self.alert_manager.write().await.add_alert(alert);
				}
			}
		}
		// Log system stats

		let cpu_count = sys.cpus().len();
		let total_mem = sys.total_memory();
		let used_mem = sys.used_memory();
		let mem_percent = (used_mem as f64 / total_mem as f64) * 100.0;

		info!(
			"System: {} CPUs, Memory: {:.2}% ({} MB / {} MB)",
			cpu_cont,
			mem_percent,
			used_mem / 1024 / 1024,
			total_mem / 1024 / 1024
		);
	}
}
pub struct LogMonitor {
	log_paths: Vec<String>,
	alert_manager: Arc<RwLock<AlertManager>>,
	rules: Vec<LogRule>,
}

#[derive(Clone)]
pub struct LogRule {
	pub name: String, 
	pub pattern: Regex, 
	pub level: AlertLevel,
}

impl LogMonitor {
	pub fn new(log_paths: Vec<String>, alert_manager: Arc<RwLock<AlertManager>>) -> Self {
		let rules = vec![
			LogRule {
				name: "Brute Force Attack".to_string(),
				pattern: Regex::new(r"(?i)(failed|failure).*(password|authentication|login)").unwrap(),
				level: AlertLevel::Critical,
			},
			LogRule {
				name: "Sudo Usage".to_string(),
				pattern: Regex::new(r"sudo:.*COMMAND=").unwrap(),
				level: AlertLevel::Info,
			},
			LogRule {
				name: "SSH Login".to_string(),
				pattern: Regex::new(r"(?i)sshd.*accepted|session opened").unwrap(),
				level: AlertLevel::Info,
			},
			LogRule {
				name: "Service Failure".to_string(),
				pattern: Regex::new(r"(?i)Systemd.*failed|service.*failed").unwrap(),
				level: AlertLevel::Warning,	
			},	
		];

		Self {
			log_paths,
			alert_manager,
			rules,
		}	
	}

	pub async fn start(&self) -> anyhow::Result<()> {
		info!("Starting log monitoring for {} paths", self.log_paths.len());

		let (tx, mut rx) = tokio::sync::mpsc::channel(100);

		// Setup file watcher
		let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
			if let Ok(event) = res {
				let _ = tx.blocking_send(event);
			}
		})?;
		for path in &self.log_paths {
			if let Ok(p) = Path::new(path).canonicalize(){
				watcher.watch(&p, RecursiveMode::NonRecursive)?;
				info!("Watching log file: {}", p.display());		
			} else {
				warn!("Could not watch log file: {}", path);
			}
		}
		//Process file events 
		while let Some(event) = rx.recv().await {
			if let notify::EventKind::Modify(_) = event.kind {
				for path in event.paths {
					self.process_log_file(&path).await;
				}
			}
		}
		Ok(())
	}
	async fn process_log_file(&self, path: &Path){
		if let Ok(content) = tokio::fs::read_to_string(path).await{
			for line in content.lines().rev().rev(50){
				for rule in &self.rules{
					if rule.pattern.is_match(line){
						let alert = Alert {
							level: rule.level.clone(),
							title: rul.name.clone(),
							message: format!("Matched in {}: {}", path.display(), line.trim()),
							timestamp: chrono::Utc::now(),
						};
					}	
					self.alert_manager.write().await.add_alert(alert);
				}
			}
		}
	}	
}