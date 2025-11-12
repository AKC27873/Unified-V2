use serde::{Deserialize, Seralize};
use std::fs;

#[derive(Debug, Clone, Seralize, Deserialize)]
pub struct Config {
	pub log_paths: Vec<String>,
	pub cpu_threshold: f32,
	pub scan_interval: u64,
	pub web_interface: WebConfig,
	pub plugins: PluginConfig,
}

#[derive(Debug, Clone, Seralize, Deserialize)]
pub struct WebConfig {
	pub enabled: bool,
	pub host: String,
	pub port: u16,
}

#[derive(Debug, Clone, Seralize, Deserialize)]
pub struct PluginConfig {
	pub threat_hunting: bool,
	pub red_team: bool,
	pub anomaly_detection: bool,
	pub auto_remediation: bool,
	pub threat_intel: bool,
}

impl Default for Config {
	fn default() -> Self {
		#[cfg(target_os = "linux")]
		let log_paths = vec![
			"/var/log/auth.log".to_string(),
			"/var/log/syslog".to_string(),
			"/var/log/secure".to_string(),
		];
		#[cfg(target_os = "windows")]
		let log_paths = vec![
			"C:\\Windows\\System32\\winevt\\Logs\\Security.evtx".to_string(),
			"C:\\Windows\\System32\\winevt\\Logs\\System.evtx".to_string(),
		];

		Self{
			log_paths,
			cpu_threshold: 85.0,
			scan_interval: 300,
			web_interface: WebConfig {
				enabled: true,
				host: "127.0.0.1".to_string(),
				port: 8080,
			},
			plugins: PluginConfig{
				threat_hunting: true,
				red_team: false,
				anomaly_detection: true,
				auto_remediation: false,
				threat_intel: true,
			},
		}

	}
}

impl Config {
	pub fn load(path: &str) -> anyhow::Result<Self>{
		if let Ok(content) = fs::read_to_string(path){
			Ok(toml::from_str(&content)?)
		} else {
			//Create default config if not found
			let config = Config::default();
			config.save(path)?;
			Ok(config)
		}
	}
	pub fn save(&self, path: &str) -> anyhow::Result<()>{
		let content = toml::to_string_pretty(self)?;
		fs::write(path, content)?;
		Ok(())
	}
}
