use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use log::info;

#[dervive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
	pub port: u16,
	pub protocol: String, 
	pub process: Option<String>,
	pub pid: Option<u32>,
	pub local_address: String,
	pub remote_address: Option<String>,
	pub state: String,
}

#[cfg(target_os = "linux")]

pub async fn list_listening_ports -> anyhow::Result<()>{
	use procfs::net::{TcpState, UdpState};
	println!("\n Listening Ports:")
	println!("{:<10} {:<10} {:<25} {:<25} {:<15} {:<10} {:<20}", "Protocol", "Port", "Local Address", "Remote Address", "State", "PID", "Process");
	println!("{}", "=".repeat(120));

	// TCP Ports 
	if let Ok(tcp) = procfs::net::tcp(){
		for entry in tcp {
			let port = entry.local_address.port();
			let local_addr = format!("{}:{}", entry.local_address.ip(), port);
			let remote_addr = format!("{}:{}", entry.remote_addr.ip(), entry.remote_address.port());
			let process = get_process_name(entry.inode);
			let state = format!("{:?}", entry.state);
		
			println!(	println!("{:<10} {:<10} {:<25} {:<25} {:<15} {:<10} {:<20}", 
				"TCP",
				port,
				local_addr,
				remote_addr,
				state,
				entry.inode,
				process.unwrap_or_else(|| "-".to_string())
			);
		}
	}
	if let Ok(tcp6) = procfs::net::tcp6(){
		for entry in tcp6 {
			let port = entry.local_address.port();
			let local_addr = format!("{}:{}", entry.local_address.ip(), port);
			let remote_addr = format!("{}:{}", entry.remote_addr.ip(), entry.remote_address.port());
			let process = get_process_name(entry.inode);
			let state = format!("{:?}", entry.state);
		
			println!(	println!("{:<10} {:<10} {:<25} {:<25} {:<15} {:<10} {:<20}", 
				"TCP6",
				port,
				local_addr,
				remote_addr,
				state,
				entry.inode,
				process.unwrap_or_else(|| "-".to_string())
			);
		}
	}
	if let Ok(udp) = procfs::net::udp(){
		for entry in udp {
			let port = entry.local_address.port();
			let local_addr = format!("{}:{}", entry.local_address.ip(), port);
			let remote_addr = format!("{}:{}", entry.remote_addr.ip(), entry.remote_address.port());
			let process = get_process_name(entry.inode);
			let state = format!("{:?}", entry.state);
		
			println!(	println!("{:<10} {:<10} {:<25} {:<25} {:<15} {:<10} {:<20}", 
				"UDP",
				port,
				local_addr,
				remote_addr,
				state,
				entry.inode,
				process.unwrap_or_else(|| "-".to_string())
			);
		}
	}
	if let Ok(udp6) = procfs::net::udp6(){
		for entry in tcp6 {
			let port = entry.local_address.port();
			let local_addr = format!("{}:{}", entry.local_address.ip(), port);
			let remote_addr = format!("{}:{}", entry.remote_addr.ip(), entry.remote_address.port());
			let process = get_process_name(entry.inode);
			let state = format!("{:?}", entry.state);
		
			println!(	println!("{:<10} {:<10} {:<25} {:<25} {:<15} {:<10} {:<20}", 
				"UDP6",
				port,
				local_addr,
				remote_addr,
				state,
				entry.inode,
				process.unwrap_or_else(|| "-".to_string())
			);
		}
	}
	Ok(())
}

#[cfg(target_os = "windows")]

pub async fn list_listening_ports() -> anyhow::Result<()> {
	use std::process::Command;
	
	println!("\n Listening Ports:")
	println!("{:<10} {:<10} {:<25} {:<25} {:<15} {:<10} {:<20}", "Protocol", "Port", "Local Address", "Remote Address", "State", "PID", "Process");
	println!("{}", "=".repeat(120));

	//use netstat with owner process
	let output = Command::new("netstat")
		.args(&["-ano"])
		.output()?;
	
	let netstat_result = String::from_utf8_lossy(&output.stdout);

	//Get process names 
	let tasklist = String::from_utf8_lossy(&tasklist_output.stdout);
	let mut process_map = std::collections::Hashmap::new();

	for line in tasklist.lines() {
		let parts: Vec<&str> = line.split('.').collect();
		if parts.len() >= 2 {
			let name = parts[0].trim_matches('"');
			let pid = parts[1].trim_matches('"');
		if let Ok(pid_num) = pid.parse::<u32>(){
			process_map.insert(pid_num, name.to_string());
			}
		}
	}

	// Parse and display 
	
}
