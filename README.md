# Unified Rust Security Monitor 

A comprohensive, cross-platform security monitoring tool written in the Rust programming version 2 [https://github.com/AKC27873/unified](unified) tool that I have made earlier in the year of 2025. 


## Features 

### 1. Cross-Platform Support 
* Linux: Ubuntu, Debian, Fedora, RHEL, CentOS, Arch, Manjaro, openSUSE, Alpine, Gentoo
* Windows: Windows10,11,Server 2016+ 
* Automatic distribution detection 
* Native Package manager intergation 


### 2. Core Monitoing
* Process Monitoring: 
	* Real-time process tracking with CPU/memory alerts
* Log Analysis: 
	* Pattern-based log monitoring with customizable rules
* Network Monitoring:
	* All listening ports (TCP/UDP, IPv4/IPv6)
	* Process-to-port mapping
	* Firewall status checking
	* Exposed port detection

* Vulnerability Scanning:
	* Outdated packages (all major package managers)
	* Security updates detection
	* File permission issues
	* SUID/SGID binaries (Linux)
	* Registry autorun analysis (Windows)
	* Windows Defender status
	* Known vulnerable applications

### 3. Package Manager Support
 * Linux 
 	* APT(Debian/Ubuntu): `apt`,security updates  
 	* DNF/YUM (Fedora/RHEL): `dnf`, `yum`, security advisories
 	* Pacman(Arch):`pacman`
 	* Zypper(OpenSUSE): `zypper`,security patches
 	* APK(Alpine):`apk`
 	* Portage(Gentoo):`emerge`
 * Windows
 	* Windows Update intergration
 	* Installed application
 	* Windows Defender monitoring
 	* Known vulnerable software detection
### 4. Web Interface 
 * Real-time dashboard with auto-refresh
 * System metrics (CPU, Memory, Uptime)
 * Alert management and filtering
 * Network port visualization
 * Vulnerability scanner results

### 5. Plugin System 
* **Threat Hunting:** Memory scanning, persistence detection
* **Anomaly Detection:** Baseline behavior monitoring
* **Threat Intelligence:** IOC matching
* **Auto-Remediation:** Automated threat response