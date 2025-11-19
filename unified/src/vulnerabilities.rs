use std::process::Command;
use log::{info, warn};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub title: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
    pub cve_id: Option<String>,
}

// Detect Linux distribution
#[cfg(target_os = "linux")]
fn detect_distro() -> String {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if line.starts_with("ID=") {
                return line.replace("ID=", "").replace("\"", "").to_lowercase();
            }
        }
    }
    "unknown".to_string()
}

pub async fn scan_packages() -> anyhow::Result<()> {
    info!("🔍 Scanning for outdated packages...");
    
    #[cfg(target_os = "linux")]
    {
        let distro = detect_distro();
        println!("\n📦 Detected Linux Distribution: {}", distro);
        
        match distro.as_str() {
            "ubuntu" | "debian" | "linuxmint" | "pop" => {
                scan_apt_packages().await?;
            }
            "fedora" | "rhel" | "centos" | "rocky" | "almalinux" => {
                scan_dnf_packages().await?;
            }
            "arch" | "manjaro" | "endeavouros" => {
                scan_pacman_packages().await?;
            }
            "opensuse" | "suse" | "sles" => {
                scan_zypper_packages().await?;
            }
            "alpine" => {
                scan_apk_packages().await?;
            }
            "gentoo" => {
                scan_portage_packages().await?;
            }
            _ => {
                warn!("⚠️  Unknown distribution, trying common package managers...");
                // Try all package managers
                let _ = scan_apt_packages().await;
                let _ = scan_dnf_packages().await;
                let _ = scan_pacman_packages().await;
            }
        }
        
        // Check for security updates specifically
        check_security_updates(&distro).await?;
    }
    
    #[cfg(target_os = "windows")]
    {
        scan_windows_updates().await?;
        scan_windows_apps().await?;
        check_windows_defender().await?;
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
async fn scan_apt_packages() -> anyhow::Result<()> {
    if Command::new("apt").arg("--version").output().is_ok() {
        println!("\n📦 Checking APT packages...");
        
        // Update package list
        let _ = Command::new("apt").args(&["update", "-qq"]).output();
        
        // Check for upgradable packages
        let output = Command::new("apt")
            .args(&["list", "--upgradable"])
            .output()?;
        
        let result = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = result.lines().filter(|l| !l.starts_with("Listing")).collect();
        
        if !lines.is_empty() {
            println!("⚠️  {} packages can be upgraded:", lines.len());
            for line in lines.iter().take(15) {
                println!("  {}", line);
            }
            if lines.len() > 15 {
                println!("  ... and {} more", lines.len() - 15);
            }
        } else {
            println!("✅ All APT packages up to date!");
        }
        
        // Check for security updates
        let security_output = Command::new("apt")
            .args(&["list", "--upgradable"])
            .output()?;
        let security = String::from_utf8_lossy(&security_output.stdout);
        let security_count = security.lines()
            .filter(|l| l.contains("security") || l.contains("Security"))
            .count();
        
        if security_count > 0 {
            println!("🚨 {} SECURITY UPDATES AVAILABLE!", security_count);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn scan_dnf_packages() -> anyhow::Result<()> {
    if Command::new("dnf").arg("--version").output().is_ok() {
        println!("\n📦 Checking DNF/YUM packages...");
        
        let output = Command::new("dnf")
            .args(&["check-update", "--quiet"])
            .output()?;
        
        let result = String::from_utf8_lossy(&output.stdout);
        if !result.is_empty() {
            let lines: Vec<&str> = result.lines().collect();
            println!("⚠️  {} updates available:", lines.len());
            for line in lines.iter().take(15) {
                println!("  {}", line);
            }
            if lines.len() > 15 {
                println!("  ... and {} more", lines.len() - 15);
            }
        } else {
            println!("✅ All DNF packages up to date!");
        }
        
        // Check for security updates
        let security_output = Command::new("dnf")
            .args(&["updateinfo", "list", "security"])
            .output()?;
        let security = String::from_utf8_lossy(&security_output.stdout);
        let security_count = security.lines().count();
        
        if security_count > 0 {
            println!("🚨 {} SECURITY UPDATES AVAILABLE!", security_count);
        }
    } else if Command::new("yum").arg("--version").output().is_ok() {
        println!("\n📦 Checking YUM packages...");
        let output = Command::new("yum")
            .args(&["check-update", "--quiet"])
            .output()?;
        
        let result = String::from_utf8_lossy(&output.stdout);
        if !result.is_empty() {
            println!("⚠️  Updates available:\n{}", result);
        } else {
            println!("✅ All YUM packages up to date!");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn scan_pacman_packages() -> anyhow::Result<()> {
    if Command::new("pacman").arg("--version").output().is_ok() {
        println!("\n📦 Checking Pacman packages...");
        
        // Update package database
        let _ = Command::new("pacman").args(&["-Sy"]).output();
        
        let output = Command::new("pacman")
            .args(&["-Qu"])
            .output()?;
        
        let result = String::from_utf8_lossy(&output.stdout);
        if !result.is_empty() {
            let lines: Vec<&str> = result.lines().collect();
            println!("⚠️  {} packages can be upgraded:", lines.len());
            for line in lines.iter().take(15) {
                println!("  {}", line);
            }
            if lines.len() > 15 {
                println!("  ... and {} more", lines.len() - 15);
            }
        } else {
            println!("✅ All Pacman packages up to date!");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn scan_zypper_packages() -> anyhow::Result<()> {
    if Command::new("zypper").arg("--version").output().is_ok() {
        println!("\n📦 Checking Zypper packages...");
        
        let output = Command::new("zypper")
            .args(&["list-updates"])
            .output()?;
        
        let result = String::from_utf8_lossy(&output.stdout);
        if !result.is_empty() {
            println!("⚠️  Updates available:\n{}", result);
        } else {
            println!("✅ All Zypper packages up to date!");
        }
        
        // Check patches
        let patches = Command::new("zypper")
            .args(&["list-patches"])
            .output()?;
        let patches_result = String::from_utf8_lossy(&patches.stdout);
        if patches_result.contains("security") {
            println!("🚨 SECURITY PATCHES AVAILABLE!");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn scan_apk_packages() -> anyhow::Result<()> {
    if Command::new("apk").arg("--version").output().is_ok() {
        println!("\n📦 Checking APK packages (Alpine)...");
        
        let output = Command::new("apk")
            .args(&["version", "-l", "<"])
            .output()?;
        
        let result = String::from_utf8_lossy(&output.stdout);
        if !result.is_empty() {
            println!("⚠️  Updates available:\n{}", result);
        } else {
            println!("✅ All APK packages up to date!");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn scan_portage_packages() -> anyhow::Result<()> {
    if Command::new("emerge").arg("--version").output().is_ok() {
        println!("\n📦 Checking Portage packages (Gentoo)...");
        
        let output = Command::new("emerge")
            .args(&["-uDNp", "@world"])
            .output()?;
        
        let result = String::from_utf8_lossy(&output.stdout);
        if result.contains("Total:") {
            println!("⚠️  Updates available:\n{}", result);
        } else {
            println!("✅ All Portage packages up to date!");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn check_security_updates(distro: &str) -> anyhow::Result<()> {
    println!("\n🔒 Checking for security-specific updates...");
    
    match distro {
        "ubuntu" | "debian" => {
            let output = Command::new("apt")
                .args(&["list", "--upgradable"])
                .output()?;
            let result = String::from_utf8_lossy(&output.stdout);
            let security: Vec<&str> = result.lines()
                .filter(|l| l.contains("security") || l.contains("-security"))
                .collect();
            
            if !security.is_empty() {
                println!("🚨 {} security updates found:", security.len());
                for update in security.iter().take(10) {
                    println!("  {}", update);
                }
            }
        }
        "fedora" | "rhel" | "centos" => {
            let output = Command::new("dnf")
                .args(&["updateinfo", "list", "security", "--available"])
                .output()?;
            let result = String::from_utf8_lossy(&output.stdout);
            if !result.is_empty() {
                println!("🚨 Security updates:\n{}", result);
            }
        }
        _ => {}
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
async fn scan_windows_updates() -> anyhow::Result<()> {
    println!("\n📦 Checking Windows Updates...");
    
    // Using PowerShell to check Windows Updates
    let ps_script = r#"
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $Updates = $Searcher.Search("IsInstalled=0 and Type='Software'")
        
        if ($Updates.Updates.Count -eq 0) {
            Write-Host "✅ No updates available"
        } else {
            Write-Host "⚠️  $($Updates.Updates.Count) updates available:"
            foreach ($Update in $Updates.Updates) {
                $severity = if ($Update.MsrcSeverity) { $Update.MsrcSeverity } else { "Normal" }
                Write-Host "  [$severity] $($Update.Title)"
            }
        }
    "#;
    
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-Command", ps_script])
        .output();
    
    if let Ok(output) = output {
        let result = String::from_utf8_lossy(&output.stdout);
        println!("{}", result);
        
        let error = String::from_utf8_lossy(&output.stderr);
        if !error.is_empty() {
            println!("ℹ️  Note: Run as Administrator for full update checking");
        }
    } else {
        println!("ℹ️  Run 'Get-WindowsUpdate' in PowerShell (as Admin) to check for updates");
        println!("   Or use Windows Update in Settings");
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
async fn scan_windows_apps() -> anyhow::Result<()> {
    println!("\n📦 Checking installed applications...");
    
    let ps_script = r#"
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Where-Object {$_.DisplayName -ne $null} |
        Sort-Object DisplayName |
        Format-Table -AutoSize
    "#;
    
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-Command", ps_script])
        .output()?;
    
    let result = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = result.lines().collect();
    
    if lines.len() > 3 {
        println!("Found {} installed applications", lines.len() - 3);
        println!("Checking for known vulnerable versions...");
        
        // Check for outdated/vulnerable software
        check_vulnerable_windows_apps(&result).await?;
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
async fn check_vulnerable_windows_apps(apps: &str) -> anyhow::Result<()> {
    let vulnerable_patterns = vec![
        ("Java", vec!["1.8.0_", "1.7.0_"]),
        ("Adobe Reader", vec!["10.", "11.", "DC 15."]),
        ("Flash Player", vec![""]), // Flash is always vulnerable now
        ("Python", vec!["2.7", "3.6", "3.7"]),
        ("OpenSSL", vec!["1.0.1", "1.0.2"]),
    ];
    
    println!("\n🔍 Scanning for known vulnerable applications...");
    
    for (app_name, vulnerable_versions) in vulnerable_patterns {
        if apps.contains(app_name) {
            for version in vulnerable_versions {
                if apps.contains(version) || version.is_empty() {
                    println!("⚠️  Found potentially vulnerable: {} (contains {})", app_name, 
                             if version.is_empty() { "EOL software" } else { version });
                }
            }
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
async fn check_windows_defender() -> anyhow::Result<()> {
    println!("\n🛡️  Checking Windows Defender status...");
    
    let ps_script = r#"
        $status = Get-MpComputerStatus
        Write-Host "Real-time Protection: $($status.RealTimeProtectionEnabled)"
        Write-Host "Anti-virus Enabled: $($status.AntivirusEnabled)"
        Write-Host "Anti-spyware Enabled: $($status.AntispywareEnabled)"
        Write-Host "Last Quick Scan: $($status.QuickScanEndTime)"
        Write-Host "Last Full Scan: $($status.FullScanEndTime)"
        Write-Host "Signature Version: $($status.AntivirusSignatureVersion)"
        Write-Host "Signature Last Updated: $($status.AntivirusSignatureLastUpdated)"
    "#;
    
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-Command", ps_script])
        .output()?;
    
    let result = String::from_utf8_lossy(&output.stdout);
    println!("{}", result);
    
    if result.contains("False") {
        println!("🚨 WARNING: Windows Defender protection is partially disabled!");
    }
    
    Ok(())
}

pub async fn scan_permissions() -> anyhow::Result<()> {
    info!("🔍 Scanning for weak file permissions...");
    
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        use std::fs;
        
        let sensitive_paths = vec![
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ssh/sshd_config",
            "/etc/sudoers",
            "/root/.ssh/authorized_keys",
            "/etc/crontab",
            "/etc/hosts.allow",
            "/etc/hosts.deny",
        ];
        
        println!("\n🔐 Checking sensitive file permissions:");
        
        for path in &sensitive_paths {
            if let Ok(metadata) = fs::metadata(path) {
                let permissions = metadata.permissions();
                let mode = permissions.mode();
                let perms = mode & 0o777;
                
                println!("  {} - {:o}", path, perms);
                
                // Check for world-readable/writable
                if mode & 0o007 != 0 {
                    println!("    🚨 WARNING: File has world permissions!");
                }
                
                // Check specific security issues
                if path.contains("shadow") && perms != 0o640 && perms != 0o600 {
                    println!("    🚨 WARNING: /etc/shadow should be 640 or 600!");
                }
                
                if path.contains("ssh") && (mode & 0o022) != 0 {
                    println!("    🚨 WARNING: SSH config should not be group/world writable!");
                }
            }
        }
        
        // Check for world-writable directories
        println!("\n🔍 Checking for world-writable directories...");
        let check_dirs = vec!["/tmp", "/var/tmp", "/dev/shm"];
        for dir in check_dirs {
            if let Ok(metadata) = fs::metadata(dir) {
                let mode = metadata.permissions().mode();
                if (mode & 0o002) != 0 && (mode & 0o1000) == 0 {
                    println!("  ⚠️  {} is world-writable without sticky bit!", dir);
                }
            }
        }
        
        // Check SUID/SGID binaries
        check_suid_binaries().await?;
    }
    
    #[cfg(target_os = "windows")]
    {
        println!("\n🔐 Checking Windows permissions and security settings...");
        
        // Check system file permissions
        check_windows_permissions().await?;
        
        // Check registry permissions
        check_registry_permissions().await?;
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
async fn check_suid_binaries() -> anyhow::Result<()> {
    println!("\n🔍 Checking SUID/SGID binaries...");
    
    let output = Command::new("find")
        .args(&["/", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-ls", "2>/dev/null"])
        .output();
    
    if let Ok(output) = output {
        let result = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = result.lines().collect();
        
        if !lines.is_empty() {
            println!("Found {} SUID/SGID binaries:", lines.len());
            
            // Show first 20
            for line in lines.iter().take(20) {
                println!("  {}", line);
            }
            
            if lines.len() > 20 {
                println!("  ... and {} more", lines.len() - 20);
            }
            
            println!("\n⚠️  Review these binaries for potential privilege escalation");
        }
    }
    
    Ok(())
}

#[cfg(target_os = "windows")]
async fn check_windows_permissions() -> anyhow::Result<()> {
    let ps_script = r#"
        # Check key system directories
        $paths = @(
            "C:\Windows\System32",
            "C:\Program Files",
            "C:\Users"
        )
        
        foreach ($path in $paths) {
            $acl = Get-Acl $path
            Write-Host "Permissions for $path"
            $acl.Access | Where-Object {$_.IdentityReference -like "*Users*"} | Format-Table
        }
    "#;
    
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-Command", ps_script])
        .output()?;
    
    let result = String::from_utf8_lossy(&output.stdout);
    println!("{}", result);
    
    Ok(())
}

#[cfg(target_os = "windows")]
async fn check_registry_permissions() -> anyhow::Result<()> {
    println!("\n🔍 Checking registry autorun locations...");
    
    let ps_script = r#"
        $runKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($key in $runKeys) {
            if (Test-Path $key) {
                Write-Host "`n$key"
                Get-ItemProperty $key | Format-List
            }
        }
    "#;
    
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-Command", ps_script])
        .output()?;
    
    let result = String::from_utf8_lossy(&output.stdout);
    if !result.is_empty() {
        println!("{}", result);
        println!("\n⚠️  Review autorun entries for suspicious programs");
    }
    
    Ok(())
}

pub async fn get_vulnerabilities() -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    
    // This would be expanded with actual real-time vulnerability checks
    // For demonstration, we'll add common vulnerability categories
    
    vulns.push(Vulnerability {
        title: "Outdated System Packages".to_string(),
        severity: "High".to_string(),
        description: "System packages are not up to date, potentially exposing to known vulnerabilities".to_string(),
        remediation: "Run system update commands for your distribution".to_string(),
        cve_id: None,
    });
    
    #[cfg(target_os = "linux")]
    {
        // Check for common Linux vulnerabilities
        if std::path::Path::new("/etc/shadow").exists() {
            if let Ok(metadata) = std::fs::metadata("/etc/shadow") {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                if (mode & 0o777) != 0o640 && (mode & 0o777) != 0o600 {
                    vulns.push(Vulnerability {
                        title: "Weak /etc/shadow Permissions".to_string(),
                        severity: "Critical".to_string(),
                        description: format!("/etc/shadow has permissions {:o}, should be 640 or 600", mode & 0o777),
                        remediation: "Run: sudo chmod 640 /etc/shadow".to_string(),
                        cve_id: None,
                    });
                }
            }
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        // Check Windows-specific vulnerabilities
        vulns.push(Vulnerability {
            title: "Windows Security Updates".to_string(),
            severity: "High".to_string(),
            description: "Check for pending Windows security updates".to_string(),
            remediation: "Run Windows Update or use PowerShell: Get-WindowsUpdate".to_string(),
            cve_id: None,
        });
    }
    
    vulns
}