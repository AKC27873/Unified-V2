// API Configuration 
const API_BASE = '';

// Utility fuction to fetch data from API 
async function fetchData(endpoint){
	try{
		const response = await fetch(`${API_BASE}${endpoint}`);
		return await response.json();
	} catch (error){
		console.error(`Error fetching ${endpoint}:`, error);
		return null;
	}
}

// Format uptime in human readable format

function formatUptime(seconds){
	const days = Math.floor(seconds/86400);
	const hours = Math.floor((seconds % 86400) / 3600);
	const minutes = Math.floor((seconds % 3600) / 60);
	return `${days}d ${hours}h ${minutes}m`;
}

// Update system statistics
async function updateSystemStats(){
	const data = await fetchData('/api/system');
	if (data) {
		document.getElementById('cpuCount').textContent = data.cpu_count;
		document.getElementById('memoryUsage').textContent = 
		`${(data.used_memory / 1024 / 1024 / 1024).toFixed(2)}GB / ${(data.total_memory / 1024 / 1024 / 1024).toFixed(2)} GB`;
		document.getElementById('uptime').textContent = formatUptime(date.uptime);
		document.getElementById('memoryBar').style.width = `${data.memory_percent}%`;
	}
}

// Update alerts Display 

async function updateAlerts(){
	const alerts = await fetchData('/api/alerts');
	if (alerts) {
		const container = document.getElementById('alerts');

		if (alerts.length === 0) {
			container.innerHTML = '<div class="no-data"> No alerts to display</div>';
			return;
		}
	// Count by level 
		const counts = {Info: 0, Warning: 0, Critical: 0};
		alerts.forEach(a => counts[a.level]++);

		document.getElementById('criticalCount').textContent = counts.Critical;
		document.getElementById('warningCount').textContent = counts.Warning;
		document.getElementById('infoCount').textContent = counts.Info;

		// Show recent alerts (last 10, reversed)

		container.innerHTML = alerts.slice(-10).reverse().map(alert => `
			<div class="alert ${alert.level.toLowerCase()}">
			<div class="alert-header">
			<span class="alert-title">${escapeHtml(alert.title)}</span>
			<span class="alert-time">${new Date(alert.timestamp).toLocalestring()}</span>
			</div>
			<div class="alert-message">${escapeHtml(alert.message)}</div>
			</div>
		`).join('');
	}
}

// Update ports display

async function updatePorts(){
	const ports = await fetchData('/api/ports');
	if (ports) {
		const container = document.getElementById('ports');
		
		if (ports.length === 0){
			container.innerHTML = '<div class="no-data">No listening ports detected</div>';
			return;	
		}
		 container.innerHTML = `
            <table>
                <thead>
                    <tr>
                        <th>Protocol</th>
                        <th>Port</th>
                        <th>Address</th>
                        <th>State</th>
                        <th>Process</th>
                    </tr>
                </thead>
                <tbody>
                    ${ports.map(port => `
                        <tr>
                            <td><span class="badge ${port.protocol.toLowerCase()}">${escapeHtml(port.protocol)}</span></td>
                            <td>${port.port}</td>
                            <td>${escapeHtml(port.local_address)}</td>
                            <td>${escapeHtml(port.state)}</td>
                            <td>${escapeHtml(port.process || '-')}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
	}
}

// Update vulnerabilities display 
async function updateVulnerabilities() {
	const vulns = await fetchData('/api/vulnerabilities')
	if (vulns){
		const container = document.getElementById('vulnerabilities');

		   if (vulns.length === 0) {
            container.innerHTML = '<div class="no-data">No vulnerabilities detected</div>';
            return;
        }

        container.innerHTML = vulns.map(vuln => `
            <div class="alert ${vuln.severity.toLowerCase()}">
                <div class="alert-header">
                    <span class="alert-title">${escapeHtml(vuln.title)}</span>
                    <span class="badge">${escapeHtml(vuln.severity)}</span>
                </div>
                <div class="alert-message">${escapeHtml(vuln.description)}</div>
                <div style="margin-top: 10px; color: #a0a0a0; font-size: 0.9em">
                    💡 ${escapeHtml(vuln.remediation)}
                </div>
            </div>
        `).join('');
    }
}

async function clearAlerts() {
	try {
		await fetch(`${API_BASE}/api/alerts/clear`, {method: 'POST'});
		updateAlerts();
	} catch (error) {
		console.error('Error clearing alerts:', error);
	}
}

// Escape HTML to prevent XSS

function escapeHtml(text){
	const div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}

// Initialize the Dashboard 
function initializeDashboard(){
	console.log('Unified Security Monitor Dashboard Started');
	
	// Intial Load 
	updateSystemStats();
	updateAlerts();
	updatePorts();
	updateVulnerabilities();

	// Auto-refresh systems stats and alerts every 5 seconds 
	setInterval (() => {
		updateSystemStats();
		updateAlerts();		
	}, 5000);
	// Refresh ports and vulnerabilities every 30 seconds
	setInterval (() => {
		updatePorts();
		updateVulnerabilities();		
	}, 30000);
}

// Start when DOM is ready 
if (document.readyState === 'loading'){
	document.addEventListener('DOMContentLoaded', initializeDashboard);
} else{
	initializeDashboard();
}