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
	}
}