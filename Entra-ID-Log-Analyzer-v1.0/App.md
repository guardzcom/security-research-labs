-- Here is the existing canvas app code I want to edit:

```html type=html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Entra ID Log Analyzer</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
tailwind.config = {
darkMode: 'class',
theme: {
extend: {
colors: {
primary: '#5D5CDE',
'primary-dark': '#4B4BC7'
}
}
}
}
</script>
<style>
.loading-spinner {
border: 3px solid #f3f4f6;
border-top: 3px solid #5D5CDE;
border-radius: 50%;
width: 20px;
height: 20px;
animation: spin 1s linear infinite;
}
@keyframes spin {
0% { transform: rotate(0deg); }
100% { transform: rotate(360deg); }
}
.correlation-tab {
color: #6B7280;
border-color: transparent;
border-bottom-width: 2px;
transition: all 0.2s;
}
.correlation-tab:hover {
color: #374151;
border-color: #D1D5DB;
}
.correlation-tab-active {
color: #5D5CDE;
border-color: #5D5CDE;
border-bottom-width: 2px;
}
.dark .correlation-tab {
color: #9CA3AF;
}
.dark .correlation-tab:hover {
color: #D1D5DB;
border-color: #4B5563;
}
.dark .correlation-tab-active {
color: #A855F7;
border-color: #A855F7;
}
</style>
</head>
<body class="bg-white dark:bg-gray-900 min-h-screen">
<!-- Dark mode detection -->
<script>
if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
document.documentElement.classList.add('dark');
}
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', event => {
if (event.matches) {
document.documentElement.classList.add('dark');
} else {
document.documentElement.classList.remove('dark');
}
});
</script>

<div class="container mx-auto px-4 py-6 max-w-7xl">
<!-- Header -->
<div class="mb-8">
<h1 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">Entra ID Log Analyzer</h1>
<p class="text-gray-600 dark:text-gray-400">Upload and analyze Azure AD/Entra ID authentication and audit logs</p>
</div>

<!-- How to Download Logs -->
<div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-8 mb-8">
<h2 class="text-xl font-semibold text-blue-900 dark:text-blue-100 mb-4">
How to Download Entra ID Sign-in Logs
</h2>
<div class="space-y-4 text-sm text-blue-800 dark:text-blue-200">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
<div>
<h3 class="font-semibold mb-3 text-base">Via Microsoft Entra Admin Center (Interactive)</h3>
<ol class="list-decimal list-inside space-y-2 text-sm leading-relaxed">
<li>Navigate to <strong>https://entra.microsoft.com</strong></li>
<li>Go to <strong>Users</strong> from the left navigation menu</li>
<li>Select <strong>Sign-in logs</strong> from the Users section</li>
<li>Set date range using <strong>"Date: Last 7 days"</strong> dropdown (adjust as needed)</li>
<li>Apply additional filters for users, applications, or status if required</li>
<li>Click <strong>"Download"</strong> button in the top toolbar</li>
<li>Select <strong>"JSON"</strong> format from the download options</li>
<li>Choose your preferred date range (maximum 250,000 records per download)</li>
<li>Confirm download and wait for file generation</li>
</ol>
</div>
<div>
<h3 class="font-semibold mb-3 text-base">Via PowerShell (Automated)</h3>
<div class="bg-blue-100 dark:bg-blue-800/30 rounded-lg p-4 font-mono text-sm">
<div class="text-blue-900 dark:text-blue-100 space-y-1">
<div># Install required module</div>
<div>Install-Module Microsoft.Graph</div>
<div class="h-2"></div>
<div># Connect with required permissions</div>
<div>Connect-MgGraph -Scopes "AuditLog.Read.All"</div>
<div class="h-2"></div>
<div># Export sign-in logs to JSON</div>
<div>Get-MgAuditLogSignIn -All | ConvertTo-Json -Depth 10</div>
<div class="h-2"></div>
<div># Save to file</div>
<div>Get-MgAuditLogSignIn -All | ConvertTo-Json -Depth 10 | Out-File "signin-logs.json"</div>
</div>
</div>
</div>
</div>
<div class="bg-blue-100 dark:bg-blue-800/30 rounded-lg p-4 mt-6">
<div class="grid grid-cols-1 lg:grid-cols-3 gap-4 text-sm">
<div>
<h4 class="font-semibold text-blue-900 dark:text-blue-100 mb-1">Recommended Timeframe</h4>
<p>Download 7-30 days of logs for comprehensive security analysis and pattern detection.</p>
</div>
<div>
<h4 class="font-semibold text-blue-900 dark:text-blue-100 mb-1">Performance Notes</h4>
<p>Large datasets over 50MB may require longer processing times. Consider filtering by specific users or applications.</p>
</div>
<div>
<h4 class="font-semibold text-blue-900 dark:text-blue-100 mb-1">Data Quality</h4>
<p>Include both interactive and non-interactive sign-ins for complete threat visibility and behavioral analysis.</p>
</div>
</div>
</div>
</div>
</div>

<!-- Input Section -->
<div class="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 mb-8">
<h2 class="text-xl font-semibold text-gray-900 dark:text-white mb-4">Log Data Input</h2>

<div class="mb-4">
<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
Upload JSON Log File
</label>
<input type="file" id="fileInput" accept=".json,.txt"
class="block w-full text-base border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary focus:border-transparent">
</div>

<div class="mb-4">
<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
Or Paste Log Data (JSON format)
</label>
<textarea id="logInput" rows="8" placeholder="Paste your Entra ID logs here in JSON format..."
class="w-full text-base border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-primary focus:border-transparent"></textarea>
</div>

<div class="flex flex-wrap gap-3">
<button onclick="analyzeLogs()"
class="px-6 py-2 bg-primary hover:bg-primary-dark text-white rounded-md font-medium transition-colors focus:ring-2 focus:ring-primary focus:ring-offset-2">
Analyze Logs
</button>
<button onclick="loadSampleData()"
class="px-6 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-md font-medium transition-colors">
Load Sample Data
</button>
<button onclick="clearData()"
class="px-6 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md font-medium transition-colors">
Clear
</button>
</div>
</div>

<!-- Analysis Results -->
<div id="analysisResults" class="hidden">
<!-- Summary Cards -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
<h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Total Events</h3>
<p id="totalEvents" class="text-2xl font-bold text-gray-900 dark:text-white">0</p>
</div>
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
<h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Successful Sign-ins</h3>
<p id="successfulSignins" class="text-2xl font-bold text-green-600">0</p>
</div>
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
<h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Failed Sign-ins</h3>
<p id="failedSignins" class="text-2xl font-bold text-red-600">0</p>
</div>
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
<h3 class="text-sm font-medium text-gray-500 dark:text-gray-400">Unique Users</h3>
<p id="uniqueUsers" class="text-2xl font-bold text-blue-600">0</p>
</div>
</div>

<!-- Charts -->
<div class="space-y-8 mb-8">
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
<h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Activity Timeline</h3>
<div class="h-64">
<canvas id="timelineChart"></canvas>
</div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
<h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Sign-in Status Distribution</h3>
<p class="text-sm text-gray-600 dark:text-gray-400 mb-4">Click segments for detailed breakdown</p>
<div class="h-64">
<canvas id="statusChart" class="cursor-pointer"></canvas>
</div>
</div>
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
<h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Privileged Actions Analysis</h3>
<p class="text-sm text-gray-600 dark:text-gray-400 mb-4">Administrative and high-privilege activities</p>
<div class="h-64">
<canvas id="privilegedChart" class="cursor-pointer"></canvas>
</div>
</div>
</div>
</div>

<!-- Tables -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
<h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Top Users by Activity</h3>
<div id="topUsers" class="overflow-x-auto">
<table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
<thead class="bg-gray-50 dark:bg-gray-700">
<tr>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">User</th>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Events</th>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Success Rate</th>
</tr>
</thead>
<tbody id="topUsersBody" class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
</tbody>
</table>
</div>
</div>
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
<h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Top Applications</h3>
<div id="topApps" class="overflow-x-auto">
<table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
<thead class="bg-gray-50 dark:bg-gray-700">
<tr>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Application</th>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Events</th>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Success Rate</th>
</tr>
</thead>
<tbody id="topAppsBody" class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
</tbody>
</table>
</div>
</div>
</div>

<!-- User Behavior Deviation Analysis -->
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 mb-8">
<h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">User Behavior Deviation Analysis</h3>

<!-- Deviation Charts Grid -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3 flex items-center">
<span class="mr-2">🌐</span>
IP Address Deviations
</h4>
<div class="h-48">
<canvas id="ipDeviationChart" class="cursor-pointer"></canvas>
</div>
<p class="text-xs text-gray-600 dark:text-gray-400 mt-2 text-center">Click bars for details</p>
</div>

<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3 flex items-center">
<span class="mr-2">⏰</span>
Time Pattern Deviations
</h4>
<div class="h-48">
<canvas id="timeDeviationChart" class="cursor-pointer"></canvas>
</div>
<p class="text-xs text-gray-600 dark:text-gray-400 mt-2 text-center">Click points for details</p>
</div>

<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3 flex items-center">
<span class="mr-2">📱</span>
Application Deviations
</h4>
<div class="h-48">
<canvas id="appDeviationChart" class="cursor-pointer"></canvas>
</div>
<p class="text-xs text-gray-600 dark:text-gray-400 mt-2 text-center">Click segments for details</p>
</div>
</div>

<!-- Geographic & Device Deviations (Text) -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3 flex items-center">
<span class="mr-2">📍</span>
Geographic Deviations
</h4>
<div id="geoDeviations" class="space-y-2 max-h-40 overflow-y-auto">
</div>
</div>

<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3 flex items-center">
<span class="mr-2">💻</span>
Device Deviations
</h4>
<div id="deviceDeviations" class="space-y-2 max-h-40 overflow-y-auto">
</div>
</div>
</div>

<!-- Deviation Summary -->
<div id="deviationSummary" class="p-4 bg-gray-50 dark:bg-gray-700 rounded-md">
</div>
</div>

<!-- Deviation Details Modal -->
<div id="deviationModal" class="hidden fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
<div class="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg max-w-2xl w-full mx-4 max-h-96 overflow-y-auto">
<div class="flex justify-between items-start mb-4">
<h3 id="modalTitle" class="text-lg font-semibold text-gray-900 dark:text-white"></h3>
<button onclick="closeDeviationModal()" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
</svg>
</button>
</div>
<div id="modalContent" class="text-gray-700 dark:text-gray-300">
</div>
</div>
</div>

<!-- Correlation Analysis -->
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 mb-8">
<h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Advanced Correlation Analysis</h3>

<!-- Correlation Summary Cards -->
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
<div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
<h4 class="text-sm font-medium text-red-800 dark:text-red-200 mb-2">Critical Threats</h4>
<p id="criticalThreats" class="text-2xl font-bold text-red-600 dark:text-red-400">0</p>
<p class="text-xs text-red-700 dark:text-red-300">Multi-vector attacks</p>
</div>
<div class="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg p-4">
<h4 class="text-sm font-medium text-orange-800 dark:text-orange-200 mb-2">Suspicious Activity</h4>
<p id="suspiciousActivity" class="text-2xl font-bold text-orange-600 dark:text-orange-400">0</p>
<p class="text-xs text-orange-700 dark:text-orange-300">Anomalous patterns</p>
</div>
<div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
<h4 class="text-sm font-medium text-blue-800 dark:text-blue-200 mb-2">Impossible Travel</h4>
<p id="impossibleTravel" class="text-2xl font-bold text-blue-600 dark:text-blue-400">0</p>
<p class="text-xs text-blue-700 dark:text-blue-300">Geographic anomalies</p>
</div>
<div class="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4">
<h4 class="text-sm font-medium text-purple-800 dark:text-purple-200 mb-2">Correlation Score</h4>
<p id="correlationScore" class="text-2xl font-bold text-purple-600 dark:text-purple-400">0</p>
<p class="text-xs text-purple-700 dark:text-purple-300">Risk multiplier</p>
</div>
</div>

<!-- Correlation Insights Tabs -->
<div class="mb-4">
<div class="border-b border-gray-200 dark:border-gray-700">
<nav class="flex space-x-8">
<button onclick="showCorrelationTab('temporal')" id="temporalTab" class="correlation-tab-active py-2 px-1 border-b-2 font-medium text-sm">
Temporal Patterns
</button>
<button onclick="showCorrelationTab('geographic')" id="geographicTab" class="correlation-tab py-2 px-1 border-b-2 font-medium text-sm">
Geographic Anomalies
</button>
<button onclick="showCorrelationTab('infrastructure')" id="infrastructureTab" class="correlation-tab py-2 px-1 border-b-2 font-medium text-sm">
Infrastructure Sharing
</button>
<button onclick="showCorrelationTab('behavioral')" id="behavioralTab" class="correlation-tab py-2 px-1 border-b-2 font-medium text-sm">
Behavioral Clustering
</button>
</nav>
</div>
</div>

<!-- Correlation Content Panels -->
<div id="temporalPanel" class="correlation-panel">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Rapid Authentication Sequences</h4>
<div id="rapidSequences" class="space-y-2 max-h-48 overflow-y-auto"></div>
</div>
<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Failed-to-Success Patterns</h4>
<div id="failedSuccessPatterns" class="space-y-2 max-h-48 overflow-y-auto"></div>
</div>
</div>
<div class="mt-4 bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Authentication Velocity Analysis</h4>
<div class="h-64">
<canvas id="velocityChart"></canvas>
</div>
</div>
</div>

<div id="geographicPanel" class="correlation-panel hidden">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Impossible Travel Incidents</h4>
<div id="impossibleTravelList" class="space-y-2 max-h-48 overflow-y-auto"></div>
</div>
<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Geographic Velocity Heatmap</h4>
<div id="geoVelocityMap" class="space-y-2 max-h-48 overflow-y-auto"></div>
</div>
</div>
<div class="mt-4 bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Country Transition Analysis</h4>
<div id="countryTransitions" class="space-y-2"></div>
</div>
</div>

<div id="infrastructurePanel" class="correlation-panel hidden">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Shared IP Addresses</h4>
<div id="sharedIPs" class="space-y-2 max-h-48 overflow-y-auto"></div>
</div>
<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Device Fingerprint Overlap</h4>
<div id="deviceOverlap" class="space-y-2 max-h-48 overflow-y-auto"></div>
</div>
</div>
<div class="mt-4 bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Infrastructure Risk Analysis</h4>
<div class="h-64">
<canvas id="infrastructureChart"></canvas>
</div>
</div>
</div>

<div id="behavioralPanel" class="correlation-panel hidden">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Behavioral Clusters</h4>
<div id="behavioralClusters" class="space-y-2 max-h-48 overflow-y-auto"></div>
</div>
<div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Privilege Escalation Patterns</h4>
<div id="privilegeEscalation" class="space-y-2 max-h-48 overflow-y-auto"></div>
</div>
</div>
<div class="mt-4 bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-3">Behavioral DNA Matching</h4>
<div class="h-64">
<canvas id="behavioralChart"></canvas>
</div>
</div>
</div>
</div>

<!-- Risk Analysis -->
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6 mb-8">
<h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Risk Analysis & Anomalies</h3>
<div id="riskAnalysis" class="space-y-4">
</div>
</div>

<!-- Detailed Logs -->
<div class="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
<h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recent Log Entries</h3>
<div class="overflow-x-auto">
<table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
<thead class="bg-gray-50 dark:bg-gray-700">
<tr>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Timestamp</th>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">User</th>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Application</th>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Status</th>
<th class="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Location</th>
</tr>
</thead>
<tbody id="detailedLogs" class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
</tbody>
</table>
</div>
</div>
</div>

<!-- Loading State -->
<div id="loadingState" class="hidden text-center py-8">
<div class="loading-spinner mx-auto mb-4"></div>
<p class="text-gray-600 dark:text-gray-400">Analyzing logs...</p>
</div>

<!-- Error State -->
<div id="errorState" class="hidden bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-4">
<div class="flex">
<div class="text-red-400">
<svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
</svg>
</div>
<div class="ml-3">
<h3 class="text-sm font-medium text-red-800 dark:text-red-200">Error</h3>
<div class="mt-2 text-sm text-red-700 dark:text-red-300">
<p id="errorMessage">An error occurred while analyzing the logs.</p>
</div>
</div>
</div>
</div>
</div>

<script>
let logData = [];
let statusChart, timelineChart, ipDeviationChart, timeDeviationChart, appDeviationChart;
let userProfiles = {};

// File input handler
document.getElementById('fileInput').addEventListener('change', function(event) {
const file = event.target.files[0];
if (file) {
const reader = new FileReader();
reader.onload = function(e) {
document.getElementById('logInput').value = e.target.result;
};
reader.readAsText(file);
}
});

function loadSampleData() {
const sampleData = [
{
"time": "2024-01-15T08:30:00Z",
"userPrincipalName": "john.doe@company.com",
"appDisplayName": "Microsoft Office 365",
"status": { "errorCode": 0 },
"location": { "city": "New York", "countryOrRegion": "US" },
"ipAddress": "192.168.1.100",
"deviceDetail": { "browser": "Chrome", "operatingSystem": "Windows" }
},
{
"time": "2024-01-15T08:35:00Z",
"userPrincipalName": "jane.smith@company.com",
"appDisplayName": "Azure Portal",
"status": { "errorCode": 50126 },
"location": { "city": "London", "countryOrRegion": "GB" },
"ipAddress": "10.0.1.50",
"deviceDetail": { "browser": "Edge", "operatingSystem": "Windows" }
},
{
"time": "2024-01-15T09:00:00Z",
"userPrincipalName": "admin@company.com",
"appDisplayName": "Microsoft Teams",
"status": { "errorCode": 0 },
"location": { "city": "Seattle", "countryOrRegion": "US" },
"ipAddress": "172.16.0.10",
"deviceDetail": { "browser": "Teams Desktop", "operatingSystem": "Windows" }
},
{
"time": "2024-01-15T09:15:00Z",
"userPrincipalName": "john.doe@company.com",
"appDisplayName": "SharePoint Online",
"status": { "errorCode": 0 },
"location": { "city": "New York", "countryOrRegion": "US" },
"ipAddress": "192.168.1.100",
"deviceDetail": { "browser": "Chrome", "operatingSystem": "Windows" }
},
{
"time": "2024-01-15T10:00:00Z",
"userPrincipalName": "test.user@company.com",
"appDisplayName": "Azure Portal",
"status": { "errorCode": 50053 },
"location": { "city": "Moscow", "countryOrRegion": "RU" },
"ipAddress": "5.45.123.45",
"deviceDetail": { "browser": "Firefox", "operatingSystem": "Linux" }
}
];

document.getElementById('logInput').value = JSON.stringify(sampleData, null, 2);
}

function clearData() {
document.getElementById('logInput').value = '';
document.getElementById('fileInput').value = '';
document.getElementById('analysisResults').classList.add('hidden');
document.getElementById('errorState').classList.add('hidden');
logData = [];
}

function showError(message) {
document.getElementById('errorMessage').textContent = message;
document.getElementById('errorState').classList.remove('hidden');
document.getElementById('loadingState').classList.add('hidden');
document.getElementById('analysisResults').classList.add('hidden');
}

function analyzeLogs() {
const input = document.getElementById('logInput').value.trim();
if (!input) {
showError('Please provide log data to analyze.');
return;
}

document.getElementById('loadingState').classList.remove('hidden');
document.getElementById('errorState').classList.add('hidden');
document.getElementById('analysisResults').classList.add('hidden');

try {
// Parse JSON data
let parsedData;
try {
parsedData = JSON.parse(input);
} catch (e) {
// Try parsing as NDJSON (newline-delimited JSON)
const lines = input.split('\n').filter(line => line.trim());
parsedData = lines.map(line => JSON.parse(line));
}

if (!Array.isArray(parsedData)) {
parsedData = [parsedData];
}

logData = parsedData;
processLogData();

} catch (error) {
showError('Invalid JSON format. Please check your log data.');
console.error('Parse error:', error);
}
}

function processLogData() {
if (logData.length === 0) {
showError('No valid log entries found.');
return;
}

// Calculate summary statistics
const totalEvents = logData.length;
const successfulSignins = logData.filter(log => (log.status?.errorCode === 0 || log.status?.errorCode === "0")).length;
const failedSignins = totalEvents - successfulSignins;
const uniqueUsers = new Set(logData.map(log => log.userPrincipalName || log.userId || 'Unknown')).size;

// Update summary cards
document.getElementById('totalEvents').textContent = totalEvents.toLocaleString();
document.getElementById('successfulSignins').textContent = successfulSignins.toLocaleString();
document.getElementById('failedSignins').textContent = failedSignins.toLocaleString();
document.getElementById('uniqueUsers').textContent = uniqueUsers.toLocaleString();

// Create charts
createStatusChart(successfulSignins, failedSignins);
createTimelineChart();

// Create tables
createTopUsersTable();
createTopAppsTable();

// Perform deviation analysis
performDeviationAnalysis();

// Perform correlation analysis
performCorrelationAnalysis();

// Perform risk analysis
performRiskAnalysis();

// Show detailed logs
showDetailedLogs();

document.getElementById('loadingState').classList.add('hidden');
document.getElementById('analysisResults').classList.remove('hidden');
}

function createStatusChart(successful, failed) {
const ctx = document.getElementById('statusChart').getContext('2d');

if (statusChart) {
statusChart.destroy();
}

statusChart = new Chart(ctx, {
type: 'doughnut',
data: {
labels: ['Successful', 'Failed'],
datasets: [{
data: [successful, failed],
backgroundColor: ['#10B981', '#EF4444'],
borderWidth: 0
}]
},
options: {
responsive: true,
maintainAspectRatio: false,
onClick: (event, elements) => {
if (elements.length > 0) {
const index = elements[0].index;
const label = statusChart.data.labels[index];
const value = statusChart.data.datasets[0].data[index];
showStatusBreakdownModal(label, value);
}
},
plugins: {
legend: {
position: 'bottom',
labels: {
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151'
}
}
}
}
});

// Create privileged chart alongside
createPrivilegedChart();
}

function createTimelineChart() {
const ctx = document.getElementById('timelineChart').getContext('2d');

if (timelineChart) {
timelineChart.destroy();
}

// Group events by hour
const hourlyData = {};
logData.forEach(log => {
const time = log.time || log.createdDateTime || log.timestamp;
if (time) {
const hour = new Date(time).getHours();
hourlyData[hour] = (hourlyData[hour] || 0) + 1;
}
});

const hours = Array.from({length: 24}, (_, i) => i);
const counts = hours.map(hour => hourlyData[hour] || 0);

timelineChart = new Chart(ctx, {
type: 'line',
data: {
labels: hours.map(h => `${h}:00`),
datasets: [{
label: 'Events per Hour',
data: counts,
borderColor: '#5D5CDE',
backgroundColor: 'rgba(93, 92, 222, 0.1)',
tension: 0.1,
fill: true
}]
},
options: {
responsive: true,
maintainAspectRatio: false,
plugins: {
legend: {
labels: {
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151'
}
}
},
scales: {
x: {
ticks: {
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151'
},
grid: {
color: document.documentElement.classList.contains('dark') ? '#374151' : '#E5E7EB'
}
},
y: {
ticks: {
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151'
},
grid: {
color: document.documentElement.classList.contains('dark') ? '#374151' : '#E5E7EB'
}
}
}
}
});
}

function createTopUsersTable() {
const userStats = {};

logData.forEach(log => {
const user = log.userPrincipalName || log.userId || 'Unknown';
if (!userStats[user]) {
userStats[user] = { total: 0, successful: 0 };
}
userStats[user].total++;
if (log.status?.errorCode === 0 || log.status?.errorCode === "0") {
userStats[user].successful++;
}
});

const sortedUsers = Object.entries(userStats)
.sort(([,a], [,b]) => b.total - a.total)
.slice(0, 10);

const tbody = document.getElementById('topUsersBody');
tbody.innerHTML = '';

sortedUsers.forEach(([user, stats]) => {
const successRate = ((stats.successful / stats.total) * 100).toFixed(1);
const row = tbody.insertRow();
row.innerHTML = `
<td class="px-3 py-2 text-sm text-gray-900 dark:text-white truncate max-w-xs">${user}</td>
<td class="px-3 py-2 text-sm text-gray-900 dark:text-white">${stats.total}</td>
<td class="px-3 py-2 text-sm">
<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${successRate >= 90 ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : successRate >= 70 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'}">
${successRate}%
</span>
</td>
`;
});
}

function createTopAppsTable() {
const appStats = {};

logData.forEach(log => {
const app = log.appDisplayName || log.resourceDisplayName || 'Unknown';
if (!appStats[app]) {
appStats[app] = { total: 0, successful: 0 };
}
appStats[app].total++;
if (log.status?.errorCode === 0 || log.status?.errorCode === "0") {
appStats[app].successful++;
}
});

const sortedApps = Object.entries(appStats)
.sort(([,a], [,b]) => b.total - a.total)
.slice(0, 10);

const tbody = document.getElementById('topAppsBody');
tbody.innerHTML = '';

sortedApps.forEach(([app, stats]) => {
const successRate = ((stats.successful / stats.total) * 100).toFixed(1);
const row = tbody.insertRow();
row.innerHTML = `
<td class="px-3 py-2 text-sm text-gray-900 dark:text-white truncate max-w-xs">${app}</td>
<td class="px-3 py-2 text-sm text-gray-900 dark:text-white">${stats.total}</td>
<td class="px-3 py-2 text-sm">
<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${successRate >= 90 ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : successRate >= 70 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'}">
${successRate}%
</span>
</td>
`;
});
}

function performRiskAnalysis() {
const riskContainer = document.getElementById('riskAnalysis');
const risks = [];

// Check for multiple failed logins
const failedLogins = logData.filter(log => log.status?.errorCode !== 0 && log.status?.errorCode !== "0");
if (failedLogins.length > logData.length * 0.3) {
risks.push({
level: 'high',
title: 'High Failed Login Rate',
description: `${((failedLogins.length / logData.length) * 100).toFixed(1)}% of login attempts failed`,
recommendation: 'Investigate potential brute force attacks or credential issues'
});
}

// Check for logins from unusual countries
const countries = {};
logData.forEach(log => {
const country = log.location?.countryOrRegion;
if (country) {
countries[country] = (countries[country] || 0) + 1;
}
});

const uncommonCountries = Object.entries(countries)
.filter(([country, count]) => count < 3 && !['US', 'GB', 'CA', 'AU', 'DE', 'FR'].includes(country));

if (uncommonCountries.length > 0) {
risks.push({
level: 'medium',
title: 'Logins from Unusual Locations',
description: `Detected logins from: ${uncommonCountries.map(([c]) => c).join(', ')}`,
recommendation: 'Verify these locations are expected for your users'
});
}

// Check for admin activities
const adminUsers = logData.filter(log =>
(log.userPrincipalName || '').toLowerCase().includes('admin') ||
(log.appDisplayName || '').toLowerCase().includes('admin')
);

if (adminUsers.length > 0) {
risks.push({
level: 'info',
title: 'Administrative Activity Detected',
description: `${adminUsers.length} admin-related events found`,
recommendation: 'Review admin activities for compliance'
});
}

riskContainer.innerHTML = '';

if (risks.length === 0) {
riskContainer.innerHTML = `
<div class="flex items-center p-4 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-md">
<div class="text-green-400">
<svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
</svg>
</div>
<div class="ml-3">
<h4 class="text-sm font-medium text-green-800 dark:text-green-200">No Major Risks Detected</h4>
<p class="text-sm text-green-700 dark:text-green-300">The analyzed logs show normal authentication patterns.</p>
</div>
</div>
`;
} else {
risks.forEach(risk => {
const colorClass = {
high: 'red',
medium: 'yellow',
info: 'blue'
}[risk.level];

riskContainer.innerHTML += `
<div class="flex items-start p-4 bg-${colorClass}-50 dark:bg-${colorClass}-900/20 border border-${colorClass}-200 dark:border-${colorClass}-800 rounded-md">
<div class="text-${colorClass}-400">
<svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
<path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
</svg>
</div>
<div class="ml-3">
<h4 class="text-sm font-medium text-${colorClass}-800 dark:text-${colorClass}-200">${risk.title}</h4>
<p class="text-sm text-${colorClass}-700 dark:text-${colorClass}-300 mt-1">${risk.description}</p>
<p class="text-sm text-${colorClass}-600 dark:text-${colorClass}-400 mt-2 font-medium">Recommendation: ${risk.recommendation}</p>
</div>
</div>
`;
});
}
}

function performDeviationAnalysis() {
// Build user behavior profiles
userProfiles = {};
logData.forEach(log => {
const user = log.userPrincipalName || log.userId || 'Unknown';
if (!userProfiles[user]) {
userProfiles[user] = {
ips: new Set(),
locations: new Set(),
devices: new Set(),
browsers: new Set(),
apps: new Set(),
hours: new Set(),
countries: new Set(),
logs: []
};
}

const profile = userProfiles[user];
profile.logs.push(log);

if (log.ipAddress) profile.ips.add(log.ipAddress);
if (log.location?.city) profile.locations.add(`${log.location.city}, ${log.location.countryOrRegion}`);
if (log.location?.countryOrRegion) profile.countries.add(log.location.countryOrRegion);
if (log.deviceDetail?.operatingSystem) profile.devices.add(log.deviceDetail.operatingSystem);
if (log.deviceDetail?.browser) profile.browsers.add(log.deviceDetail.browser);
if (log.appDisplayName) profile.apps.add(log.appDisplayName);

const time = log.time || log.createdDateTime || log.timestamp;
if (time) {
const hour = new Date(time).getHours();
profile.hours.add(hour);
}
});

// Create visual charts
createIPDeviationChart();
createTimeDeviationChart();
createAppDeviationChart();

// Create text-based geo and device deviation lists
createGeoDeviationList();
createDeviceDeviationList();

// Create summary
createDeviationSummary();
}

function createIPDeviationChart() {
const ctx = document.getElementById('ipDeviationChart').getContext('2d');

if (ipDeviationChart) {
ipDeviationChart.destroy();
}

// Collect IP deviation data - require more than 2 fingerprints
const ipDeviationData = [];
Object.entries(userProfiles).forEach(([user, profile]) => {
if (profile.logs.length >= 2 && profile.ips.size > 2) {
ipDeviationData.push({
user: user.split('@')[0] || user, // Show username only
fullUser: user,
ipCount: profile.ips.size,
ips: Array.from(profile.ips),
severity: profile.ips.size > 5 ? 'high' : profile.ips.size > 3 ? 'medium' : 'low'
});
}
});

ipDeviationData.sort((a, b) => b.ipCount - a.ipCount);
const topUsers = ipDeviationData.slice(0, 10);

if (topUsers.length === 0) {
// Show "no data" message
ctx.fillStyle = document.documentElement.classList.contains('dark') ? '#9CA3AF' : '#6B7280';
ctx.textAlign = 'center';
ctx.font = '14px sans-serif';
ctx.fillText('No IP deviations detected', ctx.canvas.width / 2, ctx.canvas.height / 2);
return;
}

ipDeviationChart = new Chart(ctx, {
type: 'bar',
data: {
labels: topUsers.map(d => d.user),
datasets: [{
label: 'Number of IP Addresses',
data: topUsers.map(d => d.ipCount),
backgroundColor: topUsers.map(d => {
switch(d.severity) {
case 'high': return '#EF4444';
case 'medium': return '#F59E0B';
default: return '#3B82F6';
}
}),
borderWidth: 0
}]
},
options: {
responsive: true,
maintainAspectRatio: false,
onClick: (event, elements) => {
if (elements.length > 0) {
const index = elements[0].index;
const userData = topUsers[index];
showDeviationModal('IP Address Deviation', userData.fullUser, {
count: userData.ipCount,
details: userData.ips.join(', '),
severity: userData.severity
});
}
},
plugins: {
legend: {
display: false
}
},
scales: {
x: {
ticks: {
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151',
maxRotation: 45
},
grid: {
color: document.documentElement.classList.contains('dark') ? '#374151' : '#E5E7EB'
}
},
y: {
ticks: {
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151'
},
grid: {
color: document.documentElement.classList.contains('dark') ? '#374151' : '#E5E7EB'
}
}
}
}
});
}

function createTimeDeviationChart() {
const ctx = document.getElementById('timeDeviationChart').getContext('2d');

if (timeDeviationChart) {
timeDeviationChart.destroy();
}

// Collect time pattern deviation data
const timeDeviationData = [];
Object.entries(userProfiles).forEach(([user, profile]) => {
if (profile.logs.length >= 2) {
const hourRange = profile.hours.size > 0 ? Math.max(...profile.hours) - Math.min(...profile.hours) : 0;
if (profile.hours.size > 8 || hourRange > 12) {
timeDeviationData.push({
user: user.split('@')[0] || user,
fullUser: user,
hourSpread: profile.hours.size,
hourRange: hourRange,
hours: Array.from(profile.hours).sort((a,b) => a-b),
severity: hourRange > 20 ? 'high' : hourRange > 16 || profile.hours.size > 12 ? 'medium' : 'low'
});
}
}
});

timeDeviationData.sort((a, b) => b.hourRange - a.hourRange);
const topUsers = timeDeviationData.slice(0, 10);

if (topUsers.length === 0) {
ctx.fillStyle = document.documentElement.classList.contains('dark') ? '#9CA3AF' : '#6B7280';
ctx.textAlign = 'center';
ctx.font = '14px sans-serif';
ctx.fillText('No time pattern deviations detected', ctx.canvas.width / 2, ctx.canvas.height / 2);
return;
}

timeDeviationChart = new Chart(ctx, {
type: 'scatter',
data: {
datasets: [{
label: 'Time Pattern Deviations',
data: topUsers.map((d, index) => ({
x: d.hourRange,
y: d.hourSpread,
userData: d
})),
backgroundColor: topUsers.map(d => {
switch(d.severity) {
case 'high': return '#EF4444';
case 'medium': return '#F59E0B';
default: return '#3B82F6';
}
}),
borderColor: topUsers.map(d => {
switch(d.severity) {
case 'high': return '#DC2626';
case 'medium': return '#D97706';
default: return '#2563EB';
}
}),
pointRadius: 8,
pointHoverRadius: 10
}]
},
options: {
responsive: true,
maintainAspectRatio: false,
onClick: (event, elements) => {
if (elements.length > 0) {
const point = elements[0];
const userData = timeDeviationChart.data.datasets[0].data[point.index].userData;
showDeviationModal('Time Pattern Deviation', userData.fullUser, {
hourSpread: userData.hourSpread,
hourRange: userData.hourRange,
details: `Active hours: ${userData.hours.map(h => h + ':00').join(', ')}`,
severity: userData.severity
});
}
},
plugins: {
legend: {
display: false
}
},
scales: {
x: {
title: {
display: true,
text: 'Hour Range',
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151'
},
ticks: {
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151'
},
grid: {
color: document.documentElement.classList.contains('dark') ? '#374151' : '#E5E7EB'
}
},
y: {
title: {
display: true,
text: 'Unique Hours',
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151'
},
ticks: {
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151'
},
grid: {
color: document.documentElement.classList.contains('dark') ? '#374151' : '#E5E7EB'
}
}
}
}
});
}

function createAppDeviationChart() {
const ctx = document.getElementById('appDeviationChart').getContext('2d');

if (appDeviationChart) {
appDeviationChart.destroy();
}

// Collect application deviation data
const appDeviationData = [];
Object.entries(userProfiles).forEach(([user, profile]) => {
if (profile.logs.length >= 2 && profile.apps.size > 3) {
appDeviationData.push({
user: user.split('@')[0] || user,
fullUser: user,
appCount: profile.apps.size,
apps: Array.from(profile.apps),
severity: profile.apps.size > 8 ? 'medium' : 'low'
});
}
});

appDeviationData.sort((a, b) => b.appCount - a.appCount);
const topUsers = appDeviationData.slice(0, 8);

if (topUsers.length === 0) {
ctx.fillStyle = document.documentElement.classList.contains('dark') ? '#9CA3AF' : '#6B7280';
ctx.textAlign = 'center';
ctx.font = '14px sans-serif';
ctx.fillText('No application deviations detected', ctx.canvas.width / 2, ctx.canvas.height / 2);
return;
}

appDeviationChart = new Chart(ctx, {
type: 'doughnut',
data: {
labels: topUsers.map(d => d.user),
datasets: [{
data: topUsers.map(d => d.appCount),
backgroundColor: [
'#EF4444', '#F59E0B', '#10B981', '#3B82F6',
'#8B5CF6', '#F97316', '#06B6D4', '#84CC16'
],
borderWidth: 0
}]
},
options: {
responsive: true,
maintainAspectRatio: false,
onClick: (event, elements) => {
if (elements.length > 0) {
const index = elements[0].index;
const userData = topUsers[index];
showDeviationModal('Application Access Deviation', userData.fullUser, {
count: userData.appCount,
details: userData.apps.join(', '),
severity: userData.severity
});
}
},
plugins: {
legend: {
position: 'right',
labels: {
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151',
boxWidth: 12,
padding: 8,
font: {
size: 10
}
}
}
}
}
});
}

function createGeoDeviationList() {
const container = document.getElementById('geoDeviations');
const geoDeviations = [];

Object.entries(userProfiles).forEach(([user, profile]) => {
if (profile.logs.length >= 2 && profile.countries.size > 1) {
geoDeviations.push({
user: user,
countries: Array.from(profile.countries),
severity: profile.countries.size > 3 ? 'high' : 'medium'
});
}
});

geoDeviations.sort((a, b) => b.countries.length - a.countries.length);

if (geoDeviations.length === 0) {
container.innerHTML = '<p class="text-sm text-gray-600 dark:text-gray-400">No geographic deviations detected</p>';
return;
}

container.innerHTML = '';
geoDeviations.slice(0, 5).forEach(deviation => {
const colorClass = deviation.severity === 'high' ? 'red' : 'yellow';
container.innerHTML += `
<div class="flex justify-between items-center p-2 bg-${colorClass}-50 dark:bg-${colorClass}-900/20 border border-${colorClass}-200 dark:border-${colorClass}-800 rounded text-xs">
<span class="font-medium text-${colorClass}-800 dark:text-${colorClass}-200 truncate">${deviation.user.split('@')[0]}</span>
<span class="text-${colorClass}-600 dark:text-${colorClass}-400">${deviation.countries.join(', ')}</span>
</div>
`;
});
}

function createDeviceDeviationList() {
const container = document.getElementById('deviceDeviations');
const deviceDeviations = [];

Object.entries(userProfiles).forEach(([user, profile]) => {
if (profile.logs.length >= 2 && (profile.devices.size > 1 || profile.browsers.size > 2)) {
deviceDeviations.push({
user: user,
devices: Array.from(profile.devices),
browsers: Array.from(profile.browsers),
total: profile.devices.size + profile.browsers.size,
severity: (profile.devices.size + profile.browsers.size) > 4 ? 'high' : 'medium'
});
}
});

deviceDeviations.sort((a, b) => b.total - a.total);

if (deviceDeviations.length === 0) {
container.innerHTML = '<p class="text-sm text-gray-600 dark:text-gray-400">No device deviations detected</p>';
return;
}

container.innerHTML = '';
deviceDeviations.slice(0, 5).forEach(deviation => {
const colorClass = deviation.severity === 'high' ? 'red' : 'yellow';
container.innerHTML += `
<div class="p-2 bg-${colorClass}-50 dark:bg-${colorClass}-900/20 border border-${colorClass}-200 dark:border-${colorClass}-800 rounded text-xs">
<div class="font-medium text-${colorClass}-800 dark:text-${colorClass}-200 truncate">${deviation.user.split('@')[0]}</div>
<div class="text-${colorClass}-600 dark:text-${colorClass}-400 mt-1">
OS: ${deviation.devices.join(', ') || 'N/A'}<br>
Browsers: ${deviation.browsers.join(', ') || 'N/A'}
</div>
</div>
`;
});
}

function createDeviationSummary() {
const container = document.getElementById('deviationSummary');
const totalUsers = Object.keys(userProfiles).length;
let usersWithDeviations = new Set();
let highSeverityCount = 0;

Object.entries(userProfiles).forEach(([user, profile]) => {
if (profile.logs.length >= 2) {
const hasIpDeviation = profile.ips.size > 1;
const hasGeoDeviation = profile.countries.size > 1;
const hasTimeDeviation = profile.hours.size > 8;
const hasDeviceDeviation = profile.devices.size > 1 || profile.browsers.size > 2;
const hasAppDeviation = profile.apps.size > 3;

if (hasIpDeviation || hasGeoDeviation || hasTimeDeviation || hasDeviceDeviation || hasAppDeviation) {
usersWithDeviations.add(user);
}

// Count high severity
if (profile.ips.size > 5 || profile.countries.size > 3 ||
(Math.max(...profile.hours) - Math.min(...profile.hours)) > 20 ||
(profile.devices.size + profile.browsers.size) > 4) {
highSeverityCount++;
}
}
});

container.innerHTML = `
<h4 class="text-sm font-medium text-gray-900 dark:text-white mb-2">Deviation Analysis Summary</h4>
<div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
<div>
<span class="font-medium text-gray-700 dark:text-gray-300">Users Analyzed:</span>
<span class="text-gray-900 dark:text-white ml-1">${totalUsers}</span>
</div>
<div>
<span class="font-medium text-gray-700 dark:text-gray-300">Users with Deviations:</span>
<span class="text-gray-900 dark:text-white ml-1">${usersWithDeviations.size} (${((usersWithDeviations.size/totalUsers)*100).toFixed(1)}%)</span>
</div>
<div>
<span class="font-medium text-gray-700 dark:text-gray-300">High-Risk Users:</span>
<span class="text-red-600 dark:text-red-400 ml-1 font-medium">${highSeverityCount}</span>
</div>
</div>
`;
}

function showDeviationModal(title, user, data) {
document.getElementById('modalTitle').textContent = `${title}: ${user}`;

let content = `
<div class="space-y-4">
<div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
<div>
<span class="text-sm font-medium text-gray-700 dark:text-gray-300">Severity Level:</span>
<span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ml-3 ${
data.severity === 'high' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' :
data.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200' :
'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
}">
${data.severity.toUpperCase()}
</span>
</div>
`;

if (data.count) {
content += `
<div class="text-right">
<span class="text-sm text-gray-600 dark:text-gray-400">Total Count:</span>
<span class="text-lg font-bold text-gray-900 dark:text-white ml-1">${data.count}</span>
</div>
`;
}

content += `</div>`;

// Add metrics for time patterns
if (data.hourSpread || data.hourRange) {
content += `
<div class="grid grid-cols-2 gap-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
<div class="text-center">
<div class="text-2xl font-bold text-blue-600 dark:text-blue-400">${data.hourSpread || 0}</div>
<div class="text-sm text-blue-800 dark:text-blue-300">Unique Hours</div>
</div>
<div class="text-center">
<div class="text-2xl font-bold text-blue-600 dark:text-blue-400">${data.hourRange || 0}h</div>
<div class="text-sm text-blue-800 dark:text-blue-300">Time Range</div>
</div>
</div>
`;
}

// Create structured lists based on deviation type
if (title.includes('IP Address')) {
content += createIPAddressList(data);
} else if (title.includes('Time Pattern')) {
content += createTimePatternList(data);
} else if (title.includes('Application')) {
content += createApplicationList(data);
}

content += `</div>`;

document.getElementById('modalContent').innerHTML = content;
document.getElementById('deviationModal').classList.remove('hidden');
}

function createIPAddressList(data) {
const ips = data.details.split(', ');
let content = `
<div>
<h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3 flex items-center">
<span class="mr-2">🌐</span>
IP Addresses Used (${ips.length})
</h4>
<div class="max-h-48 overflow-y-auto">
<ul class="space-y-2">
`;

ips.forEach((ip, index) => {
if (ip.trim() && ip.trim() !== '...') {
// Determine IP type and risk level
const isPrivate = ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.');
const ipType = isPrivate ? 'Private Network' : 'Public/External';
const riskClass = isPrivate ? 'green' : 'yellow';

content += `
<li class="flex items-center justify-between p-3 bg-${riskClass}-50 dark:bg-${riskClass}-900/20 border border-${riskClass}-200 dark:border-${riskClass}-800 rounded-lg">
<div class="flex-1">
<div class="font-mono text-sm font-medium text-gray-900 dark:text-white">${ip.trim()}</div>
<div class="text-xs text-${riskClass}-700 dark:text-${riskClass}-300">${ipType}</div>
</div>
<div class="ml-3">
<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-${riskClass}-100 text-${riskClass}-800 dark:bg-${riskClass}-900 dark:text-${riskClass}-200">
${isPrivate ? 'Internal' : 'External'}
</span>
</div>
</li>
`;
}
});

content += `
</ul>
</div>
<div class="mt-3 p-2 bg-gray-100 dark:bg-gray-700 rounded text-xs text-gray-600 dark:text-gray-400">
<strong>Risk Assessment:</strong> Multiple IP addresses may indicate account sharing, compromised credentials, or legitimate mobile usage.
</div>
</div>
`;

return content;
}

function createTimePatternList(data) {
// Parse the hours from the details string
const hoursMatch = data.details.match(/Active hours: (.+)/);
const hours = hoursMatch ? hoursMatch[1].split(', ').map(h => parseInt(h.split(':')[0])) : [];

let content = `
<div>
<h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3 flex items-center">
<span class="mr-2">⏰</span>
Activity Time Pattern Analysis
</h4>
`;

// Create time blocks visualization
content += `
<div class="mb-4">
<h5 class="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">24-Hour Activity Map</h5>
<div class="grid grid-cols-12 gap-1 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
`;

for (let hour = 0; hour < 24; hour++) {
const isActive = hours.includes(hour);
const timeLabel = `${hour.toString().padStart(2, '0')}:00`;
const bgClass = isActive ? 'bg-blue-500' : 'bg-gray-200 dark:bg-gray-600';

content += `
<div class="relative group">
<div class="${bgClass} h-6 rounded text-xs flex items-center justify-center ${isActive ? 'text-white' : 'text-gray-400'}" title="${timeLabel}">
${hour}
</div>
</div>
`;
}

content += `
</div>
<div class="flex justify-between text-xs text-gray-500 dark:text-gray-400 mt-1">
<span>00:00</span>
<span>12:00</span>
<span>23:00</span>
</div>
</div>
`;

// Time period analysis
const businessHours = hours.filter(h => h >= 9 && h <= 17).length;
const afterHours = hours.filter(h => h < 9 || h > 17).length;
const nightTime = hours.filter(h => h >= 22 || h <= 6).length;

content += `
<div class="grid grid-cols-3 gap-3 mb-4">
<div class="text-center p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
<div class="text-lg font-bold text-green-600 dark:text-green-400">${businessHours}</div>
<div class="text-xs text-green-800 dark:text-green-300">Business Hours<br>(9AM-5PM)</div>
</div>
<div class="text-center p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
<div class="text-lg font-bold text-yellow-600 dark:text-yellow-400">${afterHours}</div>
<div class="text-xs text-yellow-800 dark:text-yellow-300">After Hours<br>(Early/Late)</div>
</div>
<div class="text-center p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
<div class="text-lg font-bold text-red-600 dark:text-red-400">${nightTime}</div>
<div class="text-xs text-red-800 dark:text-red-300">Night Time<br>(10PM-6AM)</div>
</div>
</div>
`;

// Active hours list
content += `
<div>
<h5 class="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Active Hours List</h5>
<div class="max-h-32 overflow-y-auto">
<div class="flex flex-wrap gap-1">
`;

hours.sort((a, b) => a - b).forEach(hour => {
const timeLabel = `${hour.toString().padStart(2, '0')}:00`;
const isBusinessHour = hour >= 9 && hour <= 17;
const isNightTime = hour >= 22 || hour <= 6;
const colorClass = isNightTime ? 'red' : isBusinessHour ? 'green' : 'yellow';

content += `
<span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium bg-${colorClass}-100 text-${colorClass}-800 dark:bg-${colorClass}-900 dark:text-${colorClass}-200">
${timeLabel}
</span>
`;
});

content += `
</div>
</div>
<div class="mt-3 p-2 bg-gray-100 dark:bg-gray-700 rounded text-xs text-gray-600 dark:text-gray-400">
<strong>Risk Assessment:</strong> Unusual time patterns may indicate compromised accounts, shared credentials, or global team members in different time zones.
</div>
</div>
`;

return content;
}

function createApplicationList(data) {
const apps = data.details.split(', ');

let content = `
<div>
<h4 class="text-md font-semibold text-gray-900 dark:text-white mb-3 flex items-center">
<span class="mr-2">📱</span>
Applications Accessed (${apps.length})
</h4>
<div class="max-h-48 overflow-y-auto">
<ul class="space-y-2">
`;

// Categorize applications
apps.forEach((app, index) => {
if (app.trim() && app.trim() !== '...') {
// Determine app category and risk level
const appName = app.trim();
let category = 'Other';
let riskLevel = 'low';
let iconClass = '📱';

if (appName.toLowerCase().includes('office') || appName.toLowerCase().includes('teams') || appName.toLowerCase().includes('sharepoint') || appName.toLowerCase().includes('outlook')) {
category = 'Microsoft 365';
iconClass = '🏢';
riskLevel = 'low';
} else if (appName.toLowerCase().includes('azure') || appName.toLowerCase().includes('portal')) {
category = 'Azure Services';
iconClass = '☁️';
riskLevel = 'medium';
} else if (appName.toLowerCase().includes('admin') || appName.toLowerCase().includes('management')) {
category = 'Administration';
iconClass = '⚙️';
riskLevel = 'high';
} else if (appName.toLowerCase().includes('power') || appName.toLowerCase().includes('dynamics')) {
category = 'Business Apps';
iconClass = '⚡';
riskLevel = 'low';
}

const riskClass = riskLevel === 'high' ? 'red' : riskLevel === 'medium' ? 'yellow' : 'green';

content += `
<li class="flex items-center justify-between p-3 bg-${riskClass}-50 dark:bg-${riskClass}-900/20 border border-${riskClass}-200 dark:border-${riskClass}-800 rounded-lg">
<div class="flex items-center flex-1">
<span class="text-lg mr-3">${iconClass}</span>
<div>
<div class="text-sm font-medium text-gray-900 dark:text-white">${appName}</div>
<div class="text-xs text-${riskClass}-700 dark:text-${riskClass}-300">${category}</div>
</div>
</div>
<div class="ml-3">
<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-${riskClass}-100 text-${riskClass}-800 dark:bg-${riskClass}-900 dark:text-${riskClass}-200">
${riskLevel.toUpperCase()}
</span>
</div>
</li>
`;
}
});

content += `
</ul>
</div>
<div class="mt-3 p-2 bg-gray-100 dark:bg-gray-700 rounded text-xs text-gray-600 dark:text-gray-400">
<strong>Risk Assessment:</strong> Access to many applications may indicate legitimate power users, role expansion, or potential privilege escalation.
</div>
</div>
`;

return content;
}

function closeDeviationModal() {
document.getElementById('deviationModal').classList.add('hidden');
}

function showDetailedLogs() {
const tbody = document.getElementById('detailedLogs');
tbody.innerHTML = '';

const recentLogs = logData
.sort((a, b) => new Date(b.time || b.createdDateTime || b.timestamp) - new Date(a.time || a.createdDateTime || a.timestamp))
.slice(0, 20);

recentLogs.forEach(log => {
const timestamp = new Date(log.time || log.createdDateTime || log.timestamp).toLocaleString();
const user = log.userPrincipalName || log.userId || 'Unknown';
const app = log.appDisplayName || log.resourceDisplayName || 'Unknown';
const status = log.status?.errorCode === 0 || log.status?.errorCode === "0" ? 'Success' : 'Failed';
const location = log.location ? `${log.location.city || 'Unknown'}, ${log.location.countryOrRegion || 'Unknown'}` : 'Unknown';

const row = tbody.insertRow();
row.innerHTML = `
<td class="px-3 py-2 text-sm text-gray-900 dark:text-white">${timestamp}</td>
<td class="px-3 py-2 text-sm text-gray-900 dark:text-white truncate max-w-xs">${user}</td>
<td class="px-3 py-2 text-sm text-gray-900 dark:text-white truncate max-w-xs">${app}</td>
<td class="px-3 py-2 text-sm">
<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${status === 'Success' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'}">
${status}
</span>
</td>
<td class="px-3 py-2 text-sm text-gray-900 dark:text-white">${location}</td>
`;
});
}

// ===== CORRELATION ANALYSIS FUNCTIONS =====

let correlationData = {};

function performCorrelationAnalysis() {
console.log('Starting aggressive correlation analysis...');

// Initialize correlation data structure
correlationData = {
temporal: {},
geographic: {},
infrastructure: {},
behavioral: {},
threats: [],
suspiciousActivity: [],
impossibleTravel: [],
correlationScore: 0
};

// Perform different types of correlation analysis
analyzeTemporalCorrelations();
analyzeGeographicCorrelations();
analyzeInfrastructureCorrelations();
analyzeBehavioralCorrelations();

// Calculate overall correlation score
calculateCorrelationScore();

// Update UI summary cards
updateCorrelationSummary();

// Initialize with temporal panel
showCorrelationTab('temporal');
}

function analyzeTemporalCorrelations() {
const userSequences = {};
const rapidSequences = [];
const failedSuccessPatterns = [];

// Group logs by user and sort by time
logData.forEach(log => {
const user = log.userPrincipalName || log.userId || 'Unknown';
if (!userSequences[user]) {
userSequences[user] = [];
}
userSequences[user].push({
timestamp: new Date(log.time || log.createdDateTime || log.timestamp),
success: log.status?.errorCode === 0 || log.status?.errorCode === "0",
ip: log.ipAddress,
location: log.location,
app: log.appDisplayName || 'Unknown',
log: log
});
});

// Analyze each user's temporal patterns
Object.entries(userSequences).forEach(([user, events]) => {
events.sort((a, b) => a.timestamp - b.timestamp);

// Track consecutive failures for brute force detection
let consecutiveFailures = 0;
let failureStartTime = null;

for (let i = 1; i < events.length; i++) {
const prev = events[i-1];
const curr = events[i];
const timeDiff = (curr.timestamp - prev.timestamp) / 1000; // seconds

// Count consecutive failures
if (!curr.success) {
if (consecutiveFailures === 0) {
failureStartTime = curr.timestamp;
}
consecutiveFailures++;
} else {
// Check for credential stuffing attack (multiple failures followed by success)
if (consecutiveFailures >= 5) {
const attackDuration = (curr.timestamp - failureStartTime) / 1000;
correlationData.threats.push({
type: 'Credential Stuffing Attack',
user,
description: `${consecutiveFailures} consecutive failures over ${Math.round(attackDuration)}s before success`,
severity: 'critical'
});
}
consecutiveFailures = 0;
failureStartTime = null;
}

// Detect superhuman authentication speeds (< 3 seconds)
if (timeDiff < 3 && timeDiff > 0) {
rapidSequences.push({
user,
timeDiff: Math.round(timeDiff * 10) / 10,
events: [prev, curr],
riskLevel: timeDiff < 1 ? 'critical' : timeDiff < 2 ? 'high' : 'medium'
});

if (timeDiff < 1) {
correlationData.threats.push({
type: 'Automated Bot Authentication',
user,
description: `Inhuman authentication speed: ${Math.round(timeDiff * 100) / 100}s between attempts`,
severity: 'critical'
});
} else if (timeDiff < 2) {
correlationData.threats.push({
type: 'Suspicious Authentication Velocity',
user,
description: `Abnormally fast authentication: ${Math.round(timeDiff * 10) / 10}s interval`,
severity: 'critical'
});
}
}

// Detect password spray indicators (same IP, multiple users, short timeframe)
if (prev.ip === curr.ip && prev.log.userPrincipalName !== curr.log.userPrincipalName && timeDiff < 60) {
correlationData.threats.push({
type: 'Password Spray Attack',
user: `Multiple users from ${prev.ip}`,
description: `Different users authenticating from same IP within ${Math.round(timeDiff)}s`,
severity: 'critical'
});
}

// Detect impossible human recovery (failed to success in < 5 seconds)
if (timeDiff < 5 && !prev.success && curr.success) {
failedSuccessPatterns.push({
user,
timeDiff: Math.round(timeDiff * 10) / 10,
failedAttempt: prev,
successfulAttempt: curr,
riskLevel: 'critical'
});

correlationData.threats.push({
type: 'Automated Credential Success',
user,
description: `Impossible recovery: Failed to successful login in ${Math.round(timeDiff * 10) / 10}s`,
severity: 'critical'
});
}

// Detect session hijacking indicators (sudden IP change with immediate success)
if (prev.ip !== curr.ip && curr.success && timeDiff < 30) {
correlationData.threats.push({
type: 'Potential Session Hijacking',
user,
description: `IP changed from ${prev.ip} to ${curr.ip} with immediate success`,
severity: 'critical'
});
}
}

// Final check for ongoing brute force
if (consecutiveFailures >= 10) {
correlationData.threats.push({
type: 'Active Brute Force Attack',
user,
description: `${consecutiveFailures} consecutive failures detected (ongoing attack)`,
severity: 'critical'
});
}
});

correlationData.temporal = {
rapidSequences,
failedSuccessPatterns,
userSequences
};
}

function analyzeGeographicCorrelations() {
const impossibleTravel = [];
const geoVelocity = {};
const countryTransitions = {};

// Calculate distances between locations (simplified)
function calculateDistance(loc1, loc2) {
const cities = {
'New York': { lat: 40.7128, lng: -74.0060 },
'London': { lat: 51.5074, lng: -0.1278 },
'Seattle': { lat: 47.6062, lng: -122.3321 },
'Moscow': { lat: 55.7558, lng: 37.6176 },
'Tokyo': { lat: 35.6762, lng: 139.6503 },
'Sydney': { lat: -33.8688, lng: 151.2093 },
'Berlin': { lat: 52.5200, lng: 13.4050 }
};

const city1 = cities[loc1] || { lat: 0, lng: 0 };
const city2 = cities[loc2] || { lat: 0, lng: 0 };

// Haversine formula (simplified)
const R = 6371; // Earth's radius in km
const dLat = (city2.lat - city1.lat) * Math.PI / 180;
const dLng = (city2.lng - city1.lng) * Math.PI / 180;
const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
Math.cos(city1.lat * Math.PI / 180) * Math.cos(city2.lat * Math.PI / 180) *
Math.sin(dLng/2) * Math.sin(dLng/2);
const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
return R * c;
}

// Analyze user location changes
Object.entries(userProfiles).forEach(([user, profile]) => {
const locationEvents = profile.logs
.filter(log => log.location?.city && log.time)
.map(log => ({
timestamp: new Date(log.time || log.createdDateTime || log.timestamp),
city: log.location.city,
country: log.location.countryOrRegion,
log: log
}))
.sort((a, b) => a.timestamp - b.timestamp);

for (let i = 1; i < locationEvents.length; i++) {
const prev = locationEvents[i-1];
const curr = locationEvents[i];

if (prev.city !== curr.city) {
const distance = calculateDistance(prev.city, curr.city);
const timeDiff = (curr.timestamp - prev.timestamp) / (1000 * 60 * 60); // hours
const velocity = distance / timeDiff; // km/h

// Impossible travel detection (faster than commercial flight ~900 km/h)
if (velocity > 900 && distance > 500) {
impossibleTravel.push({
user,
fromCity: prev.city,
fromCountry: prev.country,
toCity: curr.city,
toCountry: curr.country,
distance: Math.round(distance),
timeDiff: Math.round(timeDiff * 10) / 10,
velocity: Math.round(velocity),
riskLevel: velocity > 2000 ? 'critical' : 'high'
});

// Only add as suspicious activity for now - will be upgraded to critical threat if multiple correlations exist
correlationData.suspiciousActivity.push({
type: 'Impossible Travel',
user,
description: `Travel from ${prev.city} to ${curr.city} (${Math.round(distance)}km in ${Math.round(timeDiff * 10) / 10}h)`,
severity: 'medium'
});
}

// Track country transitions
if (prev.country !== curr.country) {
const transition = `${prev.country} → ${curr.country}`;
countryTransitions[transition] = (countryTransitions[transition] || 0) + 1;
}
}
}

// Store velocity data for visualization
geoVelocity[user] = locationEvents;
});

correlationData.geographic = {
impossibleTravel,
geoVelocity,
countryTransitions
};
}

function analyzeInfrastructureCorrelations() {
const sharedIPs = {};
const deviceOverlap = {};
const ipUserMap = {};

// Map IPs to users
logData.forEach(log => {
const ip = log.ipAddress;
const user = log.userPrincipalName || log.userId || 'Unknown';

if (ip) {
if (!ipUserMap[ip]) {
ipUserMap[ip] = new Set();
}
ipUserMap[ip].add(user);
}
});

// Find shared infrastructure
Object.entries(ipUserMap).forEach(([ip, users]) => {
if (users.size > 1) {
const userList = Array.from(users);
sharedIPs[ip] = {
users: userList,
count: userList.length,
isPrivate: ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.'),
riskLevel: userList.length > 5 ? 'high' : userList.length > 2 ? 'medium' : 'low'
};

if (userList.length > 3 && !sharedIPs[ip].isPrivate) {
correlationData.suspiciousActivity.push({
type: 'Shared Public IP',
description: `${userList.length} users sharing public IP ${ip}`,
users: userList,
severity: 'medium'
});
}
}
});

// Analyze device fingerprint overlap
const deviceFingerprints = {};
Object.entries(userProfiles).forEach(([user, profile]) => {
profile.logs.forEach(log => {
if (log.deviceDetail) {
const fingerprint = `${log.deviceDetail.browser || 'Unknown'}_${log.deviceDetail.operatingSystem || 'Unknown'}`;
if (!deviceFingerprints[fingerprint]) {
deviceFingerprints[fingerprint] = new Set();
}
deviceFingerprints[fingerprint].add(user);
}
});
});

Object.entries(deviceFingerprints).forEach(([fingerprint, users]) => {
if (users.size > 1) {
deviceOverlap[fingerprint] = {
users: Array.from(users),
count: users.size,
riskLevel: users.size > 10 ? 'low' : users.size > 5 ? 'medium' : 'high'
};
}
});

correlationData.infrastructure = {
sharedIPs,
deviceOverlap,
ipUserMap
};
}

function analyzeBehavioralCorrelations() {
const behavioralClusters = {};
const privilegeEscalation = [];
const behavioralDNA = {};

// Create behavioral DNA for each user
Object.entries(userProfiles).forEach(([user, profile]) => {
const dna = {
avgHour: profile.hours.size > 0 ? Array.from(profile.hours).reduce((a, b) => a + b, 0) / profile.hours.size : 12,
ipVariability: profile.ips.size,
geoVariability: profile.countries.size,
appVariability: profile.apps.size,
failureRate: profile.logs.filter(log => log.status?.errorCode !== 0 && log.status?.errorCode !== "0").length / profile.logs.length,
nightActivity: Array.from(profile.hours).filter(h => h >= 22 || h <= 6).length,
weekendActivity: profile.logs.filter(log => {
const day = new Date(log.time || log.createdDateTime || log.timestamp).getDay();
return day === 0 || day === 6;
}).length
};

behavioralDNA[user] = dna;

// Detect privilege escalation patterns
const adminApps = profile.logs.filter(log =>
(log.appDisplayName || '').toLowerCase().includes('admin') ||
(log.appDisplayName || '').toLowerCase().includes('portal') ||
(log.appDisplayName || '').toLowerCase().includes('management')
);

if (adminApps.length > 0 && profile.logs.length > adminApps.length) {
const escalationRatio = adminApps.length / profile.logs.length;
if (escalationRatio > 0.3) {
privilegeEscalation.push({
user,
adminAttempts: adminApps.length,
totalAttempts: profile.logs.length,
escalationRatio: Math.round(escalationRatio * 100),
riskLevel: escalationRatio > 0.7 ? 'high' : 'medium'
});
}
}
});

// Find behavioral clusters (users with similar patterns)
const clusters = {};
Object.entries(behavioralDNA).forEach(([user1, dna1]) => {
Object.entries(behavioralDNA).forEach(([user2, dna2]) => {
if (user1 !== user2) {
const similarity = calculateBehavioralSimilarity(dna1, dna2);
if (similarity > 0.8) {
const clusterKey = [user1, user2].sort().join('_');
if (!clusters[clusterKey]) {
clusters[clusterKey] = {
users: [user1, user2],
similarity: similarity,
riskLevel: similarity > 0.95 ? 'high' : 'medium'
};

if (similarity > 0.95) {
correlationData.suspiciousActivity.push({
type: 'Behavioral Clone',
description: `Users ${user1} and ${user2} show identical behavior patterns`,
users: [user1, user2],
similarity: Math.round(similarity * 100),
severity: 'high'
});
}
}
}
}
});
});

correlationData.behavioral = {
behavioralClusters: clusters,
privilegeEscalation,
behavioralDNA
};
}

function calculateBehavioralSimilarity(dna1, dna2) {
const weights = {
avgHour: 0.2,
ipVariability: 0.2,
geoVariability: 0.15,
appVariability: 0.15,
failureRate: 0.15,
nightActivity: 0.1,
weekendActivity: 0.05
};

let similarity = 0;
Object.keys(weights).forEach(key => {
const diff = Math.abs(dna1[key] - dna2[key]);
const maxVal = Math.max(dna1[key], dna2[key], 1);
const normalizedSimilarity = 1 - (diff / maxVal);
similarity += normalizedSimilarity * weights[key];
});

return similarity;
}

function calculateCorrelationScore() {
// Perform multi-vector correlation analysis for Critical Threats
analyzeMultiVectorThreats();

let score = 0;

// Add scores based on critical threats found (now based on correlations)
score += correlationData.threats.length * 25;
score += correlationData.suspiciousActivity.length * 10;
score += correlationData.impossibleTravel.length * 15;

// Add scores for infrastructure sharing
score += Object.keys(correlationData.infrastructure.sharedIPs || {}).length * 5;

// Add scores for behavioral anomalies
score += Object.keys(correlationData.behavioral.behavioralClusters || {}).length * 10;
score += correlationData.behavioral.privilegeEscalation.length * 15;

// Cap at 100
correlationData.correlationScore = Math.min(score, 100);
}

function analyzeMultiVectorThreats() {
// Clear existing threats - we'll rebuild based on correlations
correlationData.threats = [];

// Analyze each user for multiple threat indicators
Object.entries(userProfiles).forEach(([user, profile]) => {
const threatIndicators = analyzeUserThreatIndicators(user, profile);

// Only flag as Critical Threat if multiple correlations exist
if (threatIndicators.count >= 3) {
correlationData.threats.push({
type: 'Multi-Vector Attack',
user,
description: `${threatIndicators.count} correlated threat indicators: ${threatIndicators.types.join(', ')}`,
severity: 'critical',
indicators: threatIndicators
});
} else if (threatIndicators.count === 2) {
correlationData.threats.push({
type: 'Coordinated Threat',
user,
description: `${threatIndicators.count} correlated indicators: ${threatIndicators.types.join(', ')}`,
severity: 'high',
indicators: threatIndicators
});
}
});

// Analyze cross-user correlations (infrastructure sharing + behavioral similarity)
analyzeInfrastructureBehavioralCorrelations();

// Analyze temporal + geographic correlations
analyzeTemporalGeographicCorrelations();
}

function analyzeUserThreatIndicators(user, profile) {
const indicators = {
count: 0,
types: [],
details: {}
};

// 1. Impossible Travel Indicator
const impossibleTravelEvents = correlationData.geographic.impossibleTravel.filter(travel => travel.user === user);
if (impossibleTravelEvents.length > 0) {
indicators.count++;
indicators.types.push('Impossible Travel');
indicators.details.impossibleTravel = impossibleTravelEvents;
}

// 2. Rapid Authentication Indicator
const rapidSequences = correlationData.temporal.rapidSequences.filter(seq => seq.user === user && seq.timeDiff < 2);
if (rapidSequences.length > 0) {
indicators.count++;
indicators.types.push('Rapid Authentication');
indicators.details.rapidAuthentication = rapidSequences;
}

// 3. Multiple IP Addresses Indicator (high variability)
if (profile.ips.size > 5) {
indicators.count++;
indicators.types.push('High IP Variability');
indicators.details.ipVariability = profile.ips.size;
}

// 4. Behavioral Deviation Indicator
const behavioralDNA = correlationData.behavioral.behavioralDNA[user];
if (behavioralDNA) {
let behavioralAnomalies = 0;
if (behavioralDNA.failureRate > 0.3) behavioralAnomalies++;
if (behavioralDNA.nightActivity > 3) behavioralAnomalies++;
if (behavioralDNA.geoVariability > 2) behavioralAnomalies++;
if (behavioralDNA.ipVariability > 4) behavioralAnomalies++;

if (behavioralAnomalies >= 2) {
indicators.count++;
indicators.types.push('Behavioral Anomalies');
indicators.details.behavioral = behavioralAnomalies;
}
}

// 5. Failed-to-Success Pattern Indicator
const failedSuccessPatterns = correlationData.temporal.failedSuccessPatterns.filter(pattern =>
pattern.user === user && pattern.timeDiff < 3
);
if (failedSuccessPatterns.length > 0) {
indicators.count++;
indicators.types.push('Suspicious Recovery');
indicators.details.suspiciousRecovery = failedSuccessPatterns;
}

// 6. Privilege Escalation Indicator
const privilegeEscalation = correlationData.behavioral.privilegeEscalation.find(esc => esc.user === user);
if (privilegeEscalation && privilegeEscalation.escalationRatio > 50) {
indicators.count++;
indicators.types.push('Privilege Escalation');
indicators.details.privilegeEscalation = privilegeEscalation;
}

// 7. High Geographic Variability
if (profile.countries.size > 3) {
indicators.count++;
indicators.types.push('High Geographic Variability');
indicators.details.geoVariability = profile.countries.size;
}

// 8. Shared Infrastructure Risk
const sharedIPs = Object.entries(correlationData.infrastructure.sharedIPs).filter(([ip, data]) =>
data.users.includes(user) && !data.isPrivate && data.count > 3
);
if (sharedIPs.length > 0) {
indicators.count++;
indicators.types.push('Shared Infrastructure Risk');
indicators.details.sharedInfrastructure = sharedIPs;
}

return indicators;
}

function analyzeInfrastructureBehavioralCorrelations() {
// Find users who share infrastructure AND have similar behavioral patterns
const behavioralClusters = correlationData.behavioral.behavioralClusters;
const sharedIPs = correlationData.infrastructure.sharedIPs;

Object.entries(behavioralClusters).forEach(([clusterKey, cluster]) => {
if (cluster.similarity > 0.9) {
// Check if these users also share infrastructure
const user1 = cluster.users[0];
const user2 = cluster.users[1];

const sharedInfrastructure = Object.entries(sharedIPs).filter(([ip, data]) =>
data.users.includes(user1) && data.users.includes(user2)
);

if (sharedInfrastructure.length > 0) {
correlationData.threats.push({
type: 'Coordinated Account Compromise',
user: `${user1} & ${user2}`,
description: `Identical behavioral patterns + shared infrastructure (${sharedInfrastructure.length} IPs)`,
severity: 'critical',
correlation: 'infrastructure-behavioral'
});
}
}
});
}

function analyzeTemporalGeographicCorrelations() {
// Find users with both impossible travel AND rapid authentication
const impossibleTravelUsers = new Set(correlationData.geographic.impossibleTravel.map(travel => travel.user));
const rapidAuthUsers = new Set(correlationData.temporal.rapidSequences
.filter(seq => seq.timeDiff < 2)
.map(seq => seq.user)
);

// Users with both temporal and geographic anomalies
const correlatedUsers = [...impossibleTravelUsers].filter(user => rapidAuthUsers.has(user));

correlatedUsers.forEach(user => {
const impossibleEvents = correlationData.geographic.impossibleTravel.filter(travel => travel.user === user);
const rapidEvents = correlationData.temporal.rapidSequences.filter(seq => seq.user === user && seq.timeDiff < 2);

correlationData.threats.push({
type: 'Temporal-Geographic Attack Vector',
user,
description: `Impossible travel (${impossibleEvents.length} events) + rapid authentication (${rapidEvents.length} events)`,
severity: 'critical',
correlation: 'temporal-geographic'
});
});
}

function updateCorrelationSummary() {
document.getElementById('criticalThreats').textContent = correlationData.threats.length;
document.getElementById('suspiciousActivity').textContent = correlationData.suspiciousActivity.length;
document.getElementById('impossibleTravel').textContent = correlationData.geographic.impossibleTravel.length;
document.getElementById('correlationScore').textContent = correlationData.correlationScore;
}

// Tab switching functionality
function showCorrelationTab(tabName) {
// Hide all panels
document.querySelectorAll('.correlation-panel').forEach(panel => {
panel.classList.add('hidden');
});

// Remove active class from all tabs
document.querySelectorAll('.correlation-tab, .correlation-tab-active').forEach(tab => {
tab.className = 'correlation-tab py-2 px-1 border-b-2 font-medium text-sm';
});

// Show selected panel and activate tab
document.getElementById(tabName + 'Panel').classList.remove('hidden');
document.getElementById(tabName + 'Tab').className = 'correlation-tab-active py-2 px-1 border-b-2 font-medium text-sm';

// Populate the selected tab's content
switch(tabName) {
case 'temporal':
populateTemporalPanel();
break;
case 'geographic':
populateGeographicPanel();
break;
case 'infrastructure':
populateInfrastructurePanel();
break;
case 'behavioral':
populateBehavioralPanel();
break;
}
}

function populateTemporalPanel() {
// Rapid sequences
const rapidContainer = document.getElementById('rapidSequences');
rapidContainer.innerHTML = '';

if (correlationData.temporal.rapidSequences.length === 0) {
rapidContainer.innerHTML = '<p class="text-sm text-gray-600 dark:text-gray-400">No rapid authentication sequences detected</p>';
} else {
correlationData.temporal.rapidSequences.slice(0, 10).forEach(seq => {
const colorClass = seq.riskLevel === 'critical' ? 'red' : seq.riskLevel === 'high' ? 'orange' : 'yellow';
rapidContainer.innerHTML += `
<div class="flex justify-between items-center p-3 bg-${colorClass}-50 dark:bg-${colorClass}-900/20 border border-${colorClass}-200 dark:border-${colorClass}-800 rounded-lg">
<div>
<div class="font-medium text-${colorClass}-800 dark:text-${colorClass}-200 text-sm">${seq.user.split('@')[0]}</div>
<div class="text-xs text-${colorClass}-600 dark:text-${colorClass}-400">${seq.timeDiff}s between attempts</div>
</div>
<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-${colorClass}-100 text-${colorClass}-800 dark:bg-${colorClass}-900 dark:text-${colorClass}-200">
${seq.riskLevel.toUpperCase()}
</span>
</div>
`;
});
}

// Failed-to-success patterns
const failedSuccessContainer = document.getElementById('failedSuccessPatterns');
failedSuccessContainer.innerHTML = '';

if (correlationData.temporal.failedSuccessPatterns.length === 0) {
failedSuccessContainer.innerHTML = '<p class="text-sm text-gray-600 dark:text-gray-400">No suspicious recovery patterns detected</p>';
} else {
correlationData.temporal.failedSuccessPatterns.slice(0, 10).forEach(pattern => {
const colorClass = pattern.riskLevel === 'high' ? 'orange' : 'yellow';
failedSuccessContainer.innerHTML += `
<div class="flex justify-between items-center p-3 bg-${colorClass}-50 dark:bg-${colorClass}-900/20 border border-${colorClass}-200 dark:border-${colorClass}-800 rounded-lg">
<div>
<div class="font-medium text-${colorClass}-800 dark:text-${colorClass}-200 text-sm">${pattern.user.split('@')[0]}</div>
<div class="text-xs text-${colorClass}-600 dark:text-${colorClass}-400">Recovery in ${pattern.timeDiff}s</div>
</div>
<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-${colorClass}-100 text-${colorClass}-800 dark:bg-${colorClass}-900 dark:text-${colorClass}-200">
${pattern.riskLevel.toUpperCase()}
</span>
</div>
`;
});
}

// Velocity chart
createVelocityChart();
}

function populateGeographicPanel() {
// Impossible travel
const impossibleTravelContainer = document.getElementById('impossibleTravelList');
impossibleTravelContainer.innerHTML = '';

if (correlationData.geographic.impossibleTravel.length === 0) {
impossibleTravelContainer.innerHTML = '<p class="text-sm text-gray-600 dark:text-gray-400">No impossible travel detected</p>';
} else {
correlationData.geographic.impossibleTravel.forEach(travel => {
const colorClass = travel.riskLevel === 'critical' ? 'red' : 'orange';
impossibleTravelContainer.innerHTML += `
<div class="p-3 bg-${colorClass}-50 dark:bg-${colorClass}-900/20 border border-${colorClass}-200 dark:border-${colorClass}-800 rounded-lg">
<div class="font-medium text-${colorClass}-800 dark:text-${colorClass}-200 text-sm">${travel.user.split('@')[0]}</div>
<div class="text-xs text-${colorClass}-600 dark:text-${colorClass}-400 mt-1">
${travel.fromCity} → ${travel.toCity}<br>
${travel.distance}km in ${travel.timeDiff}h (${travel.velocity} km/h)
</div>
</div>
`;
});
}

// Geographic velocity map
const geoVelocityContainer = document.getElementById('geoVelocityMap');
geoVelocityContainer.innerHTML = '';

Object.entries(correlationData.geographic.geoVelocity).slice(0, 5).forEach(([user, events]) => {
if (events.length > 1) {
const uniqueCities = [...new Set(events.map(e => e.city))];
geoVelocityContainer.innerHTML += `
<div class="p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
<div class="font-medium text-blue-800 dark:text-blue-200 text-sm">${user.split('@')[0]}</div>
<div class="text-xs text-blue-600 dark:text-blue-400 mt-1">
${uniqueCities.length} locations: ${uniqueCities.join(', ')}
</div>
</div>
`;
}
});

// Country transitions
const countryTransitionsContainer = document.getElementById('countryTransitions');
countryTransitionsContainer.innerHTML = '';

const transitions = Object.entries(correlationData.geographic.countryTransitions)
.sort(([,a], [,b]) => b - a)
.slice(0, 8);

if (transitions.length === 0) {
countryTransitionsContainer.innerHTML = '<p class="text-sm text-gray-600 dark:text-gray-400">No country transitions detected</p>';
} else {
transitions.forEach(([transition, count]) => {
countryTransitionsContainer.innerHTML += `
<div class="flex justify-between items-center p-2 bg-gray-100 dark:bg-gray-700 rounded">
<span class="text-sm text-gray-700 dark:text-gray-300">${transition}</span>
<span class="font-medium text-gray-900 dark:text-white">${count}</span>
</div>
`;
});
}
}

function populateInfrastructurePanel() {
// Shared IPs
const sharedIPsContainer = document.getElementById('sharedIPs');
sharedIPsContainer.innerHTML = '';

const sharedIPEntries = Object.entries(correlationData.infrastructure.sharedIPs)
.sort(([,a], [,b]) => b.count - a.count)
.slice(0, 10);

if (sharedIPEntries.length === 0) {
sharedIPsContainer.innerHTML = '<p class="text-sm text-gray-600 dark:text-gray-400">No shared IP addresses detected</p>';
} else {
sharedIPEntries.forEach(([ip, data]) => {
const colorClass = data.riskLevel === 'high' ? 'red' : data.riskLevel === 'medium' ? 'yellow' : 'blue';
sharedIPsContainer.innerHTML += `
<div class="p-3 bg-${colorClass}-50 dark:bg-${colorClass}-900/20 border border-${colorClass}-200 dark:border-${colorClass}-800 rounded-lg">
<div class="font-mono text-sm font-medium text-${colorClass}-800 dark:text-${colorClass}-200">${ip}</div>
<div class="text-xs text-${colorClass}-600 dark:text-${colorClass}-400 mt-1">
${data.count} users • ${data.isPrivate ? 'Private' : 'Public'} IP
</div>
</div>
`;
});
}

// Device overlap
const deviceOverlapContainer = document.getElementById('deviceOverlap');
deviceOverlapContainer.innerHTML = '';

const deviceEntries = Object.entries(correlationData.infrastructure.deviceOverlap)
.sort(([,a], [,b]) => b.count - a.count)
.slice(0, 10);

if (deviceEntries.length === 0) {
deviceOverlapContainer.innerHTML = '<p class="text-sm text-gray-600 dark:text-gray-400">No device fingerprint overlap detected</p>';
} else {
deviceEntries.forEach(([fingerprint, data]) => {
const colorClass = data.riskLevel === 'high' ? 'red' : data.riskLevel === 'medium' ? 'yellow' : 'green';
deviceOverlapContainer.innerHTML += `
<div class="p-3 bg-${colorClass}-50 dark:bg-${colorClass}-900/20 border border-${colorClass}-200 dark:border-${colorClass}-800 rounded-lg">
<div class="text-sm font-medium text-${colorClass}-800 dark:text-${colorClass}-200">${fingerprint.replace('_', ' / ')}</div>
<div class="text-xs text-${colorClass}-600 dark:text-${colorClass}-400 mt-1">
${data.count} users sharing this configuration
</div>
</div>
`;
});
}

// Infrastructure chart
createInfrastructureChart();
}

function populateBehavioralPanel() {
// Behavioral clusters
const behavioralClustersContainer = document.getElementById('behavioralClusters');
behavioralClustersContainer.innerHTML = '';

const clusterEntries = Object.entries(correlationData.behavioral.behavioralClusters)
.sort(([,a], [,b]) => b.similarity - a.similarity)
.slice(0, 10);

if (clusterEntries.length === 0) {
behavioralClustersContainer.innerHTML = '<p class="text-sm text-gray-600 dark:text-gray-400">No behavioral clusters detected</p>';
} else {
clusterEntries.forEach(([, cluster]) => {
const colorClass = cluster.riskLevel === 'high' ? 'red' : 'yellow';
behavioralClustersContainer.innerHTML += `
<div class="p-3 bg-${colorClass}-50 dark:bg-${colorClass}-900/20 border border-${colorClass}-200 dark:border-${colorClass}-800 rounded-lg">
<div class="text-sm font-medium text-${colorClass}-800 dark:text-${colorClass}-200">
${cluster.users.map(u => u.split('@')[0]).join(' & ')}
</div>
<div class="text-xs text-${colorClass}-600 dark:text-${colorClass}-400 mt-1">
${Math.round(cluster.similarity * 100)}% behavioral similarity
</div>
</div>
`;
});
}

// Privilege escalation
const privilegeEscalationContainer = document.getElementById('privilegeEscalation');
privilegeEscalationContainer.innerHTML = '';

if (correlationData.behavioral.privilegeEscalation.length === 0) {
privilegeEscalationContainer.innerHTML = '<p class="text-sm text-gray-600 dark:text-gray-400">No privilege escalation patterns detected</p>';
} else {
correlationData.behavioral.privilegeEscalation.forEach(escalation => {
const colorClass = escalation.riskLevel === 'high' ? 'red' : 'orange';
privilegeEscalationContainer.innerHTML += `
<div class="p-3 bg-${colorClass}-50 dark:bg-${colorClass}-900/20 border border-${colorClass}-200 dark:border-${colorClass}-800 rounded-lg">
<div class="text-sm font-medium text-${colorClass}-800 dark:text-${colorClass}-200">${escalation.user.split('@')[0]}</div>
<div class="text-xs text-${colorClass}-600 dark:text-${colorClass}-400 mt-1">
${escalation.escalationRatio}% admin access attempts
</div>
</div>
`;
});
}

// Behavioral chart
createBehavioralChart();
}

function createVelocityChart() {
const ctx = document.getElementById('velocityChart').getContext('2d');

// Prepare velocity data
const velocityData = [];
Object.entries(correlationData.temporal.userSequences).forEach(([user, events]) => {
if (events.length > 1) {
for (let i = 1; i < events.length; i++) {
const timeDiff = (events[i].timestamp - events[i-1].timestamp) / 1000;
if (timeDiff < 3600) { // Only show events within 1 hour
velocityData.push({
x: timeDiff,
y: 1,
user: user
});
}
}
}
});

new Chart(ctx, {
type: 'scatter',
data: {
datasets: [{
label: 'Authentication Velocity',
data: velocityData,
backgroundColor: 'rgba(239, 68, 68, 0.6)',
borderColor: 'rgba(220, 38, 38, 1)',
pointRadius: 6
}]
},
options: {
responsive: true,
maintainAspectRatio: false,
plugins: {
legend: { display: false }
},
scales: {
x: {
title: { display: true, text: 'Time Between Events (seconds)' },
type: 'logarithmic'
},
y: {
title: { display: true, text: 'Event Count' },
beginAtZero: true
}
}
}
});
}

function createInfrastructureChart() {
const ctx = document.getElementById('infrastructureChart').getContext('2d');

const ipData = Object.entries(correlationData.infrastructure.sharedIPs)
.map(([ip, data]) => ({
ip: ip.split('.').pop(), // Show last octet for privacy
count: data.count,
isPrivate: data.isPrivate
}))
.sort((a, b) => b.count - a.count)
.slice(0, 10);

new Chart(ctx, {
type: 'bar',
data: {
labels: ipData.map(d => d.ip),
datasets: [{
label: 'Users per IP',
data: ipData.map(d => d.count),
backgroundColor: ipData.map(d => d.isPrivate ? '#10B981' : '#F59E0B'),
borderWidth: 0
}]
},
options: {
responsive: true,
maintainAspectRatio: false,
plugins: {
legend: { display: false }
},
scales: {
x: {
title: { display: true, text: 'IP Address (last octet)' }
},
y: {
title: { display: true, text: 'Number of Users' },
beginAtZero: true
}
}
}
});
}

function createBehavioralChart() {
const ctx = document.getElementById('behavioralChart').getContext('2d');

const dnaData = Object.entries(correlationData.behavioral.behavioralDNA)
.map(([user, dna]) => ({
x: dna.ipVariability,
y: dna.failureRate * 100,
user: user.split('@')[0]
}))
.slice(0, 20);

new Chart(ctx, {
type: 'scatter',
data: {
datasets: [{
label: 'Behavioral Profile',
data: dnaData,
backgroundColor: 'rgba(139, 92, 246, 0.6)',
borderColor: 'rgba(124, 58, 237, 1)',
pointRadius: 8
}]
},
options: {
responsive: true,
maintainAspectRatio: false,
plugins: {
legend: { display: false }
},
scales: {
x: {
title: { display: true, text: 'IP Address Variability' },
beginAtZero: true
},
y: {
title: { display: true, text: 'Failure Rate (%)' },
beginAtZero: true
}
}
}
});
}

// Privileged Actions Chart
function createPrivilegedChart() {
const ctx = document.getElementById('privilegedChart').getContext('2d');

// Analyze privileged actions from log data
const privilegedData = analyzePrivilegedActions();

if (privilegedData.total === 0) {
// Show "no data" message
ctx.fillStyle = document.documentElement.classList.contains('dark') ? '#9CA3AF' : '#6B7280';
ctx.textAlign = 'center';
ctx.font = '14px sans-serif';
ctx.fillText('No privileged actions detected', ctx.canvas.width / 2, ctx.canvas.height / 2);
return;
}

new Chart(ctx, {
type: 'doughnut',
data: {
labels: privilegedData.labels,
datasets: [{
data: privilegedData.values,
backgroundColor: [
'#DC2626', // Critical - Red
'#EA580C', // High - Orange
'#CA8A04', // Medium - Yellow
'#16A34A', // Low - Green
'#2563EB' // Info - Blue
],
borderWidth: 0
}]
},
options: {
responsive: true,
maintainAspectRatio: false,
onClick: (event, elements) => {
if (elements.length > 0) {
const index = elements[0].index;
const label = privilegedData.labels[index];
const value = privilegedData.values[index];
const details = privilegedData.details[index];
showPrivilegedBreakdownModal(label, value, details);
}
},
plugins: {
legend: {
position: 'bottom',
labels: {
color: document.documentElement.classList.contains('dark') ? '#D1D5DB' : '#374151',
usePointStyle: true,
padding: 15
}
}
}
}
});
}

function analyzePrivilegedActions() {
const privilegedCategories = {
'Critical Admin': 0,
'High Privilege': 0,
'Medium Privilege': 0,
'Low Privilege': 0,
'Info Access': 0
};

const privilegedDetails = {
'Critical Admin': [],
'High Privilege': [],
'Medium Privilege': [],
'Low Privilege': [],
'Info Access': []
};

logData.forEach(log => {
const appName = (log.appDisplayName || '').toLowerCase();
const user = log.userPrincipalName || log.userId || 'Unknown';
const isSuccess = log.status?.errorCode === 0 || log.status?.errorCode === "0";

// Critical Admin Actions
if (appName.includes('global admin') ||
appName.includes('security center') ||
appName.includes('identity governance') ||
appName.includes('privileged identity management')) {
privilegedCategories['Critical Admin']++;
privilegedDetails['Critical Admin'].push({
user: user.split('@')[0],
app: log.appDisplayName,
timestamp: log.time || log.createdDateTime || log.timestamp,
success: isSuccess,
ip: log.ipAddress
});
}
// High Privilege Actions
else if (appName.includes('azure portal') ||
appName.includes('azure active directory') ||
appName.includes('microsoft 365 admin') ||
appName.includes('exchange admin') ||
appName.includes('compliance center')) {
privilegedCategories['High Privilege']++;
privilegedDetails['High Privilege'].push({
user: user.split('@')[0],
app: log.appDisplayName,
timestamp: log.time || log.createdDateTime || log.timestamp,
success: isSuccess,
ip: log.ipAddress
});
}
// Medium Privilege Actions
else if (appName.includes('sharepoint admin') ||
appName.includes('teams admin') ||
appName.includes('power platform') ||
appName.includes('intune') ||
appName.includes('defender')) {
privilegedCategories['Medium Privilege']++;
privilegedDetails['Medium Privilege'].push({
user: user.split('@')[0],
app: log.appDisplayName,
timestamp: log.time || log.createdDateTime || log.timestamp,
success: isSuccess,
ip: log.ipAddress
});
}
// Low Privilege Actions
else if (appName.includes('admin') ||
appName.includes('management') ||
appName.includes('governance')) {
privilegedCategories['Low Privilege']++;
privilegedDetails['Low Privilege'].push({
user: user.split('@')[0],
app: log.appDisplayName,
timestamp: log.time || log.createdDateTime || log.timestamp,
success: isSuccess,
ip: log.ipAddress
});
}
// Info Access (PowerBI, Analytics, etc.)
else if (appName.includes('power bi') ||
appName.includes('analytics') ||
appName.includes('reporting') ||
appName.includes('dashboard')) {
privilegedCategories['Info Access']++;
privilegedDetails['Info Access'].push({
user: user.split('@')[0],
app: log.appDisplayName,
timestamp: log.time || log.createdDateTime || log.timestamp,
success: isSuccess,
ip: log.ipAddress
});
}
});

// Filter out empty categories
const labels = [];
const values = [];
const details = [];

Object.entries(privilegedCategories).forEach(([category, count]) => {
if (count > 0) {
labels.push(category);
values.push(count);
details.push(privilegedDetails[category]);
}
});

return {
labels,
values,
details,
total: values.reduce((a, b) => a + b, 0)
};
}

// Status Breakdown Modal
function showStatusBreakdownModal(status, count) {
const isSuccess = status === 'Successful';
const relevantLogs = logData.filter(log => {
const logSuccess = log.status?.errorCode === 0 || log.status?.errorCode === "0";
return logSuccess === isSuccess;
});

let modalContent = `
<div class="space-y-6">
<div class="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
<div>
<h2 class="text-xl font-semibold text-gray-900 dark:text-white">${status} Sign-ins Analysis</h2>
<p class="text-sm text-gray-600 dark:text-gray-400 mt-1">Total events: ${count.toLocaleString()}</p>
</div>
<div class="text-4xl font-bold ${isSuccess ? 'text-green-600' : 'text-red-600'}">${count.toLocaleString()}</div>
</div>

<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
`;

// Top users for this status
const userStats = {};
relevantLogs.forEach(log => {
const user = log.userPrincipalName || log.userId || 'Unknown';
userStats[user] = (userStats[user] || 0) + 1;
});

const topUsers = Object.entries(userStats)
.sort(([,a], [,b]) => b - a)
.slice(0, 8);

modalContent += `
<div>
<h3 class="text-lg font-medium text-gray-900 dark:text-white mb-3">Top Users</h3>
<div class="space-y-2 max-h-64 overflow-y-auto">
`;

topUsers.forEach(([user, userCount]) => {
const percentage = ((userCount / count) * 100).toFixed(1);
modalContent += `
<div class="flex justify-between items-center p-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded-lg">
<div class="truncate flex-1 mr-3">
<div class="font-medium text-gray-900 dark:text-white text-sm">${user}</div>
<div class="text-xs text-gray-500 dark:text-gray-400">${percentage}% of ${status.toLowerCase()} events</div>
</div>
<div class="text-lg font-bold ${isSuccess ? 'text-green-600' : 'text-red-600'}">${userCount}</div>
</div>
`;
});

// Top applications for this status
const appStats = {};
relevantLogs.forEach(log => {
const app = log.appDisplayName || log.resourceDisplayName || 'Unknown';
appStats[app] = (appStats[app] || 0) + 1;
});

const topApps = Object.entries(appStats)
.sort(([,a], [,b]) => b - a)
.slice(0, 8);

modalContent += `
</div>
</div>
<div>
<h3 class="text-lg font-medium text-gray-900 dark:text-white mb-3">Top Applications</h3>
<div class="space-y-2 max-h-64 overflow-y-auto">
`;

topApps.forEach(([app, appCount]) => {
const percentage = ((appCount / count) * 100).toFixed(1);
modalContent += `
<div class="flex justify-between items-center p-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded-lg">
<div class="truncate flex-1 mr-3">
<div class="font-medium text-gray-900 dark:text-white text-sm">${app}</div>
<div class="text-xs text-gray-500 dark:text-gray-400">${percentage}% of ${status.toLowerCase()} events</div>
</div>
<div class="text-lg font-bold ${isSuccess ? 'text-green-600' : 'text-red-600'}">${appCount}</div>
</div>
`;
});

modalContent += `
</div>
</div>
</div>
`;

// Additional insights for failed logins
if (!isSuccess) {
const errorStats = {};
relevantLogs.forEach(log => {
const errorCode = log.status?.errorCode || 'Unknown';
errorStats[errorCode] = (errorStats[errorCode] || 0) + 1;
});

const topErrors = Object.entries(errorStats)
.sort(([,a], [,b]) => b - a)
.slice(0, 5);

modalContent += `
<div class="mt-6">
<h3 class="text-lg font-medium text-gray-900 dark:text-white mb-3">Top Error Codes</h3>
<div class="grid grid-cols-1 gap-3">
`;

topErrors.forEach(([errorCode, errorCount]) => {
const percentage = ((errorCount / count) * 100).toFixed(1);
let errorDescription = 'Unknown Error';

// Common error code descriptions
switch(errorCode) {
case '50126': errorDescription = 'Invalid username or password'; break;
case '50053': errorDescription = 'Account locked or disabled'; break;
case '50055': errorDescription = 'Password expired'; break;
case '50074': errorDescription = 'Strong authentication required (MFA)'; break;
case '50076': errorDescription = 'Strong authentication required'; break;
case '50079': errorDescription = 'User needs to enroll for MFA'; break;
case '50158': errorDescription = 'External security challenge not satisfied'; break;
default: if (errorCode !== 'Unknown') errorDescription = `Error code ${errorCode}`;
}

modalContent += `
<div class="flex justify-between items-center p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
<div class="flex-1">
<div class="font-medium text-red-800 dark:text-red-200 text-sm">${errorDescription}</div>
<div class="text-xs text-red-600 dark:text-red-400">Code: ${errorCode} • ${percentage}% of failures</div>
</div>
<div class="text-lg font-bold text-red-600 dark:text-red-400">${errorCount}</div>
</div>
`;
});

modalContent += `
</div>
</div>
`;
}

modalContent += `</div>`;

// Show modal
document.getElementById('modalTitle').textContent = `${status} Sign-ins Breakdown`;
document.getElementById('modalContent').innerHTML = modalContent;
document.getElementById('deviationModal').classList.remove('hidden');
}

// Privileged Actions Breakdown Modal
function showPrivilegedBreakdownModal(category, count, details) {
let modalContent = `
<div class="space-y-6">
<div class="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
<div>
<h2 class="text-xl font-semibold text-gray-900 dark:text-white">${category} Actions</h2>
<p class="text-sm text-gray-600 dark:text-gray-400 mt-1">Total privileged actions: ${count.toLocaleString()}</p>
</div>
<div class="text-4xl font-bold text-purple-600">${count.toLocaleString()}</div>
</div>

<div class="max-h-96 overflow-y-auto">
<h3 class="text-lg font-medium text-gray-900 dark:text-white mb-3">Recent Actions</h3>
<div class="space-y-2">
`;

// Sort by timestamp and show recent actions
const sortedDetails = details
.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
.slice(0, 20);

sortedDetails.forEach(action => {
const timestamp = new Date(action.timestamp).toLocaleString();
const statusColor = action.success ? 'green' : 'red';
const statusText = action.success ? 'Success' : 'Failed';

modalContent += `
<div class="flex items-center justify-between p-3 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded-lg">
<div class="flex-1">
<div class="flex items-center space-x-3">
<div class="font-medium text-gray-900 dark:text-white text-sm">${action.user}</div>
<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-${statusColor}-100 text-${statusColor}-800 dark:bg-${statusColor}-900 dark:text-${statusColor}-200">
${statusText}
</span>
</div>
<div class="text-sm text-gray-600 dark:text-gray-400 mt-1">${action.app}</div>
<div class="flex items-center space-x-4 text-xs text-gray-500 dark:text-gray-400 mt-1">
<span>${timestamp}</span>
${action.ip ? `<span>IP: ${action.ip}</span>` : ''}
</div>
</div>
</div>
`;
});

modalContent += `
</div>
</div>

<div class="p-4 bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg">
<h4 class="font-medium text-purple-800 dark:text-purple-200 mb-2">Risk Assessment</h4>
<p class="text-sm text-purple-700 dark:text-purple-300">
${getRiskAssessment(category, count, details)}
</p>
</div>
</div>
`;

// Show modal
document.getElementById('modalTitle').textContent = `${category} Privileged Actions Analysis`;
document.getElementById('modalContent').innerHTML = modalContent;
document.getElementById('deviationModal').classList.remove('hidden');
}

function getRiskAssessment(category, count, details) {
const uniqueUsers = new Set(details.map(d => d.user)).size;
const failureRate = details.filter(d => !d.success).length / details.length;
const uniqueIPs = new Set(details.map(d => d.ip).filter(ip => ip)).size;

let assessment = '';

switch(category) {
case 'Critical Admin':
assessment = `Critical administrative actions require immediate review. ${uniqueUsers} unique user(s) performed these actions with a ${(failureRate * 100).toFixed(1)}% failure rate.`;
break;
case 'High Privilege':
assessment = `High-privilege activities from ${uniqueUsers} user(s) across ${uniqueIPs} IP address(es). Monitor for unauthorized access patterns.`;
break;
case 'Medium Privilege':
assessment = `Medium-privilege operations show ${uniqueUsers} active administrator(s). Review for policy compliance and necessary access.`;
break;
case 'Low Privilege':
assessment = `Administrative activities from ${uniqueUsers} user(s). Consider principle of least privilege and role-based access.`;
break;
case 'Info Access':
assessment = `Information access by ${uniqueUsers} user(s). Monitor for data exfiltration patterns and unusual access times.`;
break;
default:
assessment = `Review these privileged actions for compliance with organizational security policies.`;
}

if (failureRate > 0.2) {
assessment += ` High failure rate detected - investigate potential security incidents.`;
}

return assessment;
}
</script>
</body>
</html>


```
