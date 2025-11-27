// Global variables
const API_BASE_URL = 'http://localhost:5000';
let dashboardData = null;
let statusChart = null;

// DOM elements
const detectionToggle = document.getElementById('detection-toggle');
const refreshBtn = document.getElementById('refresh-btn');
const navLinks = document.querySelectorAll('.nav-menu a');

// Notification Center Logic
let notifications = [];

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
  initializeDashboard();
  loadDashboardData();
  initializeNavigation();
  
  // Set up event listeners
  detectionToggle.addEventListener('change', toggleDetection);
  refreshBtn.addEventListener('click', refreshData);
  document.getElementById('generate-report-btn').addEventListener('click', generateReport);
  
  // Add form submission listeners
  document.getElementById('blacklist-form').addEventListener('submit', addToBlacklist);
  document.getElementById('whitelist-form').addEventListener('submit', addToWhitelist);
  
  // Set up API key management
  document.getElementById('api-key-form').addEventListener('submit', addApiKey);
  
  // Set up search and filter for scan history
  document.getElementById('scan-search').addEventListener('input', filterScanHistory);
  document.getElementById('status-filter').addEventListener('change', filterScanHistory);
  
  // Notification bell logic
  const bell = document.getElementById('notification-bell');
  const dropdown = document.getElementById('notification-dropdown');
  const clearBtn = document.getElementById('clear-notifications');
  bell.addEventListener('click', (e) => {
    e.stopPropagation();
    dropdown.classList.toggle('hidden');
  });
  clearBtn.addEventListener('click', clearNotifications);
  document.addEventListener('click', (e) => {
    if (!dropdown.classList.contains('hidden')) {
      dropdown.classList.add('hidden');
    }
  });
  dropdown.addEventListener('click', (e) => e.stopPropagation());
  updateNotificationUI();
});

// Initialize dashboard with saved settings
function initializeDashboard() {
  chrome.storage.sync.get(['phishingDetectionEnabled'], (result) => {
    const isDetectionEnabled = result.phishingDetectionEnabled !== undefined 
      ? result.phishingDetectionEnabled 
      : true;
      
    detectionToggle.checked = isDetectionEnabled;
  });
}

// Initialize navigation
function initializeNavigation() {
  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      
      // Get the section id from data attribute
      const sectionId = link.getAttribute('data-section');
      
      // Remove active class from all links and sections
      navLinks.forEach(navLink => navLink.classList.remove('active'));
      document.querySelectorAll('.dashboard-section').forEach(section => {
        section.classList.remove('active');
      });
      
      // Add active class to clicked link and corresponding section
      link.classList.add('active');
      document.getElementById(sectionId).classList.add('active');
    });
  });
}

// Toggle phishing detection
function toggleDetection() {
  const isDetectionEnabled = detectionToggle.checked;
  
  // Save setting to Chrome storage
  chrome.storage.sync.set({ phishingDetectionEnabled: isDetectionEnabled });
  
  // Send message to background script and content script
  chrome.runtime.sendMessage({ action: 'toggleDetection', enabled: isDetectionEnabled });
  
  // Send to active Gmail tab if present
  chrome.tabs.query({ active: true, url: '*://mail.google.com/*' }, (tabs) => {
    if (tabs.length > 0) {
      chrome.tabs.sendMessage(tabs[0].id, { action: 'toggleDetection', enabled: isDetectionEnabled });
    }
  });
}

// Refresh all data
function refreshData() {
  refreshBtn.innerHTML = '<span class="btn-icon">⟳</span><span class="btn-text">Refreshing...</span>';
  refreshBtn.disabled = true;
  
  loadDashboardData().then(() => {
    refreshBtn.innerHTML = '<span class="btn-icon">&#8635;</span><span class="btn-text">Refresh Data</span>';
    refreshBtn.disabled = false;
  }).catch(error => {
    console.error('Error refreshing data:', error);
    refreshBtn.innerHTML = '<span class="btn-icon">&#8635;</span><span class="btn-text">Refresh Failed</span>';
    setTimeout(() => {
      refreshBtn.innerHTML = '<span class="btn-icon">&#8635;</span><span class="btn-text">Refresh Data</span>';
      refreshBtn.disabled = false;
    }, 2000);
  });
}

// Load all dashboard data
async function loadDashboardData() {
  try {
    console.log('Loading dashboard data...');
    const response = await fetch(`${API_BASE_URL}/get_dashboard_data`);
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || `HTTP error ${response.status}`);
    }
    
    dashboardData = await response.json();
    console.log('Dashboard data loaded successfully:', dashboardData);
    
    if (!dashboardData || !dashboardData.statistics) {
      throw new Error('Invalid dashboard data format');
    }
    
    // Update dashboard with the data
    updateStatistics(dashboardData.statistics);
    updateStatusChart(dashboardData.statistics);
    updateRecentActivity(dashboardData.recent_scans);
    updateScanHistory(dashboardData.recent_scans);
    updateBlacklist(dashboardData.blacklist);
    updateWhitelist(dashboardData.whitelist);
    
    return dashboardData;
  } catch (error) {
    console.error('Error loading dashboard data:', error);
    showError(`Failed to load dashboard data: ${error.message}`);
    // Initialize with default values if data loading fails
    const defaultStats = {
      total_scans: 0,
      phishing_scans: 0,
      suspicious_scans: 0,
      safe_scans: 0
    };
    updateStatistics(defaultStats);
    updateStatusChart(defaultStats);
    return null;
  }
}

// Update statistics section
function updateStatistics(statistics) {
  try {
    console.log('Updating statistics:', statistics);
    document.getElementById('total-scans').textContent = statistics.total_scans || 0;
    document.getElementById('phishing-scans').textContent = statistics.phishing_scans || 0;
    document.getElementById('suspicious-scans').textContent = statistics.suspicious_scans || 0;
    document.getElementById('safe-scans').textContent = statistics.safe_scans || 0;
  } catch (error) {
    console.error('Error updating statistics:', error);
    showError(`Failed to update statistics: ${error.message}`);
  }
}

// Update status chart
function updateStatusChart(statistics) {
  try {
    console.log('Updating status chart with statistics:', statistics);
    const canvas = document.getElementById('status-chart');
    console.log('Canvas element:', canvas);
    
    if (!canvas) {
      throw new Error('Canvas element not found');
    }
    
    // If chart already exists, destroy it
    if (statusChart) {
      console.log('Destroying existing chart');
      statusChart.destroy();
    }
    
    // Create new chart
    console.log('Creating new chart');
    statusChart = new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: ['Safe', 'Suspicious', 'Phishing'],
        datasets: [{
          data: [
            statistics.safe_scans || 0,
            statistics.suspicious_scans || 0,
            statistics.phishing_scans || 0
          ],
          backgroundColor: [
            '#28a745',
            '#ffc107',
            '#dc3545'
          ],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: true,
            position: 'bottom'
          }
        }
      }
    });
    console.log('Chart created successfully');
  } catch (error) {
    console.error('Error updating status chart:', error);
    showError(`Failed to update chart: ${error.message}`);
  }
}

// Update recent activity section
function updateRecentActivity(scans) {
  const activityContainer = document.getElementById('recent-activities');
  
  if (!scans || scans.length === 0) {
    activityContainer.innerHTML = '<div class="no-data">No recent activity</div>';
    return;
  }
  
  // Take only the 10 most recent scans
  const recentScans = scans.slice(0, 10);
  
  // Clear previous activities
  activityContainer.innerHTML = '';
  
  // Add each activity
  recentScans.forEach(scan => {
    const activityItem = document.createElement('div');
    activityItem.className = 'activity-item';
    
    // Format the date
    const scanDate = new Date(scan.scan_date);
    const formattedDate = scanDate.toLocaleString();
    
    // Truncate URL
    const displayUrl = truncateUrl(scan.url, 40);
    
    activityItem.innerHTML = `
      <div><strong>${scan.status}</strong>: ${displayUrl}</div>
      <div class="activity-time">${formattedDate}</div>
    `;
    
    activityContainer.appendChild(activityItem);
  });
}

// Helper function to determine scan status based on blacklist/whitelist
function getScanStatus(url, domain, scanStatus, blacklist, whitelist) {
  if (blacklist && blacklist.some(entry => entry.pattern === domain || entry.pattern === url)) {
    return 'phishing';
  }
  if (whitelist && whitelist.some(entry => entry.pattern === domain || entry.pattern === url)) {
    return 'safe';
  }
  return scanStatus;
}

// Update scan history table
function updateScanHistory(scans) {
  const tableBody = document.getElementById('scan-history-tbody');
  
  if (!scans || scans.length === 0) {
    tableBody.innerHTML = `
      <tr>
        <td colspan="5" class="no-data">No scan history available</td>
      </tr>
    `;
    return;
  }
  
  // Clear previous history
  tableBody.innerHTML = '';
  
  // Add each scan
  scans.forEach(scan => {
    const row = document.createElement('tr');
    // Use the new logic to determine status
    const status = getScanStatus(scan.url, scan.domain, scan.status, dashboardData.blacklist, dashboardData.whitelist);
    
    // Determine status class
    let statusClass = '';
    switch (status.toLowerCase()) {
      case 'safe':
        statusClass = 'status-safe';
        break;
      case 'suspicious':
        statusClass = 'status-suspicious';
        break;
      case 'phishing':
        statusClass = 'status-phishing';
        break;
      default:
        statusClass = '';
    }
    
    row.innerHTML = `
      <td title="${scan.url}">${truncateUrl(scan.url, 30)}</td>
      <td>${scan.domain || '-'}</td>
      <td><span class="status-badge ${statusClass}">${status}</span></td>
      <td>${scan.detection_ratio || '-'}</td>
      <td>${scan.scan_date}</td>
    `;
    
    tableBody.appendChild(row);
  });
}

// Add a URL or domain to the blacklist
async function addToBlacklist(event) {
  event.preventDefault();
  
  const pattern = document.getElementById('blacklist-pattern').value.trim();
  const patternType = document.getElementById('blacklist-type').value;
  const notes = document.getElementById('blacklist-notes').value.trim();
  
  if (!pattern) {
    showError('Please enter a domain or URL');
    return;
  }
  
  try {
    const response = await fetch(`${API_BASE_URL}/manage_blacklist`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        pattern,
        pattern_type: patternType,
        notes
      }),
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to add to blacklist');
    }
    
    // Clear form
    document.getElementById('blacklist-form').reset();
    
    // Refresh data
    loadDashboardData();
    
    showSuccess('Added to blacklist successfully');
  } catch (error) {
    console.error('Error adding to blacklist:', error);
    showError(error.message);
  }
}

// Add a URL or domain to the whitelist
async function addToWhitelist(event) {
  event.preventDefault();
  
  const pattern = document.getElementById('whitelist-pattern').value.trim();
  const patternType = document.getElementById('whitelist-type').value;
  const notes = document.getElementById('whitelist-notes').value.trim();
  
  if (!pattern) {
    showError('Please enter a domain or URL');
    return;
  }
  
  try {
    const response = await fetch(`${API_BASE_URL}/manage_whitelist`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        pattern,
        pattern_type: patternType,
        notes
      }),
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to add to whitelist');
    }
    
    // Clear form
    document.getElementById('whitelist-form').reset();
    
    // Refresh data
    loadDashboardData();
    
    showSuccess('Added to whitelist successfully');
  } catch (error) {
    console.error('Error adding to whitelist:', error);
    showError(error.message);
  }
}

// Update blacklist table
function updateBlacklist(blacklist) {
  const tableBody = document.getElementById('blacklist-tbody');
  
  if (!blacklist || blacklist.length === 0) {
    tableBody.innerHTML = `
      <tr>
        <td colspan="5" class="no-data">No blacklist entries</td>
      </tr>
    `;
    return;
  }
  
  // Clear previous entries
  tableBody.innerHTML = '';
  
  // Add each entry
  blacklist.forEach(entry => {
    const row = document.createElement('tr');
    
    row.innerHTML = `
      <td title="${entry.pattern}">${truncateUrl(entry.pattern, 30)}</td>
      <td>${entry.pattern_type}</td>
      <td>${entry.date_added}</td>
      <td title="${entry.notes || ''}">${truncateText(entry.notes, 20) || '-'}</td>
      <td>
        <button class="action-btn delete-btn" data-id="${entry.id}" data-list="blacklist">Delete</button>
      </td>
    `;
    
    tableBody.appendChild(row);
  });
  
  // Add event listeners to delete buttons
  tableBody.querySelectorAll('.delete-btn').forEach(button => {
    button.addEventListener('click', handleListItemDelete);
  });
}

// Update whitelist table
function updateWhitelist(whitelist) {
  const tableBody = document.getElementById('whitelist-tbody');
  
  if (!whitelist || whitelist.length === 0) {
    tableBody.innerHTML = `
      <tr>
        <td colspan="5" class="no-data">No whitelist entries</td>
      </tr>
    `;
    return;
  }
  
  // Clear previous entries
  tableBody.innerHTML = '';
  
  // Add each entry
  whitelist.forEach(entry => {
    const row = document.createElement('tr');
    
    row.innerHTML = `
      <td title="${entry.pattern}">${truncateUrl(entry.pattern, 30)}</td>
      <td>${entry.pattern_type}</td>
      <td>${entry.date_added}</td>
      <td title="${entry.notes || ''}">${truncateText(entry.notes, 20) || '-'}</td>
      <td>
        <button class="action-btn delete-btn" data-id="${entry.id}" data-list="whitelist">Delete</button>
      </td>
    `;
    
    tableBody.appendChild(row);
  });
  
  // Add event listeners to delete buttons
  tableBody.querySelectorAll('.delete-btn').forEach(button => {
    button.addEventListener('click', handleListItemDelete);
  });
}

// Handle deletion of blacklist/whitelist items
async function handleListItemDelete(event) {
  const button = event.currentTarget;
  const id = button.getAttribute('data-id');
  const list = button.getAttribute('data-list');
  
  if (!confirm(`Are you sure you want to remove this item from the ${list}?`)) {
    return;
  }
  
  try {
    const endpoint = list === 'blacklist' ? '/manage_blacklist' : '/manage_whitelist';
    
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ id }),
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || `Failed to remove from ${list}`);
    }
    
    // Refresh data
    loadDashboardData();
    
    showSuccess(`Removed from ${list} successfully`);
  } catch (error) {
    console.error(`Error removing from ${list}:`, error);
    showError(error.message);
  }
}

// Filter scan history based on search and status filter
function filterScanHistory() {
  if (!dashboardData || !dashboardData.recent_scans) {
    return;
  }
  
  const searchTerm = document.getElementById('scan-search').value.toLowerCase();
  const statusFilter = document.getElementById('status-filter').value.toLowerCase();
  
  // Filter scans based on search term and status
  const filteredScans = dashboardData.recent_scans.filter(scan => {
    // Check if URL or domain matches search term
    const urlMatch = scan.url.toLowerCase().includes(searchTerm);
    const domainMatch = scan.domain && scan.domain.toLowerCase().includes(searchTerm);
    
    // Check if status matches filter (or if "all" is selected)
    const statusMatch = statusFilter === 'all' || scan.status.toLowerCase() === statusFilter;
    
    return (urlMatch || domainMatch) && statusMatch;
  });
  
  // Update table with filtered scans
  updateScanHistory(filteredScans);
}

// Helper function to truncate URL for display
function truncateUrl(url, maxLength = 30) {
  if (!url) return '';
  
  if (url.length <= maxLength) {
    return url;
  }
  
  // Try to extract domain
  let domain = url;
  try {
    const urlObj = new URL(url);
    domain = urlObj.hostname;
  } catch (e) {
    // URL parsing failed, use original string
  }
  
  if (domain.length <= maxLength) {
    return domain;
  }
  
  return domain.substring(0, maxLength - 3) + '...';
}

// Helper function to truncate text
function truncateText(text, maxLength = 30) {
  if (!text) return '';
  
  if (text.length <= maxLength) {
    return text;
  }
  
  return text.substring(0, maxLength - 3) + '...';
}

// Show success message (toast notification)
function showSuccess(message) {
  // Create toast element
  const toast = document.createElement('div');
  toast.className = 'toast success';
  toast.textContent = message;
  
  // Add to document
  document.body.appendChild(toast);
  
  // Remove after delay
  setTimeout(() => {
    toast.remove();
  }, 3000);
}

// Show error message (toast notification)
function showError(message) {
  const errorContainer = document.getElementById('error-message') || createErrorContainer();
  errorContainer.textContent = message;
  errorContainer.style.display = 'block';
  
  // Hide error after 5 seconds
  setTimeout(() => {
    errorContainer.style.display = 'none';
  }, 5000);
}

// Create error container if it doesn't exist
function createErrorContainer() {
  const container = document.createElement('div');
  container.id = 'error-message';
  container.className = 'error-message';
  document.querySelector('.dashboard-container').prepend(container);
  return container;
}

// Add toast styles to document
document.head.insertAdjacentHTML('beforeend', `
  <style>
    .toast {
      position: fixed;
      bottom: 20px;
      right: 20px;
      padding: 12px 20px;
      border-radius: 4px;
      color: white;
      font-size: 14px;
      z-index: 1000;
      animation: fadeIn 0.3s, fadeOut 0.3s 2.7s;
    }
    
    .toast.success {
      background-color: #28a745;
    }
    
    .toast.error {
      background-color: #dc3545;
    }
    
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    @keyframes fadeOut {
      from { opacity: 1; transform: translateY(0); }
      to { opacity: 0; transform: translateY(-20px); }
    }
  </style>
`);

// API Key Management Functions

// Load API keys from backend
async function loadApiKeys() {
  try {
    const response = await fetch(`${API_BASE_URL}/api_keys`);
    
    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }
    
    const data = await response.json();
    updateApiKeysList(data.api_keys);
    
    return data.api_keys;
  } catch (error) {
    console.error('Error loading API keys:', error);
    showError('Failed to load API keys. Please try again.');
    throw error;
  }
}

// Update dashboard with API keys
function updateApiKeysList(apiKeys) {
  const apiKeysList = document.getElementById('api-keys-list');
  
  if (!apiKeys || apiKeys.length === 0) {
    apiKeysList.innerHTML = '<div class="no-data">No API keys added yet</div>';
    return;
  }
  
  // Clear previous entries
  apiKeysList.innerHTML = '';
  
  // Add each API key
  apiKeys.forEach(key => {
    const keyItem = document.createElement('div');
    keyItem.className = 'api-key-item';
    
    // Format last used date
    const lastUsed = new Date(key.last_used);
    const formattedDate = lastUsed.toLocaleString();
    
    // Create status indicator based on rate limiting
    const statusIndicator = key.is_rate_limited 
      ? '<span class="status-badge status-phishing">Rate Limited</span>' 
      : '<span class="status-badge status-safe">Active</span>';
    
    keyItem.innerHTML = `
      <div class="api-key-prefix">${key.api_key_prefix}</div>
      <div class="api-key-usage">
        <span>Daily: ${key.daily_usage}</span>
        <span>Monthly: ${key.monthly_usage}</span>
        <span>Last used: ${formattedDate}</span>
        ${statusIndicator}
      </div>
      <div class="api-key-actions">
        <button class="delete-api-key" data-id="${key.id}">Remove</button>
      </div>
    `;
    
    apiKeysList.appendChild(keyItem);
  });
  
  // Add event listeners to delete buttons
  apiKeysList.querySelectorAll('.delete-api-key').forEach(button => {
    button.addEventListener('click', deleteApiKey);
  });
}

// Add API key to the backend
async function addApiKey(event) {
  event.preventDefault();
  
  const apiKeyInput = document.getElementById('api-key-input');
  const apiKey = apiKeyInput.value.trim();
  const skipValidation = document.getElementById('skip-validation-checkbox').checked;
  
  if (!apiKey) {
    showValidationError('Please enter a valid API key');
    return;
  }
  
  // Show validation in progress
  showValidationMessage(skipValidation ? 'Adding API key...' : 'Validating API key...', 'validating');
  
  try {
    const response = await fetch(`${API_BASE_URL}/api_keys`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        api_key: apiKey,
        skip_validation: skipValidation
      }),
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to add API key');
    }
    
    // Show validation success
    showValidationMessage(data.message || 'API key added successfully', 'success');
    
    // Clear form
    document.getElementById('api-key-form').reset();
    
    // Refresh API keys and dashboard data
    await Promise.all([loadApiKeys(), loadDashboardData()]);
    
    showSuccess('API key added successfully');
  } catch (error) {
    console.error('Error adding API key:', error);
    showValidationMessage(error.message || 'Invalid API key', 'error');
    showError(error.message || 'Failed to add API key');
  }
}

// Delete API key from the backend
async function deleteApiKey(event) {
  const button = event.currentTarget;
  const id = button.getAttribute('data-id');
  
  if (!confirm('Are you sure you want to remove this API key?')) {
    return;
  }
  
  try {
    const response = await fetch(`${API_BASE_URL}/api_keys`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ id }),
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Failed to remove API key');
    }
    
    // Refresh API keys and dashboard data
    await Promise.all([loadApiKeys(), loadDashboardData()]);
    
    showSuccess('API key removed successfully');
  } catch (error) {
    console.error('Error removing API key:', error);
    showError(error.message || 'Failed to remove API key');
  }
}

// Show validation message
function showValidationMessage(message, type) {
  const validationStatus = document.getElementById('validation-status');
  validationStatus.textContent = message;
  validationStatus.className = 'validation-message';
  
  if (type === 'success') {
    validationStatus.classList.add('validation-success');
  } else if (type === 'error') {
    validationStatus.classList.add('validation-error');
  }
  
  validationStatus.classList.remove('hidden');
  
  if (type !== 'validating') {
    // Hide the message after a delay
    setTimeout(() => {
      validationStatus.classList.add('hidden');
    }, 5000);
  }
}

// Show validation error
function showValidationError(message) {
  showValidationMessage(message, 'error');
}

// Update the loadDashboardData function to also load API keys
const originalLoadDashboardData = loadDashboardData;
loadDashboardData = async function() {
  try {
    await originalLoadDashboardData();
    await loadApiKeys();
    return dashboardData;
  } catch (error) {
    console.error('Error in extended loadDashboardData:', error);
    throw error;
  }
};

// Generate report from scan history
function generateReport() {
  if (!dashboardData || !dashboardData.recent_scans) {
    showError('No scan data available to generate report');
    return;
  }

  // Get filtered scans based on current search and filter
  const searchTerm = document.getElementById('scan-search').value.toLowerCase();
  const statusFilter = document.getElementById('status-filter').value.toLowerCase();
  
  const filteredScans = dashboardData.recent_scans.filter(scan => {
    const urlMatch = scan.url.toLowerCase().includes(searchTerm);
    const domainMatch = scan.domain && scan.domain.toLowerCase().includes(searchTerm);
    const statusMatch = statusFilter === 'all' || scan.status.toLowerCase() === statusFilter;
    return (urlMatch || domainMatch) && statusMatch;
  });

  // Create report data
  const reportData = {
    totalScans: filteredScans.length,
    phishingCount: filteredScans.filter(scan => scan.status.toLowerCase() === 'phishing').length,
    suspiciousCount: filteredScans.filter(scan => scan.status.toLowerCase() === 'suspicious').length,
    safeCount: filteredScans.filter(scan => scan.status.toLowerCase() === 'safe').length,
    scans: filteredScans.map(scan => ({
      url: scan.url,
      domain: scan.domain,
      status: scan.status,
      detectionRatio: scan.detection_ratio,
      scanDate: scan.scan_date
    }))
  };

  // Create and download report file
  const reportContent = JSON.stringify(reportData, null, 2);
  const blob = new Blob([reportContent], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = `scan-report-${new Date().toISOString().split('T')[0]}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showSuccess('Report generated successfully');
}

function updateNotificationUI() {
  const notificationList = document.getElementById('notification-list');
  const badge = document.getElementById('notification-badge');
  if (!notifications.length) {
    notificationList.innerHTML = '<li class="no-notifications">No notifications</li>';
    badge.style.display = 'none';
    badge.textContent = '0';
  } else {
    notificationList.innerHTML = '';
    notifications.slice().reverse().forEach((notif, idx) => {
      const li = document.createElement('li');
      li.textContent = notif.message;
      notificationList.appendChild(li);
    });
    badge.style.display = 'inline-block';
    badge.textContent = notifications.length;
  }
}

function addNotification(message) {
  notifications.push({ message, timestamp: new Date() });
  updateNotificationUI();
}

function clearNotifications() {
  notifications = [];
  updateNotificationUI();
}
