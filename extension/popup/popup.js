// Global variables
const API_BASE_URL = 'http://localhost:5000';
let isDetectionEnabled = true;

// DOM elements
const detectionToggle = document.getElementById('detection-toggle');
const detectionStatus = document.getElementById('detection-status');
const manualScanBtn = document.getElementById('manual-scan-btn');
const refreshBtn = document.getElementById('refresh-btn');
const scanResults = document.getElementById('scan-results');
const dashboardBtn = document.getElementById('dashboard-btn');

// Initialize popup
document.addEventListener('DOMContentLoaded', () => {
  initializePopup();
  loadRecentScans();
});

// Initialize popup with saved settings
function initializePopup() {
  chrome.storage.sync.get(['phishingDetectionEnabled'], (result) => {
    isDetectionEnabled = result.phishingDetectionEnabled !== undefined 
      ? result.phishingDetectionEnabled 
      : true;
      
    detectionToggle.checked = isDetectionEnabled;
    updateDetectionStatus();
  });
  
  // Set up event listeners
  detectionToggle.addEventListener('change', toggleDetection);
  manualScanBtn.addEventListener('click', triggerManualScan);
  refreshBtn.addEventListener('click', refreshData);
  dashboardBtn.addEventListener('click', openDashboard);
}

// Toggle phishing detection
function toggleDetection() {
  isDetectionEnabled = detectionToggle.checked;
  
  // Save setting to Chrome storage
  chrome.storage.sync.set({ phishingDetectionEnabled: isDetectionEnabled });
  
  // Update UI
  updateDetectionStatus();
  
  // Send message to background script and content script
  chrome.runtime.sendMessage({ action: 'toggleDetection', enabled: isDetectionEnabled });
  
  // Send to active Gmail tab if present
  chrome.tabs.query({ active: true, url: '*://mail.google.com/*' }, (tabs) => {
    if (tabs.length > 0) {
      chrome.tabs.sendMessage(tabs[0].id, { action: 'toggleDetection', enabled: isDetectionEnabled });
    }
  });
}

// Update the detection status display
function updateDetectionStatus() {
  detectionStatus.textContent = isDetectionEnabled ? 'Enabled' : 'Disabled';
  detectionStatus.className = isDetectionEnabled ? 'status-value enabled' : 'status-value disabled';
}

// Trigger manual scan for the current email
async function triggerManualScan() {
  try {
    // First check if we're on Gmail
    const tabs = await new Promise(resolve => 
      chrome.tabs.query({ active: true, url: '*://mail.google.com/*' }, resolve)
    );
    
    if (tabs.length === 0) {
      alert('Please open Gmail to scan an email.');
      return;
    }
    
    // Show loading state
    manualScanBtn.textContent = 'Scanning...';
    manualScanBtn.disabled = true;
    
    // Send message to content script to scan current email
    chrome.tabs.sendMessage(tabs[0].id, { action: 'manualScan' }, (response) => {
      // Reset button state
      manualScanBtn.innerHTML = '<span class="btn-icon">&#128269;</span><span class="btn-text">Manual Scan</span>';
      manualScanBtn.disabled = false;
      
      if (!response || response.error) {
        alert('Error: ' + (response?.error || 'No email open to scan'));
      } else {
        loadRecentScans(); // Refresh the scan results
      }
    });
  } catch (error) {
    console.error('Error during manual scan:', error);
    manualScanBtn.innerHTML = '<span class="btn-icon">&#128269;</span><span class="btn-text">Manual Scan</span>';
    manualScanBtn.disabled = false;
    alert('An error occurred while scanning.');
  }
}

// Refresh data from the backend
function refreshData() {
  loadRecentScans();
  
  // Show refresh animation
  refreshBtn.innerHTML = '<span class="btn-icon">⟳</span><span class="btn-text">Refreshing...</span>';
  refreshBtn.disabled = true;
  
  setTimeout(() => {
    refreshBtn.innerHTML = '<span class="btn-icon">&#8635;</span><span class="btn-text">Refresh</span>';
    refreshBtn.disabled = false;
  }, 1000);
}

// Load recent scan results
async function loadRecentScans() {
  try {
    const response = await fetch(`${API_BASE_URL}/get_dashboard_data`);
    
    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }
    
    const data = await response.json();
    updateScanResultsUI(data.recent_scans);
  } catch (error) {
    console.error('Error loading recent scans:', error);
    scanResults.innerHTML = '<p class="no-results">Error loading results</p>';
  }
}

// Update scan results in the UI
function updateScanResultsUI(scans) {
  if (!scans || scans.length === 0) {
    scanResults.innerHTML = '<p class="no-results">No recent scans</p>';
    return;
  }
  
  // Take only the 5 most recent scans
  const recentScans = scans.slice(0, 5);
  
  // Clear previous results
  scanResults.innerHTML = '';
  
  // Add each scan result
  recentScans.forEach(scan => {
    const scanItem = document.createElement('div');
    scanItem.className = 'scan-item';
    
    // Truncate URL for display
    const displayUrl = truncateUrl(scan.url);
    
    // Determine status class
    let statusClass = '';
    switch (scan.status.toLowerCase()) {
      case 'safe':
        statusClass = 'safe';
        break;
      case 'suspicious':
        statusClass = 'suspicious';
        break;
      case 'phishing':
        statusClass = 'phishing';
        break;
      default:
        statusClass = '';
    }
    
    scanItem.innerHTML = `
      <div class="scan-url" title="${scan.url}">${displayUrl}</div>
      <div class="scan-status ${statusClass}">${scan.status}</div>
    `;
    
    scanResults.appendChild(scanItem);
  });
}

// Helper function to truncate URL for display
function truncateUrl(url) {
  const maxLength = 30;
  
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

// Open the dashboard page
function openDashboard() {
  chrome.tabs.create({ url: chrome.runtime.getURL('/dashboard/dashboard.html') });
}
