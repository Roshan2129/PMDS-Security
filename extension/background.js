// Background script for the Phishing Mail Detection System

// Global variables
const API_BASE_URL = 'http://localhost:5000';
let isDetectionEnabled = true;

// Initialize extension settings
chrome.runtime.onInstalled.addListener(() => {
  console.log('Phishing Mail Detection System installed');
  
  // Set default settings
  chrome.storage.sync.set({
    phishingDetectionEnabled: true
  }, () => {
    console.log('Default settings initialized');
  });
});

// Listen for messages from popup or content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'toggleDetection') {
    isDetectionEnabled = message.enabled;
    console.log('Detection toggled:', isDetectionEnabled);
    
    // Update icon based on status
    updateExtensionIcon(isDetectionEnabled);
    
    sendResponse({ success: true });
  }
});

// Listen for tab navigation events
chrome.webNavigation.onDOMContentLoaded.addListener((details) => {
  // Check if the navigation is to Gmail
  if (details.url.includes('mail.google.com')) {
    // Set icon based on current detection status
    updateExtensionIcon(isDetectionEnabled);
  }
});

// Update extension icon based on detection status
function updateExtensionIcon(enabled) {
  // Use different icon colors based on status
  const iconPath = enabled ? 'icons/icon16.png' : 'icons/icon16_disabled.png';
  
  chrome.action.setIcon({ path: iconPath });
}

// Function to check if backend is running
async function checkBackendStatus() {
  try {
    const response = await fetch(`${API_BASE_URL}/`);
    return response.ok;
  } catch (error) {
    console.error('Backend server not available:', error);
    return false;
  }
}

// Check backend status periodically
setInterval(async () => {
  const isBackendRunning = await checkBackendStatus();
  
  // Update badge to indicate backend status
  if (isBackendRunning) {
    chrome.action.setBadgeText({ text: '' });
  } else {
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
  }
}, 60000); // Check every minute

// Initial backend check
checkBackendStatus().then(isRunning => {
  if (!isRunning) {
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
  }
});
