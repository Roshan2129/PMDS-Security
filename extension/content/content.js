// Global variables
const API_BASE_URL = 'http://localhost:5000';
let isDetectionEnabled = true;
let currentUrls = [];
let currentEmailSubject = '';
let isScanning = false;
let emailObserver = null;

// Initialize extension
chrome.storage.sync.get(['phishingDetectionEnabled'], (result) => {
  isDetectionEnabled = result.phishingDetectionEnabled !== undefined 
    ? result.phishingDetectionEnabled 
    : true;
    
  console.log('Phishing Mail Detection System initialized. Detection enabled:', isDetectionEnabled);
  
  // Set up email observer
  setupEmailObserver();
});

// Listen for messages from popup or background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'toggleDetection') {
    isDetectionEnabled = message.enabled;
    console.log('Detection toggled:', isDetectionEnabled);
    
    // If enabling detection and on an email, scan it
    if (isDetectionEnabled && isInEmailView()) {
      scanCurrentEmail();
    }
    
    sendResponse({ success: true });
  } 
  else if (message.action === 'manualScan') {
    // Trigger manual scan
    if (isInEmailView()) {
      scanCurrentEmail().then(results => {
        sendResponse({ success: true, results });
      }).catch(error => {
        sendResponse({ error: error.message });
      });
      return true; // Indicate async response
    } else {
      sendResponse({ error: 'No email open to scan' });
    }
  }
});

// Set up observer to detect when emails are opened
function setupEmailObserver() {
  // Disconnect existing observer if any
  if (emailObserver) {
    emailObserver.disconnect();
  }
  
  // Set up new mutation observer
  emailObserver = new MutationObserver((mutations) => {
    if (isDetectionEnabled && !isScanning) {
      // Check if we're in email view
      if (isInEmailView()) {
        scanCurrentEmail();
      }
    }
  });
  
  // Start observing
  const config = { childList: true, subtree: true };
  emailObserver.observe(document.body, config);
  
  // Initial check
  if (isDetectionEnabled && isInEmailView()) {
    scanCurrentEmail();
  }
}

// Check if user is currently viewing an email
function isInEmailView() {
  // Check for Gmail email container
  return document.querySelector('div[role="main"] .adn');
}

// Scan the current email for phishing URLs
async function scanCurrentEmail() {
  if (isScanning) return;
  
  isScanning = true;
  console.log('Scanning current email...');
  
  try {
    // Extract current email subject
    currentEmailSubject = extractEmailSubject();
    
    // Extract URLs from email
    const urls = extractUrlsFromEmail();
    
    if (urls.length === 0) {
      console.log('No URLs found in email');
      isScanning = false;
      return { message: 'No URLs found in email' };
    }
    
    // Remove any existing scan indicators
    removeExistingScanIndicators();
    
    // Add loading indicators
    urls.forEach(url => {
      addLoadingIndicator(url);
    });
    
    // Scan each URL
    const scanPromises = urls.map(url => scanUrl(url));
    const results = await Promise.all(scanPromises);
    
    // Process results
    results.forEach((result, index) => {
      if (result) {
        updateUrlIndicator(urls[index], result.status);
      }
    });
    
    console.log('Email scan completed');
    return { urls, results };
  } catch (error) {
    console.error('Error scanning email:', error);
    throw error;
  } finally {
    isScanning = false;
  }
}

// Extract the email subject
function extractEmailSubject() {
  const subjectElement = document.querySelector('.hP');
  return subjectElement ? subjectElement.textContent.trim() : '';
}

// Extract URLs from email
function extractUrlsFromEmail() {
  const emailContainer = document.querySelector('div[role="main"] .adn');
  if (!emailContainer) return [];
  
  // Get all links in the email
  const links = Array.from(emailContainer.querySelectorAll('a[href]'));
  
  // Extract unique URLs
  const uniqueUrls = new Set();
  
  links.forEach(link => {
    const url = link.href;
    
    // Skip mailto: links and javascript: links
    if (url.startsWith('mailto:') || url.startsWith('javascript:') || url.startsWith('tel:')) {
      return;
    }
    
    // Skip Gmail internal links
    if (url.includes('mail.google.com')) {
      return;
    }
    
    uniqueUrls.add(url);
    
    // Store reference to DOM element for later
    if (!currentUrls.find(item => item.url === url)) {
      currentUrls.push({
        url,
        element: link
      });
    }
  });
  
  return Array.from(uniqueUrls);
}

// Scan a URL for phishing indicators
async function scanUrl(url) {
  try {
    const response = await fetch(`${API_BASE_URL}/scan_url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        url,
        email_subject: currentEmailSubject
      }),
    });
    
    if (!response.ok) {
      throw new Error(`Server error: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error(`Error scanning URL ${url}:`, error);
    return { status: 'Error', message: error.message };
  }
}

// Add loading indicator to URL
function addLoadingIndicator(url) {
  const urlData = currentUrls.find(item => item.url === url);
  if (!urlData || !urlData.element) return;
  
  const link = urlData.element;
  
  // Create loading indicator
  const indicator = document.createElement('span');
  indicator.className = 'pmds-indicator pmds-loading';
  indicator.setAttribute('data-url', url);
  indicator.textContent = '⏳';
  indicator.title = 'Scanning URL...';
  
  // Add styles
  indicator.style.marginLeft = '4px';
  indicator.style.display = 'inline-block';
  
  // Add indicator after link
  if (link.nextSibling) {
    link.parentNode.insertBefore(indicator, link.nextSibling);
  } else {
    link.parentNode.appendChild(indicator);
  }
}

// Update URL indicator based on scan result
function updateUrlIndicator(url, status) {
  const indicator = document.querySelector(`.pmds-indicator[data-url="${url}"]`);
  if (!indicator) return;
  
  // Remove loading class
  indicator.classList.remove('pmds-loading');
  
  // Set appropriate status class and icon
  switch (status.toLowerCase()) {
    case 'safe':
      indicator.className = 'pmds-indicator pmds-safe';
      indicator.textContent = '✅';
      indicator.title = 'Safe URL';
      indicator.style.color = '#28a745';
      break;
    case 'suspicious':
      indicator.className = 'pmds-indicator pmds-suspicious';
      indicator.textContent = '⚠️';
      indicator.title = 'Suspicious URL';
      indicator.style.color = '#ffc107';
      break;
    case 'phishing':
      indicator.className = 'pmds-indicator pmds-phishing';
      indicator.textContent = '🚫';
      indicator.title = 'Phishing URL Detected!';
      indicator.style.color = '#dc3545';
      
      // Add overlay warning for phishing URLs
      addPhishingOverlay(url);
      break;
    default:
      indicator.className = 'pmds-indicator pmds-unknown';
      indicator.textContent = '❓';
      indicator.title = 'Unknown status';
      indicator.style.color = '#6c757d';
  }
}

// Add phishing warning overlay for dangerous URLs
function addPhishingOverlay(url) {
  const urlData = currentUrls.find(item => item.url === url);
  if (!urlData || !urlData.element) return;
  
  const link = urlData.element;
  
  // Style the link to indicate danger
  link.style.color = '#dc3545';
  link.style.backgroundColor = '#f8d7da';
  link.style.padding = '0 4px';
  link.style.borderRadius = '2px';
  link.style.textDecoration = 'line-through';
  
  // Add click interceptor
  link.addEventListener('click', function(e) {
    e.preventDefault();
    e.stopPropagation();
    
    // Show warning dialog
    const confirmNavigation = confirm(
      `⚠️ PHISHING WARNING ⚠️\n\nThis link appears to be malicious: ${url}\n\nDo you still want to proceed? This is not recommended.`
    );
    
    if (confirmNavigation) {
      window.open(url, '_blank');
    }
  });
}

// Remove existing scan indicators
function removeExistingScanIndicators() {
  const indicators = document.querySelectorAll('.pmds-indicator');
  indicators.forEach(indicator => {
    indicator.remove();
  });
  
  // Reset currentUrls array
  currentUrls = [];
}

// Add styles to document
const style = document.createElement('style');
style.textContent = `
  .pmds-indicator {
    margin-left: 4px;
    display: inline-block;
    font-size: 16px;
    cursor: help;
  }
  
  .pmds-loading {
    animation: pmds-spin 1s infinite linear;
  }
  
  @keyframes pmds-spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }
`;
document.head.appendChild(style);
