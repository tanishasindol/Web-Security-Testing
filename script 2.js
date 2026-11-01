// SecureScan - Web Security Testing Dashboard

let totalTests = 0;
let risksFound = 0;
let safeTests = 0;

// Load previous history
let history = JSON.parse(
  localStorage.getItem("scanHistory") || "[]"
);

// Update dashboard
function updateDashboard() {
  document.getElementById("totalTests").textContent =
    totalTests;
  
  document.getElementById("risksFound").textContent =
    risksFound;
  
  document.getElementById("safeTests").textContent =
    safeTests;
}

// Display test results
function displayResults(results) {
  const resultsList = document.getElementById("resultsList");
  
  resultsList.innerHTML = "";
  
  results.forEach(function(result) {
    const item = document.createElement("div");
    
    item.className = "result-item";
    
    const details = document.createElement("div");
    
    const title = document.createElement("strong");
    title.textContent = result.title;
    
    const description = document.createElement("p");
    description.textContent = result.description;
    
    const status = document.createElement("span");
    status.className = "status " + result.className;
    status.textContent = result.status;
    
    details.appendChild(title);
    details.appendChild(description);
    
    item.appendChild(details);
    item.appendChild(status);
    
    resultsList.appendChild(item);
  });
}

// Perform basic URL security checks
function scanWebsite() {
  
  const input = document.getElementById("websiteUrl");
  const message = document.getElementById("message");
  const urlValue = input.value.trim();
  
  const button = document.getElementById("scanBtn");
  
  if (!urlValue) {
    message.textContent = "Please enter a website URL.";
    message.style.color = "#dc2626";
    return;
  }
  
  let url;
  
  try {
    url = new URL(urlValue);
  } catch (error) {
    message.textContent = "Invalid URL. Enter a complete URL.";
    message.style.color = "#dc2626";
    return;
  }
  
  if (!["http:", "https:"].includes(url.protocol)) {
    message.textContent = "Only HTTP and HTTPS URLs are supported.";
    message.style.color = "#dc2626";
    return;
  }
  
  if (!url.hostname.includes(".") ||
    /\s/.test(url.hostname)) {
    message.textContent = "Please enter a valid hostname.";
    message.style.color = "#dc2626";
    return;
  }
  
  button.disabled = true;
  button.textContent = "Analyzing...";
  
  setTimeout(function() {
    
    const results = [];
    
    const fullURL = url.href;
    const lowerURL = fullURL.toLowerCase();
    
    // Check 1: HTTPS
    results.push({
      title: "HTTPS Encryption",
      description: url.protocol === "https:" ?
        "The URL uses HTTPS." :
        "The URL uses HTTP instead of HTTPS.",
      status: url.protocol === "https:" ?
        "PASSED" :
        "WARNING",
      className: url.protocol === "https:" ?
        "safe" :
        "warning"
    });
    
    // Check 2: URL credentials
    const hasCredentials =
      Boolean(url.username || url.password);
    
    results.push({
      title: "URL Credentials Check",
      description: hasCredentials ?
        "The URL contains embedded credentials." :
        "No embedded credentials detected.",
      status: hasCredentials ? "WARNING" : "PASSED",
      className: hasCredentials ? "warning" : "safe"
    });
    
    // Check 3: URL length
    const longURL = fullURL.length > 2048;
    
    results.push({
      title: "URL Length Analysis",
      description: longURL ?
        "The URL is unusually long." :
        "The URL length is within the basic limit.",
      status: longURL ? "WARNING" : "PASSED",
      className: longURL ? "warning" : "safe"
    });
    
    // Check 4: SQL injection patterns
    const sqlPattern =
      /(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|--|\/\*|\bdrop\s+table\b)/i;
    
    const sqlDetected = sqlPattern.test(lowerURL);
    
    results.push({
      title: "SQL Injection Pattern Check",
      description: sqlDetected ?
        "A string resembling a SQL injection pattern was found." :
        "No basic SQL injection patterns detected in the URL.",
      status: sqlDetected ? "WARNING" : "PASSED",
      className: sqlDetected ? "warning" : "safe"
    });
    
    // Check 5: XSS patterns
    const xssPattern =
      /(<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=)/i;
    
    const xssDetected = xssPattern.test(
      decodeURIComponentSafe(fullURL)
    );
    
    results.push({
      title: "XSS Pattern Check",
      description: xssDetected ?
        "A string resembling an XSS pattern was found." :
        "No basic XSS patterns detected in the URL.",
      status: xssDetected ? "WARNING" : "PASSED",
      className: xssDetected ? "warning" : "safe"
    });
    
    // Calculate results
    totalTests = results.length;
    
    risksFound = results.filter(function(result) {
      return result.status === "WARNING";
    }).length;
    
    safeTests = totalTests - risksFound;
    
    updateDashboard();
    displayResults(results);
    
    // Save scan history
    const scan = {
      url: fullURL,
      risks: risksFound,
      date: new Date().toLocaleString()
    };
    
    history.unshift(scan);
    history = history.slice(0, 10);
    
    localStorage.setItem(
      "scanHistory",
      JSON.stringify(history)
    );
    
    displayHistory();
    
    message.textContent =
      "Security analysis completed successfully!";
    
    message.style.color = "#15803d";
    
    button.disabled = false;
    button.textContent = "Start Security Scan →";
    
  }, 700);
}

// Safely decode URL
function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch (error) {
    return value;
  }
}

// Display scan history
function displayHistory() {
  
  const historyList =
    document.getElementById("historyList");
  
  historyList.innerHTML = "";
  
  if (history.length === 0) {
    historyList.textContent =
      "No scan history available.";
    historyList.className = "empty";
    return;
  }
  
  history.forEach(function(scan) {
    
    const item = document.createElement("div");
    item.className = "history-item";
    
    const details = document.createElement("div");
    
    const website = document.createElement("strong");
    website.textContent = scan.url;
    
    const date = document.createElement("p");
    date.textContent = scan.date;
    
    const risk = document.createElement("span");
    risk.className = "status " +
      (scan.risks > 0 ? "warning" : "safe");
    
    risk.textContent = scan.risks + " Risks";
    
    details.appendChild(website);
    details.appendChild(date);
    
    item.appendChild(details);
    item.appendChild(risk);
    
    historyList.appendChild(item);
  });
}

// Clear history
function clearHistory() {
  
  history = [];
  
  localStorage.removeItem("scanHistory");
  
  displayHistory();
}

// Load history when page opens
displayHistory();