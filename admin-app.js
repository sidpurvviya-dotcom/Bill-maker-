/**
 * Bill Maker — Super Admin Control Panel Engine
 * Handles tenant provisioning, password overrides, AES-GCM credential vault, and Gmail API integration.
 */

// ── In-Memory Security Closures ──
let ACTIVE_ADMIN_PASSWORD = ''; // Kept in memory only, never written to disk
let ADMIN_CONFIG = null;

// ── Crypto Helpers ──
// Fallback pure-JS SHA-256 implementation for insecure/file contexts
function sha256Fallback(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  var mathPow = Math.pow;
  var maxWord = mathPow(2, 32);
  var i, j;
  var result = '';
  var words = [];
  var asciiLength = ascii.length;
  var hash = [];
  var k = [];
  var primeCounter = 0;
  var isComposite = {};
  for (var candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 313; i += candidate) {
        isComposite[i] = candidate;
      }
      hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }
  ascii += '\x80';
  while (ascii.length % 64 - 56) ascii += '\x00';
  for (i = 0; i < ascii.length; i++) {
    j = ascii.charCodeAt(i);
    if (j >> 8) return '';
    words[i >> 2] |= j << ((3 - i % 4) * 8);
  }
  words[words.length] = ((asciiLength / maxWord) | 0);
  words[words.length] = (asciiLength << 3);
  for (j = 0; j < words.length; j += 16) {
    var w = words.slice(j, j + 16);
    var oldHash = hash;
    hash = hash.slice(0, 8);
    for (i = 0; i < 64; i++) {
      var w15 = w[i - 15], w2 = w[i - 2];
      var s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      var s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      w[i] = (i >= 16) ? (w[i - 16] + s0 + w[i - 7] + s1) | 0 : w[i];
      var ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      var maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      var temp1 = hash[7] + (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) + ch + k[i] + w[i];
      var temp2 = (rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22)) + maj;
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }
  for (i = 0; i < 8; i++) {
    var v = hash[i];
    if (v < 0) v += maxWord;
    var str = v.toString(16);
    while (str.length < 8) str = '0' + str;
    result += str;
  }
  return result;
}

async function hashPassword(password) {
  if (!window.crypto || !window.crypto.subtle) {
    console.warn('Web Crypto API not available. Using pure JS SHA-256 fallback.');
    return sha256Fallback(password);
  }
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (err) {
    console.warn('SubtleCrypto digest failed, falling back to JS implementation:', err);
    return sha256Fallback(password);
  }
}

// Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// PBKDF2 Key Derivation
async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt using Master Admin Password
async function encryptData(plaintext, password) {
  if (!password) throw new Error('Encryption password required');
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(plaintext)
  );
  
  // Combine salt, iv, and ciphertext into single Uint8Array
  const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
  
  return arrayBufferToBase64(combined.buffer);
}

// Decrypt using Master Admin Password
async function decryptData(encryptedB64, password) {
  if (!password) throw new Error('Decryption password required');
  const combined = new Uint8Array(base64ToArrayBuffer(encryptedB64));
  if (combined.length < 28) throw new Error('Encrypted payload too short');
  
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);
  
  const key = await deriveKey(password, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );
  
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

// ── Admin UI Logging ──
function addAdminLog(msg, type = 'info') {
  const logEl = document.getElementById('gmailLogBox');
  if (!logEl) return;
  const time = new Date().toLocaleTimeString();
  const prefix = `[${time}] [${type.toUpperCase()}] `;
  logEl.textContent += `\n${prefix}${msg}`;
  logEl.scrollTop = logEl.scrollHeight;
  
  // Persist logs locally
  try {
    const logs = JSON.parse(localStorage.getItem('bm_admin_logs') || '[]');
    logs.push({ timestamp: new Date().toISOString(), message: msg, type });
    if (logs.length > 50) logs.shift();
    localStorage.setItem('bm_admin_logs', JSON.stringify(logs));
  } catch(e) {}
}

function loadSavedLogs() {
  const logEl = document.getElementById('gmailLogBox');
  if (!logEl) return;
  try {
    const logs = JSON.parse(localStorage.getItem('bm_admin_logs') || '[]');
    if (logs.length > 0) {
      logEl.textContent = '--- Cached Admin Logs Restored ---';
      logs.forEach(log => {
        const time = new Date(log.timestamp).toLocaleTimeString();
        const prefix = `[${time}] [${log.type.toUpperCase()}] `;
        logEl.textContent += `\n${prefix}${log.message}`;
      });
      logEl.scrollTop = logEl.scrollHeight;
    }
  } catch(e) {}
}

// ── Notification Alerts Loop via Gmail API ──
async function refreshGmailAccessToken(clientId, clientSecret, refreshToken) {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    })
  });
  if (!response.ok) {
    const errText = await response.text();
    throw new Error('OAuth2 refresh token exchange failed: ' + errText);
  }
  const data = await response.json();
  return data.access_token;
}

async function sendGmailMime(accessToken, fromAddr, toAddr, subject, htmlContent) {
  const emailLines = [
    `From: ${fromAddr}`,
    `To: ${toAddr}`,
    `Subject: ${subject}`,
    `Content-Type: text/html; charset=utf-8`,
    `MIME-Version: 1.0`,
    ``,
    htmlContent
  ];
  const emailStr = emailLines.join('\r\n');
  const encodedEmail = btoa(unescape(encodeURIComponent(emailStr)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      raw: encodedEmail
    })
  });
  if (!response.ok) {
    const errText = await response.text();
    throw new Error('Gmail Send API endpoint failed: ' + errText);
  }
  return await response.json();
}

async function dispatchSystemNotification(subject, htmlBody) {
  if (!ADMIN_CONFIG) return;
  
  const encId = ADMIN_CONFIG.gmailClientId;
  const encSec = ADMIN_CONFIG.gmailClientSecret;
  const encToken = ADMIN_CONFIG.gmailRefreshToken;
  const fromEmail = ADMIN_CONFIG.adminEmail;

  if (!encId || !encSec || !encToken || !fromEmail) {
    addAdminLog('Transactional notification skipped: Gmail Linkage is not configured.', 'warning');
    return;
  }

  try {
    addAdminLog('Refreshing security access token...', 'info');
    const decId = await decryptData(encId, ACTIVE_ADMIN_PASSWORD);
    const decSec = await decryptData(encSec, ACTIVE_ADMIN_PASSWORD);
    const decToken = await decryptData(encToken, ACTIVE_ADMIN_PASSWORD);

    const accessToken = await refreshGmailAccessToken(decId, decSec, decToken);
    addAdminLog('OAuth2 verification success. Sending transactional security alert...', 'info');
    
    await sendGmailMime(accessToken, fromEmail, fromEmail, subject, htmlBody);
    addAdminLog(`Email security notification successfully dispatched to ${fromEmail}`, 'success');
  } catch(err) {
    addAdminLog('Security notification failed: ' + err.message, 'error');
    console.error('Mailer execution warning:', err);
  }
}

// ── Auth Guard & Initialization ──

// ════════════════════════════════════════════════════════════════
// ANTIGRAVITY VISION RECOGNITION ENGINE — Canvas Pixel Analysis
// ════════════════════════════════════════════════════════════════
function analyzeImageForTemplate(base64) {
  return new Promise(function(resolve) {
    var img = new Image();
    img.onload = function() {
      try {
        var W = Math.min(img.width,  600);
        var H = Math.min(img.height, 900);
        var canvas = document.createElement('canvas');
        canvas.width  = W;
        canvas.height = H;
        var ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, W, H);

        // ── Region samplers ──
        var headerH  = Math.floor(H * 0.22);  // top 22%  = header
        var bodyTop  = Math.floor(H * 0.22);
        var bodyH    = Math.floor(H * 0.55);  // middle 55% = item rows

        var headerData = ctx.getImageData(0, 0,       W, headerH).data;
        var bodyData   = ctx.getImageData(0, bodyTop,  W, bodyH  ).data;
        var fullData   = ctx.getImageData(0, 0,        W, H      ).data;

        // ── Helpers ──
        function brightness(r, g, b) { return 0.299*r + 0.587*g + 0.114*b; }
        function saturation(r, g, b) {
          var max = Math.max(r,g,b), min = Math.min(r,g,b);
          return max === 0 ? 0 : (max - min) / max;
        }
        function toHex(r, g, b) {
          return '#' + [r,g,b].map(function(v){
            return Math.max(0,Math.min(255,Math.round(v))).toString(16).padStart(2,'0');
          }).join('');
        }
        function avgColor(data) {
          var r=0,g=0,b=0,n=data.length/4;
          for (var i=0;i<data.length;i+=4){ r+=data[i]; g+=data[i+1]; b+=data[i+2]; }
          return {r:r/n, g:g/n, b:b/n};
        }

        // ── Header region ──
        var hAvg = avgColor(headerData);
        var headerBg   = toHex(hAvg.r, hAvg.g, hAvg.b);
        var hBright    = brightness(hAvg.r, hAvg.g, hAvg.b);
        var headerText = hBright < 140 ? '#ffffff' : '#1a1a1a';

        // ── Accent/theme color ──
        // Find pixel with highest saturation across full image
        var bestSat = 0, aR = 99, aG = 66, aB = 226;
        for (var i=0; i<fullData.length; i+=8) {
          var r=fullData[i], g=fullData[i+1], b=fullData[i+2];
          var bri = brightness(r,g,b);
          if (bri > 235 || bri < 18) continue;  // skip white/black
          var sat = saturation(r,g,b);
          if (sat > bestSat) { bestSat=sat; aR=r; aG=g; aB=b; }
        }
        var accentColor = toHex(aR, aG, aB);

        // ── Body brightness = font style hint ──
        var bAvg    = avgColor(bodyData);
        var bBright = brightness(bAvg.r, bAvg.g, bAvg.b);
        var font    = bBright > 215 ? 'Devanagari' : 'Georgia';

        // ── Layout density (compact vs A4) ──
        // If image taller than 1.4× wide → A4
        var layout = (img.height / img.width) > 1.4 ? 'A4' : 'compact';

        resolve({ headerBg: headerBg, headerText: headerText, color: accentColor, font: font, layout: layout });
      } catch(err) {
        console.error('Vision analysis failed:', err);
        resolve(null);
      }
    };
    img.onerror = function() { resolve(null); };
    img.src = base64;
  });
}

// Apply vision analysis result to the template form
function applyVisionResult(result) {
  if (!result) return;
  try {
    // Color pickers
    document.getElementById('tmplModalColor').value      = result.color;
    document.getElementById('tmplModalColorHex').value   = result.color.toUpperCase();
    document.getElementById('tmplModalHeaderBg').value   = result.headerBg;
    document.getElementById('tmplModalHeaderBgHex').value = result.headerBg.toUpperCase();
    document.getElementById('tmplModalHeaderText').value    = result.headerText;
    document.getElementById('tmplModalHeaderTextHex').value = result.headerText.toUpperCase();
    // Font
    if (result.font) {
      document.getElementById('tmplModalFont').value = result.font;
    }
    // Regenerate CSS with detected values
    isCssCustom = false;
    triggerCssAutoRegen();
    // Show badge on upload zone
    var badge = document.getElementById('visionResultBadge');
    if (badge) {
      badge.innerHTML =
        '<span style="color:#34d399">✔</span> Vision detected: ' +
        '<span style="font-family:monospace;font-size:10px">' +
          'Base <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' + result.color + ';vertical-align:middle;margin:0 3px;border:1px solid rgba(255,255,255,0.2)"></span>' + result.color.toUpperCase() + ' &nbsp;' +
          'Header <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' + result.headerBg + ';vertical-align:middle;margin:0 3px;border:1px solid rgba(255,255,255,0.2)"></span>' + result.headerBg.toUpperCase() + ' &nbsp;' +
          'Font: ' + result.font +
        '</span>';
      badge.style.display = 'flex';
    }
    showToast('🎨 Vision detected colors & font — fields auto-filled!');
  } catch(e) { console.error('applyVisionResult error', e); }
}
document.addEventListener('DOMContentLoaded', () => {
  // Restore server time in header
  setInterval(() => {
    document.getElementById('headerTime').textContent = new Date().toLocaleTimeString();
  }, 1000);
  document.getElementById('headerTime').textContent = new Date().toLocaleTimeString();

  checkEcosystemState();
});

function checkEcosystemState() {
  const configData = localStorage.getItem('bm_admin_config');
  const overlay = document.getElementById('authOverlay');
  
  if (!configData) {
    // Auto-initialize default SaaS Admin credentials so setup screen is bypassed
    const adminObj = {
      masterId: 'sidpurvviya@gmail.com',
      masterPasswordHash: '8e1c6b65345a32ec6ad13e61c360b0932bb41e976bd6b8c9d1c9fb8ec1dfbc85', // Siddhant@16
      adminEmail: 'sidpurvviya@gmail.com',
      businessName: 'Super Admin Group',
      gmailClientId: '',
      gmailClientSecret: '',
      gmailRefreshToken: '',
      managedUsers: []
    };
    localStorage.setItem('bm_admin_config', JSON.stringify(adminObj));
    ADMIN_CONFIG = adminObj;
  } else {
    ADMIN_CONFIG = JSON.parse(configData);
  }

  // Enforce session check: must have active admin role
  const activeSession = localStorage.getItem('bm_current_session');
  if (!activeSession) {
    window.location.href = 'login.html';
    return;
  }
  try {
    const session = JSON.parse(activeSession);
    if (!session || session.role !== 'admin') {
      throw new Error('Invalid admin session');
    }
  } catch (err) {
    console.warn('Admin auth session validation error:', err);
    localStorage.removeItem('bm_current_session');
    window.location.href = 'login.html';
    return;
  }

  // Pre-fill memory password context if not set (keeps OAuth relays working if they refresh)
  if (!ACTIVE_ADMIN_PASSWORD) {
    ACTIVE_ADMIN_PASSWORD = 'Siddhant@16';
  }

  initTemplatesEcosystem();
  loginSessionSuccess();
  if (overlay) overlay.style.display = 'none';
}

// ── SETUP & LOGIN ACTIONS ──
async function handleSetupSubmit(e) {
  e.preventDefault();
  const errorEl = document.getElementById('setupError');
  errorEl.style.display = 'none';

  const email = document.getElementById('setupEmail').value.trim();
  const password = document.getElementById('setupPassword').value;
  const confirmPassword = document.getElementById('setupConfirmPassword').value;
  const businessName = document.getElementById('setupBusinessName').value.trim();

  if (password !== confirmPassword) {
    errorEl.textContent = '❌ Passwords do not match.';
    errorEl.style.display = 'block';
    return;
  }

  try {
    const passwordHash = await hashPassword(password);
    
    const adminObj = {
      masterId: email,
      masterPasswordHash: passwordHash,
      adminEmail: email,
      businessName: businessName,
      gmailClientId: '',
      gmailClientSecret: '',
      gmailRefreshToken: '',
      managedUsers: []
    };

    localStorage.setItem('bm_admin_config', JSON.stringify(adminObj));
    ADMIN_CONFIG = adminObj;
    ACTIVE_ADMIN_PASSWORD = password; // Set active password context
    
    showToast('🚀 System Deployed Successfully!');
    loginSessionSuccess();
  } catch(err) {
    errorEl.textContent = '❌ Setup initialization failed: ' + err.message;
    errorEl.style.display = 'block';
  }
}

async function handleLoginSubmit(e) {
  e.preventDefault();
  const errorEl = document.getElementById('loginError');
  errorEl.style.display = 'none';

  const email = document.getElementById('loginEmail').value.trim();
  const password = document.getElementById('loginPassword').value;

  try {
    const passwordHash = await hashPassword(password);
    
    if (email.toLowerCase() !== ADMIN_CONFIG.masterId.toLowerCase() || passwordHash !== ADMIN_CONFIG.masterPasswordHash) {
      errorEl.textContent = '❌ Access Denied: Invalid administrator credentials.';
      errorEl.style.display = 'block';
      return;
    }

    ACTIVE_ADMIN_PASSWORD = password; // Set active password context
    showToast('🔑 Authorization Verified.');
    loginSessionSuccess();
  } catch(err) {
    errorEl.textContent = '❌ Authentication error: ' + err.message;
    errorEl.style.display = 'block';
  }
}

function loginSessionSuccess() {
  document.getElementById('setupView').style.display = 'none';
  document.getElementById('loginView').style.display = 'none';
  document.getElementById('adminDashboardView').style.display = 'flex';
  
  // Set UI Header Info
  document.getElementById('sidebarAdminName').textContent = ADMIN_CONFIG.businessName || 'Master Admin';
  document.getElementById('sidebarAvatar').textContent = (ADMIN_CONFIG.businessName || 'A').charAt(0).toUpperCase();

  // Load Saved Logs
  loadSavedLogs();

  // Wire Tab Navigation
  wireTabNavigation();

  // Refresh data
  refreshStatsAndMetrics();
  loadTenantDirectory();
  populateOverrideSelector();
  loadGmailConfigurations();
  loadTemplatesDirectory();
}

function handleLogout() {
  if (confirm('Log out from administrative context? Secure keys will be deleted from memory.')) {
    ACTIVE_ADMIN_PASSWORD = '';
    ADMIN_CONFIG = null;
    localStorage.removeItem('bm_current_session');
    window.location.href = 'login.html';
  }
}

// ── TAB NAVIGATION ──
function wireTabNavigation() {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      item.classList.add('active');
      const tabId = item.dataset.tab;
      document.getElementById(tabId).classList.add('active');

      // Update Header Text
      const titleEl = document.getElementById('currentTabTitle');
      const subtitleEl = document.getElementById('currentTabSubtitle');
      
      if (tabId === 'tab-overview') {
        titleEl.textContent = 'Overview Dashboard';
        subtitleEl.textContent = 'Real-time usage statistics and tenant configurations across the ecosystem.';
        refreshStatsAndMetrics();
      } else if (tabId === 'tab-provision') {
        titleEl.textContent = 'Provision Tenant';
        subtitleEl.textContent = 'Generate manual client accounts and assign default invoicing preferences.';
      } else if (tabId === 'tab-directory') {
        titleEl.textContent = 'Tenant Directory';
        subtitleEl.textContent = 'Audit accounts, track activity levels, and suspend or restore subscriptions.';
        loadTenantDirectory();
      } else if (tabId === 'tab-overrides') {
        titleEl.textContent = 'Credential Overrides';
        subtitleEl.textContent = 'Directly overwrite credentials on user schemas bypassing consumer prompts.';
        populateOverrideSelector();
      } else if (tabId === 'tab-gmail') {
        titleEl.textContent = 'Gmail SMTP Linkage';
        subtitleEl.textContent = 'Configure encryption parameters and Google Cloud OAuth2 transactional relays.';
        loadGmailConfigurations();
      } else if (tabId === 'tab-templates') {
        titleEl.textContent = 'Manage Templates';
        subtitleEl.textContent = 'Create, update, and delete bill and invoice styling templates.';
        loadTemplatesDirectory();
      }
    });
  });
}

// ── DATA AND METRICS LOADER ──
function getLocalTenants() {
  const users = localStorage.getItem('bm_local_users');
  if (!users) return [];
  try {
    const parsed = JSON.parse(users);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

function saveLocalTenants(tenants) {
  localStorage.setItem('bm_local_users', JSON.stringify(tenants));
}

function refreshStatsAndMetrics() {
  const tenants = getLocalTenants();
  
  const totalCount = tenants.length;
  let activeCount = 0;
  let suspendedCount = 0;
  let totalSessions = 0;
  let totalInvoices = 0;

  const recentList = document.getElementById('overviewRecentUsersList');
  recentList.innerHTML = '';

  // Sort tenants by last login or last active for recent list
  const sortedTenants = [...tenants].sort((a, b) => {
    const timeA = new Date(a.stats?.lastActive || a.stats?.lastLogin || 0);
    const timeB = new Date(b.stats?.lastActive || b.stats?.lastLogin || 0);
    return timeB - timeA;
  });

  tenants.forEach(u => {
    if (!u.subscriptionState || u.subscriptionState === 'active') {
      activeCount++;
    } else {
      suspendedCount++;
    }
    
    if (u.stats) {
      totalSessions += (u.stats.sessionCount || 0);
      totalInvoices += (u.stats.totalBills || 0);
    }
  });

  // Populate Dashboard Overview Counters
  document.getElementById('metricTotalUsers').textContent = totalCount;
  document.getElementById('metricActiveUsers').textContent = activeCount;
  document.getElementById('metricSuspendedUsers').textContent = suspendedCount;
  document.getElementById('metricTotalSessions').textContent = totalSessions;
  document.getElementById('metricTotalBills').textContent = totalInvoices;

  // Gmail mailer status
  const mailStatusEl = document.getElementById('metricMailStatus');
  const mailDescEl = document.getElementById('metricMailStatusDesc');
  if (ADMIN_CONFIG.gmailClientId && ADMIN_CONFIG.gmailRefreshToken) {
    mailStatusEl.textContent = 'CONNECTED';
    mailStatusEl.style.color = 'var(--accent-success)';
    mailDescEl.textContent = 'Transactional relays operational';
  } else {
    mailStatusEl.textContent = 'NOT LINKED';
    mailStatusEl.style.color = 'var(--text-muted)';
    mailDescEl.textContent = 'SMTP alerts will be bypassed';
  }

  // Populate recent list (limit 5)
  const limitTenants = sortedTenants.slice(0, 5);
  if (limitTenants.length === 0) {
    recentList.innerHTML = `<li style="text-align:center; padding: 30px; color: var(--text-muted)">No active tenants found. Use the "Provision Tenant" tab to add client accounts.</li>`;
  } else {
    limitTenants.forEach(u => {
      const li = document.createElement('li');
      li.className = 'recent-item';
      const initials = (u.shopName || 'U').charAt(0).toUpperCase();
      const state = u.subscriptionState || 'active';
      const lastActiveStr = u.stats?.lastActive 
        ? new Date(u.stats.lastActive).toLocaleDateString() + ' ' + new Date(u.stats.lastActive).toLocaleTimeString()
        : (u.stats?.lastLogin ? 'Logged in ' + new Date(u.stats.lastLogin).toLocaleDateString() : 'Never Active');

      li.innerHTML = `
        <div class="recent-item-left">
          <div class="recent-avatar">${initials}</div>
          <div class="recent-info-block">
            <div class="recent-shopname">${escapeHtml(u.shopName || 'Unnamed Shop')}</div>
            <div class="recent-userId">${escapeHtml(u.userId || u.email)}</div>
          </div>
        </div>
        <div class="recent-item-right">
          <span class="recent-status-badge status-badge-${state}">${state}</span>
          <div class="recent-activity-time">${lastActiveStr}</div>
        </div>
      `;
      recentList.appendChild(li);
    });
  }
}

// ── TENANT PROVISIONING ACTION ──
async function handleProvisionSubmit(e) {
  e.preventDefault();

  const errEl = document.getElementById('provisionError');
  if (errEl) errEl.style.display = 'none';

  const rawInput = document.getElementById('provUserId').value.trim();
  const userId   = rawInput.toLowerCase();          // normalise for matching
  const businessName = document.getElementById('provBusinessName').value.trim();
  const password = document.getElementById('provPassword').value;

  if (!userId) {
    if (errEl) { errEl.textContent = '❌ Username cannot be empty.'; errEl.style.display = 'block'; }
    return;
  }

  const tenants = getLocalTenants();

  // Validate uniqueness — show friendly inline error
  if (tenants.some(t => (t.username || t.userId || t.email || '').toLowerCase() === userId)) {
    if (errEl) {
      errEl.innerHTML = `❌ Username <strong>"${escapeHtml(rawInput)}"</strong> is already taken. Please try a different username.`;
      errEl.style.display = 'block';
    }
    document.getElementById('provUserId').focus();
    return;
  }

  try {
    const passwordHash = await hashPassword(password);
    
    const newTenant = {
      username: userId,          // Primary match key (normalised)
      userId: userId,            // Backward compatibility
      email: userId,             // Backward compatibility
      passwordHash: passwordHash,
      passwordText: password,    // Store plain password for credential ledger
      shopName: businessName,
      subscriptionState: 'active',
      billingPreferences: {
        pageSize: 'A4',
        autoIncrement: true
      },
      stats: {
        lastLogin: null,
        lastActive: null,
        sessionCount: 0,
        totalBills: 0
      }
    };

    tenants.push(newTenant);
    saveLocalTenants(tenants);

    // Sync admin model config reference
    if (!ADMIN_CONFIG.managedUsers) ADMIN_CONFIG.managedUsers = [];
    if (!ADMIN_CONFIG.managedUsers.includes(userId)) {
      ADMIN_CONFIG.managedUsers.push(userId);
      localStorage.setItem('bm_admin_config', JSON.stringify(ADMIN_CONFIG));
    }

    showToast(`✅ Provisioned ${businessName} successfully!`);
    document.getElementById('provisionForm').reset();
    if (errEl) errEl.style.display = 'none';
    
    // Auto redirect to Directory list
    setTimeout(() => {
      document.querySelector('[data-tab="tab-directory"]').click();
    }, 800);
  } catch(err) {
    if (errEl) { errEl.textContent = '❌ Provisioning failed: ' + err.message; errEl.style.display = 'block'; }
    else alert('❌ Provisioning failed: ' + err.message);
  }
}

// ── DIRECTORY ACTIONS ──
function loadTenantDirectory(searchQuery = '') {
  const body = document.getElementById('directoryTableBody');
  if (!body) return;
  
  const tenants = getLocalTenants();
  body.innerHTML = '';

  let filtered = tenants;
  if (searchQuery.trim()) {
    const q = searchQuery.toLowerCase();
    filtered = tenants.filter(t => 
      (t.username || t.userId || t.email || '').toLowerCase().includes(q) ||
      (t.shopName || '').toLowerCase().includes(q)
    );
  }

  if (filtered.length === 0) {
    body.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:40px; color:var(--text-muted)">No tenant accounts match the search criteria.</td></tr>`;
    return;
  }

  filtered.forEach(u => {
    const tr = document.createElement('tr');
    const initials = (u.shopName || 'U').charAt(0).toUpperCase();
    const state = u.subscriptionState || 'active';
    const lastActiveStr = u.stats?.lastActive 
      ? new Date(u.stats.lastActive).toLocaleString()
      : 'Never';
    const totalBills = u.stats?.totalBills || 0;
    const sessionCount = u.stats?.sessionCount || 0;
    const sizePref = u.billingPreferences?.pageSize || 'A4';
    const uid = u.userId || u.email;

    const isTenantAdmin = u.role === 'admin';
    const adminBtnText = isTenantAdmin ? 'Revoke Admin' : 'Make Admin';
    const adminBtnIcon = isTenantAdmin ? '👑 Admin' : '👤 User';
    const adminBtnColor = isTenantAdmin ? '#fbbf24' : '#9ca3af';
    const adminBtnBg = isTenantAdmin ? 'rgba(245,158,11,0.1)' : 'rgba(255,255,255,0.05)';
    const adminBtnBorder = isTenantAdmin ? 'rgba(245,158,11,0.25)' : 'rgba(255,255,255,0.1)';

    tr.innerHTML = `
      <td>
        <div class="td-user">
          <div class="td-user-avatar">${initials}</div>
          <div class="td-user-details">
            <span class="td-shop">${escapeHtml(u.shopName || 'Unnamed Shop')}</span>
            <span class="td-email">${escapeHtml(uid)}</span>
          </div>
        </div>
      </td>
      <td>
        <code style="background: rgba(255,255,255,0.05); padding: 4px 8px; border-radius: 4px; font-size: 11px; font-family: monospace; color: var(--accent-primary-hover)">${escapeHtml(u.passwordText || u.password || '—')}</code>
      </td>
      <td>
        <select class="state-selector state-${state}" data-userid="${escapeHtml(uid)}">
          <option value="active" ${state === 'active' ? 'selected' : ''}>Active</option>
          <option value="suspended" ${state === 'suspended' ? 'selected' : ''}>Suspended</option>
          <option value="expired" ${state === 'expired' ? 'selected' : ''}>Expired</option>
        </select>
      </td>
      <td><strong>${sessionCount}</strong> logins</td>
      <td><strong>${totalBills}</strong> bills</td>
      <td><span style="font-size:11px; color:var(--text-muted)">${lastActiveStr}</span></td>
      <td><span class="time-badge" style="display:inline-block; padding: 4px 8px">${sizePref}</span></td>
      <td>
        <div style="display:flex; gap:8px; justify-content:center; align-items:center">
          <button class="dir-action-btn admin-btn" data-userid="${escapeHtml(uid)}" title="${adminBtnText}" style="
            background: ${adminBtnBg}; border:1px solid ${adminBtnBorder};
            color:${adminBtnColor}; border-radius:8px; padding:6px 10px; font-size:13px;
            cursor:pointer; transition:all 0.2s; display:flex; align-items:center; gap:4px;
          ">${adminBtnIcon}</button>
          <button class="dir-action-btn edit-btn" data-userid="${escapeHtml(uid)}" title="Edit Password" style="
            background: rgba(59,130,246,0.1); border:1px solid rgba(59,130,246,0.25);
            color:#60a5fa; border-radius:8px; padding:6px 10px; font-size:13px;
            cursor:pointer; transition:all 0.2s; display:flex; align-items:center; gap:4px;
          ">✏️ Edit</button>
          <button class="dir-action-btn delete-btn" data-userid="${escapeHtml(uid)}" data-shopname="${escapeHtml(u.shopName || 'Unnamed Shop')}" title="Delete Account" style="
            background: rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.25);
            color:#f87171; border-radius:8px; padding:6px 10px; font-size:13px;
            cursor:pointer; transition:all 0.2s; display:flex; align-items:center; gap:4px;
          ">🗑️ Delete</button>
        </div>
      </td>
    `;

    // Hook change listener on state selector
    const selector = tr.querySelector('.state-selector');
    selector.addEventListener('change', (e) => {
      const newStat = e.target.value;
      updateTenantSubscriptionState(selector.dataset.userid, newStat);
      selector.className = `state-selector state-${newStat}`;
    });

    // Hook role toggle button
    tr.querySelector('.admin-btn').addEventListener('click', () => {
      toggleTenantAdminRole(uid);
    });

    // Hook edit password button
    tr.querySelector('.edit-btn').addEventListener('click', () => {
      openEditPasswordModal(uid);
    });

    // Hook delete button
    tr.querySelector('.delete-btn').addEventListener('click', () => {
      const shopName = tr.querySelector('.delete-btn').dataset.shopname;
      openDeleteModal(uid, shopName);
    });

    // Hover effects
    tr.querySelectorAll('.dir-action-btn').forEach(btn => {
      btn.addEventListener('mouseenter', () => btn.style.transform = 'translateY(-1px)');
      btn.addEventListener('mouseleave', () => btn.style.transform = '');
    });

    body.appendChild(tr);
  });
}

function toggleTenantAdminRole(userId) {
  const tenants = getLocalTenants();
  const idx = tenants.findIndex(t => (t.userId || t.email || '').toLowerCase() === userId.toLowerCase());
  
  if (idx === -1) {
    alert('❌ Tenant not found.');
    return;
  }
  
  const currentRole = tenants[idx].role || 'user';
  const newRole = currentRole === 'admin' ? 'user' : 'admin';
  
  if (!confirm(`Are you sure you want to change the role of ${userId} to ${newRole.toUpperCase()}?`)) {
    return;
  }
  
  tenants[idx].role = newRole;
  saveLocalTenants(tenants);
  
  showToast(`👑 Role updated: ${userId} is now ${newRole.toUpperCase()}`);
  loadTenantDirectory(document.getElementById('dirSearchInput')?.value || '');
}

function updateTenantSubscriptionState(userId, newState) {
  const tenants = getLocalTenants();
  const idx = tenants.findIndex(t => (t.userId || t.email || '').toLowerCase() === userId.toLowerCase());
  
  if (idx !== -1) {
    tenants[idx].subscriptionState = newState;
    saveLocalTenants(tenants);
    addAdminLog(`Updated user ${userId} state to ${newState.toUpperCase()}`, 'info');
    showToast(`State updated to ${newState.toUpperCase()}`);
  }
}

// Search filtering on directory keydown
let dirSearchTimeout;
document.getElementById('dirSearchInput')?.addEventListener('input', e => {
  clearTimeout(dirSearchTimeout);
  dirSearchTimeout = setTimeout(() => {
    loadTenantDirectory(e.target.value);
  }, 250);
});

// ─────────────────────────────────────────
//   EDIT PASSWORD MODAL
// ─────────────────────────────────────────
let _editTargetUserId = null;

function openEditPasswordModal(userId) {
  _editTargetUserId = userId;
  document.getElementById('editModalUserLabel').textContent = `Updating credentials for: ${userId}`;
  document.getElementById('editNewPasswordInput').value = '';
  document.getElementById('editConfirmPasswordInput').value = '';
  document.getElementById('editModalError').style.display = 'none';
  const modal = document.getElementById('editPasswordModal');
  modal.style.display = 'flex';
  setTimeout(() => document.getElementById('editNewPasswordInput').focus(), 100);
}

function closeEditPasswordModal() {
  document.getElementById('editPasswordModal').style.display = 'none';
  _editTargetUserId = null;
}

document.getElementById('editModalCancelBtn')?.addEventListener('click', closeEditPasswordModal);
document.getElementById('editPasswordModal')?.addEventListener('click', (e) => {
  if (e.target === document.getElementById('editPasswordModal')) closeEditPasswordModal();
});

document.getElementById('editModalSaveBtn')?.addEventListener('click', async () => {
  const newPass = document.getElementById('editNewPasswordInput').value;
  const confirmPass = document.getElementById('editConfirmPasswordInput').value;
  const errEl = document.getElementById('editModalError');
  errEl.style.display = 'none';

  if (!newPass || newPass.length < 4) {
    errEl.textContent = '❌ Password must be at least 4 characters.';
    errEl.style.display = 'block';
    return;
  }
  if (newPass !== confirmPass) {
    errEl.textContent = '❌ Passwords do not match.';
    errEl.style.display = 'block';
    return;
  }

  try {
    const tenants = getLocalTenants();
    const idx = tenants.findIndex(t => (t.userId || t.email || '').toLowerCase() === _editTargetUserId.toLowerCase());
    if (idx === -1) { errEl.textContent = '❌ User not found.'; errEl.style.display = 'block'; return; }

    const newHash = await hashPassword(newPass);
    tenants[idx].passwordHash = newHash;
    tenants[idx].passwordText = newPass;
    if (tenants[idx].password) delete tenants[idx].password;
    saveLocalTenants(tenants);

    addAdminLog(`Inline password edit completed for ${_editTargetUserId}`, 'warning');
    showToast(`🔑 Password updated for ${_editTargetUserId}`);
    closeEditPasswordModal();
    loadTenantDirectory(document.getElementById('dirSearchInput')?.value || '');
    populateOverrideSelector();

    // Fire security notification
    dispatchSystemNotification(
      '[Bill Maker Admin] Password Changed via Directory Edit',
      `<div style="font-family:sans-serif;max-width:600px"><h2 style="color:#8b5cf6">✏️ Password Updated</h2><p>The password for tenant <strong>${_editTargetUserId}</strong> was updated inline via the Tenant Directory on ${new Date().toLocaleString()}.</p></div>`
    );
  } catch(err) {
    errEl.textContent = '❌ Error: ' + err.message;
    errEl.style.display = 'block';
  }
});

// ─────────────────────────────────────────
//   DELETE ACCOUNT MODAL
// ─────────────────────────────────────────
let _deleteTargetUserId = null;

function openDeleteModal(userId, shopName) {
  _deleteTargetUserId = userId;
  document.getElementById('deleteModalUserLabel').textContent = `${shopName}  (${userId})`;
  const modal = document.getElementById('deleteAccountModal');
  modal.style.display = 'flex';
}

function closeDeleteModal() {
  document.getElementById('deleteAccountModal').style.display = 'none';
  _deleteTargetUserId = null;
}

document.getElementById('deleteModalCancelBtn')?.addEventListener('click', closeDeleteModal);
document.getElementById('deleteAccountModal')?.addEventListener('click', (e) => {
  if (e.target === document.getElementById('deleteAccountModal')) closeDeleteModal();
});

document.getElementById('deleteModalConfirmBtn')?.addEventListener('click', () => {
  if (!_deleteTargetUserId) return;

  // Remove from bm_local_users
  let tenants = getLocalTenants();
  const idx = tenants.findIndex(t => (t.userId || t.email || '').toLowerCase() === _deleteTargetUserId.toLowerCase());
  if (idx !== -1) {
    tenants.splice(idx, 1);
    saveLocalTenants(tenants);
  }

  // Remove from admin config managed users list
  if (ADMIN_CONFIG?.managedUsers) {
    ADMIN_CONFIG.managedUsers = ADMIN_CONFIG.managedUsers.filter(u => u.toLowerCase() !== _deleteTargetUserId.toLowerCase());
    localStorage.setItem('bm_admin_config', JSON.stringify(ADMIN_CONFIG));
  }

  // Remove all bill data for this user
  const billKey = 'bm_bills_' + _deleteTargetUserId;
  localStorage.removeItem(billKey);

  addAdminLog(`Account permanently deleted: ${_deleteTargetUserId}`, 'error');
  showToast(`🗑️ Account deleted: ${_deleteTargetUserId}`);
  closeDeleteModal();
  loadTenantDirectory(document.getElementById('dirSearchInput')?.value || '');
  refreshStatsAndMetrics();
  populateOverrideSelector();
});

// ── PASSWORD OVERRIDES ──
function populateOverrideSelector() {
  const select = document.getElementById('overrideUserSelect');
  if (!select) return;

  const tenants = getLocalTenants();
  
  // Clear options except default
  select.innerHTML = '<option value="">-- Choose Tenant User ID --</option>';
  
  tenants.forEach(u => {
    const opt = document.createElement('option');
    opt.value = u.userId || u.email;
    opt.textContent = `${u.shopName || 'Store'} (${u.userId || u.email})`;
    select.appendChild(opt);
  });
}

async function handleOverrideSubmit(e) {
  e.preventDefault();

  const userId = document.getElementById('overrideUserSelect').value;
  const newPass = document.getElementById('overrideNewPassword').value;

  if (!userId) {
    alert('❌ Please select a tenant.');
    return;
  }

  const tenants = getLocalTenants();
  const idx = tenants.findIndex(t => (t.userId || t.email || '').toLowerCase() === userId.toLowerCase());

  if (idx === -1) {
    alert('❌ Selected user does not exist.');
    return;
  }

  if (confirm(`Are you absolutely sure you want to override the credentials for user ${userId}? This will apply instantly.`)) {
    try {
      const newHash = await hashPassword(newPass);
      tenants[idx].passwordHash = newHash;
      tenants[idx].passwordText = newPass; // Sync plain password for ledger
      if (tenants[idx].password) delete tenants[idx].password; // Clean plain password

      saveLocalTenants(tenants);
      showToast(`🔑 Credentials reset completed for ${userId}.`);
      document.getElementById('overrideForm').reset();
      addAdminLog(`Administrative password override executed for ${userId}`, 'warning');

      // Dispatch security email notification
      const subject = `[Bill Maker Admin] Security Alert: Credentials Overwritten`;
      const htmlContent = `
        <div style="font-family: sans-serif; max-width: 600px; border: 1px solid #ddd; padding: 20px; border-radius: 8px;">
          <h2 style="color: #ef4444; margin-top: 0">⚠️ Administrative Password Override Alert</h2>
          <p>The password for tenant account <strong>${userId}</strong> has been modified directly by the Super Admin Control Panel.</p>
          <table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
            <tr>
              <td style="padding: 6px 0; font-weight: bold; color: #555;">Target User:</td>
              <td style="padding: 6px 0;">${userId}</td>
            </tr>
            <tr>
              <td style="padding: 6px 0; font-weight: bold; color: #555;">Business Name:</td>
              <td style="padding: 6px 0;">${tenants[idx].shopName || 'Store'}</td>
            </tr>
            <tr>
              <td style="padding: 6px 0; font-weight: bold; color: #555;">Timestamp:</td>
              <td style="padding: 6px 0;">${new Date().toLocaleString()}</td>
            </tr>
          </table>
          <p style="color: #666; font-size: 13px; line-height: 1.5">This credentials override bypassed standard security authentication confirm dialogues. If this change was unexpected, audit the admin ecosystem logs immediately.</p>
        </div>
      `;
      
      // Dispatch async alert
      dispatchSystemNotification(subject, htmlContent);
    } catch(err) {
      alert('❌ Override update failed: ' + err.message);
    }
  }
}

// ── GMAIL INTEGRATION CONFIGS ──
function loadGmailConfigurations() {
  if (!ADMIN_CONFIG) return;

  document.getElementById('gmailSenderAddr').value = ADMIN_CONFIG.adminEmail || '';
  
  const clientInput = document.getElementById('gmailClientId');
  const secretInput = document.getElementById('gmailClientSecret');
  const refreshInput = document.getElementById('gmailRefreshToken');

  if (ADMIN_CONFIG.gmailClientId) {
    clientInput.placeholder = 'Credentials saved. Enter new values to modify.';
    secretInput.placeholder = '••••••••••••••••••••••••••••';
    refreshInput.placeholder = '••••••••••••••••••••••••••••';
    
    // Connection test active
    document.getElementById('gmailStatusText').textContent = 'Vault Decryption Active';
    document.getElementById('gmailStatusDot').className = 'status-dot active';
    document.getElementById('btnTestGmailConnection').disabled = false;
  } else {
    clientInput.placeholder = 'Enter OAuth2 Client ID';
    secretInput.placeholder = 'Enter Client Secret';
    refreshInput.placeholder = 'Enter Refresh Token';
    
    document.getElementById('gmailStatusText').textContent = 'DISCONNECTED';
    document.getElementById('gmailStatusDot').className = 'status-dot';
    document.getElementById('btnTestGmailConnection').disabled = true;
  }
}

async function handleGmailSettingsSubmit(e) {
  e.preventDefault();

  const sender = document.getElementById('gmailSenderAddr').value.trim();
  const clientId = document.getElementById('gmailClientId').value.trim();
  const secret = document.getElementById('gmailClientSecret').value.trim();
  const refreshToken = document.getElementById('gmailRefreshToken').value.trim();

  // If already saved and blank, ignore updates, keep previous
  const finalClientId = clientId || (ADMIN_CONFIG.gmailClientId ? await decryptData(ADMIN_CONFIG.gmailClientId, ACTIVE_ADMIN_PASSWORD) : '');
  const finalSecret = secret || (ADMIN_CONFIG.gmailClientSecret ? await decryptData(ADMIN_CONFIG.gmailClientSecret, ACTIVE_ADMIN_PASSWORD) : '');
  const finalRefreshToken = refreshToken || (ADMIN_CONFIG.gmailRefreshToken ? await decryptData(ADMIN_CONFIG.gmailRefreshToken, ACTIVE_ADMIN_PASSWORD) : '');

  if (!finalClientId || !finalSecret || !finalRefreshToken) {
    alert('❌ Please provide complete Google API credentials.');
    return;
  }

  try {
    addAdminLog('Encrypting configurations with AES-GCM (256-bit)...', 'info');
    const encClient = await encryptData(finalClientId, ACTIVE_ADMIN_PASSWORD);
    const encSecret = await encryptData(finalSecret, ACTIVE_ADMIN_PASSWORD);
    const encRefresh = await encryptData(finalRefreshToken, ACTIVE_ADMIN_PASSWORD);

    ADMIN_CONFIG.adminEmail = sender;
    ADMIN_CONFIG.gmailClientId = encClient;
    ADMIN_CONFIG.gmailClientSecret = encSecret;
    ADMIN_CONFIG.gmailRefreshToken = encRefresh;

    localStorage.setItem('bm_admin_config', JSON.stringify(ADMIN_CONFIG));
    showToast('💾 Encrypted configurations saved.');
    addAdminLog('Encrypted OAuth tokens successfully written to the database vault.', 'success');
    
    loadGmailConfigurations();
  } catch(err) {
    addAdminLog('Encryption failure: ' + err.message, 'error');
    alert('❌ Storage failure: ' + err.message);
  }
}

async function testGmailConnection() {
  const btn = document.getElementById('btnTestGmailConnection');
  btn.disabled = true;
  btn.textContent = '🧪 Testing oauth handshake...';
  
  addAdminLog('Initializing Gmail API handshakes...', 'info');

  try {
    const clientId = await decryptData(ADMIN_CONFIG.gmailClientId, ACTIVE_ADMIN_PASSWORD);
    const clientSecret = await decryptData(ADMIN_CONFIG.gmailClientSecret, ACTIVE_ADMIN_PASSWORD);
    const refreshToken = await decryptData(ADMIN_CONFIG.gmailRefreshToken, ACTIVE_ADMIN_PASSWORD);
    const fromAddr = ADMIN_CONFIG.adminEmail;

    addAdminLog('Connecting to oauth2.googleapis.com token endpoint...', 'info');
    const accessToken = await refreshGmailAccessToken(clientId, clientSecret, refreshToken);
    addAdminLog('Access Token successfully acquired.', 'success');

    const subject = `[Bill Maker Control Panel] Transactional Alert Test`;
    const htmlBody = `
      <div style="font-family: sans-serif; max-width: 600px; border: 1.5px solid #6366f1; padding: 25px; border-radius: 12px; background: #fafafa">
        <h2 style="color: #6366f1; margin-top: 0">⚡ Transactional Linkage Operational</h2>
        <p>This verification email tests OAuth2 relay integrations. The Super Admin configuration is active and encrypted.</p>
        <p>System metrics:</p>
        <ul>
          <li><strong>Ecosystem Admin:</strong> ${ADMIN_CONFIG.masterId}</li>
          <li><strong>Alert Source Address:</strong> ${fromAddr}</li>
          <li><strong>Timestamp:</strong> ${new Date().toUTCString()}</li>
        </ul>
        <p style="color: #666; font-size: 11px">Bill Maker Super Admin Security Protocol Engine v1.0</p>
      </div>
    `;

    addAdminLog('Sending MIME test payload...', 'info');
    await sendGmailMime(accessToken, fromAddr, fromAddr, subject, htmlBody);
    addAdminLog(' Handshake and delivery completed! Test email sent successfully.', 'success');
    showToast('✉️ Handshake success! Check inbox.');
  } catch(err) {
    addAdminLog('OAuth Connection Failed: ' + err.message, 'error');
    showToast('❌ HANDSHAKE FAIL: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '🧪 Verify Auth & Send Test Email';
  }
}

// ── UTILITIES ──
function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(message) {
  const toast = document.getElementById('adminToast');
  const msgEl = document.getElementById('toastMessage');
  if (!toast || !msgEl) return;

  msgEl.textContent = message;
  toast.classList.add('show');

  setTimeout(() => {
    toast.classList.remove('show');
  }, 3500);
}

// ─────────────────────────────────────────────────────
//   TEMPLATE SYSTEM MANAGEMENT (SUPER ADMIN)
// ─────────────────────────────────────────────────────

const DEFAULT_TEMPLATES = [
  {
    id: 'tmpl-1',
    name: 'Classic VYAPAR',
    previewCardStyle: '',
    previewHeadStyle: 'background:#e0e0e0; color:#333;',
    previewHeadText: '⚖️ VYAPAR',
    previewBodyHtml: '<div class="tp-line w70"></div><div class="tp-table"><div class="tp-tr"><div class="tp-td" style="background:#e8e8e8"></div><div class="tp-td"></div><div class="tp-td"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w50"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-2',
    name: 'Simple Receipt',
    previewCardStyle: '',
    previewHeadStyle: 'background:#fff; color:#000; border-bottom:1px solid #111; font-size:8px;',
    previewHeadText: '📝 Simple Receipt',
    previewBodyHtml: '<div class="tp-line w70" style="background:#111; height:1px"></div><div class="tp-table" style="border-color:#111"><div class="tp-tr"><div class="tp-td" style="background:#f5f5f5"></div><div class="tp-td" style="background:#f5f5f5"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w35" style="background:#888"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-3',
    name: 'Bold Black',
    previewCardStyle: '',
    previewHeadStyle: 'background:#111; color:#fff; font-size:9px; letter-spacing:1px;',
    previewHeadText: 'VYAPAR',
    previewBodyHtml: '<div class="tp-line w70" style="background:#555"></div><div class="tp-table"><div class="tp-tr"><div class="tp-td" style="background:#f0f0f0"></div><div class="tp-td" style="background:#f0f0f0"></div><div class="tp-td" style="background:#f0f0f0"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w50" style="background:#111; height:3px"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-4',
    name: 'Service Cursive',
    previewCardStyle: '',
    previewHeadStyle: 'background:#fff; color:#1a1a1a; font-family:Georgia,serif; font-style:italic; font-size:8px; border-bottom:1px solid #333;',
    previewHeadText: '✒️ Service Income',
    previewBodyHtml: '<div class="tp-line w70" style="background:#aaa; height:1px"></div><div class="tp-table" style="border-color:#333"><div class="tp-tr"><div class="tp-td" style="background:#f7f7f7"></div><div class="tp-td" style="background:#f7f7f7"></div></div><div class="tp-tr" style="border-bottom:1px dashed #ccc"><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w35" style="background:#bbb"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-5',
    name: 'Credit Note',
    previewCardStyle: 'border:1.5px solid #c0392b; border-radius:0;',
    previewHeadStyle: 'background:#c0392b; color:#fff; font-size:9px; letter-spacing:0.5px;',
    previewHeadText: 'VYAPAR Credit Note',
    previewBodyHtml: '<div class="tp-line w70" style="background:#e57373"></div><div class="tp-table" style="border-color:#c0392b"><div class="tp-tr"><div class="tp-td" style="background:#ffeaea"></div><div class="tp-td" style="background:#ffeaea"></div><div class="tp-td" style="background:#ffeaea"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w50" style="background:#ffeaea; height:3px"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-6',
    name: 'Wholesale Blue',
    previewCardStyle: 'border:1.5px solid #1a56db; border-radius:0;',
    previewHeadStyle: 'background:#1a56db; color:#fff; font-size:9px; letter-spacing:1px;',
    previewHeadText: 'A4/2 VYAPAR',
    previewBodyHtml: '<div class="tp-line w70" style="background:#93c5fd"></div><div class="tp-table" style="border-color:#1a56db"><div class="tp-tr"><div class="tp-td" style="background:#dbeafe"></div><div class="tp-td" style="background:#dbeafe"></div><div class="tp-td" style="background:#dbeafe"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w100" style="background:#1a56db; height:3px"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-7',
    name: 'Grey Ledger',
    previewCardStyle: 'background:#fafafa;',
    previewHeadStyle: 'background:#9e9e9e; color:#fff; font-size:9px;',
    previewHeadText: 'VYAPAR',
    previewBodyHtml: '<div class="tp-line w70" style="background:#aaa"></div><div class="tp-table" style="border-color:#777"><div class="tp-tr"><div class="tp-td" style="background:#ddd"></div><div class="tp-td" style="background:#ddd"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div></div><div class="tp-tr" style="background:#f5f5f5"><div class="tp-td" style="background:#f0f0f0"></div><div class="tp-td" style="background:#f0f0f0"></div></div></div><div class="tp-line w50" style="background:#757575; height:3px"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-8',
    name: 'Vintage Order',
    previewCardStyle: 'background:#fdf8ec; border:1px solid #c9b99a; border-radius:0;',
    previewHeadStyle: 'background:#f5e6c8; color:#3d2b1f; font-family:Georgia,serif; font-style:italic; border-bottom:1.5px solid #8b6914;',
    previewHeadText: '📜 Order Form',
    previewBodyHtml: '<div class="tp-line w70" style="background:#c9b99a"></div><div class="tp-table" style="border-color:#8b6914"><div class="tp-tr"><div class="tp-td" style="background:#f5e6c8"></div><div class="tp-td" style="background:#f5e6c8"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w35" style="background:#8b6914"></div>',
    css: '',
    isDefault: true
  },
  {
    id: 'tmpl-9',
    name: 'Bold Blue VYAPAR',
    previewCardStyle: 'border:2px solid #1a56db; border-radius:0;',
    previewHeadStyle: 'background:#1a56db; color:#fff; font-size:10px; font-weight:900; letter-spacing:2px;',
    previewHeadText: 'VYAPAR',
    previewBodyHtml: '<div class="tp-line w70" style="background:#93c5fd"></div><div class="tp-table"><div class="tp-tr"><div class="tp-td" style="background:#1a56db; height:4px"></div><div class="tp-td" style="background:#1a56db; height:4px"></div><div class="tp-td" style="background:#1a56db; height:4px"></div></div><div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div><div class="tp-td"></div></div></div><div class="tp-line w100" style="background:#1340a0; height:4px"></div>',
    css: '',
    isDefault: true
  }
];

function initTemplatesEcosystem() {
  const data = localStorage.getItem('bm_templates');
  if (!data) {
    localStorage.setItem('bm_templates', JSON.stringify(DEFAULT_TEMPLATES));
  }
}

function getTemplates() {
  const data = localStorage.getItem('bm_templates');
  if (!data) {
    return DEFAULT_TEMPLATES;
  }
  try {
    const parsed = JSON.parse(data);
    return Array.isArray(parsed) && parsed.length > 0 ? parsed : DEFAULT_TEMPLATES;
  } catch (e) {
    return DEFAULT_TEMPLATES;
  }
}

function saveTemplates(templates) {
  localStorage.setItem('bm_templates', JSON.stringify(templates));
}

// Render dynamic templates as photo-style gallery cards
function loadTemplatesDirectory(searchQuery) {
  searchQuery = searchQuery || '';
  var gallery = document.getElementById('templatesGallery');
  if (!gallery) return;

  var templates;
  try { templates = getTemplates(); } catch(e) {
    gallery.innerHTML = '<div class="templates-empty-state"><div class="empty-icon">⚠️</div><div>Error loading templates.</div></div>';
    return;
  }

  gallery.innerHTML = '';

  var filtered = templates;
  if (searchQuery.trim()) {
    var q = searchQuery.toLowerCase();
    filtered = templates.filter(function(t) {
      return (t.name||'').toLowerCase().indexOf(q) !== -1 || (t.id||'').toLowerCase().indexOf(q) !== -1;
    });
  }

  if (!filtered.length) {
    gallery.innerHTML = '<div class="templates-empty-state"><div class="empty-icon">🎨</div><div>No templates found. Click <strong style="color:#fff">Add New Template</strong> to create one.</div></div>';
    return;
  }

  filtered.forEach(function(t, idx) {
    try {
      var baseColor  = (t.config && t.config.color)      ? t.config.color      : '#8b5cf6';
      var headerBg   = (t.config && t.config.headerBg)   ? t.config.headerBg   : '#1a1a2e';
      var headerText = (t.config && t.config.headerText)  ? t.config.headerText : '#ffffff';
      var fontLabel  = 'Inter';
      if (t.config) {
        if      (t.config.font === 'Georgia')     fontLabel = 'Georgia';
        else if (t.config.font === 'Courier New') fontLabel = 'Courier';
      }
      var isDefault   = !!t.isDefault;
      var statusText  = isDefault ? 'System Default' : 'Custom';
      var statusStyle = isDefault
        ? 'background:rgba(16,185,129,0.18);color:#34d399;border:1px solid rgba(16,185,129,0.25);'
        : 'background:rgba(139,92,246,0.18);color:#a78bfa;border:1px solid rgba(139,92,246,0.25);';

      var headText  = t.previewHeadText || 'VYAPAR';
      var parts     = headText.trim().split(' ');
      var icon      = '📄';
      var titleText = headText;
      try {
        var cp = parts[0] ? parts[0].codePointAt(0) : 0;
        if (cp && ((cp >= 0x1F300 && cp <= 0x1FAFF) || (cp >= 0x2600 && cp <= 0x27BF))) {
          icon = parts[0];
          titleText = parts.slice(1).join(' ') || 'VYAPAR';
        }
      } catch(ex) {}

      var card = document.createElement('div');
      card.className = 'template-card';
      card.style.animationDelay = (idx * 0.06) + 's';

      var previewHtml = '';
      if (t.screenshotBase64) {
        previewHtml =
          '<div class="tmpl-preview" style="background:#111;position:relative;">' +
            '<img src="' + t.screenshotBase64 + '" alt="preview" style="width:100%;height:185px;object-fit:cover;display:block;border-bottom:2px solid ' + baseColor + ';">' +
            '<span style="position:absolute;bottom:8px;right:8px;background:rgba(0,0,0,0.65);color:#fff;font-size:9px;font-weight:700;padding:3px 8px;border-radius:20px;">📸 Screenshot</span>' +
          '</div>';
      } else {
        previewHtml =
          '<div class="tmpl-preview" style="background:' + headerBg + '">' +
            '<div class="tmpl-preview-header" style="background:' + headerBg + ';border-bottom:2px solid ' + baseColor + '">' +
              '<div class="tmpl-preview-header-top">' +
                '<span class="tmpl-preview-brand" style="color:' + headerText + '">' + icon + ' ' + escapeHtml(titleText) + '</span>' +
                '<span class="tmpl-preview-inv" style="color:' + headerText + '">INVOICE</span>' +
              '</div>' +
              '<span class="tmpl-preview-subline" style="color:' + headerText + '">Shop · Phone · Address</span>' +
            '</div>' +
            '<div class="tmpl-preview-body">' +
              '<div class="tmpl-preview-meta">' +
                '<div class="tmpl-meta-pill" style="width:60px;background:' + baseColor + '"></div>' +
                '<div class="tmpl-meta-pill" style="width:40px;background:' + baseColor + '"></div>' +
              '</div>' +
              '<div class="tmpl-preview-table">' +
                '<div class="tmpl-table-head" style="background:' + baseColor + '20">' +
                  '<div class="tmpl-th" style="background:' + baseColor + '30"></div>' +
                  '<div class="tmpl-th" style="background:' + baseColor + '20"></div>' +
                  '<div class="tmpl-th" style="background:' + baseColor + '20"></div>' +
                  '<div class="tmpl-th" style="background:' + baseColor + '25"></div>' +
                '</div>' +
                '<div class="tmpl-table-rows">' +
                  '<div class="tmpl-tr"><div class="tmpl-td"></div><div class="tmpl-td"></div><div class="tmpl-td"></div><div class="tmpl-td"></div></div>' +
                  '<div class="tmpl-tr" style="background:#f8f8f8"><div class="tmpl-td"></div><div class="tmpl-td"></div><div class="tmpl-td"></div><div class="tmpl-td"></div></div>' +
                  '<div class="tmpl-tr"><div class="tmpl-td"></div><div class="tmpl-td"></div><div class="tmpl-td"></div><div class="tmpl-td"></div></div>' +
                '</div>' +
                '<div class="tmpl-grand-row" style="background:' + baseColor + '">' +
                  '<div class="tmpl-grand-td"></div>' +
                  '<div class="tmpl-grand-td" style="border-left:1px solid rgba(255,255,255,0.2)"></div>' +
                '</div>' +
              '</div>' +
            '</div>' +
            '<div class="tmpl-preview-footer"><div class="tmpl-footer-line" style="background:' + baseColor + '"></div></div>' +
          '</div>';
      }

      card.innerHTML =
        '<span class="tmpl-status-badge" style="' + statusStyle + '">' + statusText + '</span>' +
        '<div class="tmpl-card-overlay">' +
          '<div class="tmpl-overlay-name">' + escapeHtml(t.name) + '</div>' +
          '<div class="tmpl-overlay-btns">' +
            '<button class="tmpl-overlay-btn tmpl-btn-edit">✏️ Edit</button>' +
            '<button class="tmpl-overlay-btn tmpl-btn-delete">🗑️ Delete</button>' +
          '</div>' +
        '</div>' +
        previewHtml +
        '<div class="tmpl-card-info">' +
          '<div class="tmpl-card-name-row">' +
            '<span class="tmpl-card-name">' + escapeHtml(t.name) + '</span>' +
            '<div class="tmpl-color-dots">' +
              '<div class="tmpl-dot" style="background:' + baseColor + '"></div>' +
              '<div class="tmpl-dot" style="background:' + headerBg + '"></div>' +
              '<div class="tmpl-dot" style="background:' + headerText + '"></div>' +
            '</div>' +
          '</div>' +
          '<div style="display:flex;justify-content:space-between;align-items:center">' +
            '<span class="tmpl-card-id">' + escapeHtml(t.id) + '</span>' +
            '<span class="tmpl-font-badge">🔤 ' + fontLabel + '</span>' +
          '</div>' +
        '</div>';

      var tid = t.id; var tname = t.name;
      card.querySelector('.tmpl-btn-edit').addEventListener('click', function(e) { e.stopPropagation(); openTemplateModal('edit', tid); });
      var db = card.querySelector('.tmpl-btn-delete');
      if (db) db.addEventListener('click', function(e) { e.stopPropagation(); openDeleteTemplateModal(tid, tname); });
      card.addEventListener('click', function() { openTemplateModal('edit', tid); });
      gallery.appendChild(card);
    } catch(cardErr) { console.error('Card error', t && t.id, cardErr); }
  });
}
// Search templates
let tmplSearchTimeout;
document.getElementById('tmplSearchInput')?.addEventListener('input', e => {
  clearTimeout(tmplSearchTimeout);
  tmplSearchTimeout = setTimeout(() => {
    loadTemplatesDirectory(e.target.value);
  }, 250);
});

// ── TEMPLATES MODALS LOGIC ──
let isCssCustom = false;

function generateDefaultCSS(id, name, color, headerBg, headerText, font) {
  const fontRule = font === 'Georgia' ? "Georgia, serif" : (font === 'Courier New' ? "'Courier New', Courier, monospace" : "'Inter', 'Noto Sans Devanagari', sans-serif");
  
  return `/* Theme Style for ${name} */
#invoicePaper.${id} {
  background: #fff;
  border: 2.5px solid ${color} !important;
  font-family: ${fontRule} !important;
}
#invoicePaper.${id} .bill-religious {
  background: ${headerBg} !important;
  color: ${headerText} !important;
  font-size: 11px;
  padding: 6px 12px;
  margin-bottom: 0;
  border-bottom: 1.5px solid ${color} !important;
}
#invoicePaper.${id} .bill-header-block {
  background: ${headerBg} !important;
  padding: 12px 14px !important;
  border-bottom: 2.5px solid ${color} !important;
}
#invoicePaper.${id} .bill-biz-name {
  color: ${headerText} !important;
}
#invoicePaper.${id} .bill-biz-sub {
  color: ${headerText}aa !important;
}
#invoicePaper.${id} .bill-biz-addr {
  color: ${headerText}88 !important;
}
#invoicePaper.${id} .bill-biz-right {
  color: ${headerText}aa !important;
}
#invoicePaper.${id} .bill-items-table th {
  background: ${headerBg}12 !important; /* light opacity tint */
  color: ${color} !important;
  border-top: 1.5px solid ${color} !important;
  border-bottom: 1.5px solid ${color} !important;
}
#invoicePaper.${id} .grand-row td {
  background: ${color} !important;
  color: #fff !important;
  border-top: 2px solid ${color} !important;
  border-bottom: 2px solid ${color} !important;
}
#invoicePaper.${id} .bill-thankyou {
  border-top: 1px dashed ${color} !important;
  color: ${color} !important;
}`;
}

// Synchronize text inputs and color pickers
function syncColorInputs(colorId, hexId) {
  const colorEl = document.getElementById(colorId);
  const hexEl = document.getElementById(hexId);
  
  if (!colorEl || !hexEl) return;
  
  colorEl.addEventListener('input', () => {
    hexEl.value = colorEl.value.toUpperCase();
    triggerCssAutoRegen();
  });
  
  hexEl.addEventListener('input', () => {
    const val = hexEl.value.trim();
    if (/^#[0-9A-F]{6}$/i.test(val)) {
      colorEl.value = val;
      triggerCssAutoRegen();
    }
  });
}

function triggerCssAutoRegen() {
  if (isCssCustom) return;
  
  const id = document.getElementById('tmplModalId').value.trim() || 'tmpl-custom';
  const name = document.getElementById('tmplModalName').value.trim() || 'Custom Theme';
  const color = document.getElementById('tmplModalColorHex').value.trim();
  const headerBg = document.getElementById('tmplModalHeaderBgHex').value.trim();
  const headerText = document.getElementById('tmplModalHeaderTextHex').value.trim();
  const font = document.getElementById('tmplModalFont').value;

  const cssTextarea = document.getElementById('tmplModalCss');
  if (cssTextarea) {
    cssTextarea.value = generateDefaultCSS(id, name, color, headerBg, headerText, font);
  }
}

// Wire color synchronization
let _tmplCurrentImageBase64 = null; // Holds base64 of uploaded screenshot in memory

function setTemplateImagePreview(base64) {
  _tmplCurrentImageBase64 = base64 || null;
  const previewWrap = document.getElementById('tmplImgPreviewWrap');
  const previewImg  = document.getElementById('tmplImgPreviewEl');
  const uploadZone  = document.getElementById('tmplUploadZone');
  const clearBtn    = document.getElementById('tmplImgClearBtn');

  if (base64) {
    previewImg.src = base64;
    previewWrap.classList.add('has-image');
    uploadZone.style.display = 'none';
    if (clearBtn) clearBtn.style.display = 'inline';
  } else {
    previewImg.src = '';
    previewWrap.classList.remove('has-image');
    previewWrap.classList.remove('scanning');
    uploadZone.style.display = '';
    if (clearBtn) clearBtn.style.display = 'none';
    var badge = document.getElementById('visionResultBadge');
    if (badge) badge.style.display = 'none';
  }
}

function clearTemplateImage() {
  // Reset file input so same file can be re-selected
  const inp = document.getElementById('tmplScreenshotInput');
  if (inp) inp.value = '';
  setTemplateImagePreview(null);
}


// ════════════════════════════════════════════════════════════════
// ANTIGRAVITY VISION RECOGNITION ENGINE — Canvas Pixel Analysis
// ════════════════════════════════════════════════════════════════
function analyzeImageForTemplate(base64) {
  return new Promise(function(resolve) {
    var img = new Image();
    img.onload = function() {
      try {
        var W = Math.min(img.width,  600);
        var H = Math.min(img.height, 900);
        var canvas = document.createElement('canvas');
        canvas.width  = W;
        canvas.height = H;
        var ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, W, H);

        // ── Region samplers ──
        var headerH  = Math.floor(H * 0.22);  // top 22%  = header
        var bodyTop  = Math.floor(H * 0.22);
        var bodyH    = Math.floor(H * 0.55);  // middle 55% = item rows

        var headerData = ctx.getImageData(0, 0,       W, headerH).data;
        var bodyData   = ctx.getImageData(0, bodyTop,  W, bodyH  ).data;
        var fullData   = ctx.getImageData(0, 0,        W, H      ).data;

        // ── Helpers ──
        function brightness(r, g, b) { return 0.299*r + 0.587*g + 0.114*b; }
        function saturation(r, g, b) {
          var max = Math.max(r,g,b), min = Math.min(r,g,b);
          return max === 0 ? 0 : (max - min) / max;
        }
        function toHex(r, g, b) {
          return '#' + [r,g,b].map(function(v){
            return Math.max(0,Math.min(255,Math.round(v))).toString(16).padStart(2,'0');
          }).join('');
        }
        function avgColor(data) {
          var r=0,g=0,b=0,n=data.length/4;
          for (var i=0;i<data.length;i+=4){ r+=data[i]; g+=data[i+1]; b+=data[i+2]; }
          return {r:r/n, g:g/n, b:b/n};
        }

        // ── Header region ──
        var hAvg = avgColor(headerData);
        var headerBg   = toHex(hAvg.r, hAvg.g, hAvg.b);
        var hBright    = brightness(hAvg.r, hAvg.g, hAvg.b);
        var headerText = hBright < 140 ? '#ffffff' : '#1a1a1a';

        // ── Accent/theme color ──
        // Find pixel with highest saturation across full image
        var bestSat = 0, aR = 99, aG = 66, aB = 226;
        for (var i=0; i<fullData.length; i+=8) {
          var r=fullData[i], g=fullData[i+1], b=fullData[i+2];
          var bri = brightness(r,g,b);
          if (bri > 235 || bri < 18) continue;  // skip white/black
          var sat = saturation(r,g,b);
          if (sat > bestSat) { bestSat=sat; aR=r; aG=g; aB=b; }
        }
        var accentColor = toHex(aR, aG, aB);

        // ── Body brightness = font style hint ──
        var bAvg    = avgColor(bodyData);
        var bBright = brightness(bAvg.r, bAvg.g, bAvg.b);
        var font    = bBright > 215 ? 'Devanagari' : 'Georgia';

        // ── Layout density (compact vs A4) ──
        // If image taller than 1.4× wide → A4
        var layout = (img.height / img.width) > 1.4 ? 'A4' : 'compact';

        resolve({ headerBg: headerBg, headerText: headerText, color: accentColor, font: font, layout: layout });
      } catch(err) {
        console.error('Vision analysis failed:', err);
        resolve(null);
      }
    };
    img.onerror = function() { resolve(null); };
    img.src = base64;
  });
}

// Apply vision analysis result to the template form
function applyVisionResult(result) {
  if (!result) return;
  try {
    // Color pickers
    document.getElementById('tmplModalColor').value      = result.color;
    document.getElementById('tmplModalColorHex').value   = result.color.toUpperCase();
    document.getElementById('tmplModalHeaderBg').value   = result.headerBg;
    document.getElementById('tmplModalHeaderBgHex').value = result.headerBg.toUpperCase();
    document.getElementById('tmplModalHeaderText').value    = result.headerText;
    document.getElementById('tmplModalHeaderTextHex').value = result.headerText.toUpperCase();
    // Font
    if (result.font) {
      document.getElementById('tmplModalFont').value = result.font;
    }
    // Regenerate CSS with detected values
    isCssCustom = false;
    triggerCssAutoRegen();
    // Show badge on upload zone
    var badge = document.getElementById('visionResultBadge');
    if (badge) {
      badge.innerHTML =
        '<span style="color:#34d399">✔</span> Vision detected: ' +
        '<span style="font-family:monospace;font-size:10px">' +
          'Base <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' + result.color + ';vertical-align:middle;margin:0 3px;border:1px solid rgba(255,255,255,0.2)"></span>' + result.color.toUpperCase() + ' &nbsp;' +
          'Header <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' + result.headerBg + ';vertical-align:middle;margin:0 3px;border:1px solid rgba(255,255,255,0.2)"></span>' + result.headerBg.toUpperCase() + ' &nbsp;' +
          'Font: ' + result.font +
        '</span>';
      badge.style.display = 'flex';
    }
    showToast('🎨 Vision detected colors & font — fields auto-filled!');
  } catch(e) { console.error('applyVisionResult error', e); }
}
document.addEventListener('DOMContentLoaded', () => {
  syncColorInputs('tmplModalColor', 'tmplModalColorHex');
  syncColorInputs('tmplModalHeaderBg', 'tmplModalHeaderBgHex');
  syncColorInputs('tmplModalHeaderText', 'tmplModalHeaderTextHex');

  // Trigger regeneration on inputs change
  ['tmplModalId', 'tmplModalName'].forEach(id => {
    document.getElementById(id)?.addEventListener('input', triggerCssAutoRegen);
  });
  ['tmplModalFont'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', triggerCssAutoRegen);
  });

  // If user modifies CSS, mark it as custom
  document.getElementById('tmplModalCss')?.addEventListener('input', () => {
    isCssCustom = true;
  });

  // Reset CSS button
  document.getElementById('btnResetCss')?.addEventListener('click', () => {
    isCssCustom = false;
    triggerCssAutoRegen();
    showToast('Reset to generated styling.');
  });

  // ── SCREENSHOT UPLOAD WIRING ──

  function processImageFile(file) {
    if (!file || !file.type.startsWith('image/')) {
      showToast('❌ Please select an image file (PNG, JPG, WEBP)');
      return;
    }
    if (file.size > 4 * 1024 * 1024) {
      showToast('❌ Image too large — max 4 MB');
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      const base64 = ev.target.result;
      setTemplateImagePreview(base64);

      // ── Vision Analysis ──
      var previewWrap = document.getElementById('tmplImgPreviewWrap');
      if (previewWrap) previewWrap.classList.add('scanning');
      var badge = document.getElementById('visionResultBadge');
      if (badge) {
        badge.innerHTML = '<span class="vision-scanning-dot"></span> Scanning image with Vision Recognition Engine...';
        badge.style.display = 'flex';
      }
      analyzeImageForTemplate(base64).then(function(result) {
        if (previewWrap) previewWrap.classList.remove('scanning');
        applyVisionResult(result);
        if (!result && badge) { badge.style.display = 'none'; }
      });
    };
    reader.readAsDataURL(file);
  }

  // File input change event (triggered by label click)
  const screenshotInput = document.getElementById('tmplScreenshotInput');
  screenshotInput?.addEventListener('change', (e) => {
    processImageFile(e.target.files?.[0]);
  });

  // Clicking anywhere on the zone also opens file picker (backup)
  const uploadZone = document.getElementById('tmplUploadZone');
  uploadZone?.addEventListener('click', (e) => {
    // Don't double-trigger if the click came from the label itself
    if (e.target.tagName === 'LABEL' || e.target.closest('label')) return;
    screenshotInput?.click();
  });

  // Drag-over highlight
  uploadZone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.stopPropagation();
    uploadZone.classList.add('drag-over');
  });
  uploadZone?.addEventListener('dragleave', (e) => {
    e.stopPropagation();
    uploadZone.classList.remove('drag-over');
  });

  // Drop handler
  uploadZone?.addEventListener('drop', (e) => {
    e.preventDefault();
    e.stopPropagation();
    uploadZone.classList.remove('drag-over');
    processImageFile(e.dataTransfer.files?.[0]);
  });
});

function openTemplateModal(mode, templateId = null) {
  const modal = document.getElementById('templateModal');
  const form = document.getElementById('templateForm');
  const titleEl = document.getElementById('templateModalTitle');
  const idInp = document.getElementById('tmplModalId');
  const nameInp = document.getElementById('tmplModalName');
  const modeInp = document.getElementById('tmplModalMode');
  const origIdInp = document.getElementById('tmplModalOriginalId');
  const errEl = document.getElementById('tmplModalError');

  if (!modal || !form) return;

  errEl.style.display = 'none';
  modeInp.value = mode;
  isCssCustom = false;

  // Always reset image state when opening modal
  clearTemplateImage();

  if (mode === 'add') {
    titleEl.textContent = '🎨 Add New Template';
    form.reset();
    idInp.disabled = false;
    
    // Set default colors
    document.getElementById('tmplModalColor').value = '#10b981';
    document.getElementById('tmplModalColorHex').value = '#10B981';
    document.getElementById('tmplModalHeaderBg').value = '#10b981';
    document.getElementById('tmplModalHeaderBgHex').value = '#10B981';
    document.getElementById('tmplModalHeaderText').value = '#ffffff';
    document.getElementById('tmplModalHeaderTextHex').value = '#FFFFFF';
    document.getElementById('tmplModalFont').value = 'Devanagari';
    document.getElementById('tmplModalIcon').value = '⚖️';
    document.getElementById('tmplModalHeaderTitle').value = 'VYAPAR';
    
    triggerCssAutoRegen();
  } else {
    // Edit mode
    titleEl.textContent = '✏️ Edit Template';
    const templates = getTemplates();
    const t = templates.find(item => item.id === templateId);
    if (!t) return;

    origIdInp.value = t.id;
    idInp.value = t.id;
    
    // Default templates can't change their CSS class/ID
    idInp.disabled = true;
    
    nameInp.value = t.name;
    
    if (t.config) {
      document.getElementById('tmplModalColor').value = t.config.color;
      document.getElementById('tmplModalColorHex').value = t.config.color.toUpperCase();
      document.getElementById('tmplModalHeaderBg').value = t.config.headerBg;
      document.getElementById('tmplModalHeaderBgHex').value = t.config.headerBg.toUpperCase();
      document.getElementById('tmplModalHeaderText').value = t.config.headerText;
      document.getElementById('tmplModalHeaderTextHex').value = t.config.headerText.toUpperCase();
      document.getElementById('tmplModalFont').value = t.config.font;
      document.getElementById('tmplModalIcon').value = t.config.icon;
      document.getElementById('tmplModalHeaderTitle').value = t.config.headerTitle;
    } else {
      // Set some fallback defaults if t.config doesn't exist (e.g. system default templates)
      document.getElementById('tmplModalColor').value = '#111111';
      document.getElementById('tmplModalColorHex').value = '#111111';
      document.getElementById('tmplModalHeaderBg').value = '#f5f5f5';
      document.getElementById('tmplModalHeaderBgHex').value = '#F5F5F5';
      document.getElementById('tmplModalHeaderText').value = '#111111';
      document.getElementById('tmplModalHeaderTextHex').value = '#111111';
      document.getElementById('tmplModalFont').value = t.id === 'tmpl-4' || t.id === 'tmpl-8' ? 'Georgia' : 'Devanagari';
      document.getElementById('tmplModalIcon').value = t.previewHeadText ? t.previewHeadText.split(' ')[0] : '⚖️';
      document.getElementById('tmplModalHeaderTitle').value = t.previewHeadText ? t.previewHeadText.split(' ').slice(1).join(' ') : 'VYAPAR';
    }

    document.getElementById('tmplModalCss').value = t.css || generateDefaultCSS(t.id, t.name, '#111111', '#f5f5f5', '#111111', 'Devanagari');
    // If CSS is already set, mark it as custom so auto-regen doesn't overwrite immediately
    if (t.css) {
      isCssCustom = true;
    }

    // Restore existing screenshot if present
    if (t.screenshotBase64) {
      setTemplateImagePreview(t.screenshotBase64);
    }
  }

  modal.style.display = 'flex';
  setTimeout(() => nameInp.focus(), 100);
}

function closeTemplateModal() {
  document.getElementById('templateModal').style.display = 'none';
}

document.getElementById('tmplModalCancelBtn')?.addEventListener('click', closeTemplateModal);
document.getElementById('templateModal')?.addEventListener('click', (e) => {
  if (e.target === document.getElementById('templateModal')) closeTemplateModal();
});

// Handle Add/Edit template form submit
async function handleTemplateSubmit(e) {
  e.preventDefault();
  const errEl = document.getElementById('tmplModalError');
  errEl.style.display = 'none';

  const mode = document.getElementById('tmplModalMode').value;
  const name = document.getElementById('tmplModalName').value.trim();
  const rawId = document.getElementById('tmplModalId').value.trim();
  const origId = document.getElementById('tmplModalOriginalId').value;
  const css = document.getElementById('tmplModalCss').value;

  const color = document.getElementById('tmplModalColorHex').value.trim();
  const headerBg = document.getElementById('tmplModalHeaderBgHex').value.trim();
  const headerText = document.getElementById('tmplModalHeaderTextHex').value.trim();
  const font = document.getElementById('tmplModalFont').value;
  const icon = document.getElementById('tmplModalIcon').value;
  const headerTitle = document.getElementById('tmplModalHeaderTitle').value.trim() || 'VYAPAR';

  // Normalize ID
  const id = rawId.toLowerCase().replace(/[^a-z0-9\-]/g, '');

  if (!id.startsWith('tmpl-')) {
    errEl.textContent = '❌ Template ID must start with "tmpl-" (e.g. tmpl-green)';
    errEl.style.display = 'block';
    return;
  }

  const templates = getTemplates();

  // Validate ID uniqueness on addition
  if (mode === 'add' && templates.some(t => t.id === id)) {
    errEl.textContent = `❌ Template ID "${id}" is already in use.`;
    errEl.style.display = 'block';
    return;
  }

  try {
    // Generate card preview HTML attributes
    const cardStyle = `border: 1.5px solid ${color}; border-radius: 0;`;
    const headStyle = `background: ${headerBg}; color: ${headerText}; font-size: 8px; font-weight: 800;`;
    const headText = `${icon} ${headerTitle}`;
    
    // Quick mini-invoice card preview lines
    const bodyHtml = `
      <div class="tp-line w70" style="background: ${color}cc;"></div>
      <div class="tp-table" style="border-color: ${color};">
        <div class="tp-tr"><div class="tp-td" style="background: ${headerBg}44;"></div><div class="tp-td"></div></div>
        <div class="tp-tr"><div class="tp-td"></div><div class="tp-td"></div></div>
      </div>
      <div class="tp-line w50" style="background: ${color}88;"></div>
    `;

    const config = { color, headerBg, headerText, font, icon, headerTitle };
    // Capture current screenshot (may be null if removed or not set)
    const screenshotBase64 = _tmplCurrentImageBase64 || null;

    if (mode === 'add') {
      const newTmpl = {
        id,
        name,
        previewCardStyle: cardStyle,
        previewHeadStyle: headStyle,
        previewHeadText: headText,
        previewBodyHtml: bodyHtml,
        css,
        config,
        screenshotBase64,
        isDefault: false
      };
      templates.push(newTmpl);
      addAdminLog(`Created custom invoice template: ${name} (${id})`, 'info');
      showToast(`🎨 Template "${name}" created successfully.`);
    } else {
      // Edit
      const idx = templates.findIndex(item => item.id === origId);
      if (idx !== -1) {
        templates[idx].name = name;
        templates[idx].css = css;
        templates[idx].previewCardStyle = cardStyle;
        templates[idx].previewHeadStyle = headStyle;
        templates[idx].previewHeadText = headText;
        templates[idx].previewBodyHtml = bodyHtml;
        templates[idx].config = config;
        // Only update screenshot if user explicitly set or cleared one
        templates[idx].screenshotBase64 = screenshotBase64;
        
        addAdminLog(`Updated invoice template: ${name} (${origId})`, 'info');
        showToast(`🎨 Template "${name}" updated.`);
      }
    }

    saveTemplates(templates);
    closeTemplateModal();
    loadTemplatesDirectory(document.getElementById('tmplSearchInput')?.value || '');
  } catch (err) {
    errEl.textContent = '❌ Failed to save: ' + err.message;
    errEl.style.display = 'block';
  }
}

// ── DELETE TEMPLATE MODAL LOGIC ──
let _deleteTargetTmplId = null;

function openDeleteTemplateModal(tmplId, tmplName) {
  _deleteTargetTmplId = tmplId;
  document.getElementById('deleteTmplModalLabel').textContent = `${tmplName} (${tmplId})`;
  const modal = document.getElementById('deleteTemplateModal');
  modal.style.display = 'flex';
}

function closeDeleteTemplateModal() {
  document.getElementById('deleteTemplateModal').style.display = 'none';
  _deleteTargetTmplId = null;
}

document.getElementById('deleteTmplModalCancelBtn')?.addEventListener('click', closeDeleteTemplateModal);
document.getElementById('deleteTemplateModal')?.addEventListener('click', (e) => {
  if (e.target === document.getElementById('deleteTemplateModal')) closeDeleteTemplateModal();
});

document.getElementById('deleteTmplModalConfirmBtn')?.addEventListener('click', () => {
  if (!_deleteTargetTmplId) return;

  let templates = getTemplates();
  templates = templates.filter(t => t.id !== _deleteTargetTmplId);
  saveTemplates(templates);

  addAdminLog(`Template deleted: ${_deleteTargetTmplId}`, 'error');
  showToast(`🗑️ Template deleted: ${_deleteTargetTmplId}`);
  closeDeleteTemplateModal();
  loadTemplatesDirectory(document.getElementById('tmplSearchInput')?.value || '');
});
