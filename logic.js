// ==================== CONFIGURATION ====================
let currentUser = null,
    isAdmin = false,
    adminToken = null,
    sessionToken = null,
    loginAttempts = 0,
    adminLoginAttempts = 0,
    quantity = 1,
    notifyPosition = 'left',
    announcementTimer = null,
    modalTimer = null;

let cachedKeyHistory = [];
let cachedProducts = [];
let depositFixedAmounts = [];

const MAX_ATTEMPTS = 4;
const ADMIN_MAX_ATTEMPTS = 3;

// ==================== API HELPER ====================
async function api(endpoint, options = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (adminToken) headers['X-Admin-Token'] = adminToken;
    if (sessionToken) headers['X-Session-Token'] = sessionToken;
    const config = { headers, credentials: 'include', ...options };
    try {
        const response = await fetch(endpoint, config);
        const data = await response.json();
        if (!response.ok) {
            if (response.status === 401 && isAdmin && endpoint.startsWith('/api/admin')) {
                showModal('error', 'Session Expired', 'Admin session expired. Please login again.');
                setTimeout(() => {
                    isAdmin = false; adminToken = null;
                    document.getElementById('view-dashboard').classList.add('hidden');
                    document.getElementById('bubbles-bg').classList.remove('hidden');
                    document.getElementById('view-admin-login').classList.remove('hidden');
                    createBubbles();
                }, 2000);
            }
            throw { status: response.status, ...data };
        }
        return data;
    } catch (err) {
        if (err.status) throw err;
        throw { status: 0, error: 'Network error', message: 'Cannot connect to server.' };
    }
}

// ==================== ANTI-DEVTOOLS ====================
let devtoolsLocalCount = 0;
let devtoolsCooldown = false;
(function() {
    function onDevToolsDetected(reason) {
        if (devtoolsCooldown) return;
        devtoolsCooldown = true;
        setTimeout(() => { devtoolsCooldown = false; }, 10000);
        devtoolsLocalCount++;
        sendSecurityAlertDevtools('DevTools: ' + reason);
        if (devtoolsLocalCount >= 3) { showFingerprintThenBan(); }
    }
    const isMobile = /Android|iPhone|iPad|iPod|webOS|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    if (!isMobile) {
        let consecutiveDetections = 0;
        function detectDevTools() {
            const threshold = 200;
            const widthDiff = window.outerWidth - window.innerWidth > threshold;
            const heightDiff = window.outerHeight - window.innerHeight > threshold;
            if (widthDiff || heightDiff) {
                consecutiveDetections++;
                if (consecutiveDetections >= 3) { onDevToolsDetected('window size'); consecutiveDetections = 0; }
            } else { consecutiveDetections = 0; }
        }
        setInterval(detectDevTools, 1000);
        setInterval(function() {
            const start = performance.now(); debugger; const end = performance.now();
            if (end - start > 200) { onDevToolsDetected('debugger paused'); }
        }, 3000);
    }
    document.addEventListener('keydown', function(e) {
        if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i')) || (e.ctrlKey && e.shiftKey && (e.key === 'J' || e.key === 'j')) || (e.ctrlKey && (e.key === 'U' || e.key === 'u'))) {
            e.preventDefault(); e.stopPropagation();
            onDevToolsDetected('shortcut: ' + e.key); showNotifyBar(); return false;
        }
    });
})();
document.addEventListener('contextmenu', function(e) { e.preventDefault(); return false; });
document.addEventListener('dragstart', function(e) { e.preventDefault(); return false; });

async function sendSecurityAlertDevtools(message) {
    try {
        const resp = await fetch('/api/security-alert', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
            body: JSON.stringify({ event: message, is_devtools: true })
        });
        const data = await resp.json();
        if (data.banned) { showFingerprintThenBan(); }
    } catch (e) {}
}

async function sendSecurityAlert(message) {
    try {
        await fetch('/api/security-alert', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include',
            body: JSON.stringify({ event: message })
        });
    } catch (e) {}
}

// ==================== DATE FORMATTING ====================
function formatDateTime(date) {
    if (!(date instanceof Date) || isNaN(date)) date = new Date();
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    let hours = date.getHours();
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12 || 12;
    return `${day}/${month}/${year} ${String(hours).padStart(2, '0')}:${minutes} ${ampm}`;
}

// ==================== INITIALIZATION ====================
window.addEventListener('load', async () => {
    // Always verify ban status with server first (not just localStorage)
    try {
        const banCheck = await api('/api/check-ban');
        if (banCheck.banned) { showBanScreen(); return; }
        else {
            // Server says not banned - clear any stale localStorage ban
            localStorage.removeItem('abrdns_perm_ban');
            if (window.location.hash === '#banned') { window.location.hash = ''; }
        }
    } catch (e) {
        if (e.status === 403) { showBanScreen(); return; }
        // If server is unreachable, fallback to localStorage check
        const banData = localStorage.getItem('abrdns_perm_ban');
        if (banData || window.location.hash === '#banned') { showBanScreen(); return; }
    }
    if (window.location.hash === '#admin') {
        document.getElementById('view-gateway').classList.add('hidden');
        document.getElementById('bubbles-bg').classList.remove('hidden');
        document.getElementById('view-admin-login').classList.remove('hidden');
        createBubbles();
    } else { startGatewaySequence(); }
    setupSecurity();
    const banDurationSelect = document.getElementById('admin-ban-duration');
    if (banDurationSelect) {
        banDurationSelect.addEventListener('change', function() {
            const customInput = document.getElementById('admin-ban-custom-minutes');
            this.value === 'custom' ? customInput.classList.remove('hidden') : customInput.classList.add('hidden');
        });
    }
    const modalOverlay = document.getElementById('modal-overlay');
    if (modalOverlay) { modalOverlay.addEventListener('click', (e) => { if (e.target === modalOverlay) closeModal(); }); }
});

// ==================== SECURITY ====================
function setupSecurity() {
    document.addEventListener('contextmenu', (e) => { e.preventDefault(); showNotifyBar(); });
    document.addEventListener('selectstart', (e) => { if (!e.target.closest('.key-item, .history-key, .admin-key-item, .deposit-qr-img, .deposit-qr-frame, .deposit-id-value')) { e.preventDefault(); showNotifyBar(); } });
    document.addEventListener('copy', (e) => { if (!e.target.closest('.key-item, .history-key, .admin-key-item, .deposit-id-value')) { e.preventDefault(); showNotifyBar(); } });
}

function showNotifyBar() {
    const bar = document.getElementById('notify-bar');
    bar.classList.remove('show-left', 'show-right');
    void bar.offsetWidth;
    bar.classList.add('show-right');
    setTimeout(() => bar.classList.remove('show-left', 'show-right'), 2500);
}

// ==================== BAN SCREEN ====================
function showBanScreen() {
    const allViews = ['view-gateway', 'view-login', 'view-security-scan', 'view-dashboard', 'bubbles-bg', 'view-admin-login', 'view-fingerprint-verify', 'view-post-login-verify', 'view-admin-2fa-code'];
    allViews.forEach(id => { const el = document.getElementById(id); if (el) el.classList.add('hidden'); });
    const banView = document.getElementById('view-banned');
    if (banView) {
        banView.classList.remove('hidden'); banView.style.display = 'flex';
        fetch('/api/get-client-ip', { credentials: 'include' }).then(r => r.json()).then(data => {
            const ipDisplay = document.getElementById('banned-ip-display');
            if (ipDisplay && data.ip) { ipDisplay.innerText = data.ip; }
        }).catch(() => { document.getElementById('banned-ip-display').innerText = 'Unknown'; });
    }
    localStorage.setItem('abrdns_perm_ban', JSON.stringify({ banned: true, time: Date.now() }));
}

function copyBannedIP() {
    const ipDisplay = document.getElementById('banned-ip-display');
    if (ipDisplay) {
        const ip = ipDisplay.innerText;
        if (ip && ip !== '-' && ip !== 'Unknown') {
            navigator.clipboard.writeText(ip).catch(() => {});
        }
    }
}

async function showFingerprintThenBan() { await showFingerprintVerify(false); }

// ==================== BUBBLES ====================
function createBubbles() {
    const bg = document.getElementById('bubbles-bg'); bg.innerHTML = '';
    const colors = ['purple', 'blue', 'pink', 'cyan'];
    for (let i = 0; i < 20; i++) {
        const bubble = document.createElement('div');
        bubble.className = `bubble ${colors[Math.floor(Math.random() * colors.length)]}`;
        const size = Math.random() * 160 + 40;
        bubble.style.width = bubble.style.height = size + 'px';
        bubble.style.left = Math.random() * 100 + '%';
        bubble.style.animationDuration = (Math.random() * 12 + 10) + 's';
        bubble.style.animationDelay = -(Math.random() * 20) + 's';
        bg.appendChild(bubble);
    }
}

// ==================== FINGERPRINT ====================
function generateFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top'; ctx.font = '14px Arial'; ctx.fillText('fp_check', 2, 2);
    const canvasHash = canvas.toDataURL().slice(-32);
    const data = [navigator.userAgent, navigator.language, screen.width + 'x' + screen.height, screen.colorDepth, new Date().getTimezoneOffset(), navigator.hardwareConcurrency || 'unknown', navigator.platform, canvasHash].join('|');
    let hash = 0;
    for (let i = 0; i < data.length; i++) { const char = data.charCodeAt(i); hash = ((hash << 5) - hash) + char; hash = hash & hash; }
    return Math.abs(hash).toString(36) + Date.now().toString(36);
}

// ==================== GATEWAY ====================
async function startGatewaySequence() {
    const gateway = document.getElementById('view-gateway');
    const bar = document.getElementById('gateway-progress');
    const text = document.getElementById('gateway-text');
    text.innerText = 'Checking browser...'; await animateProgress(bar, 0, 30, 800);
    text.innerText = 'Verifying domain...'; await animateProgress(bar, 30, 60, 800);
    text.innerText = 'Verifying device...';
    let verified = false;
    try {
        const fingerprint = generateFingerprint();
        const resp = await fetch('/api/verify-device', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ fingerprint }) });
        const result = await resp.json();
        verified = result.verified;
        if (result.banned) { showBanScreen(); return; }
    } catch (e) { verified = true; }
    await animateProgress(bar, 60, 85, 600);
    text.innerText = verified ? 'Preparing dashboard...' : 'Verification failed...';
    await animateProgress(bar, 85, 100, 500);
    if (!verified) { showFingerprintVerify(false); return; }
    gateway.style.opacity = '0';
    setTimeout(() => {
        gateway.classList.add('hidden');
        document.getElementById('bubbles-bg').classList.remove('hidden');
        document.getElementById('view-login').classList.remove('hidden');
        createBubbles();
    }, 600);
}

function animateProgress(bar, from, to, duration) {
    return new Promise(resolve => {
        const steps = to - from; const stepTime = duration / steps; let current = from;
        const interval = setInterval(() => { current++; bar.style.width = current + '%'; if (current >= to) { clearInterval(interval); resolve(); } }, stepTime);
    });
}

// ==================== FINGERPRINT VERIFICATION ====================
async function showFingerprintVerify(willPass) {
    ['view-gateway', 'view-login', 'view-dashboard', 'bubbles-bg', 'view-admin-login', 'view-security-scan', 'view-post-login-verify', 'view-admin-2fa-code'].forEach(id => { const el = document.getElementById(id); if (el) el.classList.add('hidden'); });
    const view = document.getElementById('view-fingerprint-verify');
    const checksEl = document.getElementById('fp-checks');
    const bar = document.getElementById('fp-verify-progress');
    const textEl = document.getElementById('fp-verify-text');
    view.classList.remove('hidden');
    const checks = [
        { id: 'ip', label: 'IP Address Validation', icon: 'fa-network-wired' },
        { id: 'domain', label: 'Domain Verification', icon: 'fa-globe' },
        { id: 'user_agent', label: 'Browser Analysis', icon: 'fa-desktop' },
        { id: 'fingerprint', label: 'Device Verification', icon: 'fa-fingerprint' },
        { id: 'rate', label: 'Request Rate Check', icon: 'fa-gauge-high' }
    ];
    checksEl.innerHTML = checks.map(c => `<div class="fp-check-item" id="fp-check-${c.id}"><span class="fp-check-icon"><i class="fa-solid fa-circle-notch"></i></span><span class="fp-check-label">${c.label}</span></div>`).join('');
    bar.style.width = '0%'; textEl.innerText = 'Scanning device fingerprint...';
    let serverResult = null;
    try {
        const fingerprint = generateFingerprint();
        const resp = await fetch('/api/verify-device', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: JSON.stringify({ fingerprint }) });
        serverResult = await resp.json();
    } catch (e) { serverResult = { verified: willPass, checks: { ip: true, domain: true, user_agent: true, fingerprint: true, rate: true } }; }
    for (let i = 0; i < checks.length; i++) {
        const check = checks[i]; const el = document.getElementById('fp-check-' + check.id);
        el.classList.add('checking'); el.querySelector('.fp-check-icon').innerHTML = '<i class="fa-solid fa-spinner"></i>';
        textEl.innerText = check.label + '...';
        await new Promise(r => setTimeout(r, 600 + Math.random() * 400));
        const passed = serverResult.checks ? serverResult.checks[check.id] : willPass;
        el.classList.remove('checking'); el.classList.add(passed ? 'passed' : 'failed');
        el.querySelector('.fp-check-icon').innerHTML = passed ? '<i class="fa-solid fa-check"></i>' : '<i class="fa-solid fa-xmark"></i>';
        bar.style.width = ((i + 1) / checks.length * 100) + '%';
    }
    await new Promise(r => setTimeout(r, 500));
    if (!serverResult.verified) {
        textEl.innerText = 'VERIFICATION FAILED'; textEl.style.color = '#ef4444';
        await new Promise(r => setTimeout(r, 1500)); view.classList.add('hidden'); showBanScreen();
    } else {
        textEl.innerText = 'Device verified successfully'; textEl.style.color = '#22c55e';
        await new Promise(r => setTimeout(r, 800)); view.classList.add('hidden'); textEl.style.color = ''; return true;
    }
    return false;
}

// ==================== POST-LOGIN VERIFICATION ====================
async function showPostLoginVerify() {
    ['view-login', 'bubbles-bg'].forEach(id => { const el = document.getElementById(id); if (el) el.classList.add('hidden'); });
    const view = document.getElementById('view-post-login-verify');
    const checksEl = document.getElementById('post-login-checks');
    const bar = document.getElementById('post-login-progress');
    const textEl = document.getElementById('post-login-text');
    view.classList.remove('hidden');
    const steps = [
        { label: 'Validating session token...', delay: 500 },
        { label: 'Checking account status...', delay: 600 },
        { label: 'Loading user permissions...', delay: 400 },
        { label: 'Encrypting connection...', delay: 500 },
        { label: 'Session secured', delay: 300 }
    ];
    checksEl.innerHTML = steps.map((s, i) => `<div class="fp-check-item" id="pl-check-${i}"><span class="fp-check-icon"><i class="fa-solid fa-circle-notch"></i></span><span class="fp-check-label">${s.label}</span></div>`).join('');
    bar.style.width = '0%';
    let sessionValid = true;
    try {
        const result = await api('/api/get-data?username=' + encodeURIComponent(currentUser.username));
        if (result.is_banned) sessionValid = false;
    } catch (e) { sessionValid = false; }
    for (let i = 0; i < steps.length; i++) {
        const el = document.getElementById('pl-check-' + i);
        el.classList.add('checking'); el.querySelector('.fp-check-icon').innerHTML = '<i class="fa-solid fa-spinner"></i>';
        textEl.innerText = steps[i].label;
        await new Promise(r => setTimeout(r, steps[i].delay));
        el.classList.remove('checking'); el.classList.add(sessionValid ? 'passed' : 'failed');
        el.querySelector('.fp-check-icon').innerHTML = sessionValid ? '<i class="fa-solid fa-check"></i>' : '<i class="fa-solid fa-xmark"></i>';
        bar.style.width = ((i + 1) / steps.length * 100) + '%';
    }
    await new Promise(r => setTimeout(r, 600));
    if (!sessionValid) {
        textEl.innerText = 'Session verification failed'; textEl.style.color = '#ef4444';
        await new Promise(r => setTimeout(r, 1500)); view.classList.add('hidden'); showBanScreen(); return false;
    }
    textEl.innerText = 'Session verified'; textEl.style.color = '#22c55e';
    await new Promise(r => setTimeout(r, 500)); view.classList.add('hidden'); textEl.style.color = ''; return true;
}

// ==================== PASSWORD TOGGLE ====================
function togglePassword() {
    const passInput = document.getElementById('login-pass'); const icon = document.getElementById('toggle-pass');
    const isPass = passInput.type === 'password';
    passInput.type = isPass ? 'text' : 'password';
    icon.classList.replace(isPass ? 'fa-eye' : 'fa-eye-slash', isPass ? 'fa-eye-slash' : 'fa-eye');
}

// ==================== USER LOGIN ====================
async function attemptLogin() {
    const userIn = document.getElementById('login-user').value.trim();
    const passIn = document.getElementById('login-pass').value;
    const btn = document.getElementById('btn-login');
    const btnText = document.getElementById('btn-login-text');
    const spinner = document.getElementById('login-spinner');
    const arrow = document.getElementById('btn-login-arrow');
    if (!userIn || !passIn) { showLoginError('Please enter username and password.'); return; }
    btn.disabled = true; btnText.innerText = 'AUTHENTICATING...'; spinner.style.display = 'block'; arrow.style.display = 'none';
    try {
        const result = await api('/api/login', { method: 'POST', body: JSON.stringify({ username: userIn, password: passIn }) });
        if (result.success) {
            currentUser = { username: result.username, balance: result.balance }; sessionToken = result.token; loginAttempts = 0;
            const verified = await showPostLoginVerify();
            if (!verified) return;
            document.getElementById('view-post-login-verify').classList.add('hidden');
            document.getElementById('view-dashboard').classList.remove('hidden');
            document.getElementById('dash-username').innerText = userIn;
            preloadDashboardData();
            if (window.restoreUserViewState) { window.restoreUserViewState(); }
            else { switchTab('tab-generator', document.querySelector('[onclick*="tab-generator"]')); }
            checkAnnouncement();
        }
    } catch (err) {
        loginAttempts++;
        if (err.error === 'IP_BANNED') { await showFingerprintThenBan(); return; }
        if (err.error === 'BANNED') { showLoginError('Your account has been banned.'); }
        else {
            const remaining = err.remaining !== undefined ? err.remaining : Math.max(0, MAX_ATTEMPTS - loginAttempts);
            if (remaining <= 0) { await showFingerprintThenBan(); return; }
            showLoginError(err.message || `Authentication Failed. ${remaining} attempts remaining.`);
        }
    }
    resetLoginBtn();
}

function resetLoginBtn() {
    const btn = document.getElementById('btn-login'); const btnText = document.getElementById('btn-login-text');
    const spinner = document.getElementById('login-spinner'); const arrow = document.getElementById('btn-login-arrow');
    btn.disabled = false; btnText.innerText = 'SIGN IN'; spinner.style.display = 'none'; arrow.style.display = 'block';
}

function showLoginError(msg) {
    const err = document.getElementById('login-error'); const errText = document.getElementById('login-error-text');
    if (errText) errText.innerText = msg; else err.innerText = msg;
    err.classList.remove('hidden');
    const card = document.getElementById('login-card'); card.style.animation = 'shake 0.4s ease';
    setTimeout(() => card.style.animation = '', 400);
}

async function logout() {
    currentUser = null; isAdmin = false; sessionToken = null; adminToken = null;
    sessionStorage.clear();
    try { await fetch('/api/logout', { method: 'POST', credentials: 'include' }); } catch (e) {}
    document.getElementById('view-dashboard').classList.add('hidden');
    document.getElementById('bubbles-bg').classList.remove('hidden');
    document.getElementById('view-login').classList.remove('hidden');
    document.getElementById('login-user').value = document.getElementById('login-pass').value = '';
    document.getElementById('login-error').classList.add('hidden');
    createBubbles();
}

// ==================== ANNOUNCEMENT ====================
async function checkAnnouncement() {
    try {
        const result = await api('/api/announcement');
        if (result.announcement && result.announcement.content) {
            document.getElementById('announcement-body').innerText = result.announcement.content;
            document.getElementById('announcement-overlay').classList.remove('hidden');
            if (announcementTimer) clearTimeout(announcementTimer);
            announcementTimer = setTimeout(closeAnnouncement, 5000);
        }
    } catch (e) {}
}

function closeAnnouncement() {
    document.getElementById('announcement-overlay').classList.add('hidden');
    if (announcementTimer) { clearTimeout(announcementTimer); announcementTimer = null; }
}

// ==================== BALANCE ====================
async function updateBalance() {
    if (!currentUser) return;
    try {
        const result = await api('/api/get-data?username=' + encodeURIComponent(currentUser.username));
        if (result.username) {
            currentUser.balance = result.balance;
            document.getElementById('dash-balance').innerText = '$' + parseFloat(currentUser.balance).toFixed(2);
        }
    } catch (e) {}
}

// ==================== PRELOAD DATA ====================
async function preloadDashboardData() {
    const promises = [];
    if (currentUser && !isAdmin) {
        promises.push(updateBalance()); promises.push(loadProductDropdowns());
        promises.push(updateStatistics()); promises.push(updateHistory()); promises.push(updateTransactions());
    }
    try { await Promise.allSettled(promises); } catch (e) {}
}

// ==================== PRODUCTS ====================
async function loadProductDropdowns() {
    try {
        const result = await api('/api/products'); cachedProducts = result.products || [];
        const genProduct = document.getElementById('gen-product');
        genProduct.innerHTML = '<option value="">Select Product</option>';
        cachedProducts.forEach(p => { const opt = document.createElement('option'); opt.value = p.id; opt.innerText = p.name; genProduct.appendChild(opt); });
        const adminKeyProduct = document.getElementById('admin-key-product');
        if (adminKeyProduct) {
            adminKeyProduct.innerHTML = '<option value="">Select Product</option>';
            cachedProducts.forEach(p => { const opt = document.createElement('option'); opt.value = p.id; opt.innerText = p.name; adminKeyProduct.appendChild(opt); });
        }
    } catch (e) {}
}

function updateValidityDropdown() {
    const productId = parseInt(document.getElementById('gen-product').value);
    const product = cachedProducts.find(p => p.id === productId);
    const validitySelect = document.getElementById('gen-validity');
    validitySelect.innerHTML = '<option value="">Select Duration</option>';
    if (product && product.durations) {
        product.durations.forEach(d => { const opt = document.createElement('option'); opt.value = d.days; opt.innerText = `${d.days} Days - $${d.price}`; validitySelect.appendChild(opt); });
    }
}

function changeQty(n) { quantity = Math.max(1, quantity + n); document.getElementById('qty-display').innerText = quantity; }

// ==================== KEY GENERATION ====================
let pendingKeyGeneration = null;
function generateKeys() {
    const productId = parseInt(document.getElementById('gen-product').value);
    const days = parseInt(document.getElementById('gen-validity').value);
    const product = cachedProducts.find(p => p.id === productId);
    if (!product) { showToast('error', 'Please select a valid product'); return; }
    const duration = product.durations.find(d => d.days === days);
    if (!duration) { showToast('error', 'Please select a valid duration'); return; }
    const totalCost = (parseFloat(duration.price) * quantity).toFixed(2);
    pendingKeyGeneration = { productId, days, quantity, product, duration };
    const confirmMsg = document.getElementById('confirm-msg');
    confirmMsg.innerHTML = `<div style="text-align:left;background:rgba(139,92,246,0.08);border:1px solid rgba(139,92,246,0.2);border-radius:8px;padding:12px;margin-bottom:8px;">
        <div style="margin-bottom:6px;"><strong style="color:#a78bfa;">Product:</strong> <span style="color:#e2e8f0;">${product.name}</span></div>
        <div style="margin-bottom:6px;"><strong style="color:#a78bfa;">Duration:</strong> <span style="color:#e2e8f0;">${days} Days</span></div>
        <div style="margin-bottom:6px;"><strong style="color:#a78bfa;">Quantity:</strong> <span style="color:#e2e8f0;">${quantity}</span></div>
        <div><strong style="color:#ef4444;">Total Cost:</strong> <span style="color:#ef4444;font-weight:700;">$${totalCost}</span></div>
    </div><div style="color:#9ca3af;font-size:12px;">This will be deducted from your balance.</div>`;
    const overlay = document.getElementById('confirm-overlay');
    overlay.classList.remove('hidden'); overlay.classList.add('show');
}

async function confirmGenerate() {
    if (!pendingKeyGeneration) return;
    const { productId, days } = pendingKeyGeneration; const qty = pendingKeyGeneration.quantity;
    cancelConfirm();
    try {
        const result = await api('/api/generate-keys', { method: 'POST', body: JSON.stringify({ username: currentUser.username, product_id: productId, days: days, quantity: qty }) });
        if (result.success) {
            currentUser.balance = result.new_balance;
            document.getElementById('dash-balance').innerText = '$' + parseFloat(result.new_balance).toFixed(2);
            const resultDiv = document.getElementById('keys-result');
            resultDiv.classList.remove('hidden');
            resultDiv.innerHTML = `<div class="keys-result-title"><i class="fa-solid fa-check-circle"></i> ${result.keys.length} Key(s) Generated!</div>${result.keys.map(k => `<div class="key-item"><span class="key-text">${k}</span><i class="fa-solid fa-copy copy-icon" onclick="event.stopPropagation(); copyKey('${k}', this.parentElement)"></i></div>`).join('')}`;
            showToast('success', `${result.keys.length} key(s) generated! -$${result.total_cost.toFixed(2)}`);
        }
    } catch (err) { showToast('error', err.error || err.message || 'Failed to generate keys'); }
    pendingKeyGeneration = null;
}

function cancelConfirm() {
    const overlay = document.getElementById('confirm-overlay');
    overlay.classList.remove('show'); setTimeout(() => overlay.classList.add('hidden'), 300);
    pendingKeyGeneration = null;
}

function copyKey(key, el) {
    navigator.clipboard.writeText(key).then(() => highlightCopied(el)).catch(() => {
        const ta = document.createElement('textarea'); ta.value = key; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); highlightCopied(el);
    });
}

function highlightCopied(el) { if (el) { el.style.background = 'rgba(16, 185, 129, 0.2)'; setTimeout(() => el.style.background = '', 1000); } }

// ==================== STATISTICS ====================
async function updateStatistics() {
    try {
        const histResult = await api('/api/key-history?username=' + encodeURIComponent(currentUser.username));
        const keys = histResult.history || []; cachedKeyHistory = keys;
        document.getElementById('stat-total').innerText = keys.length;
        const prodResult = await api('/api/products'); const products = prodResult.products || [];
        const breakdown = {};
        products.forEach(p => p.durations.forEach(d => breakdown[`${p.name} ${d.days} DAY`] = 0));
        keys.forEach(k => { const label = `${k.product_name} ${k.days} DAY`; if (breakdown[label] !== undefined) breakdown[label]++; });
        const tbody = document.getElementById('stat-breakdown');
        tbody.innerHTML = Object.entries(breakdown).map(([product, count]) => `<tr><td style="text-align:left;"><i class="fa-solid fa-key" style="color:#8b5cf6;margin-right:8px;"></i>${product}</td><td style="text-align:center;font-weight:700;color:#a78bfa;">${count}</td></tr>`).join('');
    } catch (e) {}
}

// ==================== HISTORY ====================
async function updateHistory() {
    try {
        const result = await api('/api/key-history?username=' + encodeURIComponent(currentUser.username));
        const keys = result.history || []; cachedKeyHistory = keys;
        const tbody = document.getElementById('history-tbody'); const emptyMsg = document.getElementById('history-empty');
        tbody.innerHTML = '';
        if (keys.length === 0) { emptyMsg.style.display = 'block'; return; }
        emptyMsg.style.display = 'none';
        keys.forEach((k, idx) => {
            const dateStr = formatDateTime(new Date(k.created_at));
            const keyValue = k.key_code || k.key_value || '';
            const truncKey = keyValue.length > 14 ? 'Key: ' + keyValue.substring(0, 10) + '...' : keyValue;
            tbody.innerHTML += `<tr><td style="text-align:center;color:#a78bfa;font-weight:600;">${idx + 1}</td><td style="text-align:center;"><span class="history-key" onclick="copyKey('${keyValue}', this)" title="Click to copy">${truncKey}</span></td><td style="text-align:center;">${k.days}</td><td style="text-align:center;">${dateStr}</td></tr>`;
        });
    } catch (e) {}
}

// ==================== TRANSACTIONS ====================
async function updateTransactions() {
    try {
        const result = await api('/api/transactions?username=' + encodeURIComponent(currentUser.username));
        const txs = result.transactions || [];
        const container = document.getElementById('transactions-list'); const emptyMsg = document.getElementById('transactions-empty');
        container.innerHTML = '';
        if (txs.length === 0) { emptyMsg.style.display = 'block'; return; }
        emptyMsg.style.display = 'none';
        txs.forEach(t => {
            const dateStr = formatDateTime(new Date(t.created_at));
            let icon, iconClass, typeLabel, amountStr, amountColor;
            if (t.type === 'Deposit') { icon = 'fa-arrow-down'; iconClass = 'deposit'; typeLabel = 'Deposit'; amountStr = `+$${Math.abs(parseFloat(t.amount)).toFixed(2)}`; amountColor = '#10b981'; }
            else if (t.type === 'Deduction') { icon = 'fa-arrow-up'; iconClass = 'deduction'; typeLabel = 'Deduction'; amountStr = `-$${Math.abs(parseFloat(t.amount)).toFixed(2)}`; amountColor = '#ef4444'; }
            else if (t.type === 'Key Purchase') { icon = 'fa-key'; iconClass = 'purchase'; typeLabel = 'Key Purchase'; amountStr = `-$${Math.abs(parseFloat(t.amount)).toFixed(2)}`; amountColor = '#a78bfa'; }
            else { icon = 'fa-circle-info'; iconClass = 'deposit'; typeLabel = t.type || 'Transaction'; amountStr = `$${Math.abs(parseFloat(t.amount)).toFixed(2)}`; amountColor = '#9ca3af'; }
            container.innerHTML += `<div class="transaction-item" style="border-color:${amountColor}22;"><div class="tx-left"><div class="tx-icon ${iconClass}"><i class="fa-solid ${icon}"></i></div><div class="tx-details"><div class="tx-type">${typeLabel}</div><div class="tx-date">${dateStr}</div></div></div><div class="tx-amount" style="color:${amountColor};">${amountStr}</div></div>`;
        });
    } catch (e) {}
}

// ==================== ADMIN LOGIN ====================
let adminSavedPassword = null;
async function adminLogin() {
    const pass = document.getElementById('admin-pass-input').value;
    if (!pass) return;
    try {
        const result = await api('/api/admin-login', { method: 'POST', body: JSON.stringify({ password: pass }) });
        if (result.error === 'NEED_2FA') {
            adminSavedPassword = pass;
            document.getElementById('view-admin-login').classList.add('hidden');
            document.getElementById('view-admin-2fa-code').classList.remove('hidden');
            document.getElementById('admin-2fa-input').value = '';
            document.getElementById('admin-2fa-error').classList.add('hidden');
            document.getElementById('admin-2fa-input').focus();
        }
    } catch (err) {
        adminLoginAttempts++;
        if (err.error === 'IP_BANNED' || err.status === 403) { await showFingerprintThenBan(); return; }
        const errorText = document.getElementById('admin-login-error-text');
        errorText.innerText = err.message || 'Authentication failed.';
        document.getElementById('admin-login-error').classList.remove('hidden');
    }
}

async function submitAdmin2FA() {
    const code = document.getElementById('admin-2fa-input').value.trim();
    if (!code) return;
    const btn = document.getElementById('btn-admin-2fa'); const btnText = document.getElementById('btn-admin-2fa-text');
    const spinner = document.getElementById('admin-2fa-spinner'); const arrow = document.getElementById('btn-admin-2fa-arrow');
    btn.disabled = true; btnText.innerText = 'VERIFYING...'; spinner.style.display = 'block'; arrow.style.display = 'none';
    try {
        const loginResult = await api('/api/admin-login', { method: 'POST', body: JSON.stringify({ password: adminSavedPassword, twofa_code: code }) });
        if (loginResult.success) {
            isAdmin = true; adminLoginAttempts = 0; adminToken = loginResult.token;
            currentUser = { username: 'Admin', balance: 0 };
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.getElementById('tab-admin').classList.add('active');
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            const adminNavItem = document.querySelector('[onclick*="tab-admin"]');
            if (adminNavItem) adminNavItem.classList.add('active');
            document.getElementById('view-admin-2fa-code').classList.add('hidden');
            document.getElementById('bubbles-bg').classList.add('hidden');
            document.getElementById('view-dashboard').classList.remove('hidden');
            document.getElementById('dash-username').innerText = 'Admin';
            document.getElementById('dash-balance').innerText = 'ADMIN';
            const menuToggle = document.querySelector('.menu-toggle');
            if (menuToggle) menuToggle.style.display = 'none';
            await Promise.allSettled([
                typeof loadAdminUserDropdowns === 'function' ? loadAdminUserDropdowns() : Promise.resolve(),
                typeof renderAdminUsers === 'function' ? renderAdminUsers() : Promise.resolve(),
                typeof renderAdminProducts === 'function' ? renderAdminProducts() : Promise.resolve(),
                typeof renderAdminKeyPool === 'function' ? renderAdminKeyPool() : Promise.resolve(),
                typeof renderAdminBannedIPs === 'function' ? renderAdminBannedIPs() : Promise.resolve(),
                typeof renderAdminCurrentAnnouncement === 'function' ? renderAdminCurrentAnnouncement() : Promise.resolve(),
                typeof renderAdminDepositAmounts === 'function' ? renderAdminDepositAmounts() : Promise.resolve()
            ]);
            enableAdminScreenshotPrevention();
            showModal('success', 'Access Granted', 'Admin access granted!');
        }
    } catch (err) {
        if (err.error === 'IP_BANNED' || err.status === 403) { await showFingerprintThenBan(); return; }
        const errorText = document.getElementById('admin-2fa-error-text');
        errorText.innerText = err.message || 'Invalid 2FA code.';
        document.getElementById('admin-2fa-error').classList.remove('hidden');
        const card = document.getElementById('admin-2fa-card'); card.style.animation = 'shake 0.4s ease';
        setTimeout(() => card.style.animation = '', 400);
    }
    btn.disabled = false; btnText.innerText = 'Verify'; spinner.style.display = 'none'; arrow.style.display = 'block';
}

function cancelAdmin2FA() {
    adminSavedPassword = null;
    document.getElementById('view-admin-2fa-code').classList.add('hidden');
    document.getElementById('view-admin-login').classList.remove('hidden');
    document.getElementById('admin-pass-input').value = '';
    document.getElementById('admin-login-error').classList.add('hidden');
}

document.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
        const twoFaView = document.getElementById('view-admin-2fa-code');
        if (twoFaView && !twoFaView.classList.contains('hidden')) { submitAdmin2FA(); }
    }
});

// ==================== ADMIN: USERS ====================
async function renderAdminUsers() {
    try {
        const result = await api('/api/admin/users'); const users = result.users || [];
        const container = document.getElementById('admin-users-list');
        container.innerHTML = users.length === 0 ? '<div style="color:#4b5563;font-size:13px;text-align:center;padding:12px;">No users yet.</div>' : '';
        users.forEach(user => {
            container.innerHTML += `<div style="background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.2);border-radius:8px;padding:12px;margin-bottom:10px;"><div style="display:flex;justify-content:space-between;align-items:center;"><div><div style="font-weight:600;color:#a78bfa;">${user.username}</div><div style="font-size:12px;color:#9ca3af;">Balance: $${parseFloat(user.balance).toFixed(2)} | Keys: ${user.key_count || 0}</div></div><div style="display:flex;gap:8px;"><button class="btn-admin green" onclick="adminEditUserPass('${user.username}')"><i class="fa-solid fa-pen"></i></button><button class="btn-admin ${user.is_banned ? 'green' : 'red'}" onclick="adminToggleBan('${user.username}')"><i class="fa-solid fa-${user.is_banned ? 'check' : 'ban'}"></i></button><button class="btn-admin red" onclick="adminDeleteUser('${user.username}')"><i class="fa-solid fa-trash"></i></button></div></div></div>`;
        });
    } catch (e) {}
}

async function adminAddUser() {
    const user = document.getElementById('admin-new-user').value.trim();
    const pass = document.getElementById('admin-new-pass').value;
    if (!user || !pass) { showModal('error', 'Failed', 'Enter username and password'); return; }
    try {
        const result = await api('/api/admin/add-user', { method: 'POST', body: JSON.stringify({ username: user, password: pass }) });
        document.getElementById('admin-new-user').value = document.getElementById('admin-new-pass').value = '';
        renderAdminUsers(); loadAdminUserDropdowns();
        showModal('success', 'Success', result.message || 'User added!');
    } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function adminDeleteUserFromSelect() {
    const sel = document.getElementById('admin-delete-user-select'); const username = sel.value;
    if (!username) { showModal('error', 'Failed', 'Select a user'); return; }
    if (confirm(`Delete user ${username}?`)) {
        try { await api('/api/admin/delete-user', { method: 'POST', body: JSON.stringify({ username }) }); renderAdminUsers(); loadAdminUserDropdowns(); showModal('success', 'Success', 'User deleted!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
    }
}

async function adminEditUserPass(username) {
    const newPass = prompt(`New password for ${username}:`);
    if (newPass) { try { await api('/api/admin/edit-password', { method: 'POST', body: JSON.stringify({ username, password: newPass }) }); showModal('success', 'Success', 'Password updated!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); } }
}

async function adminToggleBan(username) {
    try { const result = await api('/api/admin/toggle-ban', { method: 'POST', body: JSON.stringify({ username }) }); renderAdminUsers(); showModal('success', 'Success', result.message || 'Updated!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function adminDeleteUser(username) {
    if (confirm(`Delete user ${username}?`)) {
        try { await api('/api/admin/delete-user', { method: 'POST', body: JSON.stringify({ username }) }); renderAdminUsers(); loadAdminUserDropdowns(); showModal('success', 'Success', 'Deleted!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
    }
}

async function loadAdminUserDropdowns() {
    try {
        const result = await api('/api/admin/users'); const users = result.users || [];
        const select = document.getElementById('admin-balance-user');
        select.innerHTML = '<option value="">Select User</option>';
        users.forEach(u => { const opt = document.createElement('option'); opt.value = u.username; opt.innerText = u.username; select.appendChild(opt); });
        const delSelect = document.getElementById('admin-delete-user-select');
        if (delSelect) { delSelect.innerHTML = '<option value="">Select User to Delete</option>'; users.forEach(u => { const opt = document.createElement('option'); opt.value = u.username; opt.innerText = `${u.username} ($${parseFloat(u.balance).toFixed(2)})`; delSelect.appendChild(opt); }); }
        renderAdminAccountsLog(users); renderAdminBalanceList(users);
    } catch (e) {}
}

function renderAdminAccountsLog(users) {
    const container = document.getElementById('admin-accounts-log'); if (!container) return;
    if (!users || users.length === 0) { container.innerHTML = '<div style="color:#4b5563;font-size:13px;padding:8px;">No accounts.</div>'; return; }
    container.innerHTML = users.map((u, idx) => {
        const statusColor = u.is_banned ? '#ef4444' : '#10b981'; const statusText = u.is_banned ? 'Banned' : 'Active';
        return `<div style="color:#cbd5e1;font-size:13px;padding:6px 10px;border-bottom:1px solid rgba(139,92,246,0.1);display:flex;justify-content:space-between;"><span>${idx + 1}. <span style="color:#a78bfa;font-weight:600;">${u.username}</span> - $${parseFloat(u.balance).toFixed(2)} - Keys: ${u.key_count || 0}</span><span style="color:${statusColor};font-size:11px;font-weight:600;">${statusText}</span></div>`;
    }).join('');
}

function renderAdminBalanceList(users) {
    const container = document.getElementById('admin-balance-list'); if (!container) return;
    if (!users || users.length === 0) { container.innerHTML = '<div style="color:#4b5563;font-size:13px;text-align:center;">No users.</div>'; return; }
    container.innerHTML = users.map(u => `<div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.2);border-radius:8px;padding:10px 14px;margin-bottom:8px;display:flex;justify-content:space-between;"><div style="font-weight:600;color:#10b981;">${u.username}</div><div style="font-weight:700;color:#10b981;">$${parseFloat(u.balance).toFixed(2)}</div></div>`).join('');
}

async function adminModifyBalance(action) {
    const user = document.getElementById('admin-balance-user').value;
    const amount = parseFloat(document.getElementById('admin-balance-amount').value);
    if (!user || !amount || amount <= 0) { showModal('error', 'Failed', 'Select user and enter amount'); return; }
    try {
        const result = await api('/api/admin/modify-balance', { method: 'POST', body: JSON.stringify({ username: user, amount, action }) });
        document.getElementById('admin-balance-amount').value = '';
        renderAdminUsers(); loadAdminUserDropdowns();
        showModal('success', 'Success', result.message || 'Balance updated!');
    } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

// ==================== ADMIN: PRODUCTS ====================
async function renderAdminProducts() {
    try {
        const result = await api('/api/admin/products'); const products = result.products || [];
        const container = document.getElementById('admin-products-list');
        if (products.length === 0) { container.innerHTML = '<div style="color:#4b5563;font-size:13px;text-align:center;">No products.</div>'; return; }
        container.innerHTML = products.map(p => `<div style="background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.2);border-radius:8px;padding:12px;margin-bottom:10px;"><div style="display:flex;justify-content:space-between;align-items:center;"><div style="flex:1;"><div style="font-weight:600;color:#a78bfa;">${p.name}</div><div style="font-size:12px;color:#9ca3af;margin-top:4px;">${p.durations.map(d => `<span style="display:inline-block;background:rgba(139,92,246,0.15);padding:2px 8px;border-radius:4px;margin:2px 4px 2px 0;">${d.days}d - $${d.price}</span>`).join('')}</div></div><button class="btn-admin red" onclick="adminDeleteProduct(${p.id})"><i class="fa-solid fa-trash"></i></button></div></div>`).join('');
    } catch (e) {}
}

async function adminAddProduct() {
    const name = document.getElementById('admin-prod-name').value.trim();
    const days = parseInt(document.getElementById('admin-prod-days').value);
    const price = parseFloat(document.getElementById('admin-prod-price').value);
    if (!name || !days || !price) { showModal('error', 'Failed', 'Fill all fields'); return; }
    try {
        const result = await api('/api/admin/add-product', { method: 'POST', body: JSON.stringify({ name, days, price }) });
        document.getElementById('admin-prod-name').value = document.getElementById('admin-prod-days').value = document.getElementById('admin-prod-price').value = '';
        renderAdminProducts(); loadProductDropdowns(); loadAdminProductDropdown();
        showModal('success', 'Success', result.message || 'Product added!');
    } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function adminDeleteProduct(id) {
    if (confirm('Delete this product?')) {
        try { await api('/api/admin/delete-product', { method: 'POST', body: JSON.stringify({ product_id: id }) }); renderAdminProducts(); loadProductDropdowns(); loadAdminProductDropdown(); showModal('success', 'Success', 'Deleted!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
    }
}

async function adminDeleteProductFromSelect() {
    const sel = document.getElementById('admin-delete-product-select'); const productId = sel.value;
    if (!productId) { showModal('error', 'Failed', 'Select a product'); return; }
    if (confirm('Delete this product?')) {
        try { await api('/api/admin/delete-product', { method: 'POST', body: JSON.stringify({ product_id: parseInt(productId) }) }); renderAdminProducts(); loadProductDropdowns(); loadAdminProductDropdown(); showModal('success', 'Success', 'Deleted!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
    }
}

async function loadAdminProductDropdown() {
    try {
        const result = await api('/api/admin/products'); const products = result.products || [];
        const sel = document.getElementById('admin-delete-product-select');
        if (sel) { sel.innerHTML = '<option value="">Select Product to Delete</option>'; products.forEach(p => { const opt = document.createElement('option'); opt.value = p.id; opt.innerText = `${p.name} (${p.durations.map(d => d.days + 'd').join(', ')})`; sel.appendChild(opt); }); }
    } catch (e) {}
}

// ==================== ADMIN: KEY POOL ====================
async function renderAdminKeyPool() {
    const productId = parseInt(document.getElementById('admin-key-product').value);
    try {
        const prodResult = await api('/api/admin/products'); const products = prodResult.products || [];
        const product = products.find(p => p.id === productId);
        const durationSelect = document.getElementById('admin-key-duration');
        durationSelect.innerHTML = '<option value="">Select Duration</option>';
        if (product) product.durations.forEach(d => { const opt = document.createElement('option'); opt.value = d.days; opt.innerText = `${d.days} Days`; durationSelect.appendChild(opt); });
    } catch (e) {}
    const container = document.getElementById('admin-key-pool');
    if (!productId) { container.innerHTML = ''; return; }
    try {
        const result = await api('/api/admin/key-pool?product_id=' + productId); const keys = result.keys || [];
        container.innerHTML = '<div style="color:#9ca3af;font-size:12px;margin-bottom:10px;">Available Keys:</div>' + (keys.length === 0 ? '<div style="color:#4b5563;font-size:12px;text-align:center;">No keys in pool.</div>' : keys.map(k => `<div style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.2);border-radius:6px;padding:8px;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center;font-family:monospace;color:#10b981;font-size:12px;"><span>${k.key_code} (${k.days}d)</span><button class="btn-admin red" onclick="adminRemoveKey(${k.id})"><i class="fa-solid fa-trash"></i></button></div>`).join(''));
        const delKeySelect = document.getElementById('admin-delete-key-select');
        if (delKeySelect) { delKeySelect.innerHTML = '<option value="">Select Key to Delete</option>'; keys.forEach(k => { const opt = document.createElement('option'); opt.value = k.id; opt.innerText = `${k.key_code.substring(0, 20)}... (${k.days}d)`; delKeySelect.appendChild(opt); }); }
    } catch (e) { container.innerHTML = ''; }
}

async function adminAddKey() {
    const pid = parseInt(document.getElementById('admin-key-product').value);
    const days = parseInt(document.getElementById('admin-key-duration').value);
    const keys = document.getElementById('admin-key-value').value.trim().split('\n').map(k => k.trim()).filter(k => k);
    if (!pid || isNaN(pid)) { showModal('error', 'Failed', 'Select a product'); return; }
    if (!days || isNaN(days)) { showModal('error', 'Failed', 'Select a duration'); return; }
    if (keys.length === 0) { showModal('error', 'Failed', 'Enter at least one key'); return; }
    try {
        const result = await api('/api/admin/add-keys', { method: 'POST', body: JSON.stringify({ product_id: pid, days: days, keys: keys }) });
        document.getElementById('admin-key-value').value = ''; renderAdminKeyPool();
        showModal('success', 'Success', result.message || 'Keys added!');
    } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function adminDeleteKeyFromSelect() {
    const sel = document.getElementById('admin-delete-key-select'); const keyId = sel.value;
    if (!keyId) { showModal('error', 'Failed', 'Select a key'); return; }
    try { await api('/api/admin/remove-key', { method: 'POST', body: JSON.stringify({ key_id: parseInt(keyId) }) }); renderAdminKeyPool(); showModal('success', 'Success', 'Key deleted!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function adminRemoveKey(keyId) {
    try { await api('/api/admin/remove-key', { method: 'POST', body: JSON.stringify({ key_id: keyId }) }); renderAdminKeyPool(); showModal('success', 'Success', 'Removed!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

// ==================== ADMIN: IP BLACKLIST ====================
async function adminBanIP() {
    const ip = document.getElementById('admin-ip-input').value.trim();
    const dur = document.getElementById('admin-ban-duration').value;
    if (!ip) { showModal('error', 'Failed', 'Enter IP'); return; }
    let customMinutes = 0;
    if (dur === 'custom') { customMinutes = parseInt(document.getElementById('admin-ban-custom-minutes').value) || 0; if (customMinutes <= 0) { showModal('error', 'Failed', 'Enter duration'); return; } }
    try { await api('/api/admin/ban-ip', { method: 'POST', body: JSON.stringify({ ip, duration: dur, custom_minutes: customMinutes }) }); document.getElementById('admin-ip-input').value = ''; renderAdminBannedIPs(); showModal('success', 'Success', 'IP blocked!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function adminUnbanIP() {
    const ip = document.getElementById('admin-ip-input').value.trim(); if (!ip) return;
    try { await api('/api/admin/unban-ip', { method: 'POST', body: JSON.stringify({ ip }) }); document.getElementById('admin-ip-input').value = ''; renderAdminBannedIPs(); showModal('success', 'Success', 'IP unblocked!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function renderAdminBannedIPs() {
    try {
        const result = await api('/api/admin/banned-ips'); const banned = result.banned_ips || [];
        const container = document.getElementById('admin-ip-list');
        if (banned.length === 0) { container.innerHTML = '<div style="color:#4b5563;font-size:13px;text-align:center;">No banned IPs.</div>'; return; }
        container.innerHTML = banned.map(b => `<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);border-radius:6px;padding:8px;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center;color:#ef4444;font-size:12px;"><span>${b.ip_address}${b.reason ? ' - ' + b.reason : ''}</span><button class="btn-admin green" onclick="adminUnbanIPDirect('${b.ip_address}')"><i class="fa-solid fa-unlock"></i></button></div>`).join('');
    } catch (e) {}
}

async function adminUnbanIPDirect(ip) {
    try { await api('/api/admin/unban-ip', { method: 'POST', body: JSON.stringify({ ip }) }); renderAdminBannedIPs(); showModal('success', 'Success', 'Unblocked!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function adminUnbanAll() {
    if (confirm('Unblock ALL banned IPs? This clears both server memory and database.')) {
        try {
            const result = await api('/api/admin/unban-all', { method: 'POST' });
            renderAdminBannedIPs();
            showModal('success', 'Success', result.message || 'All IPs unblocked!');
        } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
    }
}

async function adminClearMemoryBans() {
    try {
        const result = await api('/api/admin/clear-memory-bans', { method: 'POST' });
        renderAdminBannedIPs();
        showModal('success', 'Success', result.message || 'Memory bans cleared!');
    } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

// ==================== ADMIN: ANNOUNCEMENTS ====================
async function adminSendAnnouncement() {
    const text = document.getElementById('admin-announcement-text').value.trim(); if (!text) return;
    try { await api('/api/admin/send-announcement', { method: 'POST', body: JSON.stringify({ text }) }); document.getElementById('admin-announcement-text').value = ''; renderAdminCurrentAnnouncement(); showModal('success', 'Success', 'Sent!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function adminClearAnnouncement() {
    try { await api('/api/admin/clear-announcement', { method: 'POST' }); renderAdminCurrentAnnouncement(); showModal('success', 'Success', 'Cleared!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function renderAdminCurrentAnnouncement() {
    try {
        const result = await api('/api/announcement'); const ann = result.announcement;
        const container = document.getElementById('admin-current-announcement');
        container.innerHTML = ann && ann.content ? `<div style="background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.2);border-radius:8px;padding:12px;"><div style="color:#cbd5e1;font-size:13px;white-space:pre-wrap;">${ann.content}</div></div>` : '<div style="color:#4b5563;font-size:12px;">No active announcement.</div>';
    } catch (e) {}
}

// ==================== ADMIN: DEPOSIT AMOUNTS ====================
async function renderAdminDepositAmounts() {
    try {
        const result = await api('/api/admin/deposit-amounts'); const amounts = result.amounts || [];
        const container = document.getElementById('admin-deposit-amounts-list');
        if (amounts.length === 0) { container.innerHTML = '<div style="color:#4b5563;font-size:13px;text-align:center;padding:12px;">No deposit amounts set.</div>'; return; }
        container.innerHTML = amounts.map(a => {
            const statusColor = a.is_active ? '#10b981' : '#6b7280';
            const statusText = a.is_active ? 'Active' : 'Inactive';
            return `<div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.2);border-radius:8px;padding:10px 14px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;">
                <div style="display:flex;align-items:center;gap:10px;">
                    <span style="font-weight:700;color:#10b981;font-size:16px;">$${parseFloat(a.amount).toFixed(2)}</span>
                    <span style="font-size:11px;color:${statusColor};font-weight:600;">${statusText}</span>
                </div>
                <div style="display:flex;gap:6px;">
                    <button class="btn-admin ${a.is_active ? 'red' : 'green'}" onclick="adminToggleDepositAmount(${a.id})" style="padding:6px 10px;font-size:11px;">
                        <i class="fa-solid fa-${a.is_active ? 'pause' : 'play'}"></i>
                    </button>
                    <button class="btn-admin red" onclick="adminDeleteDepositAmount(${a.id})" style="padding:6px 10px;font-size:11px;">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </div>
            </div>`;
        }).join('');
    } catch (e) {}
}

async function adminAddDepositAmount() {
    const input = document.getElementById('admin-deposit-amount-input');
    const amount = parseFloat(input.value);
    if (!amount || amount <= 0) { showModal('error', 'Failed', 'Enter a valid amount'); return; }
    try {
        const result = await api('/api/admin/add-deposit-amount', { method: 'POST', body: JSON.stringify({ amount }) });
        input.value = ''; renderAdminDepositAmounts();
        showModal('success', 'Success', result.message || 'Amount added!');
    } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

async function adminDeleteDepositAmount(id) {
    if (confirm('Remove this deposit amount?')) {
        try { await api('/api/admin/delete-deposit-amount', { method: 'POST', body: JSON.stringify({ id }) }); renderAdminDepositAmounts(); showModal('success', 'Success', 'Removed!'); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
    }
}

async function adminToggleDepositAmount(id) {
    try { await api('/api/admin/toggle-deposit-amount', { method: 'POST', body: JSON.stringify({ id }) }); renderAdminDepositAmounts(); } catch (err) { showModal('error', 'Failed', err.error || 'Failed'); }
}

// ==================== ADMIN: CHANGE CREDENTIALS ====================
async function adminChangeCredentials() {
    const newPass = document.getElementById('admin-cred-new-pass').value.trim();
    const new2FA = document.getElementById('admin-cred-new-2fa').value.trim();
    const secretCode = document.getElementById('admin-cred-secret').value.trim();
    const resultDiv = document.getElementById('admin-cred-result');
    
    if (!secretCode) { resultDiv.innerHTML = '<div style="color:#ef4444;font-size:13px;padding:8px;">Enter the secret code.</div>'; return; }
    if (!newPass && !new2FA) { resultDiv.innerHTML = '<div style="color:#ef4444;font-size:13px;padding:8px;">Enter new password or 2FA code.</div>'; return; }
    
    try {
        const result = await api('/api/admin/change-credentials', {
            method: 'POST',
            body: JSON.stringify({ secret_code: secretCode, new_password: newPass, new_2fa_code: new2FA })
        });
        document.getElementById('admin-cred-new-pass').value = '';
        document.getElementById('admin-cred-new-2fa').value = '';
        document.getElementById('admin-cred-secret').value = '';
        resultDiv.innerHTML = `<div style="color:#10b981;font-size:13px;padding:8px;border:1px solid rgba(16,185,129,0.3);border-radius:8px;">${result.message}</div>`;
        showModal('success', 'Success', result.message);
    } catch (err) {
        resultDiv.innerHTML = `<div style="color:#ef4444;font-size:13px;padding:8px;border:1px solid rgba(239,68,68,0.3);border-radius:8px;">${err.error || err.message || 'Failed'}</div>`;
    }
}

// ==================== TABS & UI ====================
function switchTab(tabId, element) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    if (element) element.classList.add('active');
    closeSidebar();
    if (tabId === 'tab-statistics') updateStatistics();
    else if (tabId === 'tab-history') updateHistory();
    else if (tabId === 'tab-transactions') updateTransactions();
    else if (tabId === 'tab-admin') { renderAdminUsers(); renderAdminProducts(); renderAdminKeyPool(); loadAdminUserDropdowns(); loadAdminProductDropdown(); renderAdminBannedIPs(); renderAdminCurrentAnnouncement(); loadProductDropdowns(); renderAdminDepositAmounts(); }
}

function toggleSidebar() { document.getElementById('sidebar').classList.toggle('show'); document.getElementById('sidebar-overlay').classList.toggle('show'); }
function closeSidebar() { document.getElementById('sidebar').classList.remove('show'); document.getElementById('sidebar-overlay').classList.remove('show'); }

function showToast(type, msg) {
    const toast = document.getElementById('toast'); toast.className = `toast show ${type}`; toast.innerText = msg;
    setTimeout(() => toast.classList.remove('show'), 3000);
}

function showModal(type, title, msg) {
    const overlay = document.getElementById('modal-overlay'); overlay.classList.remove('hidden');
    document.getElementById('modal-title').innerText = title;
    document.getElementById('modal-msg').innerText = msg;
    const icon = document.getElementById('modal-icon');
    icon.innerHTML = `<i class="fa-solid fa-${type === 'success' ? 'check' : 'exclamation'}-circle"></i>`;
    icon.style.color = type === 'success' ? '#10b981' : '#ef4444';
    overlay.classList.add('show');
    if (modalTimer) clearTimeout(modalTimer);
    modalTimer = setTimeout(closeModal, 2500);
}

function closeModal() {
    const overlay = document.getElementById('modal-overlay'); overlay.classList.remove('show');
    if (modalTimer) { clearTimeout(modalTimer); modalTimer = null; }
    setTimeout(() => overlay.classList.add('hidden'), 300);
}

// ==================== EXPORT ====================
function exportPDF() {
    try {
        const { jsPDF } = window.jspdf; const doc = new jsPDF();
        doc.setFontSize(16); doc.text('ABRDNS - Statistics Report', 14, 20);
        doc.setFontSize(10); doc.text(`User: ${currentUser.username} | Date: ${formatDateTime(new Date())}`, 14, 28);
        const breakdown = {};
        cachedProducts.forEach(p => p.durations.forEach(d => breakdown[`${p.name} ${d.days} DAY`] = 0));
        cachedKeyHistory.forEach(k => { const label = `${k.product_name} ${k.days} DAY`; if (breakdown[label] !== undefined) breakdown[label]++; });
        const rows = Object.entries(breakdown).map(([product, count]) => [product, String(count)]);
        doc.autoTable({ head: [['Product', 'Total Sold']], body: rows, startY: 35, theme: 'grid', headStyles: { fillColor: [139, 92, 246] } });
        doc.save('ABRDNS_Statistics.pdf');
    } catch (e) { showToast('error', 'Failed to export PDF'); }
}

function exportCSV() {
    try {
        if (cachedKeyHistory.length === 0) { showToast('error', 'No key history'); return; }
        let csv = '#,Key,Days,Product,Date\n';
        cachedKeyHistory.forEach((k, idx) => { csv += `${idx + 1},"${k.key_code || ''}",${k.days},"${k.product_name || ''}","${formatDateTime(new Date(k.created_at))}"\n`; });
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a'); link.href = URL.createObjectURL(blob);
        link.download = `ABRDNS_Keys_${currentUser.username}.csv`; link.click(); URL.revokeObjectURL(link.href);
    } catch (e) { showToast('error', 'Failed to export CSV'); }
}

// ==================== TELEGRAM TEST ====================
async function testTelegram() {
    const resultDiv = document.getElementById('telegram-test-result');
    resultDiv.innerHTML = '<div style="color:#a78bfa;font-size:13px;padding:8px;">Sending...</div>';
    try {
        const result = await api('/api/admin/test-telegram', { method: 'POST' });
        resultDiv.innerHTML = '<div style="color:#10b981;font-size:13px;padding:8px;border:1px solid rgba(16,185,129,0.3);border-radius:8px;">Sent! Check Telegram.</div>';
    } catch (err) { resultDiv.innerHTML = `<div style="color:#ef4444;font-size:13px;padding:8px;">${err.error || 'Failed'}</div>`; }
}

// ==================== ADMIN SCREENSHOT PREVENTION ====================
function enableAdminScreenshotPrevention() {
    const style = document.createElement('style');
    style.textContent = `#tab-admin { -webkit-touch-callout: none; }`;
    document.head.appendChild(style);
    document.addEventListener('visibilitychange', function() {
        const adminTab = document.getElementById('tab-admin');
        if (!adminTab) return;
        if (document.hidden && isAdmin) { adminTab.style.filter = 'blur(20px)'; }
        else { adminTab.style.filter = 'none'; }
    });
}

// ==================== DEPOSIT SYSTEM ====================
let depositTimer = null;
let depositTimeRemaining = 300;
let selectedDepositAmount = null;

async function openDepositOverlay() {
    if (isAdmin) { showToast('error', 'Admins cannot deposit'); return; }
    const overlay = document.getElementById('deposit-overlay');
    const formStep = document.getElementById('deposit-step-form');
    const waitingStep = document.getElementById('deposit-step-waiting');
    formStep.classList.remove('hidden'); waitingStep.classList.add('hidden');
    document.getElementById('deposit-amount-input').value = '';
    document.getElementById('deposit-btn-confirm').disabled = false;
    selectedDepositAmount = null;
    overlay.classList.remove('hidden');
    
    // Load fixed deposit amounts
    try {
        const result = await api('/api/deposit-amounts');
        depositFixedAmounts = result.amounts || [];
        renderDepositAmountsGrid();
    } catch (e) {
        document.getElementById('deposit-amounts-grid').innerHTML = '<div style="color:#ef4444;font-size:13px;text-align:center;">Failed to load amounts.</div>';
    }
    
    depositTimeRemaining = 300; updateDepositTimer();
    depositTimer = setInterval(function() {
        depositTimeRemaining--;
        updateDepositTimer();
        if (depositTimeRemaining <= 0) {
            clearInterval(depositTimer); depositTimer = null;
            closeDepositOverlay();
            showToast('error', 'Deposit expired. Try again.');
        }
    }, 1000);
}

function renderDepositAmountsGrid() {
    const grid = document.getElementById('deposit-amounts-grid');
    if (depositFixedAmounts.length === 0) {
        grid.innerHTML = '<div style="color:#6b7280;font-size:13px;text-align:center;padding:10px;">No deposit amounts available.</div>';
        return;
    }
    grid.innerHTML = depositFixedAmounts.map(a => 
        `<button class="deposit-amount-btn" data-amount="${a.amount}" onclick="selectDepositAmount(${a.amount}, this)">$${parseFloat(a.amount).toFixed(2)}</button>`
    ).join('');
}

function selectDepositAmount(amount, btn) {
    // Deselect all
    document.querySelectorAll('.deposit-amount-btn').forEach(b => b.classList.remove('selected'));
    // Select this one
    btn.classList.add('selected');
    selectedDepositAmount = amount;
    document.getElementById('deposit-amount-input').value = amount;
}

function updateDepositTimer() {
    const minutes = Math.floor(depositTimeRemaining / 60);
    const seconds = depositTimeRemaining % 60;
    const label = document.getElementById('deposit-timer-label');
    const fill = document.getElementById('deposit-timer-fill');
    label.innerText = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    const pct = (depositTimeRemaining / 300) * 100;
    fill.style.width = pct + '%';
    fill.classList.remove('warning', 'danger');
    if (pct <= 20) fill.classList.add('danger');
    else if (pct <= 40) fill.classList.add('warning');
}

function downloadQRCode() {
    const link = document.createElement('a');
    link.href = '/binance-qr.png';
    link.download = 'Binance-QR-Code.png';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('success', 'QR Code downloading...');
}

function copyBinanceId() {
    navigator.clipboard.writeText('YOUR_BINANCE_ID').then(function() {
        showToast('success', 'Binance ID copied!');
    }).catch(function() {
        const el = document.createElement('textarea'); el.value = 'YOUR_BINANCE_ID';
        document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
        showToast('success', 'Binance ID copied!');
    });
}

async function confirmDeposit() {
    const amount = parseFloat(document.getElementById('deposit-amount-input').value);
    if (!amount || !selectedDepositAmount) {
        showToast('error', 'Please select a deposit amount');
        return;
    }
    const btn = document.getElementById('deposit-btn-confirm');
    btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Submitting...';
    try {
        const result = await api('/api/deposit-request', { method: 'POST', body: JSON.stringify({ username: currentUser.username, amount: amount }) });
        if (result.success) {
            if (depositTimer) { clearInterval(depositTimer); depositTimer = null; }
            document.getElementById('deposit-step-form').classList.add('hidden');
            document.getElementById('deposit-step-waiting').classList.remove('hidden');
            document.getElementById('deposit-waiting-amount-text').innerText = '$' + amount.toFixed(2);
        }
    } catch (err) {
        if (err.error === 'COOLDOWN') { showToast('error', err.message || 'Please wait before another request.'); closeDepositOverlay(); }
        else { showToast('error', err.message || 'Failed to submit.'); }
    }
    btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-check-circle"></i> Confirm Payment';
}

function cancelDeposit() { closeDepositOverlay(); }

function closeDepositOverlay() {
    if (depositTimer) { clearInterval(depositTimer); depositTimer = null; }
    document.getElementById('deposit-overlay').classList.add('hidden');
}
