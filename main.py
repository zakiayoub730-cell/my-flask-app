#!/usr/bin/env python3
"""Sensi Reseller Dashboard  - Secure Backend with Supabase
All sensitive data moved to database (settings table)."""
import os

# Load .env file BEFORE anything else
try:
    from dotenv import load_dotenv
    env_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'),
        os.path.join(os.getcwd(), '.env'),
        '/home/container/.env',
        '.env'
    ]
    env_loaded = False
    for env_path in env_paths:
        if os.path.exists(env_path):
            load_dotenv(env_path, override=True)
            print(f"[OK] .env file loaded from: {env_path}")
            env_loaded = True
            break
    if not env_loaded:
        print("[WARN] No .env file found in any path, using defaults")
except ImportError:
    print("[WARN] python-dotenv not installed, using defaults")
except Exception as e:
    print(f"[WARN] .env load error: {e}")

from flask import Flask, send_file, send_from_directory, request, jsonify, session, redirect
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import re
import requests
import time
import uuid
import hashlib
import secrets
import logging
import bcrypt
from datetime import datetime, timezone, timedelta
from functools import wraps

# ==================== APP CONFIG ====================
app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'CHANGE_ME_TO_A_RANDOM_SECRET_KEY')

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_DOMAIN'] = None

# ===== CHANGE THESE TO YOUR DOMAINS =====
CORS(app, supports_credentials=True, origins=[
    'https://teamsensi.shop',
    'https://www.teamsensi.shop',
    'https://teamsensi.shop',
    'https://www.teamsensi.shop',
    'http://127.0.0.1:20837',
    'http://127.0.0.1:20837',
])

def get_client_ip():
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.headers.get('X-Real-IP', request.remote_addr)

limiter = Limiter(
    app=app,
    key_func=get_client_ip,
    default_limits=["200 per minute"],
    storage_uri="memory://"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== SUPABASE CONFIG ====================
SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')

if not SUPABASE_URL or not SUPABASE_KEY:
    print("[ERROR] SUPABASE_URL or SUPABASE_KEY not set in .env!")
else:
    print(f"[OK] Supabase URL: {SUPABASE_URL}")
    print(f"[OK] Supabase Key: {SUPABASE_KEY[:25]}...")

# ==================== BCRYPT HELPERS ====================
def hash_password(plain_password):
    return bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password, hashed_password):
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except (ValueError, AttributeError):
        return plain_password == hashed_password

def upgrade_password_if_needed(username, plain_password, stored_password):
    try:
        bcrypt.checkpw(plain_password.encode('utf-8'), stored_password.encode('utf-8'))
        return
    except (ValueError, AttributeError):
        try:
            sb = get_supabase()
            hashed = hash_password(plain_password)
            sb.table('users').update({'password': hashed}).eq('username', username).execute()
            logger.info(f"Upgraded password hash for user: {username}")
        except Exception as e:
            logger.error(f"Password upgrade error for {username}: {e}")

# ==================== IN-MEMORY TRACKING ====================
failed_login_attempts = {}
failed_admin_attempts = {}
memory_banned_ips = {}
devtools_attempts = {}
active_admin_tokens = set()

MAX_USER_ATTEMPTS = 4
MAX_ADMIN_ATTEMPTS = 3
MAX_DEVTOOLS_ATTEMPTS = 3
ALERT_USER_ATTEMPTS = 2
ALERT_ADMIN_ATTEMPTS = 1
ALERT_DEVTOOLS_ATTEMPTS = 2

# ==================== SETTINGS CACHE ====================
_settings_cache = {}
_settings_cache_time = 0
SETTINGS_CACHE_TTL = 120  # Cache settings for 2 minutes (reduces DB calls significantly)

def get_setting(key, default=None):
    """Get a setting from database with caching."""
    global _settings_cache, _settings_cache_time
    now = time.time()
    if now - _settings_cache_time > SETTINGS_CACHE_TTL:
        try:
            sb = get_supabase()
            result = sb.table('settings').select('key, value').execute()
            _settings_cache = {}
            for row in result.data:
                val = row['value']
                _settings_cache[row['key']] = val
            _settings_cache_time = now
        except Exception as e:
            logger.error(f"Settings cache refresh error: {e}")
    return _settings_cache.get(key, default)

def set_setting(key, value):
    """Update a setting in database. Value is stored as JSONB."""
    global _settings_cache_time
    try:
        sb = get_supabase()
        existing = sb.table('settings').select('id').eq('key', key).execute()
        if existing.data:
            sb.table('settings').update({'value': value, 'updated_at': datetime.now(timezone.utc).isoformat()}).eq('key', key).execute()
        else:
            sb.table('settings').insert({'key': key, 'value': value}).execute()
        _settings_cache[key] = value
        _settings_cache_time = 0  # Force refresh
        return True
    except Exception as e:
        logger.error(f"Set setting error: {e}")
        return False

# ==================== ERROR HELPER ====================
def make_error_response(e, context="Operation"):
    err_str = str(e).lower()
    if 'supabase' in err_str or 'key' in err_str or 'not configured' in err_str:
        msg = 'Service temporarily unavailable. Please try again later.'
        logger.error(f"Database config error: {e}")
    else:
        msg = 'An unexpected error occurred. Please try again.'
        logger.error(f"Server error: {e}")
    return jsonify({'error': msg, 'message': msg}), 500

# ==================== SUPABASE CLIENT ====================
_supabase_client = None
_supabase_last_check = 0
_supabase_health_interval = 300  # Check health every 5 minutes (less overhead)
DB_MAX_RETRIES = 3
DB_RETRY_DELAY = 0.3

import threading
_supabase_lock = threading.Lock()

def get_supabase():
    global _supabase_client, _supabase_last_check
    current_time = time.time()
    
    # Fast path - client exists and healthy (no lock needed for read)
    if _supabase_client is not None:
        if (current_time - _supabase_last_check) <= _supabase_health_interval:
            return _supabase_client
        # Health check needed
        try:
            _supabase_client.table('settings').select('id').limit(1).execute()
            _supabase_last_check = current_time
            return _supabase_client
        except Exception as e:
            logger.warning(f"Supabase health check failed, reconnecting: {e}")
            _supabase_client = None
    
    # Slow path - need to create client (thread-safe)
    with _supabase_lock:
        # Double-check after acquiring lock
        if _supabase_client is not None:
            return _supabase_client
            
        if not SUPABASE_URL or not SUPABASE_KEY:
            raise Exception("SUPABASE_KEY not configured!")
        
        from supabase import create_client
        last_error = None
        for attempt in range(DB_MAX_RETRIES):
            try:
                _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
                _supabase_last_check = current_time
                logger.info(f"Supabase connected successfully (attempt {attempt + 1})")
                return _supabase_client
            except Exception as e:
                last_error = e
                logger.error(f"Supabase connection attempt {attempt + 1}/{DB_MAX_RETRIES} failed: {e}")
                if attempt < DB_MAX_RETRIES - 1:
                    time.sleep(DB_RETRY_DELAY * (attempt + 1))
        
        raise Exception(f"Database connection failed after {DB_MAX_RETRIES} attempts: {last_error}")

def db_retry(func, *args, max_retries=2, **kwargs):
    """Execute a database operation with automatic retry on failure."""
    global _supabase_client
    last_error = None
    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_error = e
            err_str = str(e).lower()
            if 'connection' in err_str or 'timeout' in err_str or 'reset' in err_str:
                logger.warning(f"DB retry {attempt + 1}/{max_retries + 1}: {e}")
                _supabase_client = None  # Force reconnect
                if attempt < max_retries:
                    time.sleep(0.2 * (attempt + 1))
                    continue
            raise
    raise last_error

# ==================== TELEGRAM ALERTS ====================
def get_telegram_config():
    """Get Telegram config from database settings."""
    bot_token = get_setting('telegram_bot_token', os.environ.get('TELEGRAM_BOT_TOKEN', ''))
    chat_id = get_setting('telegram_chat_id', os.environ.get('TELEGRAM_CHAT_ID', ''))
    return bot_token, chat_id

def escape_html(text):
    if not text:
        return 'N/A'
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def send_telegram_alert(message, ip=None):
    """Send notification to Telegram."""
    bot_token, chat_id = get_telegram_config()
    if not bot_token or not chat_id:
        logger.warning("Telegram not configured")
        return

    try:
        extra_info = ""
        if ip:
            try:
                geo = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org', timeout=3).json()
                if geo.get('status') == 'success':
                    extra_info = (
                        f"\n\U0001F30D <b>Country:</b> {escape_html(geo.get('country', 'N/A'))}"
                        f"\n\U0001F3D9 <b>City:</b> {escape_html(geo.get('city', 'N/A'))}"
                        f"\n\U0001F4E1 <b>ISP:</b> {escape_html(geo.get('isp', 'N/A'))}"
                    )
            except:
                pass

        ua = 'N/A'
        try:
            ua = request.headers.get('User-Agent', 'N/A') if request else 'N/A'
        except RuntimeError:
            pass

        text = (
            f"\U0001F6A8 <b>SECURITY ALERT</b>\n\n"
            f"\U0001F4CD <b>Dashboard:</b> ABRDNS Reseller\n"
            f"\u26A0\uFE0F <b>Event:</b> {escape_html(message)}\n"
            f"\U0001F4C5 <b>Time:</b> {datetime.now(timezone.utc).strftime('%d/%m/%Y %I:%M %p UTC')}\n"
            f"\U0001F310 <b>IP:</b> <code>{escape_html(ip or 'N/A')}</code>"
            f"{extra_info}\n"
            f"\U0001F4F1 <b>UA:</b> {escape_html(ua[:100])}"
        )

        url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
        payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'HTML'}
        resp = requests.post(url, json=payload, timeout=10)
        if not resp.ok:
            payload['parse_mode'] = ''
            payload['text'] = text.replace('<b>', '').replace('</b>', '').replace('<code>', '').replace('</code>', '')
            requests.post(url, json=payload, timeout=10)
    except Exception as e:
        logger.error(f"Telegram alert error: {e}")

def send_deposit_telegram_alert(username, amount):
    """Send deposit notification to admin via Telegram."""
    bot_token, chat_id = get_telegram_config()
    if not bot_token or not chat_id:
        return
    
    try:
        text = (
            f"\U0001F4B0 <b>NEW DEPOSIT REQUEST</b>\n\n"
            f"\U0001F464 <b>User:</b> {escape_html(username)}\n"
            f"\U0001F4B5 <b>Amount:</b> ${amount:.2f}\n"
            f"\U0001F4C5 <b>Time:</b> {datetime.now(timezone.utc).strftime('%d/%m/%Y %I:%M %p UTC')}\n"
            f"\u23F3 <b>Status:</b> Pending\n\n"
            f"\u26A0\uFE0F Please verify payment and add balance from admin panel."
        )
        url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
        payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'HTML'}
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        logger.error(f"Deposit telegram alert error: {e}")

# ==================== IP BAN CHECK ====================
# Track last DB sync time per IP to avoid constant DB queries
_ban_db_check_cache = {}
_BAN_DB_CHECK_INTERVAL = 60  # Only check DB every 60 seconds per IP

def is_ip_banned(ip):
    """Check if IP is banned - uses memory-first strategy for speed."""
    # 1. Check memory first (instant)
    if ip in memory_banned_ips:
        ban = memory_banned_ips[ip]
        if ban.get('permanent', False):
            return True
        if ban.get('until', 0) > time.time():
            return True
        else:
            del memory_banned_ips[ip]
            return False

    # 2. Only check DB periodically per IP (not every request)
    now = time.time()
    last_check = _ban_db_check_cache.get(ip, 0)
    if (now - last_check) < _BAN_DB_CHECK_INTERVAL:
        return False  # Recently checked, not banned
    
    _ban_db_check_cache[ip] = now
    
    try:
        sb = get_supabase()
        result = sb.table('banned_ips').select('*').eq('ip_address', ip).execute()
        if result.data:
            for ban in result.data:
                if ban.get('banned_until') is None:
                    # Sync to memory for future fast checks
                    memory_banned_ips[ip] = {'permanent': True, 'until': 0}
                    return True
                ban_until = datetime.fromisoformat(ban['banned_until'].replace('Z', '+00:00'))
                if ban_until > datetime.now(timezone.utc):
                    memory_banned_ips[ip] = {'permanent': False, 'until': ban_until.timestamp()}
                    return True
                else:
                    # Expired - clean up
                    sb.table('banned_ips').delete().eq('ip_address', ip).execute()
    except Exception as e:
        logger.error(f"Ban check error: {e}")
    return False

CLOUDFLARE_IP_RANGES = [
    '173.245.48.', '103.21.244.', '103.22.200.', '103.31.4.',
    '141.101.64.', '141.101.65.', '141.101.66.', '141.101.67.', '141.101.68.',
    '108.162.192.', '190.93.240.', '188.114.96.', '188.114.97.', '188.114.98.', '188.114.99.',
    '197.234.240.', '198.41.128.', '162.158.', '104.16.', '104.17.',
    '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '104.25.',
    '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.', '172.71.',
    '131.0.72.'
]

def is_cloudflare_ip(ip):
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in CLOUDFLARE_IP_RANGES)

def ban_ip(ip, permanent=False, minutes=0, reason=""):
    try:
        if is_cloudflare_ip(ip) or ip.startswith('10.') or ip.startswith('172.16.') or ip == '127.0.0.1':
            return
        
        if permanent:
            memory_banned_ips[ip] = {'permanent': True, 'until': 0}
            banned_until = None
        else:
            until = time.time() + (minutes * 60)
            memory_banned_ips[ip] = {'permanent': False, 'until': until}
            banned_until = datetime.fromtimestamp(until, tz=timezone.utc).isoformat()

        sb = get_supabase()
        sb.table('banned_ips').delete().eq('ip_address', ip).execute()
        sb.table('banned_ips').insert({
            'ip_address': ip, 'reason': reason, 'banned_until': banned_until
        }).execute()
    except Exception as e:
        logger.error(f"Ban IP error: {e}")

def unban_ip(ip):
    """Fully unban an IP from both memory and database."""
    try:
        # Always clear from memory first
        memory_banned_ips.pop(ip, None)
        # Also clear from failed attempts tracking
        failed_login_attempts.pop(ip, None)
        failed_admin_attempts.pop(ip, None)
        devtools_attempts.pop(ip, None)
        sb = get_supabase()
        sb.table('banned_ips').delete().eq('ip_address', ip).execute()
        logger.info(f"IP unbanned: {ip}")
    except Exception as e:
        logger.error(f"Unban IP error: {e}")

def unban_all_ips():
    """Clear ALL bans from both memory and database."""
    try:
        memory_banned_ips.clear()
        failed_login_attempts.clear()
        failed_admin_attempts.clear()
        devtools_attempts.clear()
        sb = get_supabase()
        sb.table('banned_ips').delete().neq('ip_address', '').execute()
        logger.info("All IPs unbanned")
    except Exception as e:
        logger.error(f"Unban all error: {e}")

# ==================== MIDDLEWARE ====================
@app.before_request
def make_session_permanent():
    session.permanent = True

@app.before_request
def check_domain_whitelist():
    is_cloudflare = request.headers.get('CF-Connecting-IP') is not None or request.headers.get('CF-RAY') is not None
    if is_cloudflare:
        return None
    
    host = request.host.lower().split(':')[0]
    # ===== CHANGE THESE TO YOUR DOMAINS =====
    allowed_domains = [
        'YOUR_DOMAIN.com', 'www.YOUR_DOMAIN.com',
        'YOUR_SERVER_HOST.com', 'localhost', '127.0.0.1'
    ]
    
    is_allowed = any(host == domain for domain in allowed_domains)
    if not is_allowed and ('bot-hosting' in host or host.startswith('172.') or host.startswith('10.')):
        is_allowed = True
    
    forwarded_host = request.headers.get('X-Forwarded-Host', '').lower().split(':')[0]
    if forwarded_host and any(forwarded_host == domain for domain in allowed_domains):
        is_allowed = True
    
    if not is_allowed:
        ip = get_client_ip()
        ban_ip(ip, permanent=True, reason=f'Direct access via {host}')
        send_telegram_alert(f"Blocked direct access via {host}", ip)
        return jsonify({'error': 'ACCESS_DENIED'}), 403

@app.before_request
def check_banned_ip():
    path = request.path.lower()
    static_ext = ('.css', '.js', '.ico', '.png', '.jpg', '.svg', '.woff', '.woff2', '.ttf')
    # Only skip ban check for static files and ban-info APIs
    allowed_api = ('/api/check-ban', '/api/get-client-ip')
    if path.endswith(static_ext):
        return None
    if path in allowed_api:
        return None
    ip = get_client_ip()
    if is_ip_banned(ip):
        # Allow admin unban endpoints even if IP is banned (so admin can unban themselves)
        if path.startswith('/api/admin/unban') or path == '/api/admin/clear-memory-bans':
            token = request.headers.get('X-Admin-Token') or request.cookies.get('admin_token')
            if token and token in active_admin_tokens:
                return None
        return jsonify({'error': 'IP_BANNED', 'banned': True}), 403

@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), display-capture=()'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https:; connect-src 'self' https:; img-src 'self' data: https:; font-src 'self' https:; frame-ancestors 'none'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    req_path = request.path.lower()
    safe_paths = ('/robots.txt', '/humans.txt', '/favicon.ico', '/sitemap.xml',
                  '/.well-known/security.txt', '/.well-known/dnt-policy.txt')
    if req_path not in safe_paths:
        blocked_extensions = ('.env', '.py', '.pyc', '.sql', '.log', '.bak', '.old',
                              '.swp', '.conf', '.ini', '.yml', '.yaml', '.toml',
                              '.pem', '.key', '.crt', '.csv', '.db', '.sqlite')
        blocked_paths = ('/.env', '/.git', '/admin.php', '/phpmyadmin', '/shell', '/cmd',
                         '/eval', '/exec', '/etc/passwd', '/xmlrpc', '/cgi-bin',
                         '/.htaccess', '/.htpasswd', '/debug', '/__pycache__')
        is_blocked_ext = any(req_path.endswith(ext) for ext in blocked_extensions) and not req_path.startswith('/api/')
        is_blocked_path = any(p in req_path for p in blocked_paths)
        if is_blocked_ext or is_blocked_path:
            ip = get_client_ip()
            _attack_counts = getattr(app, '_attack_counts', {})
            _attack_counts[ip] = _attack_counts.get(ip, 0) + 1
            app._attack_counts = _attack_counts
            count = _attack_counts[ip]
            if count == 1 or count == 5 or count % 20 == 0:
                send_telegram_alert(f"Blocked attack: {req_path} (#{count})", ip)
            if count >= 10 and not is_ip_banned(ip):
                ban_ip(ip, permanent=True, reason=f"Auto-banned: {count} attack attempts")
            response = app.response_class(response=json.dumps({'error': 'Forbidden'}), status=403, mimetype='application/json')
    return response

# ==================== ADMIN AUTH DECORATOR ====================
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Admin-Token') or request.cookies.get('admin_token')
        session_token = session.get('admin_token')
        if token and (token in active_admin_tokens or token == session_token):
            return f(*args, **kwargs)
        return jsonify({'error': 'Unauthorized', 'message': 'Admin session expired.'}), 401
    return decorated

# ==================== STATIC ROUTES ====================
@app.route('/')
def index():
    return send_file('index.html')

@app.route('/admin')
def admin_page():
    return redirect('/#admin')

@app.route('/robots.txt')
def robots():
    return app.response_class(response="User-agent: *\nDisallow: /\n", status=200, mimetype='text/plain')

# ==================== API: USER LOGIN ====================
@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def api_login():
    try:
        ip = get_client_ip()
        data = request.get_json()
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''

        if not username or not password:
            return jsonify({'error': 'Missing credentials'}), 400

        sb = get_supabase()
        result = sb.table('users').select('*').eq('username', username).execute()

        if result.data and len(result.data) > 0:
            user = result.data[0]
            if verify_password(password, user['password']):
                upgrade_password_if_needed(username, password, user['password'])
                if user.get('is_banned', False):
                    return jsonify({'error': 'BANNED', 'message': 'Your account has been banned'}), 403
                failed_login_attempts.pop(ip, None)
                session_token = secrets.token_hex(32)
                session['user_token'] = session_token
                session['username'] = username
                return jsonify({
                    'success': True, 'username': username,
                    'balance': user['balance'], 'token': session_token
                })

        failed_login_attempts[ip] = failed_login_attempts.get(ip, 0) + 1
        attempts = failed_login_attempts[ip]
        if attempts >= ALERT_USER_ATTEMPTS:
            send_telegram_alert(f"Failed login #{attempts}/{MAX_USER_ATTEMPTS} - User: \"{username}\"", ip)
        if attempts >= MAX_USER_ATTEMPTS:
            ban_ip(ip, permanent=True, reason=f"Failed login {attempts} times")
            return jsonify({'error': 'IP_BANNED'}), 403
        remaining = MAX_USER_ATTEMPTS - attempts
        return jsonify({'error': 'INVALID', 'message': f'Authentication Failed. {remaining} attempts remaining.', 'remaining': remaining}), 401
    except Exception as e:
        return make_error_response(e, "Login")

# ==================== API: ADMIN LOGIN ====================
@app.route('/api/admin-login', methods=['POST'])
@limiter.limit("10 per minute")
def api_admin_login():
    """Admin login with password + 2FA code from database settings."""
    try:
        ip = get_client_ip().strip()
        if is_ip_banned(ip):
            return jsonify({'error': 'IP_BANNED'}), 403

        data = request.get_json()
        password = data.get('password') or ''
        twofa_code = data.get('twofa_code') or ''
        
        # Get admin password hash and 2FA code from database
        admin_pass_hash = get_setting('admin_password_hash')
        admin_2fa_code = get_setting('admin_2fa_code', '000000')
        
        # If no hash in DB yet, check against hardcoded default and migrate
        if not admin_pass_hash or admin_pass_hash == '$2b$12$placeholder':
            # ===== CHANGE THIS DEFAULT PASSWORD =====
            default_pass = 'CHANGE_ME'
            if password == default_pass:
                new_hash = hash_password(default_pass)
                set_setting('admin_password_hash', new_hash)
                admin_pass_hash = new_hash
            else:
                failed_admin_attempts[ip] = failed_admin_attempts.get(ip, 0) + 1
                attempts = failed_admin_attempts[ip]
                if attempts >= MAX_ADMIN_ATTEMPTS:
                    ban_ip(ip, permanent=True, reason=f"Failed admin login {attempts} times")
                    return jsonify({'error': 'IP_BANNED'}), 403
                remaining = MAX_ADMIN_ATTEMPTS - attempts
                return jsonify({'error': 'INVALID', 'message': f'Invalid password. {remaining} attempts remaining.', 'remaining': remaining}), 401
        
        # Verify password
        if not verify_password(password, admin_pass_hash):
            failed_admin_attempts[ip] = failed_admin_attempts.get(ip, 0) + 1
            attempts = failed_admin_attempts[ip]
            if attempts >= ALERT_ADMIN_ATTEMPTS:
                send_telegram_alert(f"Failed admin password #{attempts}/{MAX_ADMIN_ATTEMPTS}", ip)
            if attempts >= MAX_ADMIN_ATTEMPTS:
                ban_ip(ip, permanent=True, reason=f"Failed admin login {attempts} times")
                return jsonify({'error': 'IP_BANNED'}), 403
            remaining = MAX_ADMIN_ATTEMPTS - attempts
            return jsonify({'error': 'INVALID', 'message': f'Invalid password. {remaining} attempts remaining.', 'remaining': remaining}), 401
        
        # Password correct - check 2FA
        if not twofa_code:
            return jsonify({'error': 'NEED_2FA', 'message': 'Password verified. Enter 2FA code.'}), 200
        
        if twofa_code != str(admin_2fa_code):
            failed_admin_attempts[ip] = failed_admin_attempts.get(ip, 0) + 1
            attempts = failed_admin_attempts[ip]
            if attempts >= MAX_ADMIN_ATTEMPTS:
                ban_ip(ip, permanent=True, reason=f"Failed admin 2FA {attempts} times")
                return jsonify({'error': 'IP_BANNED'}), 403
            remaining = MAX_ADMIN_ATTEMPTS - attempts
            return jsonify({'error': 'INVALID_2FA', 'message': f'Invalid 2FA code. {remaining} attempts remaining.', 'remaining': remaining}), 401
        
        # Both correct - grant access
        failed_admin_attempts.pop(ip, None)
        admin_token = secrets.token_hex(32)
        session['admin_token'] = admin_token
        session['is_admin'] = True
        active_admin_tokens.add(admin_token)
        send_telegram_alert(f"Admin login successful", ip)
        return jsonify({'success': True, 'token': admin_token})
    except Exception as e:
        return make_error_response(e)

# ==================== API: DEPOSIT AMOUNTS ====================
@app.route('/api/deposit-amounts', methods=['GET'])
@limiter.limit("30 per minute")
def api_get_deposit_amounts():
    """Get active fixed deposit amounts set by admin."""
    try:
        sb = get_supabase()
        result = sb.table('deposit_amounts').select('*').eq('is_active', True).order('amount').execute()
        amounts = [{'id': a['id'], 'amount': float(a['amount'])} for a in result.data]
        return jsonify({'amounts': amounts})
    except Exception as e:
        return make_error_response(e)

# ==================== API: DEPOSIT REQUEST ====================
@app.route('/api/deposit-request', methods=['POST'])
@limiter.limit("5 per minute")
def api_deposit_request():
    """User submits a deposit request - amount must be from fixed amounts list."""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        amount = data.get('amount')
        
        if not username or not amount:
            return jsonify({'error': 'Missing username or amount'}), 400
        
        try:
            amount = float(amount)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount'}), 400
        
        sb = get_supabase()
        
        # Validate amount against fixed deposit amounts
        valid_amounts = sb.table('deposit_amounts').select('amount').eq('is_active', True).execute()
        valid_list = [float(a['amount']) for a in valid_amounts.data]
        if amount not in valid_list:
            return jsonify({'error': 'Invalid deposit amount. Please select from available amounts.'}), 400
        
        # Check user exists
        user = sb.table('users').select('username').eq('username', username).execute()
        if not user.data:
            return jsonify({'error': 'User not found'}), 404
        
        # Check 3-hour cooldown
        three_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
        recent = sb.table('deposit_requests').select('*').eq('username', username).gte('created_at', three_hours_ago).order('created_at', desc=True).limit(1).execute()
        
        if recent.data:
            last_time = datetime.fromisoformat(recent.data[0]['created_at'].replace('Z', '+00:00'))
            diff = datetime.now(timezone.utc) - last_time
            remaining_seconds = int((timedelta(hours=3) - diff).total_seconds())
            if remaining_seconds > 0:
                hours = remaining_seconds // 3600
                minutes = (remaining_seconds % 3600) // 60
                return jsonify({
                    'error': 'COOLDOWN',
                    'message': f'Please wait {hours}h {minutes}m before submitting another deposit request.',
                    'remaining_seconds': remaining_seconds
                }), 429
        
        # Create deposit request
        result = sb.table('deposit_requests').insert({
            'username': username, 'amount': amount, 'status': 'pending'
        }).execute()
        
        if not result.data:
            return jsonify({'error': 'Failed to create deposit request'}), 500
        
        # Send Telegram notification to admin
        send_deposit_telegram_alert(username, amount)
        
        return jsonify({'success': True, 'message': 'Deposit request submitted.'})
    except Exception as e:
        return make_error_response(e)

# ==================== API: GET USER DATA ====================
@app.route('/api/get-data', methods=['GET'])
@limiter.limit("30 per minute")
def api_get_data():
    try:
        session_username = session.get('username')
        requested_username = request.args.get('username')
        if not session_username:
            return jsonify({'error': 'Not authenticated'}), 401
        username = requested_username or session_username
        if username != session_username:
            return jsonify({'error': 'Unauthorized'}), 403

        sb = get_supabase()
        result = sb.table('users').select('username, balance, is_banned').eq('username', username).execute()
        if result.data:
            user = result.data[0]
            return jsonify({'username': user['username'], 'balance': user['balance'], 'is_banned': user['is_banned']})
        return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return make_error_response(e)

# ==================== API: GET PRODUCTS ====================
@app.route('/api/products', methods=['GET'])
@limiter.limit("30 per minute")
def api_get_products():
    try:
        sb = get_supabase()
        result = sb.table('products').select('*').execute()
        products = []
        for p in result.data:
            durations = p.get('durations', '[]')
            if isinstance(durations, str):
                durations = json.loads(durations)
            products.append({'id': p['id'], 'name': p['name'], 'durations': durations})
        return jsonify({'products': products})
    except Exception as e:
        return make_error_response(e)

# ==================== API: GENERATE KEYS ====================
@app.route('/api/generate-keys', methods=['POST'])
@limiter.limit("30 per minute")
def api_generate_keys():
    try:
        session_username = session.get('username')
        if not session_username:
            return jsonify({'error': 'Not authenticated'}), 401
        data = request.get_json()
        username = session_username
        product_id = data.get('product_id')
        days = data.get('days')
        quantity = data.get('quantity', 1)
        if not all([product_id, days]):
            return jsonify({'error': 'Missing parameters'}), 400

        sb = get_supabase()
        user_result = sb.table('users').select('*').eq('username', username).execute()
        if not user_result.data:
            return jsonify({'error': 'User not found'}), 404
        user = user_result.data[0]
        if user.get('is_banned', False):
            return jsonify({'error': 'Account banned'}), 403

        prod_result = sb.table('products').select('*').eq('id', product_id).execute()
        if not prod_result.data:
            return jsonify({'error': 'Product not found'}), 404
        product = prod_result.data[0]
        durations = product.get('durations', '[]')
        if isinstance(durations, str):
            durations = json.loads(durations)

        days = int(days)
        quantity = min(int(quantity), 50)
        if quantity < 1 or days < 1 or days > 3650:
            return jsonify({'error': 'Invalid parameters'}), 400
        
        duration = None
        for d in durations:
            if int(d['days']) == days:
                duration = d
                break
        if not duration:
            return jsonify({'error': 'Invalid duration'}), 400

        total_cost = float(duration['price']) * int(quantity)
        user_balance = float(user['balance'])
        if user_balance < total_cost:
            return jsonify({'error': f'Insufficient balance. Need ${total_cost:.2f}, have ${user_balance:.2f}'}), 400

        pool_result = sb.table('key_pool').select('*').eq('product_id', product_id).eq('days', days).limit(quantity).execute()
        pool_keys = pool_result.data if pool_result.data else []
        if not pool_keys:
            return jsonify({'error': 'No keys available, please try again later.'}), 400
        if len(pool_keys) < quantity:
            return jsonify({'error': f'Not enough keys. Only {len(pool_keys)} in stock.'}), 400

        generated_keys = []
        key_ids_to_delete = []
        for pk in pool_keys[:quantity]:
            generated_keys.append(pk['key_code'])
            key_ids_to_delete.append(pk['id'])

        # Delete used keys from pool in batch
        for kid in key_ids_to_delete:
            sb.table('key_pool').delete().eq('id', kid).execute()

        # Update balance
        new_balance = user_balance - total_cost
        sb.table('users').update({'balance': new_balance}).eq('username', username).execute()

        # Batch insert key history
        history_batch = [
            {'username': username, 'key_code': k, 'product_name': product['name'], 'days': days, 'price': float(duration['price'])}
            for k in generated_keys
        ]
        sb.table('key_history').insert(history_batch).execute()

        # Record transaction
        sb.table('transactions').insert({
            'username': username, 'type': 'Key Purchase', 'amount': -total_cost
        }).execute()

        return jsonify({'success': True, 'keys': generated_keys, 'new_balance': new_balance, 'total_cost': total_cost})
    except Exception as e:
        return make_error_response(e)

# ==================== API: KEY HISTORY ====================
@app.route('/api/key-history', methods=['GET'])
@limiter.limit("20 per minute")
def api_key_history():
    try:
        session_username = session.get('username')
        requested_username = request.args.get('username')
        if not session_username:
            return jsonify({'error': 'Not authenticated'}), 401
        username = requested_username or session_username
        if username != session_username:
            return jsonify({'error': 'Unauthorized'}), 403
        sb = get_supabase()
        result = sb.table('key_history').select('*').eq('username', username).order('created_at', desc=True).execute()
        return jsonify({'history': result.data})
    except Exception as e:
        return make_error_response(e)

# ==================== API: TRANSACTIONS ====================
@app.route('/api/transactions', methods=['GET'])
@limiter.limit("20 per minute")
def api_transactions():
    try:
        session_username = session.get('username')
        requested_username = request.args.get('username')
        if not session_username:
            return jsonify({'error': 'Not authenticated'}), 401
        username = requested_username or session_username
        if username != session_username:
            return jsonify({'error': 'Unauthorized'}), 403
        sb = get_supabase()
        result = sb.table('transactions').select('*').eq('username', username).order('created_at', desc=True).execute()
        return jsonify({'transactions': result.data})
    except Exception as e:
        return make_error_response(e)

# ==================== API: ANNOUNCEMENTS ====================
@app.route('/api/announcement', methods=['GET'])
def api_get_announcement():
    try:
        sb = get_supabase()
        result = sb.table('announcements').select('*').order('created_at', desc=True).limit(1).execute()
        if result.data:
            return jsonify({'announcement': result.data[0]})
        return jsonify({'announcement': None})
    except Exception as e:
        return make_error_response(e)

# ==================== API: SECURITY ====================
@app.route('/api/security-alert', methods=['POST'])
@limiter.limit("20 per minute")
def api_security_alert():
    try:
        ip = get_client_ip()
        data = request.get_json()
        event = data.get('event', 'Unknown')
        is_devtools = data.get('is_devtools', False)
        send_telegram_alert(event, ip)
        if is_devtools:
            devtools_attempts[ip] = devtools_attempts.get(ip, 0) + 1
            if devtools_attempts[ip] >= MAX_DEVTOOLS_ATTEMPTS:
                ban_ip(ip, permanent=True, reason=f"DevTools opened {devtools_attempts[ip]} times")
                return jsonify({'banned': True}), 403
        return jsonify({'success': True})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/get-client-ip', methods=['GET'])
def api_get_client_ip():
    return jsonify({'ip': get_client_ip()})

@app.route('/api/check-ban', methods=['GET'])
def api_check_ban():
    ip = get_client_ip()
    return jsonify({'banned': is_ip_banned(ip), 'ip': ip})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/check-session', methods=['GET'])
def api_check_session():
    try:
        ip = get_client_ip()
        if is_ip_banned(ip):
            return jsonify({'active': False, 'reason': 'IP_BANNED'}), 403
        session_username = session.get('username')
        session_token = session.get('user_token')
        if session_username and session_token:
            try:
                sb = get_supabase()
                result = sb.table('users').select('username, balance, is_banned').eq('username', session_username).execute()
                if result.data and not result.data[0].get('is_banned', False):
                    user = result.data[0]
                    return jsonify({'active': True, 'type': 'user', 'username': user['username'], 'balance': user['balance']})
            except:
                pass
        admin_token = session.get('admin_token')
        is_admin = session.get('is_admin')
        if admin_token and is_admin and admin_token in active_admin_tokens:
            return jsonify({'active': True, 'type': 'admin'})
        return jsonify({'active': False})
    except:
        return jsonify({'active': False}), 500

@app.route('/api/verify-device', methods=['POST'])
@limiter.limit("10 per minute")
def api_verify_device():
    try:
        ip = get_client_ip()
        data = request.get_json() or {}
        fingerprint = data.get('fingerprint', '')
        user_agent = request.headers.get('User-Agent', '')
        origin = request.headers.get('Origin', '') or request.headers.get('Referer', '')
        checks = {}
        if is_ip_banned(ip):
            return jsonify({'verified': False, 'checks': {'ip': False}}), 403
        checks['ip'] = True
        # ===== CHANGE THESE TO YOUR DOMAINS =====
        allowed_origins = ['YOUR_DOMAIN.com', 'YOUR_SERVER_HOST.com', 'localhost', '127.0.0.1']
        checks['domain'] = not origin or any(d in origin for d in allowed_origins)
        suspicious_uas = ['sqlmap', 'nikto', 'nmap', 'masscan', 'dirbuster']
        checks['user_agent'] = bool(user_agent) and not any(s in user_agent.lower() for s in suspicious_uas)
        checks['fingerprint'] = bool(fingerprint) and len(fingerprint) >= 8
        checks['rate'] = True
        all_passed = all(checks.values())
        if not all_passed:
            failed = [k for k, v in checks.items() if not v]
            send_telegram_alert(f"Device verification FAILED: {', '.join(failed)}", ip)
        return jsonify({'verified': all_passed, 'checks': checks})
    except Exception as e:
        return jsonify({'verified': False}), 500

# ==================== API: TEST TELEGRAM ====================
@app.route('/api/admin/test-telegram', methods=['POST'])
@admin_required
def test_telegram():
    try:
        bot_token, chat_id = get_telegram_config()
        if not bot_token or not chat_id:
            return jsonify({'error': 'Telegram not configured'}), 400
        text = f"\U0001F7E2 <b>TEST NOTIFICATION</b>\n\n\U0001F4C5 <b>Time:</b> {datetime.now(timezone.utc).strftime('%d/%m/%Y %I:%M %p UTC')}\nNotifications are working!"
        url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
        resp = requests.post(url, json={'chat_id': chat_id, 'text': text, 'parse_mode': 'HTML'}, timeout=10)
        if resp.ok:
            return jsonify({'success': True, 'message': 'Test notification sent!'})
        return jsonify({'error': f'Telegram API error: {resp.json().get("description", "Unknown")}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ADMIN API ROUTES ====================
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    try:
        sb = get_supabase()
        users = sb.table('users').select('*').execute()
        key_history = sb.table('key_history').select('username').execute()
        key_counts = {}
        for kh in key_history.data:
            u = kh['username']
            key_counts[u] = key_counts.get(u, 0) + 1
        result = []
        for u in users.data:
            result.append({
                'username': u['username'], 'balance': u['balance'],
                'is_banned': u['is_banned'], 'key_count': key_counts.get(u['username'], 0)
            })
        return jsonify({'users': result})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/add-user', methods=['POST'])
@admin_required
def admin_add_user():
    try:
        data = request.get_json()
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        if not username or not password:
            return jsonify({'error': 'Missing username or password'}), 400
        sb = get_supabase()
        existing = sb.table('users').select('username').eq('username', username).execute()
        if existing.data:
            return jsonify({'error': 'User already exists'}), 409
        sb.table('users').insert({'username': username, 'password': hash_password(password), 'balance': 0, 'is_banned': False}).execute()
        return jsonify({'success': True, 'message': 'User added!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/delete-user', methods=['POST'])
@admin_required
def admin_delete_user():
    try:
        data = request.get_json()
        username = data.get('username')
        if not username:
            return jsonify({'error': 'Missing username'}), 400
        sb = get_supabase()
        sb.table('users').delete().eq('username', username).execute()
        return jsonify({'success': True, 'message': 'User deleted!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/toggle-ban', methods=['POST'])
@admin_required
def admin_toggle_ban():
    try:
        data = request.get_json()
        username = data.get('username')
        if not username:
            return jsonify({'error': 'Missing username'}), 400
        sb = get_supabase()
        result = sb.table('users').select('is_banned').eq('username', username).execute()
        if not result.data:
            return jsonify({'error': 'User not found'}), 404
        new_status = not result.data[0]['is_banned']
        sb.table('users').update({'is_banned': new_status}).eq('username', username).execute()
        return jsonify({'success': True, 'banned': new_status, 'message': f'User {"banned" if new_status else "unbanned"}!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/edit-password', methods=['POST'])
@admin_required
def admin_edit_password():
    try:
        data = request.get_json()
        username = data.get('username')
        new_password = data.get('password')
        if not username or not new_password:
            return jsonify({'error': 'Missing data'}), 400
        sb = get_supabase()
        sb.table('users').update({'password': hash_password(new_password)}).eq('username', username).execute()
        return jsonify({'success': True, 'message': 'Password updated!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/modify-balance', methods=['POST'])
@admin_required
def admin_modify_balance():
    try:
        data = request.get_json()
        username = data.get('username')
        amount = data.get('amount', 0)
        action = data.get('action')
        if not username or not amount or not action:
            return jsonify({'error': 'Missing data'}), 400
        sb = get_supabase()
        result = sb.table('users').select('balance').eq('username', username).execute()
        if not result.data:
            return jsonify({'error': 'User not found'}), 404
        current = float(result.data[0]['balance'])
        amount = float(amount)
        if action == 'add':
            new_balance = current + amount
            sb.table('transactions').insert({'username': username, 'type': 'Deposit', 'amount': amount}).execute()
        else:
            new_balance = max(0, current - amount)
            sb.table('transactions').insert({'username': username, 'type': 'Deduction', 'amount': -amount}).execute()
        sb.table('users').update({'balance': new_balance}).eq('username', username).execute()
        return jsonify({'success': True, 'new_balance': new_balance, 'message': f'Balance updated!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/products', methods=['GET'])
@admin_required
def admin_get_products():
    try:
        sb = get_supabase()
        result = sb.table('products').select('*').execute()
        products = []
        for p in result.data:
            durations = p.get('durations', '[]')
            if isinstance(durations, str):
                durations = json.loads(durations)
            products.append({'id': p['id'], 'name': p['name'], 'durations': durations})
        return jsonify({'products': products})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/add-product', methods=['POST'])
@admin_required
def admin_add_product():
    try:
        data = request.get_json()
        name = (data.get('name') or '').strip()
        days = data.get('days')
        price = data.get('price')
        if not name or not days or price is None:
            return jsonify({'error': 'Missing data'}), 400
        sb = get_supabase()
        existing = sb.table('products').select('*').eq('name', name).execute()
        if existing.data:
            product = existing.data[0]
            durations = product.get('durations', [])
            if isinstance(durations, str):
                durations = json.loads(durations)
            for d in durations:
                if int(d['days']) == int(days):
                    return jsonify({'error': 'Duration already exists'}), 409
            durations.append({'days': int(days), 'price': float(price)})
            # Pass list directly - Supabase JSONB handles it natively
            sb.table('products').update({'durations': durations}).eq('id', product['id']).execute()
        else:
            # Pass list directly - NOT json.dumps (JSONB column)
            sb.table('products').insert({'name': name, 'durations': [{'days': int(days), 'price': float(price)}]}).execute()
        return jsonify({'success': True, 'message': 'Product added!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/delete-product', methods=['POST'])
@admin_required
def admin_delete_product():
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        if not product_id:
            return jsonify({'error': 'Missing product ID'}), 400
        sb = get_supabase()
        sb.table('products').delete().eq('id', product_id).execute()
        return jsonify({'success': True, 'message': 'Product deleted!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/key-pool', methods=['GET'])
@admin_required
def admin_get_key_pool():
    try:
        product_id = request.args.get('product_id')
        sb = get_supabase()
        if product_id:
            result = sb.table('key_pool').select('*').eq('product_id', product_id).execute()
        else:
            result = sb.table('key_pool').select('*').execute()
        return jsonify({'keys': result.data})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/add-keys', methods=['POST'])
@admin_required
def admin_add_keys():
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        days = data.get('days')
        keys = data.get('keys', [])
        if not product_id or not days or not keys:
            return jsonify({'error': 'Missing data'}), 400
        sb = get_supabase()
        # Batch insert all keys at once for speed
        batch = []
        for k in keys:
            k = k.strip()
            if k:
                batch.append({'product_id': product_id, 'key_code': k, 'days': int(days)})
        if not batch:
            return jsonify({'error': 'No valid keys provided'}), 400
        added = 0
        # Insert in chunks of 50 to avoid payload limits
        for i in range(0, len(batch), 50):
            chunk = batch[i:i+50]
            try:
                sb.table('key_pool').upsert(chunk, on_conflict='product_id,key_code').execute()
                added += len(chunk)
            except Exception as e:
                # Fallback: insert one by one
                for item in chunk:
                    try:
                        sb.table('key_pool').insert(item).execute()
                        added += 1
                    except:
                        pass
        return jsonify({'success': True, 'added': added, 'message': f'{added} key(s) added!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/remove-key', methods=['POST'])
@admin_required
def admin_remove_key():
    try:
        data = request.get_json()
        key_id = data.get('key_id')
        if not key_id:
            return jsonify({'error': 'Missing key ID'}), 400
        sb = get_supabase()
        sb.table('key_pool').delete().eq('id', key_id).execute()
        return jsonify({'success': True, 'message': 'Key removed!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/banned-ips', methods=['GET'])
@admin_required
def admin_get_banned_ips():
    try:
        sb = get_supabase()
        result = sb.table('banned_ips').select('*').execute()
        return jsonify({'banned_ips': result.data})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/ban-ip', methods=['POST'])
@admin_required
def admin_ban_ip():
    try:
        data = request.get_json()
        ip = (data.get('ip') or '').strip()
        duration = data.get('duration', 'permanent')
        custom_minutes = data.get('custom_minutes', 0)
        if not ip:
            return jsonify({'error': 'Missing IP'}), 400
        if duration == 'permanent':
            ban_ip(ip, permanent=True, reason="Admin ban - permanent")
        elif duration == 'custom':
            ban_ip(ip, minutes=custom_minutes, reason=f"Admin ban - {custom_minutes} min")
        else:
            minutes = int(duration.replace('temp-', ''))
            ban_ip(ip, minutes=minutes, reason=f"Admin ban - {minutes} min")
        return jsonify({'success': True, 'message': 'IP blocked!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/unban-ip', methods=['POST'])
@admin_required
def admin_unban_ip():
    try:
        data = request.get_json()
        ip = (data.get('ip') or '').strip()
        if not ip:
            return jsonify({'error': 'Missing IP'}), 400
        unban_ip(ip)
        return jsonify({'success': True, 'message': f'IP {ip} fully unblocked (memory + database)!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/unban-all', methods=['POST'])
@admin_required
def admin_unban_all():
    """Clear ALL banned IPs from memory and database."""
    try:
        unban_all_ips()
        return jsonify({'success': True, 'message': 'All IPs unblocked from memory and database!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/clear-memory-bans', methods=['POST'])
@admin_required
def admin_clear_memory_bans():
    """Clear only in-memory bans (useful when DB was manually cleaned)."""
    try:
        count = len(memory_banned_ips)
        memory_banned_ips.clear()
        failed_login_attempts.clear()
        failed_admin_attempts.clear()
        devtools_attempts.clear()
        return jsonify({'success': True, 'message': f'Cleared {count} memory bans + all attempt counters!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/send-announcement', methods=['POST'])
@admin_required
def admin_send_announcement():
    try:
        data = request.get_json()
        text = (data.get('text') or '').strip()
        if not text:
            return jsonify({'error': 'Missing text'}), 400
        text = re.sub(r'<[^>]+>', '', text)[:500]
        sb = get_supabase()
        sb.table('announcements').delete().neq('id', 0).execute()
        sb.table('announcements').insert({'content': text}).execute()
        return jsonify({'success': True, 'message': 'Announcement sent!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/clear-announcement', methods=['POST'])
@admin_required
def admin_clear_announcement():
    try:
        sb = get_supabase()
        sb.table('announcements').delete().neq('id', 0).execute()
        return jsonify({'success': True, 'message': 'Announcement cleared!'})
    except Exception as e:
        return make_error_response(e)

# ==================== ADMIN: DEPOSIT AMOUNTS MANAGEMENT ====================
@app.route('/api/admin/deposit-amounts', methods=['GET'])
@admin_required
def admin_get_deposit_amounts():
    """Get all deposit amounts (active and inactive)."""
    try:
        sb = get_supabase()
        result = sb.table('deposit_amounts').select('*').order('amount').execute()
        return jsonify({'amounts': result.data})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/add-deposit-amount', methods=['POST'])
@admin_required
def admin_add_deposit_amount():
    """Add a new fixed deposit amount."""
    try:
        data = request.get_json()
        amount = data.get('amount')
        if not amount:
            return jsonify({'error': 'Missing amount'}), 400
        try:
            amount = float(amount)
        except:
            return jsonify({'error': 'Invalid amount'}), 400
        if amount <= 0 or amount > 100000:
            return jsonify({'error': 'Amount must be between $0.01 and $100,000'}), 400
        
        sb = get_supabase()
        existing = sb.table('deposit_amounts').select('id').eq('amount', amount).execute()
        if existing.data:
            sb.table('deposit_amounts').update({'is_active': True}).eq('amount', amount).execute()
            return jsonify({'success': True, 'message': f'${amount:.2f} reactivated!'})
        
        sb.table('deposit_amounts').insert({'amount': amount, 'is_active': True}).execute()
        return jsonify({'success': True, 'message': f'${amount:.2f} added!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/delete-deposit-amount', methods=['POST'])
@admin_required
def admin_delete_deposit_amount():
    """Delete a fixed deposit amount."""
    try:
        data = request.get_json()
        amount_id = data.get('id')
        if not amount_id:
            return jsonify({'error': 'Missing ID'}), 400
        sb = get_supabase()
        sb.table('deposit_amounts').delete().eq('id', amount_id).execute()
        return jsonify({'success': True, 'message': 'Amount removed!'})
    except Exception as e:
        return make_error_response(e)

@app.route('/api/admin/toggle-deposit-amount', methods=['POST'])
@admin_required
def admin_toggle_deposit_amount():
    """Toggle active/inactive status of deposit amount."""
    try:
        data = request.get_json()
        amount_id = data.get('id')
        if not amount_id:
            return jsonify({'error': 'Missing ID'}), 400
        sb = get_supabase()
        result = sb.table('deposit_amounts').select('is_active').eq('id', amount_id).execute()
        if not result.data:
            return jsonify({'error': 'Not found'}), 404
        new_status = not result.data[0]['is_active']
        sb.table('deposit_amounts').update({'is_active': new_status}).eq('id', amount_id).execute()
        return jsonify({'success': True, 'is_active': new_status})
    except Exception as e:
        return make_error_response(e)

# ==================== ADMIN: CHANGE PASSWORD & 2FA ====================
@app.route('/api/admin/change-credentials', methods=['POST'])
@admin_required
def admin_change_credentials():
    """Change admin password and/or 2FA code. Requires secret code to apply."""
    try:
        data = request.get_json()
        secret_code = data.get('secret_code', '')
        new_password = data.get('new_password', '').strip()
        new_2fa_code = data.get('new_2fa_code', '').strip()
        
        # ===== CHANGE THIS SECRET CODE =====
        if secret_code != 'YOUR_SECRET_CODE':
            return jsonify({'error': 'Invalid secret code. Changes not applied.'}), 403
        
        changes = []
        
        if new_password:
            if len(new_password) < 4:
                return jsonify({'error': 'Password must be at least 4 characters'}), 400
            new_hash = hash_password(new_password)
            set_setting('admin_password_hash', new_hash)
            changes.append('Password updated')
        
        if new_2fa_code:
            if len(new_2fa_code) < 3 or len(new_2fa_code) > 10:
                return jsonify({'error': '2FA code must be 3-10 characters'}), 400
            set_setting('admin_2fa_code', new_2fa_code)
            changes.append('2FA code updated')
        
        if not changes:
            return jsonify({'error': 'No changes provided'}), 400
        
        ip = get_client_ip()
        send_telegram_alert(f"Admin credentials changed: {', '.join(changes)}", ip)
        
        return jsonify({'success': True, 'message': '. '.join(changes) + '.'})
    except Exception as e:
        return make_error_response(e)

# ==================== CATCH-ALL STATIC ====================
ALLOWED_STATIC_FILES = {'style.css', 'logic.js', 'data.js', 'favicon.ico', 'binance-qr.png'}

@app.route('/<path:path>')
def serve(path):
    if '..' in path or path.startswith('/'):
        ip = get_client_ip()
        ban_ip(ip, permanent=True, reason=f"Directory traversal: {path}")
        return jsonify({'error': 'Forbidden'}), 403
    if path in ALLOWED_STATIC_FILES:
        safe_path = os.path.normpath(os.path.join(app.static_folder, path))
        if safe_path.startswith(os.path.normpath(app.static_folder)) and os.path.isfile(safe_path):
            return send_from_directory(app.static_folder, path)
    return jsonify({'error': 'Not Found'}), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Too many requests. Please slow down.'}), 429

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not Found'}), 404

# ==================== MAIN ====================
if __name__ == '__main__':
    try:
        sb = get_supabase()
        logger.info("Server starting with Supabase connection")
        
        # 1. Clean wrongly banned infrastructure IPs
        try:
            all_bans = sb.table('banned_ips').select('*').execute()
            cleaned = 0
            loaded = 0
            for ban in (all_bans.data or []):
                ip = ban.get('ip_address', '')
                if is_cloudflare_ip(ip) or ip.startswith('10.') or ip.startswith('172.16.') or ip == '127.0.0.1':
                    sb.table('banned_ips').delete().eq('ip_address', ip).execute()
                    cleaned += 1
                else:
                    # 2. Sync DB bans to memory for instant checking
                    banned_until = ban.get('banned_until')
                    if banned_until is None:
                        memory_banned_ips[ip] = {'permanent': True, 'until': 0}
                        loaded += 1
                    else:
                        try:
                            ban_dt = datetime.fromisoformat(banned_until.replace('Z', '+00:00'))
                            if ban_dt > datetime.now(timezone.utc):
                                memory_banned_ips[ip] = {'permanent': False, 'until': ban_dt.timestamp()}
                                loaded += 1
                            else:
                                # Expired ban - clean it
                                sb.table('banned_ips').delete().eq('ip_address', ip).execute()
                                cleaned += 1
                        except:
                            memory_banned_ips[ip] = {'permanent': True, 'until': 0}
                            loaded += 1
            if cleaned:
                print(f"[OK] Cleaned {cleaned} expired/invalid banned IPs")
            print(f"[OK] Loaded {loaded} active bans into memory")
        except Exception as e:
            logger.warning(f"Ban sync failed: {e}")
        
        # 3. Pre-warm settings cache
        try:
            get_setting('admin_password_hash')
            print("[OK] Settings cache warmed up")
        except:
            pass
            
    except Exception as e:
        logger.warning(f"Supabase initial connection failed: {e}")

    server_port = int(os.environ.get('SERVER_PORT', 20837))
    print(f"[OK] Starting server on port: {server_port}")
    app.run(host='0.0.0.0', port=server_port, debug=False)
