-- =====================================================
-- ABRDNS Reseller Dashboard - COMPLETE Database Schema
-- Run this ENTIRE script in Supabase SQL Editor
-- Go to: https://supabase.com/dashboard > SQL Editor > New Query
-- =====================================================

-- =====================================================
-- STEP 1: DROP ALL EXISTING TABLES (clean slate)
-- =====================================================
DROP TABLE IF EXISTS admin_2fa_requests CASCADE;
DROP TABLE IF EXISTS deposit_requests CASCADE;
DROP TABLE IF EXISTS deposit_amounts CASCADE;
DROP TABLE IF EXISTS key_history CASCADE;
DROP TABLE IF EXISTS transactions CASCADE;
DROP TABLE IF EXISTS key_pool CASCADE;
DROP TABLE IF EXISTS banned_ips CASCADE;
DROP TABLE IF EXISTS announcements CASCADE;
DROP TABLE IF EXISTS products CASCADE;
DROP TABLE IF EXISTS settings CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- =====================================================
-- STEP 2: CREATE ALL TABLES
-- =====================================================

-- 1. Settings table (stores admin password, 2FA code, Binance ID, etc.)
CREATE TABLE settings (
    id SERIAL PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Default settings: CHANGE THESE VALUES!
-- admin_password_hash: "$2b$12$placeholder" means it will use the
-- default password from main.py on first login then auto-hash it.
-- admin_2fa_code: The code required for 2-step admin login.
-- binance_id: Your Binance Pay ID number.
INSERT INTO settings (key, value) VALUES
    ('admin_password_hash', '"$2b$12$placeholder"'),
    ('admin_2fa_code', '"000000"'),
    ('announcement', 'null'),
    ('binance_id', '"1184166252"'),
    ('binance_qr_url', '"/binance-qr.png"')
ON CONFLICT (key) DO NOTHING;

-- 2. Users table
CREATE TABLE users (
    id UUID DEFAULT gen_random_uuid(),
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    balance DECIMAL(10, 2) DEFAULT 0.00,
    is_banned BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Products table
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    durations JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Key history table
CREATE TABLE key_history (
    id SERIAL PRIMARY KEY,
    username TEXT REFERENCES users(username) ON DELETE CASCADE,
    key_code TEXT NOT NULL,
    product_name TEXT NOT NULL,
    days INTEGER NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Transactions table
CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    username TEXT REFERENCES users(username) ON DELETE CASCADE,
    amount DECIMAL(10, 2) NOT NULL,
    type TEXT NOT NULL,
    product_name TEXT,
    quantity INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Key pool table
CREATE TABLE key_pool (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
    key_code TEXT NOT NULL,
    days INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(product_id, key_code)
);

-- 7. Banned IPs table
CREATE TABLE banned_ips (
    ip_address TEXT PRIMARY KEY,
    reason TEXT DEFAULT '',
    banned_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. Announcements table
CREATE TABLE announcements (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9. Admin 2FA requests table
CREATE TABLE admin_2fa_requests (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    ip_address TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    telegram_message_id BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP + INTERVAL '5 minutes')
);

-- 10. Deposit requests table
CREATE TABLE deposit_requests (
    id SERIAL PRIMARY KEY,
    username TEXT REFERENCES users(username) ON DELETE CASCADE,
    amount DECIMAL(10, 2) NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 11. Deposit amounts table (fixed amounts that admin configures)
CREATE TABLE deposit_amounts (
    id SERIAL PRIMARY KEY,
    amount DECIMAL(10, 2) NOT NULL UNIQUE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Default deposit amounts (admin can change these from the panel)
INSERT INTO deposit_amounts (amount) VALUES (5), (10), (15), (20), (25), (30)
ON CONFLICT (amount) DO NOTHING;


-- =====================================================
-- STEP 3: ENABLE ROW LEVEL SECURITY (RLS) ON ALL TABLES
-- =====================================================

ALTER TABLE settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_pool ENABLE ROW LEVEL SECURITY;
ALTER TABLE banned_ips ENABLE ROW LEVEL SECURITY;
ALTER TABLE announcements ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_2fa_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE deposit_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE deposit_amounts ENABLE ROW LEVEL SECURITY;


-- =====================================================
-- STEP 4: CREATE RLS POLICIES
-- Authentication is handled by the Flask backend (not Supabase Auth).
-- The backend uses the anon key, so we allow all operations.
-- This is safe because Supabase URL/Key are never exposed to the client.
-- =====================================================

CREATE POLICY "settings_allow_all" ON settings FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "users_allow_all" ON users FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "products_allow_all" ON products FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "key_history_allow_all" ON key_history FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "transactions_allow_all" ON transactions FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "key_pool_allow_all" ON key_pool FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "banned_ips_allow_all" ON banned_ips FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "announcements_allow_all" ON announcements FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "admin_2fa_allow_all" ON admin_2fa_requests FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "deposit_requests_allow_all" ON deposit_requests FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "deposit_amounts_allow_all" ON deposit_amounts FOR ALL USING (true) WITH CHECK (true);


-- =====================================================
-- STEP 5: CREATE INDEXES FOR PERFORMANCE
-- =====================================================

CREATE INDEX IF NOT EXISTS idx_key_history_username ON key_history(username);
CREATE INDEX IF NOT EXISTS idx_key_history_created ON key_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_username ON transactions(username);
CREATE INDEX IF NOT EXISTS idx_transactions_created ON transactions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_key_pool_product ON key_pool(product_id, days);
CREATE INDEX IF NOT EXISTS idx_deposit_requests_username ON deposit_requests(username);
CREATE INDEX IF NOT EXISTS idx_deposit_requests_created ON deposit_requests(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_banned_ips_address ON banned_ips(ip_address);
CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key);


-- =====================================================
-- DONE! All 11 tables created with RLS policies and indexes.
-- Now create your .env file and upload the project files.
-- =====================================================
