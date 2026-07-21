-- HeartSync production schema

CREATE TABLE IF NOT EXISTS users (
    id                    SERIAL PRIMARY KEY,
    email                 TEXT UNIQUE NOT NULL,
    password_hash         TEXT NOT NULL,
    name                  TEXT NOT NULL,
    dob                   DATE,
    gender                TEXT DEFAULT '',
    interested_in         TEXT DEFAULT 'Everyone',
    goals                 TEXT DEFAULT 'Long-term partnership',
    bio                   TEXT DEFAULT '',
    location              TEXT DEFAULT '',
    hobbies               JSONB DEFAULT '[]',
    photos                JSONB DEFAULT '[]',
    verified              BOOLEAN DEFAULT FALSE,
    is_premium            BOOLEAN DEFAULT FALSE,
    premium_tier          TEXT DEFAULT '',
    onboarding_complete   BOOLEAN DEFAULT FALSE,
    notif_email_matches   BOOLEAN DEFAULT TRUE,
    notif_push_messages   BOOLEAN DEFAULT TRUE,
    incognito             BOOLEAN DEFAULT FALSE,
    stripe_customer_id    TEXT DEFAULT '',
    is_admin              BOOLEAN DEFAULT FALSE,
    banned                BOOLEAN DEFAULT FALSE,
    created_at            TIMESTAMPTZ DEFAULT NOW()
);

-- Safe to re-run: adds the columns above to a pre-existing users table too.
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS swipes (
    id          SERIAL PRIMARY KEY,
    swiper_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    swiped_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action      TEXT NOT NULL CHECK (action IN ('like','pass','superlike')),
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(swiper_id, swiped_id)
);

CREATE TABLE IF NOT EXISTS matches (
    id          SERIAL PRIMARY KEY,
    user1_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user2_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user1_id, user2_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id          SERIAL PRIMARY KEY,
    match_id    INTEGER NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    sender_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    text        TEXT NOT NULL,
    read        BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_swipes_swiper ON swipes(swiper_id);
CREATE INDEX IF NOT EXISTS idx_swipes_swiped ON swipes(swiped_id);
CREATE INDEX IF NOT EXISTS idx_matches_user1 ON matches(user1_id);
CREATE INDEX IF NOT EXISTS idx_matches_user2 ON matches(user2_id);
CREATE INDEX IF NOT EXISTS idx_messages_match ON messages(match_id);

-- Site-wide content the admin can override (homepage photos, hero copy, etc).
-- Single-row table: id is always 1.
CREATE TABLE IF NOT EXISTS site_settings (
    id                  INTEGER PRIMARY KEY DEFAULT 1,
    hero_title          TEXT,
    hero_subtitle       TEXT,
    hero_image_1        TEXT,
    hero_image_2        TEXT,
    hero_image_3        TEXT,
    hero_image_4        TEXT,
    hero_image_5        TEXT,
    hero_image_6        TEXT,
    hero_image_7        TEXT,
    hero_image_8        TEXT,
    hero_image_9        TEXT,
    hero_image_10       TEXT,
    hero_image_accent   TEXT,
    gallery_image_1     TEXT,
    gallery_image_2     TEXT,
    gallery_image_3     TEXT,
    safety_image        TEXT,
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT single_row CHECK (id = 1)
);
-- Safe to re-run: adds the carousel columns to any pre-existing site_settings table.
ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS hero_image_3 TEXT;
ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS hero_image_4 TEXT;
ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS hero_image_5 TEXT;
ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS hero_image_6 TEXT;
ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS hero_image_7 TEXT;
ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS hero_image_8 TEXT;
ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS hero_image_9 TEXT;
ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS hero_image_10 TEXT;
ALTER TABLE site_settings ADD COLUMN IF NOT EXISTS hero_image_accent TEXT;
INSERT INTO site_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- =====================================================================
-- ADMINS (completely separate identity from `users` — the dating-app
-- members table above. Admins log in with a username + password only,
-- on a separate /admin path, and never touch the members' email system.)
-- =====================================================================
CREATE TABLE IF NOT EXISTS admins (
    id             SERIAL PRIMARY KEY,
    username       TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- =====================================================================
-- PAYMENTS
-- =====================================================================

-- Paystack Popup payment attempts, so we can verify/poll and reconcile them.
CREATE TABLE IF NOT EXISTS paystack_transactions (
    id           SERIAL PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reference    TEXT UNIQUE NOT NULL,
    tier         TEXT NOT NULL,
    amount       INTEGER NOT NULL,
    currency     TEXT DEFAULT 'NGN',
    ussd_type    TEXT,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending | success | failed
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_paystack_tx_user ON paystack_transactions(user_id);

-- Gift card redemptions. The user only ever submits the gift card's ID/code;
-- an admin manually verifies it out-of-band and approves or rejects it here.
CREATE TABLE IF NOT EXISTS giftcard_redemptions (
    id            SERIAL PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code          TEXT NOT NULL,
    tier          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
    admin_note    TEXT DEFAULT '',
    reviewed_by   INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    reviewed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_giftcard_user ON giftcard_redemptions(user_id);
CREATE INDEX IF NOT EXISTS idx_giftcard_status ON giftcard_redemptions(status);
