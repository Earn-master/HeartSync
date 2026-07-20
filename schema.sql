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
    created_at            TIMESTAMPTZ DEFAULT NOW()
);

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
