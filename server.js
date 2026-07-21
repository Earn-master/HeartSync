require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const { pool, runMigrations } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('FATAL: JWT_SECRET is not set. Set it in your Railway environment variables (any long random string).');
    process.exit(1);
}

const PORT = process.env.PORT || 3000;
const MAX_PHOTOS = 6;

// The admin dashboard is a fully separate system from regular user accounts —
// admins are their own table, log in with a username + password only (never
// an email), and are managed at ADMIN_JWT_SECRET / /api/admin-auth/*. See below.
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || (JWT_SECRET + ':admin');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json({ limit: '20mb' })); // photos / site images are sent as base64 data URLs

// ---------- Stripe (optional - only activates if STRIPE_SECRET_KEY is set) ----------
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
    stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
}

// ---------- Paystack (optional - only activates if PAYSTACK_SECRET_KEY is set) ----------
// Used specifically for USSD payments (Nigeria). Node 18+ has global fetch built in.
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || null;
const PAYSTACK_CURRENCY = process.env.PAYSTACK_CURRENCY || 'NGN';
const PAYSTACK_AMOUNTS = {
    plus: process.env.PAYSTACK_AMOUNT_PLUS ? parseInt(process.env.PAYSTACK_AMOUNT_PLUS, 10) : null,
    gold: process.env.PAYSTACK_AMOUNT_GOLD ? parseInt(process.env.PAYSTACK_AMOUNT_GOLD, 10) : null,
    platinum: process.env.PAYSTACK_AMOUNT_PLATINUM ? parseInt(process.env.PAYSTACK_AMOUNT_PLATINUM, 10) : null
};
const PAYSTACK_USSD_BANKS = { '737': 'GTBank', '919': 'UBA', '822': 'Sterling Bank', '966': 'Polaris Bank' };

async function paystackRequest(endpoint, method, body) {
    const res = await fetch(`https://api.paystack.co${endpoint}`, {
        method,
        headers: {
            'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
            'Content-Type': 'application/json'
        },
        body: body ? JSON.stringify(body) : undefined
    });
    const data = await res.json();
    return { ok: res.ok, data };
}

// ---------- Helpers ----------
function signToken(user) {
    return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

function calcAge(dob) {
    if (!dob) return null;
    const d = new Date(dob);
    const diff = Date.now() - d.getTime();
    return Math.floor(diff / (1000 * 60 * 60 * 24 * 365.25));
}

function publicProfile(row) {
    return {
        id: row.id,
        name: row.name,
        age: calcAge(row.dob),
        bio: row.bio,
        location: row.location,
        goals: row.goals,
        hobbies: row.hobbies || [],
        photos: row.photos || [],
        avatar: (row.photos && row.photos[0]) || null,
        verified: row.verified
    };
}

function meProfile(row) {
    return {
        id: row.id,
        email: row.email,
        name: row.name,
        dob: row.dob,
        gender: row.gender,
        interestedIn: row.interested_in,
        goals: row.goals,
        bio: row.bio,
        location: row.location,
        hobbies: row.hobbies || [],
        photos: row.photos || [],
        avatar: (row.photos && row.photos[0]) || null,
        verified: row.verified,
        isPremium: row.is_premium,
        premiumTier: row.premium_tier,
        onboardingComplete: row.onboarding_complete,
        notifEmailMatches: row.notif_email_matches,
        notifPushMessages: row.notif_push_messages,
        incognito: row.incognito,
        age: calcAge(row.dob)
    };
}

async function authRequired(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Not authenticated.' });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [payload.id]);
        if (!result.rows[0]) return res.status(401).json({ error: 'Account no longer exists.' });
        if (result.rows[0].banned) return res.status(403).json({ error: 'This account has been suspended.' });
        req.user = result.rows[0];
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired session.' });
    }
}

// Matches + messaging are a Premium-only feature — free members can still swipe
// and build up matches on the backend, but viewing/opening them requires a plan.
function premiumRequired(req, res, next) {
    if (!req.user.is_premium) {
        return res.status(402).json({ error: 'Upgrade to Premium to view your matches and chat.', requiresUpgrade: true });
    }
    next();
}

async function getOrCreateMatchId(userAId, userBId) {
    const [u1, u2] = userAId < userBId ? [userAId, userBId] : [userBId, userAId];
    const existing = await pool.query('SELECT id FROM matches WHERE user1_id=$1 AND user2_id=$2', [u1, u2]);
    if (existing.rows[0]) return existing.rows[0].id;
    return null;
}

// =====================================================================
// AUTH
// =====================================================================
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        if (!email || !password || !name) {
            return res.status(400).json({ error: 'Name, email and password are required.' });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters.' });
        }
        const normalizedEmail = String(email).trim().toLowerCase();
        const existing = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
        if (existing.rows[0]) {
            return res.status(409).json({ error: 'An account with that email already exists.' });
        }
        const hash = await bcrypt.hash(password, 12);
        const result = await pool.query(
            `INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING *`,
            [normalizedEmail, hash, name.trim()]
        );
        const user = result.rows[0];
        res.status(201).json({ token: signToken(user), user: meProfile(user) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Signup failed. Please try again.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
        const normalizedEmail = String(email).trim().toLowerCase();
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
        let user = result.rows[0];
        if (!user) return res.status(401).json({ error: 'Incorrect email or password.' });
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ error: 'Incorrect email or password.' });
        if (user.banned) return res.status(403).json({ error: 'This account has been suspended. Contact support if you think this is a mistake.' });
        res.json({ token: signToken(user), user: meProfile(user) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Login failed. Please try again.' });
    }
});

app.get('/api/me', authRequired, (req, res) => {
    res.json({ user: meProfile(req.user) });
});

app.put('/api/me', authRequired, async (req, res) => {
    try {
        const allowed = ['name', 'dob', 'gender', 'interestedIn', 'goals', 'bio', 'location', 'hobbies',
            'notifEmailMatches', 'notifPushMessages', 'incognito'];
        const colMap = {
            name: 'name', dob: 'dob', gender: 'gender', interestedIn: 'interested_in', goals: 'goals',
            bio: 'bio', location: 'location', hobbies: 'hobbies',
            notifEmailMatches: 'notif_email_matches', notifPushMessages: 'notif_push_messages', incognito: 'incognito'
        };
        const sets = [];
        const values = [];
        let i = 1;
        for (const key of allowed) {
            if (Object.prototype.hasOwnProperty.call(req.body, key)) {
                let val = req.body[key];
                if (key === 'hobbies') val = JSON.stringify(val || []);
                sets.push(`${colMap[key]} = $${i}`);
                values.push(val);
                i++;
            }
        }
        // Mark onboarding complete once core fields exist
        if (req.body.completeOnboarding) {
            sets.push(`onboarding_complete = TRUE`);
        }
        if (sets.length === 0) return res.json({ user: meProfile(req.user) });
        values.push(req.user.id);
        const result = await pool.query(
            `UPDATE users SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`,
            values
        );
        res.json({ user: meProfile(result.rows[0]) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not update profile.' });
    }
});

app.post('/api/me/photos', authRequired, async (req, res) => {
    try {
        const { photoDataUrl } = req.body;
        if (!photoDataUrl || !photoDataUrl.startsWith('data:image/')) {
            return res.status(400).json({ error: 'A valid image is required.' });
        }
        const photos = req.user.photos || [];
        if (photos.length >= MAX_PHOTOS) {
            return res.status(400).json({ error: `You can upload up to ${MAX_PHOTOS} photos.` });
        }
        photos.push(photoDataUrl);
        const result = await pool.query('UPDATE users SET photos = $1 WHERE id = $2 RETURNING *', [JSON.stringify(photos), req.user.id]);
        res.json({ user: meProfile(result.rows[0]) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not upload photo.' });
    }
});

app.delete('/api/me/photos/:index', authRequired, async (req, res) => {
    try {
        const idx = parseInt(req.params.index, 10);
        const photos = (req.user.photos || []).filter((_, i) => i !== idx);
        const result = await pool.query('UPDATE users SET photos = $1 WHERE id = $2 RETURNING *', [JSON.stringify(photos), req.user.id]);
        res.json({ user: meProfile(result.rows[0]) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not remove photo.' });
    }
});

app.delete('/api/me', authRequired, async (req, res) => {
    try {
        await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not delete account.' });
    }
});

// =====================================================================
// DISCOVERY + SWIPING
// =====================================================================
app.get('/api/discover', authRequired, async (req, res) => {
    try {
        const me = req.user;
        const params = [me.id];
        let genderFilter = '';
        if (me.interested_in && me.interested_in !== 'Everyone') {
            const wanted = me.interested_in === 'Men' ? 'Man' : me.interested_in === 'Women' ? 'Woman' : null;
            if (wanted) {
                params.push(wanted);
                genderFilter = ` AND u.gender = $${params.length}`;
            }
        }
        const result = await pool.query(
            `SELECT u.* FROM users u
             WHERE u.id != $1
               AND u.onboarding_complete = TRUE
               AND u.incognito = FALSE
               AND NOT EXISTS (SELECT 1 FROM swipes s WHERE s.swiper_id = $1 AND s.swiped_id = u.id)
               ${genderFilter}
             ORDER BY u.created_at DESC
             LIMIT 30`,
            params
        );
        res.json({ profiles: result.rows.map(publicProfile) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load profiles.' });
    }
});

app.post('/api/swipe', authRequired, async (req, res) => {
    try {
        const { targetId, action } = req.body;
        if (!targetId || !['like', 'pass', 'superlike'].includes(action)) {
            return res.status(400).json({ error: 'A target profile and valid action are required.' });
        }
        if (Number(targetId) === req.user.id) return res.status(400).json({ error: 'You cannot swipe on yourself.' });

        const targetResult = await pool.query('SELECT * FROM users WHERE id = $1', [targetId]);
        const target = targetResult.rows[0];
        if (!target) return res.status(404).json({ error: 'Profile not found.' });

        await pool.query(
            `INSERT INTO swipes (swiper_id, swiped_id, action) VALUES ($1, $2, $3)
             ON CONFLICT (swiper_id, swiped_id) DO UPDATE SET action = EXCLUDED.action`,
            [req.user.id, targetId, action]
        );

        let matched = false;
        let matchId = null;

        if (action === 'like' || action === 'superlike') {
            const reciprocal = await pool.query(
                `SELECT id FROM swipes WHERE swiper_id = $1 AND swiped_id = $2 AND action IN ('like','superlike')`,
                [targetId, req.user.id]
            );
            if (reciprocal.rows[0]) {
                const [u1, u2] = req.user.id < target.id ? [req.user.id, target.id] : [target.id, req.user.id];
                const matchInsert = await pool.query(
                    `INSERT INTO matches (user1_id, user2_id) VALUES ($1, $2)
                     ON CONFLICT (user1_id, user2_id) DO UPDATE SET user1_id = EXCLUDED.user1_id
                     RETURNING id`,
                    [u1, u2]
                );
                matched = true;
                matchId = matchInsert.rows[0].id;

                // Notify the other user in real time if they're connected
                io.to(`user_${target.id}`).emit('new_match', {
                    matchId,
                    profile: publicProfile(req.user)
                });
            }
        }

        res.json({ matched, matchId, matchedProfile: matched ? publicProfile(target) : null });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not process swipe.' });
    }
});

// =====================================================================
// MATCHES + MESSAGING
// =====================================================================
app.get('/api/matches', authRequired, premiumRequired, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT m.id AS match_id, m.created_at AS matched_at,
                    u.id, u.name, u.dob, u.photos, u.verified,
                    (SELECT text FROM messages WHERE match_id = m.id ORDER BY created_at DESC LIMIT 1) AS last_msg,
                    (SELECT created_at FROM messages WHERE match_id = m.id ORDER BY created_at DESC LIMIT 1) AS last_msg_at,
                    (SELECT COUNT(*) FROM messages WHERE match_id = m.id AND sender_id != $1 AND read = FALSE) AS unread_count
             FROM matches m
             JOIN users u ON u.id = (CASE WHEN m.user1_id = $1 THEN m.user2_id ELSE m.user1_id END)
             WHERE m.user1_id = $1 OR m.user2_id = $1
             ORDER BY COALESCE((SELECT created_at FROM messages WHERE match_id = m.id ORDER BY created_at DESC LIMIT 1), m.created_at) DESC`,
            [req.user.id]
        );
        const matches = result.rows.map(r => ({
            matchId: r.match_id,
            id: r.id,
            name: r.name,
            age: calcAge(r.dob),
            avatar: (r.photos && r.photos[0]) || null,
            verified: r.verified,
            lastMsg: r.last_msg || 'You matched! Say hello 👋',
            time: r.last_msg_at || r.matched_at,
            unread: Number(r.unread_count) > 0
        }));
        res.json({ matches });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load matches.' });
    }
});

async function assertMatchMembership(matchId, userId) {
    const result = await pool.query('SELECT * FROM matches WHERE id = $1 AND (user1_id = $2 OR user2_id = $2)', [matchId, userId]);
    return result.rows[0] || null;
}

app.get('/api/messages/:matchId', authRequired, premiumRequired, async (req, res) => {
    try {
        const match = await assertMatchMembership(req.params.matchId, req.user.id);
        if (!match) return res.status(403).json({ error: 'Not part of this match.' });

        const messages = await pool.query(
            'SELECT * FROM messages WHERE match_id = $1 ORDER BY created_at ASC',
            [req.params.matchId]
        );
        await pool.query(
            'UPDATE messages SET read = TRUE WHERE match_id = $1 AND sender_id != $2',
            [req.params.matchId, req.user.id]
        );
        res.json({
            messages: messages.rows.map(m => ({
                id: m.id,
                sender: m.sender_id === req.user.id ? 'me' : 'them',
                text: m.text,
                time: m.created_at
            }))
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load messages.' });
    }
});

app.post('/api/messages/:matchId', authRequired, premiumRequired, async (req, res) => {
    try {
        const match = await assertMatchMembership(req.params.matchId, req.user.id);
        if (!match) return res.status(403).json({ error: 'Not part of this match.' });
        const text = (req.body.text || '').trim();
        if (!text) return res.status(400).json({ error: 'Message cannot be empty.' });

        const result = await pool.query(
            'INSERT INTO messages (match_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *',
            [req.params.matchId, req.user.id, text]
        );
        const msg = result.rows[0];
        const otherUserId = match.user1_id === req.user.id ? match.user2_id : match.user1_id;

        const payload = { matchId: Number(req.params.matchId), id: msg.id, sender: 'them', text: msg.text, time: msg.created_at, senderId: req.user.id };
        io.to(`match_${req.params.matchId}`).emit('new_message', payload);
        io.to(`user_${otherUserId}`).emit('inbox_update', { matchId: Number(req.params.matchId) });

        res.status(201).json({ message: { id: msg.id, sender: 'me', text: msg.text, time: msg.created_at } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not send message.' });
    }
});

app.get('/api/stats', authRequired, async (req, res) => {
    try {
        const [matches, likes] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS c FROM matches WHERE user1_id = $1 OR user2_id = $1', [req.user.id]),
            pool.query(`SELECT COUNT(*)::int AS c FROM swipes WHERE swiped_id = $1 AND action IN ('like','superlike')`, [req.user.id])
        ]);
        const fields = ['name', 'dob', 'gender', 'bio', 'location'];
        let filled = 0;
        fields.forEach(f => { if (req.user[f]) filled++; });
        if ((req.user.photos || []).length > 0) filled++;
        if ((req.user.hobbies || []).length > 0) filled++;
        const completion = Math.round((filled / (fields.length + 2)) * 100);
        res.json({ totalMatches: matches.rows[0].c, likesReceived: likes.rows[0].c, profileCompletion: completion });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load stats.' });
    }
});

// =====================================================================
// LIVE SITE-WIDE STATS (real numbers, shown on the landing page)
// =====================================================================
app.get('/api/public/stats', async (req, res) => {
    try {
        const [users, matches, verified] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS c FROM users'),
            pool.query('SELECT COUNT(*)::int AS c FROM matches'),
            pool.query('SELECT COUNT(*)::int AS c FROM users WHERE verified = TRUE')
        ]);
        const totalUsers = users.rows[0].c;
        const verifiedPct = totalUsers > 0 ? Math.round((verified.rows[0].c / totalUsers) * 100) : 0;
        res.json({
            matches: matches.rows[0].c,
            members: totalUsers,
            verifiedPercent: verifiedPct
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load stats.' });
    }
});

// =====================================================================
// PUBLIC SITE SETTINGS (homepage images/copy the admin has customized)
// =====================================================================
app.get('/api/site-settings', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM site_settings WHERE id = 1');
        const row = result.rows[0] || {};
        res.json({
            heroTitle: row.hero_title || null,
            heroSubtitle: row.hero_subtitle || null,
            heroImage1: row.hero_image_1 || null,
            heroImage2: row.hero_image_2 || null,
            heroImage3: row.hero_image_3 || null,
            heroImage4: row.hero_image_4 || null,
            heroImage5: row.hero_image_5 || null,
            heroImage6: row.hero_image_6 || null,
            heroImage7: row.hero_image_7 || null,
            heroImage8: row.hero_image_8 || null,
            heroImage9: row.hero_image_9 || null,
            heroImage10: row.hero_image_10 || null,
            heroImageAccent: row.hero_image_accent || null,
            galleryImage1: row.gallery_image_1 || null,
            galleryImage2: row.gallery_image_2 || null,
            galleryImage3: row.gallery_image_3 || null,
            safetyImage: row.safety_image || null
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load site settings.' });
    }
});

// =====================================================================
// PREMIUM CHECKOUT (real Stripe integration, opt-in via env vars)
// =====================================================================
app.post('/api/premium/checkout', authRequired, async (req, res) => {
    if (!stripe) {
        return res.status(501).json({
            error: 'Payments are not configured on this deployment yet. Set STRIPE_SECRET_KEY, STRIPE_PRICE_PLUS, STRIPE_PRICE_GOLD and STRIPE_PRICE_PLATINUM in your environment to enable real checkout.'
        });
    }
    try {
        const { tier } = req.body; // 'plus' | 'gold' | 'platinum'
        const priceIds = { plus: process.env.STRIPE_PRICE_PLUS, gold: process.env.STRIPE_PRICE_GOLD, platinum: process.env.STRIPE_PRICE_PLATINUM };
        if (!['plus', 'gold', 'platinum'].includes(tier)) return res.status(400).json({ error: 'Choose a valid plan.' });
        const priceId = priceIds[tier];
        if (!priceId) return res.status(400).json({ error: 'That plan is not configured.' });

        const session = await stripe.checkout.sessions.create({
            mode: 'subscription',
            customer_email: req.user.email,
            line_items: [{ price: priceId, quantity: 1 }],
            success_url: `${req.headers.origin}/?upgrade=success`,
            cancel_url: `${req.headers.origin}/?upgrade=cancelled`,
            metadata: { userId: String(req.user.id), tier }
        });
        res.json({ url: session.url });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not start checkout.' });
    }
});

// Stripe webhook to actually flip the is_premium flag once payment succeeds.
// Requires raw body, so it's mounted before the JSON body applies to this path.
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.status(404).end();
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const userId = session.metadata && session.metadata.userId;
        const tier = (session.metadata && session.metadata.tier) || 'gold';
        if (userId) {
            await pool.query('UPDATE users SET is_premium = TRUE, premium_tier = $1, stripe_customer_id = $2 WHERE id = $3', [tier, session.customer, userId]);
        }
    }
    res.json({ received: true });
});

// =====================================================================
// PAYSTACK USSD CHECKOUT (Nigeria) — opt-in via PAYSTACK_SECRET_KEY
// =====================================================================
app.get('/api/premium/paystack/banks', (req, res) => {
    res.json({
        enabled: !!(PAYSTACK_SECRET_KEY && PAYSTACK_AMOUNTS.plus && PAYSTACK_AMOUNTS.gold && PAYSTACK_AMOUNTS.platinum),
        currency: PAYSTACK_CURRENCY,
        banks: Object.entries(PAYSTACK_USSD_BANKS).map(([code, name]) => ({ code, name }))
    });
});

app.post('/api/premium/paystack/ussd/initiate', authRequired, async (req, res) => {
    if (!PAYSTACK_SECRET_KEY) {
        return res.status(501).json({ error: 'USSD payments are not configured on this deployment yet. Set PAYSTACK_SECRET_KEY, PAYSTACK_AMOUNT_GOLD and PAYSTACK_AMOUNT_PLATINUM in your environment to enable it.' });
    }
    try {
        const { tier, bankCode } = req.body; // 'plus' | 'gold' | 'platinum', '737' | '919' | '822' | '966'
        if (!['plus', 'gold', 'platinum'].includes(tier)) return res.status(400).json({ error: 'Choose a valid plan.' });
        if (!PAYSTACK_USSD_BANKS[bankCode]) return res.status(400).json({ error: 'Choose a valid bank for USSD payment.' });
        const amount = PAYSTACK_AMOUNTS[tier];
        if (!amount) return res.status(400).json({ error: 'That plan is not configured for USSD payment.' });

        const reference = `hsync_${req.user.id}_${Date.now()}`;
        const { ok, data } = await paystackRequest('/transaction/charge', 'POST', {
            reference,
            amount,
            email: req.user.email,
            currency: PAYSTACK_CURRENCY,
            ussd: { type: bankCode },
            metadata: { userId: String(req.user.id), tier }
        });
        if (!ok || !data.status) {
            return res.status(400).json({ error: (data && data.message) || 'Could not start the USSD charge.' });
        }

        await pool.query(
            `INSERT INTO paystack_transactions (user_id, reference, tier, amount, currency, ussd_type, status)
             VALUES ($1, $2, $3, $4, $5, $6, 'pending')`,
            [req.user.id, reference, tier, amount, PAYSTACK_CURRENCY, bankCode]
        );

        res.json({
            reference,
            ussdCode: data.data.ussd_code || null,
            displayText: data.data.display_text || `Dial the USSD code shown to complete your ${PAYSTACK_USSD_BANKS[bankCode]} payment.`,
            status: data.data.status || 'pay_offline'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not start USSD checkout.' });
    }
});

// The frontend polls this after showing the USSD code, so the user sees
// their Premium unlock the moment they finish paying on their phone.
app.get('/api/premium/paystack/verify/:reference', authRequired, async (req, res) => {
    if (!PAYSTACK_SECRET_KEY) return res.status(501).json({ error: 'USSD payments are not configured on this deployment.' });
    try {
        const txResult = await pool.query('SELECT * FROM paystack_transactions WHERE reference = $1 AND user_id = $2', [req.params.reference, req.user.id]);
        const tx = txResult.rows[0];
        if (!tx) return res.status(404).json({ error: 'Transaction not found.' });

        if (tx.status === 'success') return res.json({ status: 'success' });

        const { ok, data } = await paystackRequest(`/transaction/verify/${encodeURIComponent(req.params.reference)}`, 'GET');
        if (!ok || !data.status) return res.json({ status: 'pending' });

        const paystackStatus = data.data && data.data.status;
        if (paystackStatus === 'success') {
            await pool.query('UPDATE users SET is_premium = TRUE, premium_tier = $1 WHERE id = $2', [tx.tier, req.user.id]);
            await pool.query(`UPDATE paystack_transactions SET status = 'success', updated_at = NOW() WHERE reference = $1`, [tx.reference]);
            return res.json({ status: 'success' });
        }
        if (paystackStatus === 'failed' || paystackStatus === 'abandoned') {
            await pool.query(`UPDATE paystack_transactions SET status = 'failed', updated_at = NOW() WHERE reference = $1`, [tx.reference]);
            return res.json({ status: 'failed' });
        }
        res.json({ status: 'pending' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not verify payment.' });
    }
});

// Paystack webhook — the reliable way this gets confirmed even if the user
// never returns to the tab to trigger the /verify poll above.
app.post('/api/webhooks/paystack', express.raw({ type: 'application/json' }), async (req, res) => {
    if (!PAYSTACK_SECRET_KEY) return res.status(404).end();
    try {
        const crypto = require('crypto');
        const signature = req.headers['x-paystack-signature'];
        const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(req.body).digest('hex');
        if (hash !== signature) return res.status(401).end();

        const event = JSON.parse(req.body.toString('utf8'));
        if (event.event === 'charge.success') {
            const reference = event.data.reference;
            const metadata = event.data.metadata || {};
            const txResult = await pool.query('SELECT * FROM paystack_transactions WHERE reference = $1', [reference]);
            const tx = txResult.rows[0];
            const userId = (tx && tx.user_id) || (metadata && metadata.userId);
            const tier = (tx && tx.tier) || (metadata && metadata.tier) || 'gold';
            if (userId) {
                await pool.query('UPDATE users SET is_premium = TRUE, premium_tier = $1 WHERE id = $2', [tier, userId]);
                await pool.query(`UPDATE paystack_transactions SET status = 'success', updated_at = NOW() WHERE reference = $1`, [reference]);
            }
        }
        res.json({ received: true });
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: 'Invalid webhook.' });
    }
});

// =====================================================================
// PAYPAL — coming soon. Endpoint exists so the frontend has something real
// to call, but it always reports that PayPal checkout isn't live yet.
// =====================================================================
app.post('/api/premium/paypal/checkout', authRequired, (req, res) => {
    res.status(501).json({ error: 'PayPal is coming soon and is not available yet. Please use Card, USSD, or Gift Card for now.', comingSoon: true });
});

// =====================================================================
// GIFT CARD REDEMPTION — the user only ever submits the gift card's ID/code.
// Nothing is auto-verified; an admin manually checks it and approves or
// rejects it from the separate admin dashboard.
// =====================================================================
app.post('/api/premium/giftcard/redeem', authRequired, async (req, res) => {
    try {
        const { tier, code } = req.body;
        if (!['plus', 'gold', 'platinum'].includes(tier)) return res.status(400).json({ error: 'Choose a valid plan.' });
        if (!trimmedCode) return res.status(400).json({ error: 'Enter your gift card ID/code.' });
        if (trimmedCode.length > 100) return res.status(400).json({ error: 'That code looks too long to be valid.' });

        const result = await pool.query(
            `INSERT INTO giftcard_redemptions (user_id, code, tier, status) VALUES ($1, $2, $3, 'pending') RETURNING *`,
            [req.user.id, trimmedCode, tier]
        );
        res.status(201).json({
            redemption: {
                id: result.rows[0].id,
                code: result.rows[0].code,
                tier: result.rows[0].tier,
                status: result.rows[0].status,
                createdAt: result.rows[0].created_at
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not submit gift card.' });
    }
});

// Lets the user see the status of gift cards they've submitted.
app.get('/api/premium/giftcard/mine', authRequired, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, code, tier, status, admin_note, created_at, reviewed_at FROM giftcard_redemptions
             WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20`,
            [req.user.id]
        );
        res.json({
            redemptions: result.rows.map(r => ({
                id: r.id, code: r.code, tier: r.tier, status: r.status,
                adminNote: r.admin_note, createdAt: r.created_at, reviewedAt: r.reviewed_at
            }))
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load gift card submissions.' });
    }
});

// =====================================================================
// ADMIN DASHBOARD — completely separate auth system from regular users.
// Admins live in their own `admins` table and log in at /admin with just
// a username + password (no email, no shared login with the dating app).
// =====================================================================
function signAdminToken(admin) {
    return jwt.sign({ adminId: admin.id, username: admin.username, scope: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: '12h' });
}

async function adminTokenRequired(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Admin authentication required.' });
    try {
        const payload = jwt.verify(token, ADMIN_JWT_SECRET);
        if (payload.scope !== 'admin') return res.status(401).json({ error: 'Invalid admin session.' });
        const result = await pool.query('SELECT * FROM admins WHERE id = $1', [payload.adminId]);
        if (!result.rows[0]) return res.status(401).json({ error: 'Admin account no longer exists.' });
        req.admin = result.rows[0];
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired admin session.' });
    }
}

// One-time bootstrap: if no admins exist yet and ADMIN_USERNAME/ADMIN_PASSWORD
// are set in the environment, create the first admin account automatically.
async function bootstrapFirstAdmin() {
    try {
        const { rows } = await pool.query('SELECT COUNT(*)::int AS c FROM admins');
        if (rows[0].c > 0) return;
        const username = (process.env.ADMIN_USERNAME || '').trim();
        const password = process.env.ADMIN_PASSWORD || '';
        if (!username || !password) {
            console.warn('No admin account exists yet. Set ADMIN_USERNAME and ADMIN_PASSWORD in your environment to create the first one automatically, or insert one directly into the admins table.');
            return;
        }
        const hash = await bcrypt.hash(password, 12);
        await pool.query('INSERT INTO admins (username, password_hash) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING', [username.toLowerCase(), hash]);
        console.log(`Bootstrapped first admin account: ${username.toLowerCase()}`);
    } catch (err) {
        console.error('Could not bootstrap first admin account:', err);
    }
}

app.post('/api/admin-auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
        const normalized = String(username).trim().toLowerCase();
        const result = await pool.query('SELECT * FROM admins WHERE username = $1', [normalized]);
        const admin = result.rows[0];
        if (!admin) return res.status(401).json({ error: 'Incorrect username or password.' });
        const valid = await bcrypt.compare(password, admin.password_hash);
        if (!valid) return res.status(401).json({ error: 'Incorrect username or password.' });
        res.json({ token: signAdminToken(admin), admin: { id: admin.id, username: admin.username } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Admin login failed. Please try again.' });
    }
});

app.get('/api/admin-auth/me', adminTokenRequired, (req, res) => {
    res.json({ admin: { id: req.admin.id, username: req.admin.username } });
});

// Change the current admin's own password.
app.put('/api/admin-auth/password', adminTokenRequired, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required.' });
        if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
        const valid = await bcrypt.compare(currentPassword, req.admin.password_hash);
        if (!valid) return res.status(401).json({ error: 'Current password is incorrect.' });
        const hash = await bcrypt.hash(newPassword, 12);
        await pool.query('UPDATE admins SET password_hash = $1 WHERE id = $2', [hash, req.admin.id]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not change password.' });
    }
});

// List / create other admin accounts (any logged-in admin can add another).
app.get('/api/admin-auth/admins', adminTokenRequired, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, created_at FROM admins ORDER BY created_at ASC');
        res.json({ admins: result.rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load admins.' });
    }
});

app.post('/api/admin-auth/admins', adminTokenRequired, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
        if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
        const normalized = String(username).trim().toLowerCase();
        const existing = await pool.query('SELECT id FROM admins WHERE username = $1', [normalized]);
        if (existing.rows[0]) return res.status(409).json({ error: 'That username is already taken.' });
        const hash = await bcrypt.hash(password, 12);
        const result = await pool.query('INSERT INTO admins (username, password_hash) VALUES ($1, $2) RETURNING id, username, created_at', [normalized, hash]);
        res.status(201).json({ admin: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not create admin.' });
    }
});

app.delete('/api/admin-auth/admins/:id', adminTokenRequired, async (req, res) => {
    try {
        const targetId = Number(req.params.id);
        if (targetId === req.admin.id) return res.status(400).json({ error: "You can't delete your own admin account while logged in as it." });
        const result = await pool.query('DELETE FROM admins WHERE id = $1 RETURNING id', [targetId]);
        if (!result.rows[0]) return res.status(404).json({ error: 'Admin not found.' });
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not delete admin.' });
    }
});

const adminAuth = [adminTokenRequired];

function adminUserRow(row) {
    return {
        id: row.id,
        name: row.name,
        email: row.email,
        age: calcAge(row.dob),
        gender: row.gender,
        location: row.location,
        verified: row.verified,
        isPremium: row.is_premium,
        premiumTier: row.premium_tier,
        isAdmin: row.is_admin,
        banned: row.banned,
        onboardingComplete: row.onboarding_complete,
        photoCount: (row.photos || []).length,
        createdAt: row.created_at
    };
}

app.get('/api/admin/overview', adminAuth, async (req, res) => {
    try {
        const [users, verified, premium, admins, banned, matches, messages, newUsers, pendingGiftcards] = await Promise.all([
            pool.query('SELECT COUNT(*)::int AS c FROM users'),
            pool.query('SELECT COUNT(*)::int AS c FROM users WHERE verified = TRUE'),
            pool.query('SELECT COUNT(*)::int AS c FROM users WHERE is_premium = TRUE'),
            pool.query('SELECT COUNT(*)::int AS c FROM admins'),
            pool.query('SELECT COUNT(*)::int AS c FROM users WHERE banned = TRUE'),
            pool.query('SELECT COUNT(*)::int AS c FROM matches'),
            pool.query('SELECT COUNT(*)::int AS c FROM messages'),
            pool.query(`SELECT COUNT(*)::int AS c FROM users WHERE created_at > NOW() - INTERVAL '7 days'`),
            pool.query(`SELECT COUNT(*)::int AS c FROM giftcard_redemptions WHERE status = 'pending'`)
        ]);
        res.json({
            totalUsers: users.rows[0].c,
            verifiedUsers: verified.rows[0].c,
            premiumUsers: premium.rows[0].c,
            adminUsers: admins.rows[0].c,
            bannedUsers: banned.rows[0].c,
            totalMatches: matches.rows[0].c,
            totalMessages: messages.rows[0].c,
            newUsersLast7Days: newUsers.rows[0].c,
            pendingGiftcards: pendingGiftcards.rows[0].c
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load overview.' });
    }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const search = (req.query.search || '').trim();
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const pageSize = 25;
        const offset = (page - 1) * pageSize;

        let where = '';
        const params = [];
        if (search) {
            params.push(`%${search}%`);
            where = `WHERE name ILIKE $${params.length} OR email ILIKE $${params.length}`;
        }
        const countResult = await pool.query(`SELECT COUNT(*)::int AS c FROM users ${where}`, params);
        params.push(pageSize, offset);
        const result = await pool.query(
            `SELECT * FROM users ${where} ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
            params
        );
        res.json({
            users: result.rows.map(adminUserRow),
            total: countResult.rows[0].c,
            page,
            pageSize
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load users.' });
    }
});

app.put('/api/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const targetId = Number(req.params.id);
        const colMap = {
            verified: 'verified',
            isPremium: 'is_premium',
            premiumTier: 'premium_tier',
            isAdmin: 'is_admin',
            banned: 'banned',
            name: 'name',
            location: 'location'
        };
        const sets = [];
        const values = [];
        let i = 1;
        for (const key of Object.keys(colMap)) {
            if (Object.prototype.hasOwnProperty.call(req.body, key)) {
                sets.push(`${colMap[key]} = $${i}`);
                values.push(req.body[key]);
                i++;
            }
        }
        if (sets.length === 0) return res.status(400).json({ error: 'No valid fields to update.' });
        values.push(targetId);
        const result = await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $${i} RETURNING *`, values);
        if (!result.rows[0]) return res.status(404).json({ error: 'User not found.' });
        res.json({ user: adminUserRow(result.rows[0]) });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not update user.' });
    }
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const targetId = Number(req.params.id);
        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [targetId]);
        if (!result.rows[0]) return res.status(404).json({ error: 'User not found.' });
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not delete user.' });
    }
});

app.get('/api/admin/matches', adminAuth, async (req, res) => {
    try {
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const pageSize = 25;
        const offset = (page - 1) * pageSize;
        const countResult = await pool.query('SELECT COUNT(*)::int AS c FROM matches');
        const result = await pool.query(
            `SELECT m.id, m.created_at, u1.name AS user1_name, u1.email AS user1_email,
                    u2.name AS user2_name, u2.email AS user2_email,
                    (SELECT COUNT(*)::int FROM messages WHERE match_id = m.id) AS message_count
             FROM matches m
             JOIN users u1 ON u1.id = m.user1_id
             JOIN users u2 ON u2.id = m.user2_id
             ORDER BY m.created_at DESC LIMIT $1 OFFSET $2`,
            [pageSize, offset]
        );
        res.json({
            matches: result.rows.map(r => ({
                id: r.id,
                createdAt: r.created_at,
                user1: { name: r.user1_name, email: r.user1_email },
                user2: { name: r.user2_name, email: r.user2_email },
                messageCount: r.message_count
            })),
            total: countResult.rows[0].c,
            page,
            pageSize
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load matches.' });
    }
});

app.delete('/api/admin/matches/:id', adminAuth, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM matches WHERE id = $1 RETURNING id', [req.params.id]);
        if (!result.rows[0]) return res.status(404).json({ error: 'Match not found.' });
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not delete match.' });
    }
});

// ---- Gift card redemptions (manual verification queue) ----
app.get('/api/admin/giftcards', adminAuth, async (req, res) => {
    try {
        const status = ['pending', 'approved', 'rejected'].includes(req.query.status) ? req.query.status : null;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const pageSize = 25;
        const offset = (page - 1) * pageSize;
        const where = status ? 'WHERE g.status = $1' : '';
        const params = status ? [status] : [];
        const countResult = await pool.query(`SELECT COUNT(*)::int AS c FROM giftcard_redemptions g ${where}`, params);
        const limitParams = [...params, pageSize, offset];
        const result = await pool.query(
            `SELECT g.*, u.name AS user_name, u.email AS user_email
             FROM giftcard_redemptions g
             JOIN users u ON u.id = g.user_id
             ${where}
             ORDER BY g.created_at DESC
             LIMIT $${limitParams.length - 1} OFFSET $${limitParams.length}`,
            limitParams
        );
        res.json({
            redemptions: result.rows.map(r => ({
                id: r.id,
                code: r.code,
                tier: r.tier,
                status: r.status,
                adminNote: r.admin_note,
                user: { id: r.user_id, name: r.user_name, email: r.user_email },
                createdAt: r.created_at,
                reviewedAt: r.reviewed_at
            })),
            total: countResult.rows[0].c,
            page,
            pageSize
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load gift card submissions.' });
    }
});

app.put('/api/admin/giftcards/:id', adminAuth, async (req, res) => {
    try {
        const { status, note } = req.body; // 'approved' | 'rejected'
        if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ error: 'Status must be approved or rejected.' });
        const result = await pool.query('SELECT * FROM giftcard_redemptions WHERE id = $1', [req.params.id]);
        const redemption = result.rows[0];
        if (!redemption) return res.status(404).json({ error: 'Gift card submission not found.' });
        if (redemption.status !== 'pending') return res.status(400).json({ error: 'This submission has already been reviewed.' });

        await pool.query(
            `UPDATE giftcard_redemptions SET status = $1, admin_note = $2, reviewed_by = $3, reviewed_at = NOW() WHERE id = $4`,
            [status, note || '', req.admin.id, req.params.id]
        );
        if (status === 'approved') {
            await pool.query('UPDATE users SET is_premium = TRUE, premium_tier = $1 WHERE id = $2', [redemption.tier, redemption.user_id]);
        }
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not update gift card submission.' });
    }
});

// ---- Site content (homepage images + hero copy) ----
app.get('/api/admin/site-settings', adminAuth, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM site_settings WHERE id = 1');
        res.json({ settings: result.rows[0] || {} });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not load site settings.' });
    }
});

app.put('/api/admin/site-settings', adminAuth, async (req, res) => {
    try {
        const colMap = {
            heroTitle: 'hero_title',
            heroSubtitle: 'hero_subtitle',
            heroImage1: 'hero_image_1',
            heroImage2: 'hero_image_2',
            heroImage3: 'hero_image_3',
            heroImage4: 'hero_image_4',
            heroImage5: 'hero_image_5',
            heroImage6: 'hero_image_6',
            heroImage7: 'hero_image_7',
            heroImage8: 'hero_image_8',
            heroImage9: 'hero_image_9',
            heroImage10: 'hero_image_10',
            heroImageAccent: 'hero_image_accent',
            galleryImage1: 'gallery_image_1',
            galleryImage2: 'gallery_image_2',
            galleryImage3: 'gallery_image_3',
            safetyImage: 'safety_image'
        };
        const imageKeys = [
            'heroImage1', 'heroImage2', 'heroImage3', 'heroImage4', 'heroImage5',
            'heroImage6', 'heroImage7', 'heroImage8', 'heroImage9', 'heroImage10',
            'heroImageAccent', 'galleryImage1', 'galleryImage2', 'galleryImage3', 'safetyImage'
        ];
        const sets = [];
        const values = [];
        let i = 1;
        for (const key of Object.keys(colMap)) {
            if (Object.prototype.hasOwnProperty.call(req.body, key)) {
                let val = req.body[key];
                if (imageKeys.includes(key) && val && !val.startsWith('data:image/')) {
                    return res.status(400).json({ error: `${key} must be a valid image.` });
                }
                sets.push(`${colMap[key]} = $${i}`);
                values.push(val || null);
                i++;
            }
        }
        if (sets.length === 0) return res.status(400).json({ error: 'No valid fields to update.' });
        sets.push('updated_at = NOW()');
        const result = await pool.query(
            `UPDATE site_settings SET ${sets.join(', ')} WHERE id = 1 RETURNING *`,
            values
        );
        res.json({ settings: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Could not update site settings.' });
    }
});

// =====================================================================
// SOCKET.IO (real-time messaging + match notifications)
// =====================================================================
io.use((socket, next) => {
    try {
        const token = socket.handshake.auth && socket.handshake.auth.token;
        if (!token) return next(new Error('Authentication required'));
        const payload = jwt.verify(token, JWT_SECRET);
        socket.userId = payload.id;
        next();
    } catch (err) {
        next(new Error('Authentication failed'));
    }
});

io.on('connection', (socket) => {
    socket.join(`user_${socket.userId}`);

    socket.on('join_match', async (matchId) => {
        const membership = await assertMatchMembership(matchId, socket.userId);
        if (membership) socket.join(`match_${matchId}`);
    });

    socket.on('typing', ({ matchId }) => {
        socket.to(`match_${matchId}`).emit('typing', { matchId, userId: socket.userId });
    });
});

// =====================================================================
// Static frontend + health check
// =====================================================================
app.get('/healthz', (req, res) => res.json({ ok: true }));

// The admin dashboard is a totally separate static site (its own HTML/CSS/JS,
// its own login screen, its own token) served from /admin, so it never shares
// a codebase, session, or login form with the member-facing app below.
app.use('/admin', express.static(path.join(__dirname, 'public-admin')));
app.get('/admin*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public-admin', 'admin.html'));
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

runMigrations()
    .then(() => bootstrapFirstAdmin())
    .then(() => {
        server.listen(PORT, () => console.log(`HeartSync server running on port ${PORT}`));
    })
    .catch(err => {
        console.error('Failed to run database migrations:', err);
        process.exit(1);
    });
