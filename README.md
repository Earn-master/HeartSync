# HeartSync

Real, working dating app backend + frontend — PostgreSQL, JWT auth, live matching/swiping, and real-time chat via Socket.io. No mock data.

## Deploy on Railway (via GitHub)

1. Push this folder to a GitHub repo.
2. In Railway: **New Project → Deploy from GitHub repo**, pick the repo.
3. Add a database: **New → Database → PostgreSQL**. Railway sets `DATABASE_URL` automatically.
4. On your app service, add these Variables:
   - `JWT_SECRET` — any long random string (generate with `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`)
   - `ADMIN_EMAILS` — comma-separated email(s) that should get admin dashboard access, e.g. `you@example.com`. Sign up (or log in, if you already have an account) with that email and you'll be promoted to admin automatically; an "Admin" link then appears in the nav.
   - Optional, for real payments: `STRIPE_SECRET_KEY`, `STRIPE_PRICE_GOLD`, `STRIPE_PRICE_PLATINUM`, `STRIPE_WEBHOOK_SECRET`
5. Railway will run `npm install` then `npm start` automatically (see `Procfile`). The schema is created automatically on first boot.
6. Once deployed, open the Railway-provided URL — the site is live.

## Admin dashboard

Set `ADMIN_EMAILS` (see above), then sign up or log in with that email. You'll see an **Admin** link in the navbar with four tabs:

- **Overview** — live counts of members, verified/premium/admin/suspended users, matches, and messages.
- **Users** — search, verify/unverify, grant/remove premium, promote/demote admins, suspend/unsuspend, or delete accounts.
- **Homepage Content** — edit the hero headline/subheadline and replace any of the 6 default stock photos (hero, gallery, safety section) with your own uploads. Changes go live for every visitor immediately, and can be reset back to the default per-photo.
- **Matches** — view and delete matches (and their message history) if needed for moderation.

You can promote additional admins later from the Users tab itself, so `ADMIN_EMAILS` only needs to cover your first account.

## Local development

```
cp .env.example .env   # fill in DATABASE_URL (a local/hosted Postgres) and JWT_SECRET
npm install
npm start
```

## Notes

- Photos are stored as base64 in Postgres, so no extra file-storage service is required.
- Premium checkout only activates once Stripe env vars are set; otherwise it tells users honestly that payments aren't enabled yet.
- Landing page hero/gallery images are stock photography (picsum/pravatar) for decoration only — swap them for your own brand images anytime.
