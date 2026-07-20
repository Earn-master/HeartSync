# HeartSync

Real, working dating app backend + frontend — PostgreSQL, JWT auth, live matching/swiping, and real-time chat via Socket.io. No mock data.

## Deploy on Railway (via GitHub)

1. Push this folder to a GitHub repo.
2. In Railway: **New Project → Deploy from GitHub repo**, pick the repo.
3. Add a database: **New → Database → PostgreSQL**. Railway sets `DATABASE_URL` automatically.
4. On your app service, add these Variables:
   - `JWT_SECRET` — any long random string (generate with `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`)
   - Optional, for real payments: `STRIPE_SECRET_KEY`, `STRIPE_PRICE_GOLD`, `STRIPE_PRICE_PLATINUM`, `STRIPE_WEBHOOK_SECRET`
5. Railway will run `npm install` then `npm start` automatically (see `Procfile`). The schema is created automatically on first boot.
6. Once deployed, open the Railway-provided URL — the site is live.

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
