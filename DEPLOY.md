# Deploying the CloudNova dashboard

The dashboard is a FastAPI app. It binds `127.0.0.1` locally; to expose it publicly
you MUST set a password (the server refuses otherwise).

## Render (recommended, uses render.yaml)
1. Push to GitHub (already done if you're reading this on `main`).
2. render.com → New → Blueprint → pick this repo.
3. Set `CLOUDNOVA_WEB_PASSWORD` to a strong secret in the dashboard.
4. Deploy. Render injects `$PORT`; the app reads it automatically.

## Railway / Fly / any Procfile host
- `Procfile` runs `cloudnova-web`.
- Set env: `CLOUDNOVA_WEB_HOST=0.0.0.0`, `CLOUDNOVA_WEB_PASSWORD=<secret>`,
  optionally `CLOUDNOVA_WEB_USER=<name>`.

## Landing page (Vercel)
Host a static/Next.js marketing page on Vercel and link "Launch app" to the Render
URL. Point your domain's root at Vercel and `app.` at Render.

## Security notes
- HTTP Basic auth protects every route except `/health`.
- Security headers (CSP, X-Frame-Options, HSTS, nosniff) are set on every response.
- The dashboard exposes only the defensive scanner + mentor — not Range's
  target-facing commands. Keep it that way for a public deployment.
