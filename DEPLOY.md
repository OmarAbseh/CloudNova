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
The marketing page lives in `site/` (static HTML, dark/red, 3D hero, pricing).
1. Vercel → New Project → import this repo.
2. Set **Root Directory** to `site`, framework preset **Other** (no build step).
3. Deploy. Point your domain's root at Vercel and `app.` at the Render dashboard URL.
4. Edit "Launch app" links in `site/index.html` to your Render URL.

## CI security gate (GitHub Action)
`action.yml` is a reusable action. In any repo:

```yaml
# .github/workflows/security.yml
name: CloudNova
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # for SARIF upload
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: OmarAbseh/CloudNova@main
        with:
          path: .
          fail-on: high
```
It scans, uploads findings to GitHub code scanning (SARIF), and fails the build on
high-severity findings.

## Security notes
- HTTP Basic auth protects every route except `/health`.
- Security headers (CSP, X-Frame-Options, HSTS, nosniff) are set on every response.
- The dashboard exposes only the defensive scanner + mentor — not Range's
  target-facing commands. Keep it that way for a public deployment.
