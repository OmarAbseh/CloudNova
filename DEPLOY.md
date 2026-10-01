# Deploying the CloudNova dashboard

The dashboard is a FastAPI app. It binds `127.0.0.1` locally. To expose it
publicly you MUST configure the Floatly Platform (Supabase), that is what
supplies accounts and per-organization isolation, and the server refuses to
bind a public interface without it.

## Render (recommended, uses render.yaml)
1. Push to GitHub (already done if you're reading this on `main`).
2. render.com → New → Blueprint → pick this repo.
3. Set `SUPABASE_URL` and `SUPABASE_ANON_KEY` in the dashboard. The anon key is
   safe to expose: it carries no authority of its own, because every request
   made with it is still filtered by Row-Level Security.
4. Deploy. Render injects `$PORT`; the app reads it automatically.

Do **not** set `SUPABASE_SERVICE_ROLE_KEY` in the web environment. It bypasses
RLS entirely, the dashboard never uses it, and the server warns at startup if
it finds one.

## Railway / Fly / any Procfile host
- `Procfile` runs `cloudnova-web`.
- Set env: `CLOUDNOVA_WEB_HOST=0.0.0.0`, `SUPABASE_URL=...`,
  `SUPABASE_ANON_KEY=...`.

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
      - uses: OmarAbseh/CloudNova@6455efb42221e3555e1437475d10cced69147238  # v-pin; see note below
        with:
          path: .
          fail-on: high
          ref: 6455efb42221e3555e1437475d10cced69147238
```
It scans, uploads findings to GitHub code scanning (SARIF), and fails the build on
high-severity findings.

**Pin to a commit, not a branch.** `@main` means whatever that branch points at
when the workflow runs, so anyone who can move the branch can change what
executes in your CI, and this action installs and runs a package. A commit SHA
is immutable, which is why GitHub's own hardening guidance recommends it. The
`ref` input is pinned to the same commit so the installed CloudNova matches the
action definition; left at its `main` default it would float independently.

Update the pin deliberately, the same way you would bump any other dependency.

## Security notes
- Accounts are Supabase-backed. Every route except `/health`, `/login` and
  `/signup` requires a session, and the session cookie is verified against
  Supabase on each request rather than trusted on its own.
- Scans, findings and targets are scoped per organization by Row-Level
  Security, so the database, not the application, decides what a user sees.
- Security headers (CSP, X-Frame-Options, HSTS, nosniff) are set on every
  response, including redirects.
- The dashboard exposes only the defensive scanner + mentor, not Range's
  target-facing commands. Keep it that way for a public deployment.
