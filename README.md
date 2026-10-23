# agy-hub — Antigravity CLI hub on Render

Runs Google's **Antigravity CLI** (`agy`) in its browser hub mode on a free
Render web service — the same hub you open at `localhost:4400` in Termux,
but at a public `*.onrender.com` URL you can open in Chrome on your phone.

How it fits together:

- `agy --hub` serves the chat UI on `127.0.0.1:4400` (loopback only, no login).
- `proxy.mjs` is a tiny dependency-free gate in front of it: it listens on
  Render's `$PORT`, requires a **Basic-auth password** (`HUB_PASSWORD`), and
  forwards HTTP + WebSocket traffic to the hub. Nothing reaches the hub
  without the password.
- `start.sh` boots everything: restores the Google sign-in if token files
  were provided as Render secret files, attaches the GitHub MCP bridge
  (`github-bridge`), starts the hub, then starts the gate.
- `render.yaml` is a Render Blueprint so the service is created with the
  right settings in one go.

## Deploy (about 10 minutes, all free)

1. **Create a GitHub repo** (e.g. `agy-hub`) and put these files in it.
2. **Render:** New + → **Blueprint** → connect the repo.
   (Or: New + → Web Service → connect repo → Runtime: **Docker**, Plan: **Free**.)
3. **Set the one secret:** in the service's **Environment** tab set
   `HUB_PASSWORD` to a password you choose. Never commit it anywhere.
   (`MCP_BRIDGE_URL` is already set by render.yaml.)
4. **Deploy.** The first build downloads and installs agy — a few minutes.
5. **Open your service URL** (e.g. `https://agy-hub.onrender.com`) in Chrome.
   The browser asks for a username and password — any username works,
   password is your `HUB_PASSWORD`. The Antigravity hub loads.
6. **Sign in through the browser** (no Shell needed — Shell is paid on
   Render). The hub's own "Continue with Google" button can't work raw on
   Render: it makes agy open Google sign-in in a browser *on the server*,
   and a headless container has none. So `start.sh` installs a browser
   shim that captures the sign-in link instead, and the gate serves it:
   1. In the hub tab, tap **Continue with Google**. It will spin — expected,
      leave it spinning.
   2. Open `<your service URL>/signin` in a second tab (same password).
   3. Tap **Open Google sign-in**, sign in with the AI Pro account.
   4. Google then sends your browser to a `localhost` page that won't
      load — normal. **Copy that whole address-bar URL.**
   5. Back on the `/signin` tab, paste the URL into the box and tap
      **Finish sign-in**.
   6. Switch back to the hub tab — you're signed in. Chat away.

## The honest limits (free tier)

- **Sleep:** after ~15 idle minutes Render stops the service. The next visit
  wakes it in about a minute. A task that is *running* when it sleeps dies.
- **Amnesia:** Render wipes the disk on restart/redeploy, so chat history
  resets and you redo the 1-minute browser sign-in via `/signin`.
  To make sign-in survive restarts, add these two files as **Secret Files**
  in the Render dashboard (Environment → Secret Files) — `start.sh` picks
  them up automatically at boot:
  - `antigravity-oauth-token`
  - `jetski-standalone-oauth-token`
- **Security:** the password gate is the only lock. With it, someone would
  need your `HUB_PASSWORD` to reach the hub — and through it, your AI Pro
  quota and the GitHub bridge. Pick a real password.

## Local test (already verified on the VM, 2026-10-23)

The gate was tested against the real hub: no password → 401, wrong password
→ 401, correct password → the hub page loads, WebSocket upgrade → 101,
`/healthz` → 200 without auth (that's what render.yaml's health check uses).

The browser sign-in was verified end to end against an unsigned hub
(2026-10-23): triggering the hub's Login made the shim capture the real
Google OAuth URL; the gate's `/signin` page served it; a pasted
`localhost:<port>/auth/callback?code=...&state=...` URL was forwarded to
agy's callback listener, which validated the state and attempted the token
exchange with Google (a fake code correctly came back
`invalid_grant / Malformed auth code` — a real code completes the sign-in).
