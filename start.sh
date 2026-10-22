#!/usr/bin/env bash
# Boot sequence for the agy hub on Render.
set -u
export PATH="$HOME/.local/bin:$PATH"

# --- 1. Restore the Google sign-in, if it was provided as Render secret files.
# Render secret files land in /etc/secrets/. Upload these two files there
# (optional — without them you sign in once via the Render Shell instead):
#   antigravity-oauth-token        -> ~/.gemini/antigravity-cli/
#   jetski-standalone-oauth-token  -> ~/.gemini/
mkdir -p "$HOME/.gemini/antigravity-cli"
if [ -f /etc/secrets/antigravity-oauth-token ]; then
  cp /etc/secrets/antigravity-oauth-token "$HOME/.gemini/antigravity-cli/antigravity-oauth-token"
  chmod 600 "$HOME/.gemini/antigravity-cli/antigravity-oauth-token"
  echo "Seeded antigravity-oauth-token from secret file."
fi
if [ -f /etc/secrets/jetski-standalone-oauth-token ]; then
  cp /etc/secrets/jetski-standalone-oauth-token "$HOME/.gemini/jetski-standalone-oauth-token"
  chmod 600 "$HOME/.gemini/jetski-standalone-oauth-token"
  echo "Seeded jetski-standalone-oauth-token from secret file."
fi

# --- 2. Attach the GitHub MCP bridge (same one the desktop app uses).
# Set MCP_BRIDGE_URL in Render env if the bridge address or key changes.
agy mcp add github-bridge "${MCP_BRIDGE_URL:-https://mcp-2-75va.onrender.com}" || true

# --- 3. Start the hub (binds 127.0.0.1:4400 only — never exposed directly).
AGY_ENABLE_HUB=1 agy --hub &
HUB_PID=$!

# Wait until the hub answers before opening the gate.
for i in $(seq 1 60); do
  if curl -s --noproxy '*' -o /dev/null http://127.0.0.1:4400/; then
    echo "Hub is up."
    break
  fi
  if ! kill -0 "$HUB_PID" 2>/dev/null; then
    echo "Hub exited during startup." >&2
    exit 1
  fi
  sleep 1
done

# --- 4. Start the auth gate in front (this is the process Render talks to).
exec node proxy.mjs
