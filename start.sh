#!/usr/bin/env bash
# Boot sequence for the agy hub on Render.
set -u
export PATH="$HOME/.local/bin:$PATH"

# --- 1. Restore the Google sign-in, if it was provided as Render secret files.
# Render secret files land in /etc/secrets/. Upload these two files there
# (optional — without them you sign in through the browser via /signin):
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

# --- 2b. Browser-opener shim — this is what makes browser sign-in work.
# When the hub wants to sign in, agy generates a Google OAuth URL and tries to
# open it in a browser ON THIS MACHINE (there is none — it's a headless
# container, so the hub page's "Continue with Google" button just spins).
# These shims intercept every browser-open call agy can make ($BROWSER,
# xdg-open & friends) and save the URL instead. The gate (proxy.mjs) then
# serves that URL on its /signin page so the user can open it on their phone.
mkdir -p "$HOME/.hub-bin" "$HOME/.agy-signin"
cat > "$HOME/.hub-bin/browser-open" <<'SHIM'
#!/bin/sh
mkdir -p "$HOME/.agy-signin"
tmp="$HOME/.agy-signin/.signin-url.tmp"
printf '%s\n' "$1" > "$tmp"
mv "$tmp" "$HOME/.agy-signin/signin-url.txt"
exit 0
SHIM
chmod +x "$HOME/.hub-bin/browser-open"
for n in xdg-open sensible-browser debian-sensible-browser www-browser \
         x-www-browser gnome-open kde-open gio open; do
  cp "$HOME/.hub-bin/browser-open" "$HOME/.hub-bin/$n"
done
rm -f "$HOME/.agy-signin/signin-url.txt"

# --- 3. Start the hub (binds 127.0.0.1:4400 only — never exposed directly).
# BROWSER/PATH point agy at the shim above (only for the agy process).
AGY_ENABLE_HUB=1 BROWSER="$HOME/.hub-bin/browser-open" \
  PATH="$HOME/.hub-bin:$PATH" agy --hub &
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
