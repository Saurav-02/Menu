// agy-hub gate proxy: Basic-auth gate + reverse proxy (HTTP + WebSocket)
// in front of the Antigravity hub on 127.0.0.1:4400.
// - Listens on 0.0.0.0:$PORT (Render assigns $PORT).
// - Every request (except /healthz) needs Basic auth: any username, password = $HUB_PASSWORD.
// - Dependency-free Node.js (http + net only).
//
// Browser sign-in (/signin): the hub's own "Continue with Google" button
// makes agy open the Google OAuth URL in a browser on the SERVER (headless
// container — none exists, so it spins forever). start.sh intercepts that
// browser-open with a shim that saves the URL to ~/.agy-signin/signin-url.txt.
// This gate serves that URL on /signin; after the user signs in on their
// phone, Google redirects the phone browser to
// http://localhost:<port>/auth/callback?code=...&state=... (dead end on the
// phone, but the URL in the address bar holds the code). The user pastes
// that URL back into /signin, and the gate forwards code+state to the real
// callback listener inside this container, completing the sign-in.
import http from "node:http";
import net from "node:net";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PORT = Number(process.env.PORT || 10000);
const TARGET_HOST = "127.0.0.1";
const TARGET_PORT = 4400;
const PASSWORD = process.env.HUB_PASSWORD || "";
const SIGNIN_URL_FILE = path.join(os.homedir(), ".agy-signin", "signin-url.txt");

if (!PASSWORD) {
  console.error("HUB_PASSWORD is not set — refusing to start an ungated proxy.");
  process.exit(1);
}

function passwordOk(req) {
  const h = req.headers["authorization"] || "";
  if (!h.startsWith("Basic ")) return false;
  let decoded = "";
  try { decoded = Buffer.from(h.slice(6), "base64").toString("utf8"); } catch { return false; }
  const idx = decoded.indexOf(":");
  if (idx < 0) return false;
  const given = Buffer.from(decoded.slice(idx + 1));
  const want = Buffer.from(PASSWORD);
  return given.length === want.length && crypto.timingSafeEqual(given, want);
}

function deny(res) {
  // The 401 body is what a visitor sees if they cancel the password prompt
  // or type a wrong password — make it the same notice as the landing page.
  res.writeHead(401, { "WWW-Authenticate": 'Basic realm="agy-hub"', "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(noticeHtml(false));
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Read the Google sign-in URL the shim captured, plus where its OAuth
// callback listener lives (parsed out of the URL's redirect_uri).
function readSignin() {
  try {
    const url = fs.readFileSync(SIGNIN_URL_FILE, "utf8").trim();
    if (!url.startsWith("https://accounts.google.com/")) return null;
    const u = new URL(url);
    const redir = u.searchParams.get("redirect_uri") || "";
    const m = redir.match(/^http:\/\/localhost:(\d+)\/auth\/callback$/);
    const st = fs.statSync(SIGNIN_URL_FILE);
    return { url, cbPort: m ? Number(m[1]) : null, state: u.searchParams.get("state") || "", ageSec: Math.max(0, Math.round((Date.now() - st.mtimeMs) / 1000)) };
  } catch { return null; }
}

function page(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title>
<style>body{font-family:system-ui,sans-serif;background:#111;color:#eee;margin:0;padding:20px}
.card{max-width:560px;margin:24px auto;background:#1d1d1f;border-radius:14px;padding:22px}
a.btn,button{display:block;width:100%;box-sizing:border-box;text-align:center;background:#2f6fed;color:#fff;border:0;border-radius:10px;padding:14px;font-size:16px;text-decoration:none;cursor:pointer;margin:14px 0}
textarea{width:100%;box-sizing:border-box;background:#000;color:#eee;border:1px solid #444;border-radius:10px;padding:10px;font-size:13px;min-height:74px}
.small{color:#aaa;font-size:13px;line-height:1.5} code{background:#000;padding:1px 5px;border-radius:5px}</style></head>
<body><div class="card">${body}</div></body></html>`;
}

// Public notice for visitors without the password: this is a personal,
// self-deployed page and they don't have permission to access it. Shown as
// the landing page (with an owner sign-in button) and as the 401 body.
function noticeHtml(withButton) {
  const btn = withButton ? `<p><a class="btn" href="/enter">I'm the owner — sign in</a></p>` : "";
  return page("Private page", `<div style="text-align:center">
<p style="font-size:44px;margin:6px 0">🔒</p>
<h2>This is a personal page</h2>
<p class="small">This hub is privately self-deployed by its owner for personal use. It isn't a public service, and you don't have permission to access it.</p>
${btn}
<p class="small">If you received this link by mistake, you can safely close this tab.</p>
</div>`);
}

function noticePage(res) {
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(noticeHtml(true));
}

// Shown when the gate is up but the hub behind it isn't answering (hub
// crashed, or still starting): a full-screen "sleeping" page that reloads
// itself every 20s, so a waiting visitor lands in the hub once it's back.
function sleepingHtml() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="20"><title>Antigravity is sleeping</title>
<style>body{font-family:system-ui,sans-serif;background:#111;color:#eee;margin:0;padding:20px}
.card{max-width:560px;margin:24px auto;background:#1d1d1f;border-radius:14px;padding:22px}
a.btn{display:block;width:100%;box-sizing:border-box;text-align:center;background:#2f6fed;color:#fff;border:0;border-radius:10px;padding:14px;font-size:16px;text-decoration:none;cursor:pointer;margin:14px 0}
.small{color:#aaa;font-size:13px;line-height:1.5}</style></head>
<body><div class="card"><div style="text-align:center">
<p style="font-size:44px;margin:6px 0">😴</p>
<h2>Antigravity is sleeping</h2>
<p class="small">The hub naps when it's idle — and while it restarts — to save energy. It usually wakes within a minute or two. This page reloads itself, so just leave it open and the hub will appear on its own.</p>
<p><a class="btn" href="/">Check now</a></p>
</div></div></body></html>`;
}

function signinPage(res, note = "") {
  const s = readSignin();
  let body = `<h2>Sign in to Antigravity</h2>`;
  if (note) body += `<p>${note}</p>`;
  if (!s) {
    body += `<p class="small">No sign-in request yet. First open the hub tab and tap <b>Continue with Google</b> (it will spin — that's expected), then come back here and reload this page.</p>`;
  } else {
    body += `<p class="small">Sign-in link captured ${s.ageSec}s ago. If Google says the link expired, tap Continue with Google in the hub tab again and reload this page for a fresh one.</p>
<p><a class="btn" href="${esc(s.url)}" target="_blank" rel="noopener">Open Google sign-in</a></p>
<p class="small">After you sign in, Google sends your browser to a <code>localhost</code> page that won't load — that's normal. <b>Copy that whole address-bar URL</b>, paste it below, and tap Finish.</p>
<form method="POST" action="/signin/finish">
<textarea name="pasted" placeholder="Paste the full localhost URL here (http://localhost:.../auth/callback?code=...)"></textarea>
<button type="submit">Finish sign-in</button>
</form>`;
  }
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(page("Sign in", body));
}

// Ask the hub whether sign-in landed ( fetch its page for a CSRF token,
// then call its GetAuthStatus RPC — both stay inside this container ).
async function hubSignedIn() {
  try {
    const html = await new Promise((resolve, reject) => {
      http.get({ host: TARGET_HOST, port: TARGET_PORT, path: "/" }, (r) => {
        let d = ""; r.on("data", (c) => (d += c)); r.on("end", () => resolve(d));
      }).on("error", reject);
    });
    const csrf = (html.match(/"csrfToken":"([^"]+)"/) || [])[1];
    if (!csrf) return false;
    const body = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: TARGET_HOST, port: TARGET_PORT, path: "/exa.language_server_pb.LanguageServerService/GetAuthStatus", method: "POST", headers: { "Content-Type": "application/json", "x-codeium-csrf-token": csrf } },
        (r) => { let d = ""; r.on("data", (c) => (d += c)); r.on("end", () => resolve(d)); }
      );
      req.on("error", reject);
      req.end("{}");
    });
    const j = JSON.parse(body);
    const a = (j && j.authResult) || {};
    return !!(a.hasValidAuth || a.email || a.name || a.userInfo || a.account);
  } catch { return false; }
}

function finishSignin(req, res) {
  let data = "";
  req.on("data", (c) => { data += c; if (data.length > 65536) req.destroy(); });
  req.on("end", async () => {
    const pasted = (new URLSearchParams(data).get("pasted") || "").trim();
    const s = readSignin();
    if (!s || !s.cbPort) return signinPage(res, "No active sign-in request was found. Tap Continue with Google in the hub tab first, then reload this page and try again.");
    let code = "", state = "";
    try {
      const u = new URL(pasted);
      code = u.searchParams.get("code") || "";
      state = u.searchParams.get("state") || "";
    } catch {
      // Not a URL — maybe they pasted just the code.
      if (/^[A-Za-z0-9_\-\/]+$/.test(pasted) && pasted.length > 8) { code = pasted; state = s.state; }
    }
    if (!code) return signinPage(res, "That paste didn't contain a sign-in code. Copy the <b>whole</b> address-bar URL from the page that failed to load and paste it here.");
    const qs = new URLSearchParams({ code, ...(state ? { state } : {}) }).toString();
    // Forward to agy's OAuth callback listener inside this container.
    await new Promise((resolve) => {
      http.get({ host: TARGET_HOST, port: s.cbPort, path: `/auth/callback?${qs}` }, (r) => { r.resume(); r.on("end", resolve); })
        .on("error", () => resolve());
    });
    await new Promise((r) => setTimeout(r, 1500));
    if (await hubSignedIn()) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(page("Signed in", `<h2>You're signed in ✓</h2><p class="small">Switch back to the hub tab — it should open straight into the chat now (reload it if it still shows the welcome screen).</p>`));
    } else {
      signinPage(res, "Google didn't accept that code — codes expire fast and work only once. Tap <b>Continue with Google</b> in the hub tab again for a fresh link, reload this page, and redo it in one go.");
    }
  });
}

// Session backup (/backup): start.sh already restores the Google sign-in
// at boot from Render secret files, but there was no way to GET the token
// files out of the running container (Render's Shell is paid). This page —
// behind the same Basic-auth password as everything else — serves the two
// token files as downloads so they can be uploaded once as secret files.
// After that, every restart/redeploy boots already signed in.
const TOKEN_FILES = {
  "antigravity-oauth-token": path.join(os.homedir(), ".gemini", "antigravity-cli", "antigravity-oauth-token"),
  "jetski-standalone-oauth-token": path.join(os.homedir(), ".gemini", "jetski-standalone-oauth-token"),
};

function backupPage(res) {
  let body = `<h2>Session backup</h2>
<p class="small">These two files <b>are</b> your hub's Google sign-in. Download both, then in the Render dashboard open your service → <b>Environment → Secret Files → Add Secret File</b> and upload each one with its filename <b>exactly</b> as shown. From the next boot on, the hub restores them automatically and opens already signed in — no Google step after a restart.</p>
<p class="small">Treat the downloads like a password: anyone holding them can act as your signed-in hub. This page sits behind the same hub password prompt as the hub itself.</p>`;
  for (const [name, file] of Object.entries(TOKEN_FILES)) {
    let st = null;
    try { st = fs.statSync(file); } catch { /* not signed in yet */ }
    if (st) {
      body += `<p><a class="btn" href="/backup/${esc(name)}" download>Download ${esc(name)}</a><br><span class="small">${st.size} bytes · saved ${esc(st.mtime.toISOString())}</span></p>`;
    } else {
      body += `<p class="small"><code>${esc(name)}</code> — not found. Sign in to the hub first, then reload this page.</p>`;
    }
  }
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(page("Session backup", body));
}

function backupDownload(res, name) {
  const file = TOKEN_FILES[name];
  if (!file) { res.writeHead(404, { "Content-Type": "text/plain" }); res.end("not found\n"); return; }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { "Content-Type": "text/plain" }); res.end("token file not found — sign in first\n"); return; }
    res.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${name}"`,
      "Content-Length": data.length,
      "Cache-Control": "no-store",
    });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  if (req.url === "/healthz") { res.writeHead(200, { "Content-Type": "text/plain" }); res.end("ok\n"); return; }
  const pathOnly = (req.url || "").split("?")[0];
  if (!passwordOk(req)) {
    // Public landing: a visitor without the password sees the notice page,
    // not a bare browser prompt. The prompt appears when they tap the
    // owner sign-in button (/enter) or open any other protected path.
    if (req.method === "GET" && pathOnly === "/") return noticePage(res);
    return deny(res);
  }
  if (pathOnly === "/enter") { res.writeHead(302, { Location: "/" }); res.end(); return; }
  if (pathOnly === "/signin" && req.method === "GET") return signinPage(res);
  if (pathOnly === "/signin/finish" && req.method === "POST") return finishSignin(req, res);
  if (pathOnly === "/backup" && req.method === "GET") return backupPage(res);
  if (pathOnly.startsWith("/backup/") && req.method === "GET") return backupDownload(res, decodeURIComponent(pathOnly.slice("/backup/".length)));
  const fwdHeaders = { ...req.headers, host: `${TARGET_HOST}:${TARGET_PORT}` };
  const upstream = http.request(
    { host: TARGET_HOST, port: TARGET_PORT, path: req.url, method: req.method, headers: fwdHeaders },
    (up) => { res.writeHead(up.statusCode || 502, up.headers); up.pipe(res); }
  );
  upstream.on("error", () => {
    // Gate is up but the hub behind it isn't answering (crashed or still
    // starting): serve the sleeping page — it auto-reloads until the hub
    // is back, instead of a bare "hub unreachable" error.
    if (!res.headersSent) {
      res.writeHead(503, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(sleepingHtml());
    } else res.end();
  });
  req.pipe(upstream);
});

// WebSocket / upgrade passthrough (the hub UI streams over WS).
server.on("upgrade", (req, socket, head) => {
  if (!passwordOk(req)) {
    socket.write("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"agy-hub\"\r\nConnection: close\r\n\r\n");
    socket.destroy();
    return;
  }
  const upstream = net.connect(TARGET_PORT, TARGET_HOST, () => {
    const fwd = { ...req.headers, host: `${TARGET_HOST}:${TARGET_PORT}` };
    const headers = Object.entries(fwd).map(([k, v]) => `${k}: ${v}`).join("\r\n");
    upstream.write(`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n${headers}\r\n\r\n`);
    if (head && head.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.on("error", () => socket.destroy());
  socket.on("error", () => upstream.destroy());
});

server.listen(PORT, "0.0.0.0", () => console.log(`gate proxy listening on :${PORT} -> ${TARGET_HOST}:${TARGET_PORT}`));
