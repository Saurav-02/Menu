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
import zlib from "node:zlib";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { packStateText, stateInfo } from "./statetool.mjs";

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
  // Chat backup: the hub's conversations live only on this container's
  // throwaway disk. This packs them into one file that rides the same
  // secret-file route as the sign-in token (start.sh restores it at boot).
  const info = stateInfo(STATE_DIR);
  body += `<h2 style="margin-top:28px">Chat backup</h2>`;
  if (info.files > 0) {
    body += `<p class="small">Your conversations and settings (${info.files} files, ${(info.bytes / 1024).toFixed(0)} KB, last changed ${esc(new Date(info.newest).toISOString())}) packed into one <b>text</b> file. Download it, open it, copy <b>all</b> the text, and paste it in Render as the contents of a secret file named <b>exactly</b> <code>agy-state.tar.gz</code>. (It's text on purpose: Render's secret-file box is a paste box, and pasting the raw binary version corrupts it.) Every boot then restores your chats. It's a snapshot — re-download and re-paste after important chats to refresh it.</p>
<p><a class="btn" href="/backup/state" download>Download chat backup (text)</a></p>`;
  } else {
    body += `<p class="small">No chats found yet — start a conversation in the hub first, then reload this page.</p>`;
  }
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(page("Session backup", body));
}

const STATE_DIR = path.join(os.homedir(), ".gemini");

function backupDownload(res, name) {
  if (name === "state") {
    let text;
    try { text = packStateText(STATE_DIR); } catch { text = null; }
    if (!text) { res.writeHead(404, { "Content-Type": "text/plain" }); res.end("no chat state found\n"); return; }
    res.writeHead(200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Content-Disposition": 'attachment; filename="agy-state-base64.txt"',
      "Content-Length": Buffer.byteLength(text),
      "Cache-Control": "no-store",
    });
    res.end(text);
    return;
  }
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

// --- Optional automatic chat-state sync to GitHub -------------------------
// Active only when STATE_GITHUB_REPO + STATE_GITHUB_TOKEN are both set
// (a fine-grained PAT with Contents RW on that one PRIVATE repo). The gate
// packs the chat state (the same base64 text /backup serves) every few
// minutes when it changed and PUTs it to agy-state.txt on branch main;
// start.sh pulls it back at boot (section 1d, winning over the secret
// file), so restarts restore the freshest chats with no manual
// download/paste. Failures are logged once per attempt and swallowed —
// sync must never disturb request handling.
const SYNC_REPO = process.env.STATE_GITHUB_REPO || "";
const SYNC_TOKEN = process.env.STATE_GITHUB_TOKEN || "";
const SYNC_API = (process.env.STATE_GITHUB_API || "https://api.github.com").replace(/\/+$/, "");
const SYNC_INTERVAL_MS = Number(process.env.STATE_SYNC_INTERVAL_MS || 180000);
const SYNC_INITIAL_MS = Number(process.env.STATE_SYNC_INITIAL_MS || 30000);
const SYNC_URL = `${SYNC_API}/repos/${SYNC_REPO}/contents/agy-state.txt`;

let syncLastHash = "";
let syncSha = null;
let syncBusy = false;

function syncHeaders(extra = {}) {
  return {
    Authorization: `Bearer ${SYNC_TOKEN}`,
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "agy-hub-gate",
    ...extra,
  };
}

// Learn the current file's sha (needed to overwrite it). Returns false on
// 404 — the file doesn't exist yet, so a PUT without sha creates it.
async function syncFetchSha() {
  const r = await fetch(`${SYNC_URL}?ref=main`, { headers: syncHeaders({ Accept: "application/vnd.github+json" }) });
  if (r.status === 404) { syncSha = null; return false; }
  if (!r.ok) throw new Error(`GET state sha -> HTTP ${r.status}`);
  const j = await r.json();
  syncSha = j.sha || null;
  return true;
}

async function syncPushOnce() {
  if (syncBusy) return;
  syncBusy = true;
  try {
    const info = stateInfo(STATE_DIR);
    if (!info || info.files === 0) return;
    const text = packStateText(STATE_DIR);
    const hash = crypto.createHash("sha256").update(text).digest("hex");
    if (hash === syncLastHash) return; // unchanged since last good push
    // Two base64 layers are intended: the file content IS our base64 text,
    // and the Contents API base64-wraps whatever file bytes it stores.
    const content = Buffer.from(text, "utf8").toString("base64");
    for (let attempt = 0; attempt < 2; attempt++) {
      if (syncSha === null && attempt === 0) await syncFetchSha();
      const body = { message: "hub state snapshot", branch: "main", content };
      if (syncSha) body.sha = syncSha;
      const r = await fetch(SYNC_URL, {
        method: "PUT",
        headers: syncHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(body),
      });
      if (r.ok) {
        const j = await r.json().catch(() => null);
        if (j && j.content && j.content.sha) syncSha = j.content.sha;
        syncLastHash = hash;
        console.log(`state sync: pushed snapshot (${text.length} chars) to ${SYNC_REPO}`);
        return;
      }
      if ((r.status === 409 || r.status === 422) && attempt === 0) {
        syncSha = null;
        await syncFetchSha(); // stale sha — refresh and retry the PUT once
        continue;
      }
      throw new Error(`PUT state -> HTTP ${r.status}`);
    }
  } catch (e) {
    console.log(`state sync: ${e && e.message ? e.message : e} (will retry next tick)`);
  } finally {
    syncBusy = false;
  }
}

if (SYNC_REPO && SYNC_TOKEN) {
  console.log(`state sync: on — ${SYNC_REPO} every ${Math.round(SYNC_INTERVAL_MS / 1000)}s`);
  const firstSync = setTimeout(syncPushOnce, SYNC_INITIAL_MS);
  firstSync.unref();
  const syncTimer = setInterval(syncPushOnce, SYNC_INTERVAL_MS);
  syncTimer.unref();
}

// --- PWA install + view entry points --------------------------------------
// The hub UI ships no web-app manifest, so Chrome/Android only offers
// "create shortcut", never "Install app". The gate supplies the missing
// pieces itself: a manifest, two icons (embedded below — minimal
// monochrome: white four-point spark on a near-black rounded square), and
// a pass-through service worker. /manifest.webmanifest and /pwa/* are
// served WITHOUT auth (nothing sensitive in them) so Chrome can always
// fetch them; the manifest link + SW registration are injected into the
// hub's HTML as it passes through the proxy (see sendUpstreamHtml).
const ICON_192_PNG = Buffer.from("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", "base64");
const ICON_512_PNG = Buffer.from("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", "base64");

const MANIFEST_JSON = JSON.stringify({
  name: "Antigravity Hub",
  short_name: "Antigravity",
  description: "Personal Antigravity hub",
  start_url: "/",
  scope: "/",
  display: "standalone",
  background_color: "#000000",
  theme_color: "#000000",
  icons: [
    { src: "/pwa/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
    { src: "/pwa/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
    { src: "/pwa/icon-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
  ],
  shortcuts: [
    { name: "Desktop view", url: "/view/desktop" },
    { name: "Mobile view", url: "/view/mobile" },
  ],
});

// Pass-through service worker: takes control on activate, but its fetch
// handler never calls respondWith, so every request — including the hub's
// realtime traffic — goes to the network exactly as without a worker.
const SW_JS = `self.addEventListener("install", () => { self.skipWaiting(); });
self.addEventListener("activate", (event) => { event.waitUntil(self.clients.claim()); });
self.addEventListener("fetch", () => { /* pass-through: no respondWith */ });
`;

const PWA_SNIPPET = `<link rel="manifest" href="/manifest.webmanifest"><meta name="theme-color" content="#000000"><link rel="apple-touch-icon" href="/pwa/icon-192.png"><script>if("serviceWorker" in navigator){addEventListener("load",function(){navigator.serviceWorker.register("/pwa/sw.js",{scope:"/"}).catch(function(){})})}</script>`;

function servePwa(pathOnly, res) {
  if (pathOnly === "/manifest.webmanifest") {
    res.writeHead(200, { "Content-Type": "application/manifest+json; charset=utf-8", "Content-Length": Buffer.byteLength(MANIFEST_JSON), "Cache-Control": "no-cache" });
    res.end(MANIFEST_JSON);
    return true;
  }
  if (pathOnly === "/pwa/icon-192.png" || pathOnly === "/pwa/icon-512.png") {
    const buf = pathOnly === "/pwa/icon-192.png" ? ICON_192_PNG : ICON_512_PNG;
    res.writeHead(200, { "Content-Type": "image/png", "Content-Length": buf.length, "Cache-Control": "public, max-age=604800" });
    res.end(buf);
    return true;
  }
  if (pathOnly === "/pwa/sw.js") {
    // Service-Worker-Allowed lets this script (served from /pwa/) control
    // the whole origin — its natural scope would only cover /pwa/.
    res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "Service-Worker-Allowed": "/", "Content-Length": Buffer.byteLength(SW_JS), "Cache-Control": "no-cache" });
    res.end(SW_JS);
    return true;
  }
  return false;
}

// Desktop-view spoof: when the hubview cookie says "desktop", the hub
// still decides its layout in the browser — via the viewport meta (layout
// width -> CSS media queries + matchMedia + innerWidth) and via
// navigator.userAgent sniffing. The gate rewrites the served HTML before
// the browser parses it: the viewport meta gets a desktop width, and this
// script — placed immediately after <head>, before any app script —
// overrides the navigator identity the app reads. Verified in a real
// browser (2026-10-24): the navigator-identity overrides alone flip the
// app into its desktop shell; the meta widening docks the sidebar at
// desktop width. Mobile/no-cookie pages get exactly the PWA-only
// injection below, untouched.
function spoofSnippet() {
  return `<script>(function(){try{
var UA=${JSON.stringify(DESKTOP_UA)};
function def(o,p,v){try{Object.defineProperty(o,p,{get:function(){return v;},configurable:true});}catch(e){}}
def(navigator,"userAgent",UA);
def(navigator,"platform","Win32");
def(navigator,"maxTouchPoints",0);
var brands=[{brand:"Chromium",version:"130"},{brand:"Google Chrome",version:"130"},{brand:"Not-A.Brand",version:"99"}];
var uad={brands:brands,mobile:false,platform:"Windows",getHighEntropyValues:function(){return Promise.resolve({brands:brands,mobile:false,platform:"Windows",platformVersion:"15.0.0",architecture:"x86",bitness:"64",model:"",uaFullVersion:"130.0.0.0",fullVersionList:brands});},toJSON:function(){return{brands:brands,mobile:false,platform:"Windows"};}};
def(navigator,"userAgentData",uad);
}catch(e){}})();</script>`;
}

// Returns the modified HTML, or null when no injection is needed/possible
// (idempotent: a page that already references the manifest is left alone,
// so its bytes pass through untouched).
function injectPwa(html, view) {
  if (html.includes("manifest.webmanifest")) return null;
  let out = html;
  if (view === "desktop") {
    // Widen the layout viewport: replace the page's viewport meta with a
    // desktop-width one (or insert one if the page has none).
    if (/<meta[^>]*name="viewport"[^>]*>/i.test(out)) {
      out = out.replace(/<meta[^>]*name="viewport"[^>]*>/i, '<meta name="viewport" content="width=1280" />');
    } else {
      const h = out.match(/<head[^>]*>/i);
      if (h) { const at = h.index + h[0].length; out = out.slice(0, at) + '<meta name="viewport" content="width=1280" />' + out.slice(at); }
    }
    // Spoof script goes first in <head>, before every app script.
    const h = out.match(/<head[^>]*>/i);
    if (h) { const at = h.index + h[0].length; out = out.slice(0, at) + spoofSnippet() + out.slice(at); }
  }
  const close = out.search(/<\/head\s*>/i);
  if (close >= 0) return out.slice(0, close) + PWA_SNIPPET + out.slice(close);
  const open = out.match(/<head[^>]*>/i);
  if (open) { const at = open.index + open[0].length; return out.slice(0, at) + PWA_SNIPPET + out.slice(at); }
  return out === html ? null : out;
}

// Hub HTML is buffered (it is just the app shell) so the PWA snippet can
// be spliced into <head>. A compressed body is decoded, injected, and
// re-sent uncompressed with corrected headers; when nothing changes, the
// original bytes go out untouched. Non-HTML responses never come through
// here — they stream through byte-identical.
function sendUpstreamHtml(res, up, view) {
  const chunks = [];
  up.on("data", (c) => chunks.push(c));
  up.on("end", () => {
    const raw = Buffer.concat(chunks);
    const headers = { ...up.headers };
    let body = raw;
    const enc = (up.headers["content-encoding"] || "").toLowerCase().trim();
    let decoded = null;
    try {
      if (enc === "gzip") decoded = zlib.gunzipSync(raw);
      else if (enc === "deflate") decoded = zlib.inflateSync(raw);
      else if (enc === "br") decoded = zlib.brotliDecompressSync(raw);
      else if (!enc || enc === "identity") decoded = raw;
    } catch { decoded = null; }
    if (decoded) {
      const out = injectPwa(decoded.toString("utf8"), view);
      if (out !== null) {
        body = Buffer.from(out, "utf8");
        delete headers["content-encoding"];
        delete headers["etag"];
      }
    }
    delete headers["transfer-encoding"];
    headers["content-length"] = body.length;
    res.writeHead(up.statusCode || 502, headers);
    res.end(body);
  });
  up.on("error", () => { try { res.end(); } catch { /* response already gone */ } });
}

// --- Desktop / mobile view cookie -----------------------------------------
// /view/desktop and /view/mobile (also the manifest's shortcut targets)
// record the owner's preference in a long-lived cookie. When the cookie
// says "desktop", the gate rewrites the User-Agent it forwards to the hub
// to a desktop Chrome string; "mobile" (or no cookie) forwards the real
// one. NOTE, verified against the real hub (2026-10-24): the hub serves
// byte-identical HTML/JS/CSS for mobile and desktop UAs — its layout is
// chosen in the browser (navigator.userAgent + viewport media queries),
// so this rewrite alone cannot force the desktop layout; it is kept as
// the standard server-side lever, harmless if the hub ever keys off the
// header. Chrome's own "Desktop site" mode remains the reliable switch.
const DESKTOP_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

function hubView(req) {
  for (const part of (req.headers.cookie || "").split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === "hubview") return part.slice(eq + 1).trim();
  }
  return "";
}

function viewRedirect(res, view) {
  res.writeHead(302, { Location: "/", "Set-Cookie": `hubview=${view}; Path=/; Max-Age=31536000; SameSite=Lax`, "Cache-Control": "no-store" });
  res.end();
}

const server = http.createServer((req, res) => {
  if (req.url === "/healthz") { res.writeHead(200, { "Content-Type": "text/plain" }); res.end("ok\n"); return; }
  const pathOnly = (req.url || "").split("?")[0];
  // PWA assets are public on purpose: Chrome must be able to fetch the
  // manifest, icons and service worker without credentials.
  if (req.method === "GET" && servePwa(pathOnly, res)) return;
  if (!passwordOk(req)) {
    // Public landing: a visitor without the password sees the notice page,
    // not a bare browser prompt. The prompt appears when they tap the
    // owner sign-in button (/enter) or open any other protected path.
    if (req.method === "GET" && pathOnly === "/") return noticePage(res);
    return deny(res);
  }
  if (pathOnly === "/enter") { res.writeHead(302, { Location: "/" }); res.end(); return; }
  if (pathOnly === "/view/desktop") return viewRedirect(res, "desktop");
  if (pathOnly === "/view/mobile") return viewRedirect(res, "mobile");
  if (pathOnly === "/signin" && req.method === "GET") return signinPage(res);
  if (pathOnly === "/signin/finish" && req.method === "POST") return finishSignin(req, res);
  if (pathOnly === "/backup" && req.method === "GET") return backupPage(res);
  if (pathOnly.startsWith("/backup/") && req.method === "GET") return backupDownload(res, decodeURIComponent(pathOnly.slice("/backup/".length)));
  const fwdHeaders = { ...req.headers, host: `${TARGET_HOST}:${TARGET_PORT}` };
  if (hubView(req) === "desktop") fwdHeaders["user-agent"] = DESKTOP_UA;
  const upstream = http.request(
    { host: TARGET_HOST, port: TARGET_PORT, path: req.url, method: req.method, headers: fwdHeaders },
    (up) => {
      // HTML gets the PWA snippet spliced into <head>; everything else
      // streams through untouched.
      const ct = (up.headers["content-type"] || "").toLowerCase();
      if (ct.includes("text/html")) return sendUpstreamHtml(res, up, hubView(req));
      res.writeHead(up.statusCode || 502, up.headers); up.pipe(res);
    }
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
    if (hubView(req) === "desktop") fwd["user-agent"] = DESKTOP_UA;
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
