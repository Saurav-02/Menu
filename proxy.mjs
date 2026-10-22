// agy-hub gate proxy: Basic-auth gate + reverse proxy (HTTP + WebSocket)
// in front of the Antigravity hub on 127.0.0.1:4400.
// - Listens on 0.0.0.0:$PORT (Render assigns $PORT).
// - Every request (except /healthz) needs Basic auth: any username, password = $HUB_PASSWORD.
// - Dependency-free Node.js (http + net only).
import http from "node:http";
import net from "node:net";
import crypto from "node:crypto";

const PORT = Number(process.env.PORT || 10000);
const TARGET_HOST = "127.0.0.1";
const TARGET_PORT = 4400;
const PASSWORD = process.env.HUB_PASSWORD || "";

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
  res.writeHead(401, { "WWW-Authenticate": 'Basic realm="agy-hub"', "Content-Type": "text/plain" });
  res.end("Authentication required.\n");
}

const server = http.createServer((req, res) => {
  if (req.url === "/healthz") { res.writeHead(200, { "Content-Type": "text/plain" }); res.end("ok\n"); return; }
  if (!passwordOk(req)) return deny(res);
  const upstream = http.request(
    { host: TARGET_HOST, port: TARGET_PORT, path: req.url, method: req.method, headers: req.headers },
    (up) => { res.writeHead(up.statusCode || 502, up.headers); up.pipe(res); }
  );
  upstream.on("error", () => { if (!res.headersSent) res.writeHead(502); res.end("hub unreachable\n"); });
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
    const headers = Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join("\r\n");
    upstream.write(`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n${headers}\r\n\r\n`);
    if (head && head.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.on("error", () => socket.destroy());
  socket.on("error", () => upstream.destroy());
});

server.listen(PORT, "0.0.0.0", () => console.log(`gate proxy listening on :${PORT} -> ${TARGET_HOST}:${TARGET_PORT}`));
