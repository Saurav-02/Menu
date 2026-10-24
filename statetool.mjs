// statetool.mjs — pack/unpack the Antigravity chat state as a single
// .tar.gz, with zero dependencies (Node core only: fs + zlib).
//
// Why: Render wipes the container disk on every restart, taking the hub's
// conversation history with it. The sign-in token already survives via a
// Render secret file (see start.sh); this gives the chat state the same
// ride: proxy.mjs packs it for download on /backup, and start.sh unpacks
// the secret file `agy-state.tar.gz` back into place at boot.
//
// Used two ways:
//   - imported by proxy.mjs:  packState(baseDir) / stateInfo(baseDir)
//   - CLI (from start.sh):    node statetool.mjs unpack <archive> <destDir>
//                             node statetool.mjs pack <baseDir> <outFile>
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

// The chat state worth preserving, relative to ~/.gemini/antigravity-cli.
// Everything else in that dir is regenerable (bin/, log/, cache/...).
export const STATE_PATHS = [
  "conversations",
  "brain",
  "annotations",
  "conversation_summaries.db",
  "agyhub_summaries_proto.pb",
  "jetbox_summaries_proto.pb",
  "history.jsonl",
  "settings.json",
  "antigravity_state.pbtxt",
];

function walk(base, rel, out) {
  const abs = path.join(base, rel);
  let st;
  try { st = fs.statSync(abs); } catch { return; }
  if (st.isDirectory()) {
    out.push({ rel: rel + "/", size: 0, mode: st.mode, mtime: st.mtime, dir: true });
    for (const name of fs.readdirSync(abs).sort()) walk(base, path.join(rel, name), out);
  } else if (st.isFile()) {
    out.push({ rel, size: st.size, mode: st.mode, mtime: st.mtime, dir: false, abs });
  }
}

export function stateInfo(baseDir) {
  const entries = [];
  for (const rel of STATE_PATHS) walk(baseDir, rel, entries);
  let bytes = 0, newest = 0;
  for (const e of entries) { bytes += e.size; if (!e.dir && e.mtime.getTime() > newest) newest = e.mtime.getTime(); }
  return { files: entries.filter((e) => !e.dir).length, bytes, newest };
}

// --- minimal ustar writer -------------------------------------------------
function octal(value, len) {
  return value.toString(8).padStart(len - 1, "0") + "\0";
}

function tarHeader(name, size, mode, mtimeSec, type) {
  const h = Buffer.alloc(512);
  // Long names ride in a GNU longname entry; the header keeps a truncated
  // name that longname-aware readers (GNU tar, this file) ignore.
  h.write(name.slice(0, 100), 0, 100, "utf8");
  h.write(octal(mode & 0o7777, 8), 100, 8, "ascii");
  h.write(octal(0, 8), 108, 8, "ascii");
  h.write(octal(0, 8), 116, 8, "ascii");
  h.write(octal(size, 12), 124, 12, "ascii");
  h.write(octal(mtimeSec, 12), 136, 12, "ascii");
  h.write("        ", 148, 8, "ascii"); // checksum placeholder (spaces)
  h.write(type, 156, 1, "ascii");
  h.write("ustar\0", 257, 6, "ascii");
  h.write("00", 263, 2, "ascii");
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "ascii");
  return h;
}

function pad512(buf) {
  const rem = buf.length % 512;
  return rem === 0 ? buf : Buffer.concat([buf, Buffer.alloc(512 - rem)]);
}

export function packState(baseDir) {
  const entries = [];
  for (const rel of STATE_PATHS) walk(baseDir, rel, entries);
  const chunks = [];
  for (const e of entries) {
    if (e.rel.length > 100) {
      const nameBuf = Buffer.from(e.rel + "\0", "utf8");
      chunks.push(tarHeader("././@LongLink", nameBuf.length, 0o644, 0, "L"));
      chunks.push(pad512(nameBuf));
    }
    if (e.dir) {
      chunks.push(tarHeader(e.rel, 0, e.mode, Math.floor(e.mtime.getTime() / 1000), "5"));
    } else {
      const data = fs.readFileSync(e.abs);
      chunks.push(tarHeader(e.rel, data.length, e.mode, Math.floor(e.mtime.getTime() / 1000), "0"));
      chunks.push(pad512(data));
    }
  }
  chunks.push(Buffer.alloc(1024)); // end-of-archive marker
  return zlib.gzipSync(Buffer.concat(chunks), { level: 9 });
}

// Paste-safe form: base64 text of the packed archive. Render's secret-file
// editor is a paste box, and pasting raw binary corrupts it (seen live:
// gunzip "incorrect header check" at boot). Base64 is plain ASCII, so it
// survives paste, text editors, and chat apps untouched.
export function packStateText(baseDir) {
  return packState(baseDir).toString("base64");
}

// --- minimal ustar reader ---------------------------------------------------
export function unpackState(gzBuffer, destDir) {
  // Accept both the raw .tar.gz and its base64 text form (see above) —
  // sniff the gzip magic bytes; anything else is treated as base64 text.
  let raw = gzBuffer;
  if (!(raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b)) {
    raw = Buffer.from(raw.toString("utf8").replace(/\s+/g, ""), "base64");
  }
  const tar = zlib.gunzipSync(raw);
  const root = path.resolve(destDir);
  fs.mkdirSync(root, { recursive: true });
  let off = 0, longName = null, count = 0;
  while (off + 512 <= tar.length) {
    const h = tar.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    const rawName = h.subarray(0, 100).toString("utf8").replace(/\0.*$/s, "");
    const prefix = h.subarray(345, 500).toString("utf8").replace(/\0.*$/s, "");
    const size = parseInt(h.subarray(124, 136).toString("ascii").replace(/\0.*$/s, "").trim() || "0", 8);
    const mode = parseInt(h.subarray(100, 108).toString("ascii").replace(/\0.*$/s, "").trim() || "644", 8);
    const type = String.fromCharCode(h[156]);
    const data = tar.subarray(off + 512, off + 512 + size);
    if (type === "L") {
      longName = data.toString("utf8").replace(/\0.*$/s, "");
    } else {
      const name = longName || (prefix ? prefix + "/" + rawName : rawName);
      longName = null;
      const dest = path.resolve(root, name);
      if (dest !== root && !dest.startsWith(root + path.sep)) {
        throw new Error(`unsafe path in archive: ${name}`);
      }
      if (type === "5") {
        fs.mkdirSync(dest, { recursive: true });
      } else if (type === "0" || type === "\0") {
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, data);
        try { fs.chmodSync(dest, mode & 0o7777); } catch { /* best effort */ }
        count++;
      }
    }
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return count;
}

// --- CLI ---------------------------------------------------------------------
if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd, a, b] = process.argv.slice(2);
  if (cmd === "pack") {
    const buf = packState(a);
    fs.writeFileSync(b, buf);
    console.log(`packed ${buf.length} bytes -> ${b}`);
  } else if (cmd === "unpack") {
    const n = unpackState(fs.readFileSync(a), b);
    console.log(`unpacked ${n} files -> ${b}`);
  } else {
    console.error("usage: statetool.mjs pack <baseDir> <outFile> | unpack <archive> <destDir>");
    process.exit(2);
  }
}
