#!/usr/bin/env node
/*
 * One-shot login-envelope capture for a TP-Link VIGI NVR YOU OWN OR ADMINISTER.
 *
 * Optional dev utility. Not part of the MCP server, not imported by it, not
 * needed to install or test it. Use it once to see exactly what the vendor web
 * UI sends when it logs in, so the server's auth flow can be confirmed against
 * your firmware. For day-to-day checks prefer `tplink-local-mcp --check-auth`.
 *
 * Makes EXACTLY ONE login attempt. Never retries. Writes captures/capture.json
 * and captures/stok.txt (both contain a live session token: do not share them).
 * The plaintext password is never written anywhere.
 *
 *   NVR_HOST=<nvr-host> NVR_USER=admin NVR_PASS=... CHROME_PATH=/path/to/chrome \
 *     node capture.js
 */
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const puppeteer = require("puppeteer-core");

const SELECTORS = { user: "#userName", pass: "#lgPwd", submit: "#loginSub" }; // fw 1.1.3
const SETTLE_MS = 5000;
const TIMEOUT_MS = 30000;

function requireEnv(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (!value) {
    console.error(`missing required environment variable ${name}`);
    process.exit(2);
  }
  return value;
}

function chromePath() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const candidates = [
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  ];
  const found = candidates.find((p) => fs.existsSync(p));
  if (!found) {
    console.error("Chrome not found; set CHROME_PATH");
    process.exit(2);
  }
  return found;
}

const KEPT_HEADERS = new Set(["content-type", "x-requested-with", "accept"]);

function keepHeaders(headers) {
  return Object.fromEntries(
    Object.entries(headers).filter(([k]) => KEPT_HEADERS.has(k.toLowerCase()) || k.startsWith("x-"))
  );
}

function writePrivate(file, text) {
  fs.writeFileSync(file, text, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

async function main() {
  const host = requireEnv("NVR_HOST");
  const user = requireEnv("NVR_USER", "admin");
  const pass = requireEnv("NVR_PASS");
  const origin = `https://${host}`;
  const outDir = path.resolve(process.cwd(), "captures");

  const exchanges = [];
  let loginSeen = false;
  let stok = null;

  const browser = await puppeteer.launch({
    executablePath: chromePath(),
    headless: true,
    acceptInsecureCerts: true, // NVRs use self-signed certificates
    args: ["--ignore-certificate-errors"],
  });
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(TIMEOUT_MS);

    page.on("response", async (response) => {
      const request = response.request();
      if (request.method() !== "POST" || !request.url().startsWith(origin)) return;
      const postData = request.postData() ?? "";
      let body = null;
      try {
        body = await response.text();
      } catch {
        body = null; // navigation may discard the body
      }
      const isLogin = /"login"\s*:/.test(postData);
      if (isLogin) {
        if (loginSeen) {
          console.error("a second login request was observed; aborting");
          process.exit(3);
        }
        loginSeen = true;
        const match = body && body.match(/"stok"\s*:\s*"([0-9A-Fa-f]+)"/);
        if (match) stok = match[1];
      }
      exchanges.push({
        path: new URL(request.url()).pathname,
        request_headers: keepHeaders(request.headers()),
        request_body: postData, // sent as-is; the password field is RSA-encrypted
        status: response.status(),
        response_body: body,
        is_login: isLogin,
      });
    });

    await page.goto(origin, { waitUntil: "networkidle2" });
    await page.waitForSelector(SELECTORS.user);
    await page.click(SELECTORS.user, { clickCount: 3 });
    await page.type(SELECTORS.user, user);
    await page.type(SELECTORS.pass, pass);
    await page.click(SELECTORS.submit); // the one and only login attempt
    await new Promise((resolve) => setTimeout(resolve, SETTLE_MS));
  } finally {
    await browser.close();
  }

  let serialized = JSON.stringify(
    {
      warning: "Contains a live session token. Do not share. Delete when done.",
      captured_at: new Date().toISOString(),
      login_attempts: loginSeen ? 1 : 0,
      exchanges,
    },
    null,
    2
  );
  if (serialized.includes(pass)) {
    // Defensive: should never happen because the UI encrypts the password.
    serialized = serialized.split(pass).join("<plaintext-password-removed>");
    console.error("warning: plaintext password appeared in traffic and was removed");
  }

  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  writePrivate(path.join(outDir, "capture.json"), serialized + "\n");
  if (stok) writePrivate(path.join(outDir, "stok.txt"), stok + "\n");

  console.log(`wrote ${exchanges.length} exchange(s) to ${outDir}`);
  console.log(loginSeen ? (stok ? "login succeeded" : "login attempted; no token returned") : "no login request observed");
  if (!stok) process.exitCode = 1;
}

main().catch((err) => {
  console.error(`capture failed: ${err && err.message ? err.message : err}`);
  process.exit(1);
});
