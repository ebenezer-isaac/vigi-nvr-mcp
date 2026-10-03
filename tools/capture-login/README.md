# capture-login (optional dev utility)

A one-shot script that drives the VIGI NVR's own web UI in headless Chrome. It
logs in **once** and records the JSON request/response envelopes the UI sends.

**This tool is not part of the MCP server.** The server does not import it,
does not need Node, and runs no browser. Installing the Python package or
running its tests never touches this folder. It has its own `package.json`.

## When to use it

Use it once, to check the login envelope on firmware this project has not
been tested on. That covers the request shape, `encrypt_type`, how the
password field is built, and the reply. Use it only on **a device you own or
administer**.

For routine checks, use the browser-free CLI instead:

```sh
vigi-nvr-mcp --check-auth           # challenge only, no login
vigi-nvr-mcp --check-auth --login   # plus exactly one login
```

## Safety

- It makes **exactly one** login attempt and never retries. VIGI NVRs lock the
  admin account after repeated failures. Check the password before running.
- If the page sends a second login request, the script aborts.
- The plaintext password is never written to disk. Request bodies are saved
  as sent; the UI RSA-encrypts the password field before sending it.
- Outputs go to `./captures/` (git-ignored, mode 0600): `capture.json` and
  `stok.txt`. **Both contain a live session token. Do not share or commit them.**
  Delete them when you are done. On firmware that uses `encrypt_type` 1, the
  captured password field is a password-equivalent hash, so treat it as a secret.

## Usage

```sh
cd tools/capture-login
npm install            # installs puppeteer-core only; uses your system Chrome
NVR_HOST=<nvr-host> NVR_USER=admin NVR_PASS='<password>' \
  CHROME_PATH=/path/to/chrome node capture.js
```

The login form selectors (`#userName`, `#lgPwd`, `#loginSub`) match firmware
1.1.3. Adjust `SELECTORS` in `capture.js` if your firmware differs.

Passing the password through the environment keeps it out of shell history
only if your shell is set up for that. Prefer `read -s NVR_PASS; export NVR_PASS`.
