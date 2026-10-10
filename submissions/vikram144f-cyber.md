# Security Assessment — vikram144f-cyber

**Challenge commit:** main
**Date:** 2026-10-10

> Include only findings you can explain. Do not edit application code in this PR.

## Finding 1 — Mass Assignment Privilege Escalation to Admin

- **Severity:** Critical
- **Affected file and line(s):** `src/server.js:58-66`
- **Affected route or feature:** `POST /api/profile`
- **Evidence:**
  The profile update handler directly applies attacker-controlled JSON properties to the user record in memory via `Object.assign` without filtering permitted fields:
  ```javascript
  let changes;
  try { changes = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: "expected JSON" }); }
  if (!changes || typeof changes !== "object" || Array.isArray(changes)) return json(res, 400, { error: "expected a JSON object" });
  Object.assign(user, changes);
  return json(res, 200, { ok: true, profile: { username: user.username, displayName: user.displayName, role: user.role } });
  ```
  **Local Reproduction Steps:**
  1. Sign in as demo user `alex` (`maple123`).
  2. While authenticated, submit a POST request to `/api/profile` using browser console or HTTP client:
     ```javascript
     fetch('/api/profile', {
       method: 'POST',
       headers: { 'Content-Type': 'application/json' },
       body: JSON.stringify({ role: 'admin' })
     });
     ```
  3. Navigate to `http://127.0.0.1:3000/admin`. The authorization check (`user.role !== "admin"`) passes and renders the admin page containing the flag `OSPC{synthetic_training_flag}`.
- **Impact:** Any standard authenticated user can arbitrarily elevate their role to `admin` or overwrite internal account properties (including passwords or IDs), gaining complete administrative compromise over the application.
- **Recommended mitigation:** Enforce a strict allowlist of modifiable fields and assign each field explicitly instead of performing an unconstrained `Object.assign`:
  ```javascript
  if (typeof changes.displayName === "string") {
    user.displayName = changes.displayName;
  }
  ```

## Finding 2 — Insecure Direct Object Reference (IDOR) on Notes Endpoint

- **Severity:** High
- **Affected file and line(s):** `src/server.js:41-48`
- **Affected route or feature:** `GET /api/notes/:id`
- **Evidence:**
  The endpoint verifies that the incoming request is authenticated with `getUserFromRequest(req)`, but does not check whether the requested note is owned by the authenticated user (`note.owner === user.id`):
  ```javascript
  const id = Number(url.pathname.split("/").pop());
  const note = notes.find(item => item.id === id);
  if (!note) return json(res, 404, { error: "note not found" });
  return json(res, 200, { id: note.id, title: note.title, body: note.body });
  ```
  **Local Reproduction Steps:**
  1. Sign in as `alex` (`maple123`), whose assigned note ID is `101`.
  2. In the browser or terminal, send a request to `http://127.0.0.1:3000/api/notes/202` (which belongs to user `sam`).
  3. The server responds with `200 OK` exposing `sam`'s private note content: `{"id":202,"title":"Club idea","body":"Try a beginner-friendly web security workshop."}`.
- **Impact:** Any logged-in user can access private notes created by any other user by simply enumerating sequential integer IDs.
- **Recommended mitigation:** Verify resource ownership against the current session user ID before returning data:
  ```javascript
  if (note.owner !== user.id) {
    return json(res, 403, { error: "forbidden" });
  }
  ```

## Finding 3 — Reflected Cross-Site Scripting (XSS) in Directory Search

- **Severity:** High
- **Affected file and line(s):** `src/server.js:75-80`
- **Affected route or feature:** `GET /search`
- **Evidence:**
  The `q` query parameter is read directly from the URL and concatenated unescaped into both an HTML input attribute and an `<h2>` heading:
  ```javascript
  const query = url.searchParams.get("q") || "";
  ...
  return send(res, 200, page("Directory search", `<h1>Club directory search</h1><form method="get" action="/search"><label>Search names <input name="q" value="${query}"></label><button>Search</button></form><h2>Results for: ${query}</h2><ul>${items}</ul><p><a href="/">Home</a></p>`));
  ```
  **Local Reproduction Steps:**
  1. Open a browser and visit:
     `http://127.0.0.1:3000/search?q=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E`
  2. The raw HTML response renders `<input name="q" value=""><script>alert(document.domain)</script>">`.
  3. An alert dialog box executes in the browser.
- **Impact:** An attacker can construct a malicious link and send it to legitimate users. When clicked, arbitrary JavaScript executes in the context of the victim's session. Since session cookies lack the `HttpOnly` flag, the attacker can extract credentials, hijack the session, or perform actions on behalf of the victim.
- **Recommended mitigation:** Escape untrusted input before rendering it in HTML contexts by converting characters like `&`, `<`, `>`, `"`, and `'` to their respective HTML entities.

## Finding 4 — Forged Session Authentication via Predictable Session Tokens

- **Severity:** High
- **Affected file and line(s):** `src/web.js:31-42`
- **Affected route or feature:** Session Token Generation & Verification
- **Evidence:**
  Session tokens are generated using simple Base64URL encoding without a cryptographic signature (HMAC), secret key, or server-side random session storage:
  ```javascript
  function makeSessionToken(username) {
    return Buffer.from(`${username}:ospc-demo-session`).toString("base64url");
  }

  function getUserFromRequest(req) {
    const token = cookies(req).sid;
    if (!token) return null;
    try {
      const username = Buffer.from(token, "base64url").toString().split(":")[0];
      return users.find(user => user.username === username) || null;
    } catch { return null; }
  }
  ```
  **Local Reproduction Steps:**
  1. Compute the Base64URL representation of an arbitrary username with `:ospc-demo-session`:
     `Buffer.from("sam:ospc-demo-session").toString("base64url")` evaluates to `c2FtOm9zcGMtZGVtby1zZXNzaW9u`.
  2. Without logging in, send an HTTP request with the cookie header:
     `Cookie: sid=c2FtOm9zcGMtZGVtby1zZXNzaW9u`
  3. Request `http://127.0.0.1:3000/dashboard`. The server decodes `sam` from the cookie and grants full access to Sam's account without requiring credentials.
- **Impact:** An attacker can bypass the login mechanism and forge valid session tokens for any known user account simply by constructing the predictable string format.
- **Recommended mitigation:** Implement cryptographically secure session identifiers generated with `crypto.randomBytes()`, stored in a server-side session registry, or use cryptographically signed tokens (e.g., HMAC-SHA256) backed by a strong secret key.

## Finding 5 — Missing `HttpOnly` Cookie Flag on Session Cookie

- **Severity:** Medium
- **Affected file and line(s):** `src/server.js:30`
- **Affected route or feature:** `POST /login`
- **Evidence:**
  When a user signs in, the server sets the `sid` cookie without the `HttpOnly` or `Secure` attributes:
  ```javascript
  return send(res, 302, "", "text/plain; charset=utf-8", { "Set-Cookie": `sid=${makeSessionToken(user.username)}; Path=/; SameSite=Lax`, Location: "/dashboard" });
  ```
  **Local Reproduction Steps:**
  1. Sign in as `alex`.
  2. Open the browser developer console and run `document.cookie`.
  3. The `sid` cookie is printed in plaintext and fully accessible to client-side scripts.
- **Impact:** When paired with the Reflected XSS vulnerability in Finding 3, client-side scripts injected by an attacker can read `document.cookie` directly and exfiltrate session tokens over the network.
- **Recommended mitigation:** Append `HttpOnly` (and `Secure` in HTTPS environments) to the `Set-Cookie` header:
  ```javascript
  { "Set-Cookie": `sid=${makeSessionToken(user.username)}; Path=/; SameSite=Lax; HttpOnly; Secure` }
  ```

## Review notes

- **How I approached the review:**
  - Performed manual source code auditing starting from request routing in `src/server.js` and helper utilities in `src/web.js`.
  - Audited data boundaries and access control checks on endpoints (`/api/notes/:id`, `/api/profile`, `/admin`).
  - Tested input reflection paths on `/search` for sanitization and output encoding.
  - Verified authentication workflows and session generation mechanics in `src/web.js`.
  - Replicated each potential finding on the running local instance (`http://127.0.0.1:3000`) using synthetic test accounts.
- **Assumptions or limitations:**
  - The application is an in-memory single-process Node.js demonstration with synthetic accounts (`alex`, `sam`).
  - No database engines (SQL or NoSQL) are present; all queries rely on native JavaScript array filters.
  - No application code was modified as required by the challenge instructions.
