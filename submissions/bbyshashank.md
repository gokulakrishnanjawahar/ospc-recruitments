# Security Assessment — bbyshashank

**Challenge commit:** main
**Date:** 2026-10-10

> 

## Finding 1 — Mass assignment in profile update allows privilege escalation

- **Severity:** High
- **Affected file and line(s):** `src/server.js`, around line 64 (`Object.assign(user, changes);`)
- **Affected route or feature:** `POST /api/profile`
- **Evidence:** The route parses the JSON body and copies every field into the signed-in user object. The profile page only mentions `displayName`, but nothing blocks other fields. Locally, while signed in as `alex`, sending `{"role":"admin"}` changes the role. `GET /admin` (which only checks `user.role !== "admin"`) then shows the admin page.
- **Impact:** Any signed-in user can make themselves admin and reach admin-only features. They could also overwrite other fields such as `username` or `password`.
- **Recommended mitigation:** Copy only an allowlist of fields (here, `displayName`) and validate its type and length. Never let a client set `role`.

## Finding 2 — Passwords stored and compared in plain text

- **Severity:** Medium
- **Affected file and line(s):** `src/data.js`, lines ~4-7 (`password: "maple123"` and similar); `src/server.js`, line ~28 (password comparison in `POST /login`)
- **Affected route or feature:** Account storage and `POST /login`
- **Evidence:** Passwords are stored exactly as typed, and login checks `item.password === body.get("password")`.
- **Impact:** If the data is ever exposed (leak, backup, logging, a future bug), all passwords are readable at once. Users often reuse passwords on other sites.
- **Recommended mitigation:** Store only salted hashes made with a slow password-hashing function (bcrypt, scrypt or Argon2) and compare hashes on login.

## Finding 3 — Forgeable session cookie

- **Severity:** High
- **Affected file and line(s):** `src/web.js`, `makeSessionToken` (lines ~31-33) and `getUserFromRequest` (lines ~35-42)
- **Affected route or feature:** Authentication for every signed-in page
- **Evidence:** The `sid` cookie is only the text `<username>:ospc-demo-session` encoded in base64url. Encoding is not encryption and there is no secret or signature. `getUserFromRequest` decodes it and trusts the username inside. Anyone who knows a username can build the cookie for that user. Usernames can be guessed, and the demo accounts are shown on the home page.
- **Impact:** Account takeover without the password.
- **Recommended mitigation:** Use a random, unguessable session ID stored on the server, or sign the token with a secret key (for example HMAC) and add an expiry. Also set `HttpOnly` (and `Secure` when served over HTTPS) on the cookie.

## Finding 4 — Reflected cross-site scripting (XSS) in directory search

- **Severity:** Medium
- **Affected file and line(s):** `src/server.js`, lines ~75-79 (`value="${query}"` and `Results for: ${query}`)
- **Affected route or feature:** `GET /search?q=...` (no login needed)
- **Evidence:** The `q` parameter is inserted into the HTML without escaping. Locally, searching for `<script>alert(1)</script>` makes the page run that script.
- **Impact:** An attacker can send a victim a crafted link and run code in the victim's browser on this site. Because the session cookie has no `HttpOnly` flag, the script could read it, which combines with Finding 3.
- **Recommended mitigation:** HTML-escape all user input before putting it in a page (`<` to `&lt;`, `"` to `&quot;`, etc.), or use a templating library that escapes by default. Add a Content-Security-Policy header as defense in depth.

## Finding 5 — Broken access control on notes (IDOR)

- **Severity:** Medium
- **Affected file and line(s):** `src/server.js`, lines ~41-47 (`GET /api/notes/` handler)
- **Affected route or feature:** `GET /api/notes/<id>`
- **Evidence:** The route checks that the user is signed in but never checks that `note.owner === user.id`. Locally, signed in as `alex`, opening `/api/notes/202` returns Sam's private note.
- **Impact:** Any signed-in user can read every other user's notes by trying ids, which are small and predictable.
- **Recommended mitigation:** Before returning a note, check that it belongs to the signed-in user, and return 404 or 403 otherwise.

## Review notes

- **How I approached the review:** I ran the app locally, then read `src/server.js`, `src/web.js` and `src/data.js` and followed how login, sessions, profile updates, search and notes work. I used an AI assistant as a learning aid to understand the code and wrote up the findings myself.
- **Assumptions or limitations:** I treated this as a demo with in-memory data and only tested locally with the fictional accounts. Line numbers are approximate. I did not look for denial-of-service or deployment issues. A lower-severity extra: `/search` shows every user's email address without login.
