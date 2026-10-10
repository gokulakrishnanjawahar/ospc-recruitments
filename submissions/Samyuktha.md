Security Assessment — Samyuktha

**Challenge commit:** main
**Date:** 2026-10-10

> Include only findings you can explain. Do not edit application code in this PR.

## Finding 1 — Insecure Direct Object Reference (IDOR) on Notes
- **Severity:** Medium
- **Affected file and line(s):** `server.js`, lines 45–52
- **Affected route or feature:** `/api/notes/:id`
- **Evidence:** The route fetches notes via `notes.find(item => item.id === id)` without verifying whether the currently logged-in user owns that specific note.
- **Impact:** An authenticated user can iterate through numeric note IDs to read private notes belonging to other users.
- **Recommended mitigation:** Verify that `note.owner === user.id` before returning note contents.

## Finding 2 — Mass Assignment Vulnerability in Profile Update
- **Severity:** High
- **Affected file and line(s):** `server.js`, lines 61–68
- **Affected route or feature:** `POST /api/profile`
- **Evidence:** The endpoint parses incoming JSON and uses `Object.assign(user, changes)` directly on the user record without restricting allowed fields.
- **Impact:** An attacker can inject `"role": "admin"` into the JSON payload to elevate their privileges to administrator.
- **Recommended mitigation:** Explicitly assign only safe properties (e.g., `displayName`) instead of blindly merging the entire JSON object.

## Finding 3 — Reflected Cross-Site Scripting (XSS) in Directory Search
- **Severity:** Medium
- **Affected file and line(s):** `server.js`, lines 74–79
- **Affected route or feature:** `/search` query string parameter `q`
- **Evidence:** The search term `q` is reflected directly into the HTML template string via template literals (`<h2>Results for: ${query}</h2>`) without escaping.
- **Impact:** An attacker can craft a malicious URL with JavaScript payload that executes in the browser of users viewing the search results page.
- **Recommended mitigation:** HTML-escape or sanitize user search input before rendering it back in the template.

## Finding 4 — Plaintext Password Storage
- **Severity:** Medium
- **Affected file and line(s):** `src/data.js`, lines 1–6
- **Affected route or feature:** User database / Authentication
- **Evidence:** User passwords are saved in plain text (`password: "maple123"`) and compared directly during login checks.
- **Impact:** Any compromise of the data source or source code repository immediately exposes user credentials in cleartext.
- **Recommended mitigation:** Use strong cryptographic hashing algorithms (such as bcrypt or Argon2) with unique salts for passwords.

## Finding 5 — Insecure / Reversible Session Token Encoding
- **Severity:** Medium
- **Affected file and line(s):** `src/web.js`, lines 35–43
- **Affected route or feature:** Session cookie generation (`makeSessionToken`)
- **Evidence:** Session cookies are encoded using simple unsigned Base64URL based on the username (`username:ospc-demo-session`).
- **Impact:** Users can decode their session cookie, modify the username to target other accounts (e.g., `alex`), re-encode it, and bypass authorization.
- **Recommended mitigation:** Use cryptographically signed tokens or secure server-side session IDs.

## Review notes
- **How I approached the review:** Performed static source code analysis of the route handlers, authentication flows, and data access logic.
- **Assumptions or limitations:** Evaluated statically using the provided fictional local dataset.
