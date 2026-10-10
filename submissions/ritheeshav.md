```markdown
# Security Assessment — <ritheeshav>

**Challenge commit:** <main>
**Date:** 2026-10-10

> Include only findings you can explain. Do not edit application code in this PR.

## Finding 1 — Insecure Direct Object Reference (IDOR) in Note Viewing

- **Severity:** High
- **Affected file and line(s):** `src/server.js` within the `GET /api/notes/:id` route logic.
- **Affected route or feature:** Note viewing API (`/api/notes/:id`)
- **Evidence:** The application retrieves note data based solely on the `id` parameter provided in the user's request without verifying ownership.
  1. Logged into the application as the demo user `alex` (User ID 1).
  2. Navigated to Alex's "Weekend plan" note via the dashboard link (Note ID `101`).
  3. Modified the note ID in the browser's address bar to point to an unowned ID, such as `/api/notes/202`.
  4. The application successfully loaded and displayed "Club idea", a private note belonging to `sam` (User ID 2), bypassing intended access controls.
- **Impact:** An authenticated attacker can arbitrarily access and read private notes belonging to any other user on the platform by sequentially guessing or brute-forcing note ID numbers. This results in a complete breach of data confidentiality for user notes.
- **Recommended mitigation:** Implement authorization checks on the backend route. Before sending the note data to the client, verify that the `owner` attribute of the requested note exactly matches the `id` of the currently authenticated user session. If they do not match, return an HTTP 403 Forbidden response.

## Finding 2 — Insecure Session Management via Predictable Base64 Tokens

- **Severity:** Critical
- **Affected file and line(s):** `src/web.js`, specifically within the `makeSessionToken` and `getUserFromRequest` functions.
- **Affected route or feature:** Authentication and Session Management (`sid` cookie)
- **Evidence:** The application does not use cryptographically secure or randomized session identifiers. Instead, it creates session tokens by base64-encoding a predictable string format: `<username>:ospc-demo-session`.
  1. Logged in as the standard demo user `alex`.
  2. Generated a base64 encoded payload for the target user `sam` using the known format: `btoa('sam:ospc-demo-session')`, resulting in the string `c2FtOm9zcGMtZGVtby1zZXNzaW9u`.
  3. Replaced the existing `sid` cookie value in the browser's developer tools with this forged base64 string.
  4. Refreshed the page and successfully hijacked Sam's authenticated session, viewing their dashboard without requiring a password.
- **Impact:** An attacker can trivially forge a valid session cookie for any known username on the platform. This leads to complete account takeover, allowing the attacker to view private data, perform actions on behalf of the victim, and potentially escalate privileges if an administrative username is known or guessed.
- **Recommended mitigation:** Replace the base64 encoding mechanism with a secure session management approach. Use cryptographically strong, random session IDs stored in a secure backend store (e.g., Redis or a database), or implement properly signed JSON Web Tokens (JWTs) using a strong, secret cryptographic key.

## Finding 3 — Privilege Escalation via Mass Assignment

- **Severity:** High
- **Affected file and line(s):** `src/server.js` within the `POST /api/profile` route block.
- **Affected route or feature:** Profile Update API (`/api/profile`)
- **Evidence:** The application uses `Object.assign(user, changes);` to merge user-supplied JSON directly into the authenticated user's session object in memory without validating or restricting the submitted keys.
  1. Logged in as the standard user `alex`.
  2. Opened the browser's developer console and issued a custom POST request to `/api/profile` with the JSON payload: `{"role": "admin"}`.
  3. Navigated to `/admin`.
  4. The application granted access and displayed the restricted training flag, confirming the `role` property was successfully overwritten in the backend user object.
- **Impact:** Any authenticated standard user can elevate their privileges to an administrator role by modifying their own session properties. In a real-world scenario, this grants unauthorized access to restricted administrative features, sensitive user data, and system configurations.
- **Recommended mitigation:** Implement strict input whitelisting. Do not pass raw, unvalidated JSON objects directly into `Object.assign` or database update functions. Explicitly extract and map only the permitted fields from the request body (e.g., `user.displayName = changes.displayName || user.displayName;`).

## Review notes

- **How I approached the review:** I began with a black-box exploration of the application, logging in as the demo user `alex` to map out the accessible features, URLs, and data inputs (such as the search bar, profile updates, and note viewing). Once I understood the intended application logic, I transitioned to a white-box source code review, specifically targeting the routing files (`src/server.js` and `src/web.js`) that handled the features I had manually explored. I looked specifically for missing authorization checks, improper input sanitization, and insecure session generation.
- **Assumptions or limitations:** The assessment was strictly limited to the local, synthetic environment provided in the repository. I assumed the underlying Node.js runtime and host operating system were secure. The review focused purely on application-layer logic flaws (such as IDOR, Mass Assignment, and XSS) without conducting automated vulnerability scanning or testing external infrastructure.