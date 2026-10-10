# Security Review — OSPC Recruitment Challenge

**Challenge commit:** a1a053f2d268540278ca52a40b07d864398f3546

**Date:** 10 October 2026

## Finding 1 — Passwords Are Stored as Plain Text

- **Severity:** Low
- **Affected file and line(s):** `src/data.js` — user records (verify exact lines).
- **Affected route or feature:** User data and login.
- **Evidence:** In `data.js`, the user objects contain passwords as normal strings. In `server.js`, the login code compares the password entered by the user with the stored password. This means the passwords can be read directly from the source code.
- **Impact:** Anyone who can access the source code or stored user data can see these passwords. In this challenge, the accounts use fictional data, so the immediate risk is limited.
- **Recommended mitigation:** For a real application, passwords should be stored as secure password hashes using a suitable algorithm such as Argon2id or bcrypt, rather than as plain text.

## Finding 2 — Session Tokens Are Predictable

- **Severity:** High
- **Affected file and line(s):** `src/web.js` — `makeSessionToken()` and `getUserFromRequest()` (verify exact lines).
- **Affected route or feature:** Login and session authentication.
- **Evidence:** The session token is created using the username and a fixed string, then encoded using Base64URL. Base64URL only changes how data is represented; it does not protect the data. The session-handling code decodes the token and identifies the user without verifying a cryptographic signature or an unpredictable session identifier.
- **Impact:** Someone who understands how the token is created may be able to create a cookie for another fictional user. If the server accepts that cookie, the attacker could access that user's account.
- **Recommended mitigation:** Generate unpredictable session IDs using a cryptographically secure random generator and validate sessions securely on the server. Alternatively, use properly signed tokens with appropriate validation.

## Finding 3 — The Notes API Does Not Check Note Ownership

- **Severity:** Medium
- **Affected file and line(s):** `src/server.js` — `GET /api/notes/:id` (verify exact lines).
- **Affected route or feature:** Viewing notes.
- **Evidence:** The notes endpoint checks whether the user is logged in and then searches for a note using its ID. However, the code does not appear to check whether the note belongs to the logged-in user before returning its contents. The dashboard filters notes by owner, so the API should enforce the same restriction.
- **Impact:** A logged-in user may be able to view another user's note if they know or can guess its ID. This could expose information that should be private.
- **Recommended mitigation:** Before returning a note, check that its owner matches the logged-in user's ID. Only allow access to another user's note when the requester has explicit permission.

## Finding 4 — Profile Updates May Allow Users to Change Their Role

- **Severity:** High
- **Affected file and line(s):** `src/server.js` — `POST /api/profile` (verify exact lines).
- **Affected route or feature:** Editing a user's profile.
- **Evidence:** The profile-update handler uses `Object.assign(user, changes)` to copy the submitted properties into the user object. The code does not appear to restrict updates to fields such as `displayName`. Since the user object also contains a `role` property, this could allow a user to modify a field that should be controlled by the application.
- **Impact:** If the server accepts a user-supplied role change, a normal member could potentially give themselves administrative privileges and access restricted features.
- **Recommended mitigation:** Allow users to update only specific fields, such as `displayName`. The server should reject changes to sensitive fields like `role` and check permissions on every administrative route.

## Finding 5 — User Input Is Inserted into HTML Without Escaping

- **Severity:** High
- **Affected file and line(s):** `src/server.js` — directory search and HTML-generating routes; `src/web.js` — `page()` helper (verify exact lines).
- **Affected route or feature:** Directory search and page rendering.
- **Evidence:** The application builds HTML using template strings and inserts values such as search queries, display names, and note titles into the generated page. These values are not consistently escaped before being inserted into HTML. If a value contains HTML or JavaScript, the browser may interpret it as code instead of ordinary text.
- **Impact:** If an attacker can get crafted input displayed to another user, it may be possible to execute JavaScript in that user's browser under the application's origin. The actual impact depends on which values can be controlled and where they are displayed.
- **Recommended mitigation:** Escape untrusted values according to their HTML context. Use a templating engine with automatic escaping or safe text-rendering methods instead of inserting untrusted values directly into HTML.

## Review notes

- **How I approached the review:** I started by looking at the user data in `data.js`. Then I followed how login and session handling work in `web.js`. After that, I checked the routes in `server.js`, especially profile updates, note access, and HTML generation. I also tried the documented profile-update request using the fictional data provided by the application.

- **Assumptions or limitations:** This review is based on the source code of the training application and its fictional accounts. I have not confirmed that every potential exploit works. The exact line numbers should be checked against the challenge commit. The session, profile-update, and HTML-injection issues need safe local testing to confirm their exploitability. The plaintext passwords are synthetic demo credentials, so that finding may be less important than the others. No application code was modified.
