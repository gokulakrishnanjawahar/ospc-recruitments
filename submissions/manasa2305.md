# Security Assessment — manasa2305

**Challenge commit:** `a1a053f`  
**Date:** 2026-10-10

## Finding 1 — Broken Access Control in Notes API (IDOR)

- **Severity:** Medium
- **Affected file and line(s):** `src/server.js`, approximately lines 41–48
- **Affected route or feature:** `GET /api/notes/:id`
- **Evidence:** The endpoint checks whether a user is authenticated and retrieves a note using `notes.find(item => item.id === id)`. It does not verify that the requested note's `owner` matches the authenticated user's ID.

  During local testing, while signed in as Alex, I ran the following command in the browser console:

  ```javascript
  fetch("/api/notes/202")
    .then(r => r.json())
    .then(console.log);
  ```

  The API returned note `202`, titled `Club idea`, with its body, even though that note belongs to Sam. This demonstrates that an authenticated user can access another user's note by specifying its ID.

- **Impact:** Any authenticated user who can identify or guess another user's note ID may be able to read that user's private notes.
- **Recommended mitigation:** Verify ownership on every note access by checking that the note belongs to the authenticated user before returning its contents. Return an appropriate denial or not-found response when access is unauthorized.

## Finding 2 — Predictable Session Tokens Allow Account Impersonation

- **Severity:** High
- **Affected file and line(s):** `src/web.js`, approximately lines 31–40
- **Affected route or feature:** Session creation and authentication across protected routes
- **Evidence:** `makeSessionToken()` creates a token by Base64url-encoding the username and a fixed string. `getUserFromRequest()` decodes the supplied cookie, extracts the username, and retrieves the corresponding user without verifying a signature or validating a server-side session.

  During local testing, setting the predictable session cookie resulted in a dashboard authenticated as Sam without entering Sam's password.

  **Reproduction steps:**

  1. Started the application locally at `http://127.0.0.1:3000`.
  2. Signed out of the application.
  3. Opened the browser Developer Tools Console.
  4. Set the predictable session cookie and navigated to the dashboard:

     ```javascript
     document.cookie = "sid=c2FtOm9zcGMtZGVtby1zZXNzaW9u; path=/";
     location.href = "/dashboard";
     ```

  5. Observed that the dashboard displayed Sam's account without requiring Sam's password.

  **Result:** The application accepted the predictable cookie as an authenticated session.

- **Impact:** An attacker who can construct a token for a known username may impersonate that user and access functionality available to that account.
- **Recommended mitigation:** Generate cryptographically random session identifiers and validate them against server-side session records. Configure appropriate cookie attributes, including `HttpOnly`, `Secure` when using HTTPS, and `SameSite`. Invalidate sessions on logout and relevant authentication changes.

## Finding 3 — Mass Assignment Allows Privilege Escalation

- **Severity:** High
- **Affected file and line(s):** `src/server.js`, approximately lines 60–67
- **Affected route or feature:** `POST /api/profile`
- **Evidence:** The `POST /api/profile` handler applies all properties supplied in the request body to the authenticated user's object using `Object.assign(user, changes)`, without restricting updates to approved profile fields.

  While signed in as Alex, whose initial role was `member`, I ran the following command in the browser console:

  ```javascript
  fetch("/api/profile", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role: "admin" })
  })
    .then(r => r.json())
    .then(console.log);
  ```

  After the request, the dashboard displayed Alex's role as `admin`. This demonstrates that a member can modify a security-sensitive field through the profile endpoint.

- **Impact:** An authenticated member can elevate their privileges and access administrator-only functionality, including the admin area.
- **Recommended mitigation:** Allowlist editable profile fields, such as `displayName`, and reject unauthorized changes to security-sensitive fields such as `role`. Enforce server-side authorization for administrative functionality.

## Finding 4 — Reflected Cross-Site Scripting (XSS) in Directory Search

- **Severity:** Medium
- **Affected file and line(s):** `src/server.js`, approximately lines 83–88
- **Affected route or feature:** `GET /search`
- **Evidence:** The application reads the `q` query parameter and interpolates it directly into generated HTML in both the search results heading and the input's `value` attribute.

  During local testing, I opened this crafted URL in the browser:

  ```text
  http://127.0.0.1:3000/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E
  ```

  A JavaScript alert displaying `127.0.0.1` appeared. This demonstrates that the user-controlled search parameter was interpreted as HTML and caused JavaScript to execute in the local application's origin.

- **Impact:** An attacker may craft a search URL that executes JavaScript in the browser of a user who opens it. Depending on the victim's session and the application's security controls, this could expose page data or enable actions in the victim's authenticated context.
- **Recommended mitigation:** Contextually encode untrusted values before inserting them into HTML text and attributes. Prefer safe DOM APIs for rendering user-controlled content, and consider an appropriate Content Security Policy as an additional defense.

## Review notes

- **How I approached the review:** Reviewed the application source in `src/server.js`, `src/web.js`, and `src/data.js`. Ran the application locally and used only the supplied fictional demo accounts and data. Tested note ownership, search rendering, profile updates, and session handling in the local browser.
- **Assumptions or limitations:** Testing was limited to the local challenge application and its synthetic data. Severity ratings are based on observed behavior and may be adjusted to match the challenge's severity guidance. The findings describe the tested implementation; no application code changes were made as part of this assessment.
