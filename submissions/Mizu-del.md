# OSPC Security Review

**Challenge commit:** `a1a053f2d268540278ca52a40b07d864398f3546`  
**Date:** 2026-10-10

## Finding 1: Forged session cookie permits authentication bypass

- **Severity:** High
- **Affected file:** `src/web.js`, lines 31–42
- **Affected feature:** Session authentication
- **Evidence:** Generated the Base64URL value for `alex:forged` and sent it as the `sid` cookie without logging in. The request to `/api/notes/101` returned HTTP 200 and Alex's note.
- **Impact:** An unauthenticated person who can construct a suitable session cookie may impersonate a user and access their data.
- **Recommended mitigation:** Generate session identifiers using cryptographically secure randomness and validate them against server-side session records, or use a properly authenticated session mechanism. Never trust a username extracted from an unsigned client-controlled token.

## Finding 2: Broken object-level authorization exposes another user's note

- **Severity:** High
- **Affected file:** `src/server.js`, lines 41–48
- **Affected feature:** `GET /api/notes/:id`
- **Evidence:** While authenticated as Alex, requested `/api/notes/202`. The server returned Sam's note, including its title and body.
- **Impact:** Authenticated users can access notes belonging to other users by changing the note ID.
- **Recommended mitigation:** Verify that the requested note belongs to the authenticated user before returning its contents. Deny access when ownership does not match.

## Finding 3: Mass assignment permits privilege escalation

- **Severity:** High
- **Affected file:** `src/server.js`, lines 58–66
- **Affected feature:** `POST /api/profile`
- **Evidence:** While authenticated as Alex, submitted a JSON body containing `{"role":"admin"}`. The role change succeeded, and the `/admin` page became accessible.
- **Impact:** A normal user can grant themselves administrative privileges and access functionality restricted to administrators.
- **Recommended mitigation:** Accept only explicitly permitted profile fields using an allowlist. Never allow users to modify authorization-related fields such as `role` through a general profile-update endpoint.

## Finding 4: Reflected HTML injection in search results

- **Severity:** Medium
- **Affected file:** `src/server.js`, lines 75–80
- **Affected feature:** `GET /search`
- **Evidence:** Visited `/search?q=%3Cem%3Etest%3C%2Fem%3E`. The word `test` was rendered in italics, demonstrating that supplied search input was interpreted as HTML.
- **Impact:** Unescaped input is inserted into the returned HTML. Depending on which markup or script contexts are exploitable, this may expose users to cross-site scripting.
- **Recommended mitigation:** HTML-escape untrusted input before inserting it into HTML, or use context-aware template escaping. Further testing is required to establish whether JavaScript execution is possible.

## Review notes

Reviewed the application source code and tested the identified behaviors against the local demo using its synthetic training data. The session-forgery, cross-user note access, and role-escalation findings were verified through HTTP requests. The search finding was verified as HTML injection; JavaScript execution was not established. No application code was modified.
