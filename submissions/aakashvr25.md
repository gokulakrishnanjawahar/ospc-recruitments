# Security Assessment — aakashvr25

**Challenge commit:** a1a053f
**Date:** 2026-10-10

> Include only findings you can explain. Do not edit application code in this PR.

## Finding 1 — Forgeable, non-expiring session token (authentication bypass)

- **Severity:** Critical
- **Affected file and line(s):** `src/web.js` lines 31–33 (`makeSessionToken`) and lines 35–42 (`getUserFromRequest`); cookie set in `src/server.js` around line 30 (login handler)
- **Affected route or feature:** Session handling, so every authenticated route (`/dashboard`, `/api/notes/:id`, `/api/profile`, `/admin`, `/profile`)
- **Evidence:** `makeSessionToken` returns the base64url encoding of `<username>:ospc-demo-session`. There is no secret, signature, random value or expiry. `getUserFromRequest` decodes the cookie, takes the part before the colon, and looks that username up in `users`, so the server fully trusts client-supplied data. Local check: log in as `alex`, read the `sid` cookie in DevTools (Application → Cookies), and base64-decode it to see the pattern. Then create the same pattern for `sam`, replace the cookie value, and reload `/dashboard`. The page should show Sam's account. The `Set-Cookie` header also has no `HttpOnly`, `Secure` or expiry, and `/logout` only clears the cookie in the browser (nothing is invalidated server-side).
- **Impact:** Anyone who knows or guesses a username can build a valid session for that user without the password, which is full account takeover. Tokens never expire or get revoked. Because the cookie lacks `HttpOnly`, any script injection (Finding 4) can also read it.
- **Recommended mitigation:** Use random, unguessable server-side session IDs, or signed tokens (e.g. HMAC or JWT with a strong secret and expiry). Invalidate sessions on logout, and set `HttpOnly`, `Secure` and a lifetime on the cookie.

## Finding 2 — Mass assignment allows privilege escalation to admin

- **Severity:** Critical
- **Affected file and line(s):** `src/server.js` lines 58–66, specifically `Object.assign(user, changes)` at about line 64
- **Affected route or feature:** `POST /api/profile` (profile edit), which leads to `/admin`
- **Evidence:** The handler parses the client's JSON and copies every property onto the in-memory user object with `Object.assign(user, changes)`. There is no allow-list, so the client can set `role`, `id`, `password`, `email` and other fields, not just `displayName`. Local check: signed in as `alex` (role `member`), send a profile update that includes a `role` field set to `admin`, then open `/admin`. The admin page (training flag) should now load instead of "Access denied", because `/admin` only checks `user.role !== "admin"`.
- **Impact:** Any signed-in member can make themselves an administrator. They can also change `id` to take over another user's notes, or change `password` and `email`. Changes persist in memory until the server restarts.
- **Recommended mitigation:** Accept only an explicit allow-list of editable fields (just `displayName`), validate their type and length, and never let clients set `role`, `id` or credentials.

## Finding 3 — Insecure direct object reference (IDOR) on notes

- **Severity:** High
- **Affected file and line(s):** `src/server.js` lines 41–48 (the `/api/notes/` handler)
- **Affected route or feature:** `GET /api/notes/:id`
- **Evidence:** The handler checks only that the requester is signed in, then looks up the note by the numeric ID in the URL and returns it. It never compares `note.owner` with `user.id`. The dashboard (lines 33–39) filters notes by owner, but the API route does not enforce the same rule. Local check: sign in as `alex`, open his note link (`/api/notes/101`), then change the ID to Sam's note ID (`202`, visible in `src/data.js`). The response should return Sam's private note.
- **Impact:** Any authenticated user can read any other user's private notes. IDs are small, sequential-looking integers, so they are easy to enumerate.
- **Recommended mitigation:** Enforce an ownership check on the server (`note.owner === user.id`) and return 403 or 404 otherwise. Consider non-guessable IDs as defence in depth.

## Finding 4 — Cross-site scripting (reflected and stored) due to unescaped output

- **Severity:** High
- **Affected file and line(s):** `src/server.js` lines 75–80 (`/search`: `q` inserted unescaped in the input's `value` attribute and in the "Results for" heading; user names and emails inserted unescaped in results), and line 38 and the note-title line near 37 (`/dashboard`: `displayName` and `note.title` unescaped); `src/web.js` lines 10–14 (`page()` adds no Content-Security-Policy)
- **Affected route or feature:** `GET /search?q=...` (reflected) and `/dashboard` / search results (stored, through the display name)
- **Evidence:** Dynamic values are concatenated directly into HTML template strings with no output encoding. Local check (harmless markup only): visit `/search?q=<b>test</b>` and see whether the text renders as bold HTML instead of literal text, which shows the input is not escaped. Stored path: because of Finding 2, a user can set `displayName` to HTML, which is then rendered on `/dashboard` and in `/search` results shown to other users.
- **Impact:** An attacker can craft a link that runs script in a victim's browser, or plant script in a display name that runs for anyone who views it. Combined with the cookie lacking `HttpOnly` (Finding 1), injected script could read the session cookie and take over accounts. The page could also be altered to phish credentials.
- **Recommended mitigation:** HTML-escape all dynamic output (and attribute-escape values placed in attributes), add a Content-Security-Policy that blocks inline scripts, and set `HttpOnly` on the session cookie.

## Finding 5 — Unauthenticated exposure of user directory and email addresses

- **Severity:** Medium
- **Affected file and line(s):** `src/server.js` lines 75–80 (`/search` handler); data in `src/data.js`
- **Affected route or feature:** `GET /search`
- **Evidence:** The `/search` handler has no call to `getUserFromRequest`, so it needs no login. It filters all users by display name and prints `displayName — email` for each match. Local check: in a private/incognito window without signing in, open `/search?q=a` and see the names and email addresses listed. Emails also mirror the login usernames (`alex@example.test` for user `alex`).
- **Impact:** Anyone on the network can list users and email addresses without an account. This aids phishing, username enumeration and targeted password guessing. In this demo the data is synthetic, but in a real app it would be a personal-data leak.
- **Recommended mitigation:** Require authentication for the directory, return only the fields that are needed (no emails by default), and rate-limit searches.

## Review notes

- **How I approached the review:** I ran the app locally with `npm start` and read all three source files (`src/server.js`, `src/web.js`, `src/data.js`). I mapped each route, checked how authentication and roles are enforced, and looked at how user input reaches the HTML output and the data objects. I then checked each suspected issue locally using only the two demo accounts (`alex`, `sam`). I did not modify any application code.
- **Assumptions or limitations:** Line numbers are from the checked-out version and may be off by a line or two. Severity ratings assume the app were deployed beyond localhost. Other lower-severity issues I noticed but did not report separately: plaintext password storage and no rate limiting or lockout on login (`src/data.js`, `POST /login`), the state-changing `GET /logout`, and missing security headers such as CSP and X-Frame-Options. I did not test denial-of-service behaviour (for example, `readBody` destroys the request on oversized bodies without settling its promise). I also did not test against anything outside this local app.