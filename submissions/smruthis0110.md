# Security Assessment — smruthis0110

**Challenge commit:** a1a053f (`main`)
**Date:** 2026-10-10

> Include only findings you can explain. Do not edit application code in this PR.

## Finding 1 — Session tokens are predictable and unsigned, allowing impersonation of any user

* **Severity:** Critical
* **Affected file and line(s):** `src/web.js` lines 31–33 (`makeSessionToken`) and 35–42 (`getUserFromRequest`); `src/server.js` line 30 (cookie is issued)
* **Affected route or feature:** Authentication for every signed-in route (`/dashboard`, `/api/notes/:id`, `/api/profile`, `/admin`)
* **Evidence:** The `sid` cookie is just `base64url("<username>:ospc-demo-session")`. There is no random value, signature, HMAC or server-side session store. `getUserFromRequest` decodes the cookie, takes the text before the first `:`, and trusts it as the logged-in user. Locally, logging in as `sam` returns `sid=c2FtOm9zcGMtZGVtby1zZXNzaW9u`. Sending that same cookie without ever submitting a password returns the dashboard "Hello, Sam Lee". The constant suffix is identical for all users, so a token for any username can be computed offline.
* **Impact:** Anyone who knows or guesses a username can become that user without the password. This bypasses authentication entirely and gives access to that user's data and actions. Usernames are easy to learn here (they are shown on the home page and match the email local-part in the directory). Because the token never changes, never expires and `/logout` only clears the browser's copy, a leaked token stays valid forever.
* **Recommended mitigation:** Issue a long random session ID (for example 128 bits from `crypto.randomBytes`) and keep session state on the server, with expiry and invalidation on logout. If a stateless token is preferred, sign it with a server-side secret (HMAC or a JWT library) and include an expiry. Rotate the session ID on login.

## Finding 2 — Mass assignment in profile update lets any user make themselves admin

* **Severity:** High
* **Affected file and line(s):** `src/server.js` lines 58–66, specifically line 64 (`Object.assign(user, changes)`); the role check it defeats is on line 71
* **Affected route or feature:** `POST /api/profile` and the `/admin` area
* **Evidence:** The endpoint copies every key from the request's JSON body onto the live user record, with no allow-list. The UI only advertises `displayName`, but the server accepts any field. Locally, as `alex` (role `member`), `GET /admin` returned 403. After `POST /api/profile` with `{"role":"admin"}`, the response showed `"role": "admin"` and `GET /admin` returned 200 with the admin page. The same call can overwrite `id`, `username`, `password` and `email`.
* **Impact:** Vertical privilege escalation: any signed-in user can gain admin access in one request. Overwriting `id` could also make a user's dashboard list another user's notes, and overwriting `password` or `username` can lock out the real owner or cause account confusion. In a real application this would expose all admin functions.
* **Recommended mitigation:** Update only an explicit allow-list of fields (here just `displayName`) and validate type and length. Never bind raw request objects onto internal records. Keep roles and identifiers server-controlled, and check authorization for sensitive fields separately.

## Finding 3 — Broken object-level authorization (IDOR) on note retrieval

* **Severity:** Medium
* **Affected file and line(s):** `src/server.js` lines 41–48 (the missing ownership check is between lines 45 and 47)
* **Affected route or feature:** `GET /api/notes/:id`
* **Evidence:** The handler checks only that someone is signed in, then returns whichever note matches the numeric ID from the URL. It never compares `note.owner` with the current user's `id`, unlike the dashboard (line 36), which does filter by owner. Locally, signed in as `alex` (who owns note 101), `GET /api/notes/202` returned `sam`'s note ("Club idea") with its title and body.
* **Impact:** Any authenticated user can read every other user's notes by changing the ID. IDs are small sequential-looking integers, so enumeration is trivial. The impact depends on what notes contain, but private user content is exposed.
* **Recommended mitigation:** Enforce ownership on the server for every object lookup (`note.owner === user.id`, or role-based rules), and return 404 or 403 otherwise. Consider non-guessable IDs as defense in depth, not as the control.

## Finding 4 — Plaintext passwords and no brute-force protection on login

* **Severity:** Medium
* **Affected file and line(s):** `src/data.js` (user records hold `password` as plain text); `src/server.js` line 28 (direct string comparison in `POST /login`)
* **Affected route or feature:** `POST /login`
* **Evidence:**Passwords are stored as readable strings (for example `maple123`, `orbit456`) and login compares the submitted value directly with the stored one. There is no hashing, no per-user salt, and no limit on failed attempts: repeated wrong passwords for one username are processed with no lockout or delay.
* **Impact:**  Any leak of the data store (backup, log, memory dump, or the profile overwrite in Finding 2) exposes every password immediately, and users who reuse passwords elsewhere are put at risk. Without rate limiting, an attacker can guess passwords for known usernames at full speed.
* **Recommended mitigation:** Store passwords with a slow, salted hash (argon2id, bcrypt or scrypt) and compare using the library's verify function. Add per-account and per-IP rate limiting or progressive delays, and return a generic error message for failed logins.

## Finding 5 — Unauthenticated directory search discloses user names and email addresses

* **Severity:** Low
* **Affected file and line(s):** `src/server.js` lines 75–80
* **Affected route or feature:** `GET /search`
* **Evidence:** The route has no authentication check and filters with `includes(query)`. An empty query matches everyone, so `GET /search?q=` with no cookie returns every user's display name and email (`Alex Rivera — alex@example.test`, `Sam Lee — sam@example.test`).
* **Impact:** Anyone on the network can harvest the full member list and email addresses. This supports phishing and username guessing, and it gives an attacker the account names needed to exploit Finding 1. Severity is Low because the data is limited to name and email, and the information may be intended to be semi-public in a club directory; if it is not, it should be restricted.
* **Recommended mitigation:** Require sign-in for the directory, return only the fields that are needed (for example name only), and require a minimum query length or add pagination and rate limiting to prevent bulk enumeration.

## Review notes

* **How I approached the review:** I read all three source files (`src/server.js`, `src/web.js`, `src/data.js`) and traced each route from request to response, looking at authentication, authorization, input handling and output encoding. I then confirmed each finding locally by starting the server on a spare port with `PORT=3917` and sending `curl` requests that used only the synthetic demo accounts. I did not change any application code.
* **Assumptions or limitations:**

  * Severity ratings assume this were a real application and not a training exercise.
  * I confirmed XSS by inspecting the raw HTML in the response, not by running a payload in a browser.
  * Other issues I noticed but did not report as separate findings, so as not to duplicate causes or go beyond the requested number: plaintext password storage and comparison in `src/data.js` / `src/server.js` line 28; no login rate limiting or lockout; the session cookie lacks `Secure` and an expiry; and `/logout` is a state-changing GET request.
  * The README says the app runs on port 3000, but my copy of `src/server.js` defaulted to 3001 in the working tree (the committed version uses 3000), so I set `PORT` explicitly.

