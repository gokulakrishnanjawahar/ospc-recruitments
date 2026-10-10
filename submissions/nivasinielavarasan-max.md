# Security Review Findings

## Finding 1: Predictable and forgeable session tokens

**Severity:** High

**Affected file:** `src/web.js`

**Affected functions:** `makeSessionToken()` and `getUserFromRequest()`

### Description

The application creates session tokens by Base64URL-encoding the username and a fixed string. Base64URL is encoding, not encryption or a cryptographic signature. The server decodes the supplied session cookie and trusts the username without verifying token authenticity or checking a server-side session record.

### Evidence

- `makeSessionToken()` constructs the token from `${username}:ospc-demo-session`.
- `getUserFromRequest()` decodes the `sid` cookie and looks up the username without verifying a signature.

### Impact

An attacker who can construct a valid token may impersonate another existing account without knowing its password.

### Recommended mitigation

Use unpredictable, cryptographically secure session identifiers backed by server-side session records, or properly signed tokens with signature verification, expiry, and appropriate session invalidation.

---

## Finding 2: Privilege escalation through mass assignment

**Severity:** High

**Affected file:** `src/server.js`

**Affected routes:** `POST /api/profile` and `GET /admin`

### Description

The profile endpoint accepts a JSON object and applies all supplied properties to the authenticated user's object using `Object.assign(user, changes)`. It does not restrict modifications to approved profile fields. The admin route subsequently relies on the mutable `user.role` property for authorization.

### Evidence

- `POST /api/profile` assigns all submitted properties to the user object.
- `GET /admin` grants access when `user.role === "admin"`.
- In local testing, Alex initially received HTTP 403 at `/admin`. After submitting a profile update containing `{"role":"admin"}`, the admin area became accessible.

### Impact

A regular member can elevate their privileges to administrator and access functionality restricted to administrators.

### Recommended mitigation

Allowlist permitted profile fields, such as `displayName`, and reject attempts to modify authorization-related properties. Manage role changes through a separate, properly authorized administrative process.

---

## Finding 3: Broken object-level authorization (IDOR) in the notes API

**Severity:** Medium

**Affected file:** `src/server.js`

**Affected route:** `GET /api/notes/:id`

### Description

The notes API verifies that a user is authenticated and that the requested note exists, but it does not verify that the note belongs to that user.

The dashboard filters notes by ownership, but the API does not enforce the same restriction.

### Evidence

- `src/data.js` defines note `101` as belonging to Alex (user ID `1`) and note `202` as belonging to Sam (user ID `2`).
- The notes API retrieves a note by ID and returns its title and body without checking `note.owner === user.id`.
- During local testing, Alex retrieved note `202`, which belongs to Sam.

### Impact

An authenticated user can access another user's notes by requesting their note identifiers, exposing data that should be restricted by ownership.

### Recommended mitigation

Verify the authenticated user's authorization to access each requested note before returning its contents. Apply ownership checks consistently to all endpoints that access user-owned objects.

---

## Finding 4: Unescaped user input in HTML responses

**Severity:** Medium — final severity should reflect the challenge's rubric

**Affected files:** `src/server.js` and `src/web.js`

**Affected routes:** `GET /search`, `POST /api/profile`, and `GET /dashboard`

### Description

The application inserts untrusted input directly into HTML without context-appropriate output encoding. The shared `page()` helper interpolates the supplied body directly into the HTML document.

The search handler inserts the query into its results heading and search input. The profile endpoint accepts a user-controlled `displayName`, which the dashboard later inserts into its greeting.

### Evidence

- `GET /search` interpolates the query into HTML.
- `POST /api/profile` accepts a user-supplied display name.
- `GET /dashboard` interpolates `user.displayName` into a page heading.
- `src/web.js`, `page()`, inserts the body without escaping it.
- A local search test using `<b>TEST</b>` rendered the word in bold.
- A profile update using `<b>Profile Test</b>` caused the dashboard greeting to render the name in bold.

### Impact

The observed behaviour confirms that untrusted input can be interpreted as HTML. Depending on the payload and rendering context, this may permit cross-site scripting (XSS) and potentially execute malicious JavaScript in a user's browser under the application's origin.

The tests demonstrated HTML injection, but did not independently verify JavaScript execution.

### Recommended mitigation

Apply context-appropriate output encoding to untrusted values inserted into HTML. Prefer safe text-rendering APIs and avoid constructing HTML by concatenating user-controlled strings. Input validation alone is not sufficient to prevent XSS.

---

## Review notes

- Testing was performed against the local challenge application using its fictional demo accounts and data.
- No application source code was modified.
- Findings are based on source-code inspection and the local behaviours documented above.
