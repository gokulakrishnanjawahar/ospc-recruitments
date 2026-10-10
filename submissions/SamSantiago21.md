# Security Assessment — SamSantiago21

**Challenge commit:** `a1a053f`
**Date:** 2026-10-10

## Finding 1 — Predictable and Forgeable Session Tokens

- **Severity:** High
- **Affected file and line(s):** `src/web.js`, lines 31–40
- **Affected route or feature:** Session generation and authentication; `/dashboard`, `/api/notes/:id`, and other authenticated routes.
- **Evidence:** The `makeSessionToken()` function creates a token by Base64URL-encoding the username and a fixed string. The `getUserFromRequest()` function decodes the cookie and extracts the username, then returns the matching user without verifying a cryptographic signature or validating a server-side session. During local testing, a manually constructed token for the fictional `alex` account was accepted, and the dashboard returned HTTP `200 OK`.
- **Impact:** An attacker who can determine the token format and a valid username may forge a session cookie and impersonate that account. This could expose account-specific information or enable actions available to the impersonated user.
- **Recommended mitigation:** Use unpredictable, securely generated session identifiers backed by server-side session records, or cryptographically signed tokens with appropriate validation. Enforce expiration and invalidate sessions on logout. Set appropriate cookie attributes, including `HttpOnly` and `Secure` when using HTTPS.

## Finding 2 — Broken Object-Level Authorization (BOLA/IDOR)

- **Severity:** Medium
- **Affected file and line(s):** `src/server.js`, lines 41–47
- **Affected route or feature:** `GET /api/notes/:id`
- **Evidence:** The route checks whether a user is authenticated and whether the requested note exists, but it does not verify that the note belongs to the authenticated user. During local testing, a session for the fictional `alex` account requested `/api/notes/202` and received HTTP `200 OK` with the note titled `Club idea`, owned by the fictional `sam` account.
- **Impact:** An authenticated user may retrieve notes belonging to other users by changing the note ID in the request. In a real application containing private notes, this could result in unauthorized disclosure of user data.
- **Recommended mitigation:** Enforce object-level authorization on every request. Verify that the requested note belongs to the authenticated user before returning its contents, or use an authorization-aware data lookup.

## Finding 3 — Mass Assignment Enables Privilege Escalation

- **Severity:** High
- **Affected file and line(s):** `src/server.js`, lines 58–65; administrative authorization check at lines 68–72
- **Affected route or feature:** `POST /api/profile` and `GET /admin`
- **Evidence:** The profile endpoint parses a JSON object and passes all supplied properties to `Object.assign(user, changes)`. During local testing, submitting `{"role":"admin"}` using the fictional `sam` account changed the account's role to `admin`. A subsequent request to `/admin` returned HTTP `200 OK` and displayed the synthetic training flag.
- **Impact:** An authenticated user can modify a security-sensitive account property and gain administrative privileges. In a deployed application, this could allow unauthorized access to administrative functionality and protected resources.
- **Recommended mitigation:** Explicitly allowlist the fields users may update, such as `displayName`. Never accept authorization roles or other security-sensitive attributes directly from a user-controlled profile request. Enforce authorization on the server for every privileged operation.

## Finding 4 — Reflected Cross-Site Scripting (XSS) in Directory Search

- **Severity:** Medium
- **Affected file and line(s):** `src/server.js`, lines 75–79
- **Affected route or feature:** `GET /search`, query parameter `q`
- **Evidence:** The search route reads the `q` query parameter and interpolates it directly into the generated HTML response. The value is inserted into an HTML input attribute and the results heading without context-appropriate output encoding. A local request containing `<script>alert(1)</script>` returned the script markup unescaped. Opening the crafted search URL in the browser caused `alert(1)` to execute.
- **Impact:** An attacker could send a crafted search URL to a victim. If the victim opens it in a vulnerable browser context, attacker-controlled JavaScript may execute within the application's origin. Potential consequences depend on the application's functionality and the victim's access.
- **Recommended mitigation:** Contextually encode untrusted data before inserting it into HTML. Use safe DOM APIs for text where applicable, avoid constructing HTML from untrusted strings, and consider a restrictive Content Security Policy as an additional layer of defense.

## Review notes

- **How I approached the review:** I inspected the Node.js application source code, focusing on authentication and session handling, authorization checks, user-controlled input, and HTML response generation. I used the application's fictional accounts and local HTTP requests to validate suspected weaknesses. The tests demonstrated session forgery, cross-user note access, profile-based privilege escalation, and browser execution of reflected JavaScript.
- **Assumptions or limitations:** All testing was conducted against the local training application using synthetic data. The impact statements describe plausible consequences in a real deployment and are not claims that external systems were affected. Severity ratings reflect the demonstrated behavior and potential impact of comparable weaknesses in a deployed application. No application code was modified as part of this assessment.
