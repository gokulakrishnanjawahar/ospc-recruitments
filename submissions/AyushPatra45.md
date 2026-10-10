# Security Assessment — AyushPatra45
**Registration number:** 25BCE1661
**Date:** 2026-10-10

## Finding 1 — A signed-in user can read another user's notes

- **Severity:** Medium. A member can read another member's private notes without permission. This route exposes note contents, but does not provide a way to edit or delete them.
- **Affected file and line(s):** `src/server.js`, lines 41–47; `src/data.js`, lines 9–11.
- **Affected route or feature:** `GET /api/notes/:id`.
- **Evidence:** The route checks that a user is signed in, then searches for a note using only the ID from the URL. It returns the note without comparing `note.owner` with the signed-in user's ID. The dashboard does filter notes by owner at line 36, but that restriction is missing from the API. In the demo data, note `101` belongs to Alex and note `202` belongs to Sam. A local check is to sign in as Alex and request `/api/notes/202`. The expected result is an access denial because Alex does not own that note.
- **Impact:** A signed-in member can request another member's note by changing the ID in the URL from 101 to 202. This exposes the note's title and body.
- **Recommended mitigation:** Look up the note using both its ID and the signed-in user's ID, or explicitly check ownership before returning it. Apply any intended sharing rules on the server. Unpredictable IDs alone would not fix the missing permission check.

## Finding 2 — Profile updates allow a member to become an administrator

- **Severity:** High. A normal member can change a field that controls access to an administrator-only route.
- **Affected file and line(s):** `src/server.js`, lines 58–65 and 68–72.
- **Affected route or feature:** `POST /api/profile` and `GET /admin`.
- **Evidence:** The profile route accepts a JSON object and calls `Object.assign(user, changes)`. It does not restrict which account properties can be updated. A request containing `{"role":"admin"}` can therefore change the signed-in user's role. The admin route then checks this same property with `user.role !== "admin"`. The role check exists, but the member can change the value it trusts. This unrestricted copying of input into an account object is called mass assignment.
- **Impact:** A member can promote their own account and view the administrator page. In this demo, that page exposes a synthetic training flag. 
- **Recommended mitigation:** Explicitly allow only intended profile fields, such as a validated `displayName`. Keep role, account ID, and other security-sensitive fields out of ordinary profile updates. Require separate authorization for any administrative role changes.
- How I approached: 1. Sign in as Alex at http://127.0.0.1:3000.
2. Open Chrome’s JavaScript Console.
3. Enter this code and press Enter:
fetch("/api/profile", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ role: "admin" })
})
  .then(response => response.json())
  .then(console.log);
This sends the role change using your current signed-in session.
4. Check the console response. If it shows "role": "admin", open:
http://127.0.0.1:3000/admin

## Finding 3 — Session cookies can be forged to impersonate another user

- **Severity:** High. Knowing a valid username is enough to impersonate that account without its password or an existing authenticated session.
- **Affected file and line(s):** `src/web.js`, lines 31–41; `src/server.js`, lines 26–30.
- **Affected route or feature:** The `sid` cookie and every route using `getUserFromRequest`.
- **Evidence:** `makeSessionToken` creates the cookie value by Base64url-encoding the username followed by `:ospc-demo-session`. Base64 is an encoding, not a signature or encryption. `getUserFromRequest` decodes the cookie, takes the text before the first colon, and looks for a matching username. It does not check a server-side session record, a cryptographic signature, or even the fixed suffix. Although `/login` checks a password, later requests can bypass that check by supplying a fabricated cookie.
- **Impact:** Someone who knows a demo username can act as that user, view their dashboard and notes, and submit profile changes. Session forgery does not itself turn a member into an administrator; the profile update flaw in Finding 2 provides that separate escalation path.
- **Recommended mitigation:** Generate unpredictable session IDs with a cryptographically secure random generator and validate them against server-side session records. Add expiration and invalidate sessions on logout. Set `HttpOnly` on session cookies, and use `Secure` when serving an application over HTTPS. Cookie flags alone do not fix a forgeable token.
- How I approached: 1. Click Sign out.
2. Keep the app open at http://127.0.0.1:3000 and open the Console.
3. Enter:
document.cookie =
  "sid=" + btoa("sam:ospc-demo-session") + "; Path=/; SameSite=Lax";
This encodes the predictable session text and sets it as your browser’s cookie.
4. Open http://127.0.0.1:3000/dashboard.

## Finding 4 — Search and profile values are rendered as HTML without escaping

- **Severity:** High. Attacker-controlled values can execute JavaScript under the app's origin when another person visits an affected page. Exploitation requires that page visit; the stored case also requires a profile update.
- **Affected file and line(s):** `src/server.js`, line 38, lines 58–64, and lines 75–79; `src/web.js`, lines 10–13.
- **Affected route or feature:** `GET /search?q=...`, `POST /api/profile`, and `GET /dashboard`.
- **Evidence:** The search route inserts `q` directly into an HTML input attribute and a heading. There is no HTML escaping before the response is sent. This provides a reflected cross-site scripting (XSS) entry point. The profile route also accepts a `displayName`, which is stored on the user object and later inserted directly into the dashboard and directory search results. This provides a stored XSS entry point. The stored value lasts until the app restarts because the data is kept in memory. Both cases are grouped here because they share the same missing output-escaping problem.
- **Impact:** Injected JavaScript runs with the affected page's origin and can make requests with the visitor's session. A crafted search link could affect someone who opens it. A saved profile value could affect directory visitors without requiring each visitor to enter the value themselves. The session cookie also lacks `HttpOnly`, so JavaScript can read it, although session forgery is already covered separately in Finding 3.
- **Recommended mitigation:** Escape values for their specific HTML context, including quoted attributes and HTML text, or use a template system that escapes by default. Treat profile names as plain text and validate their type and length. Add a restrictive Content Security Policy as an additional protection; it should not replace correct output escaping.

