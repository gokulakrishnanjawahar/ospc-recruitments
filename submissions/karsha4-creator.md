# Security Review Findings by KARSHA:

I reviewed the OSPC demo application and found four potential security issues in the source code. The findings below explain what I noticed and what could happen if these issues are exploitable.

## 1. Mass Assignment in Profile Update

**Severity:** High (provisional)  
**File:** `src/server.js`  
**Endpoint:** `POST /api/profile`

**Description:**  
The profile API uses `Object.assign(user, changes)` to apply the JSON received from the user. It does not restrict which fields can be updated. Since the application also uses the `role` field to control access to the admin page, changing this field could allow a normal user to gain admin privileges.

**Suggested fix:**  
Allow updates only to permitted fields, such as `displayName`. Users should not be able to change their own role through the profile API.

## 2. Missing Note Ownership Check (IDOR)

**Severity:** High (provisional)  
**File:** `src/server.js`  
**Endpoint:** `GET /api/notes/:id`

**Description:**  
The notes endpoint checks whether the user is signed in and whether the requested note exists. However, it does not check whether the note belongs to that user before returning its contents. A signed-in user may therefore be able to access another user's notes by changing the note ID.

**Suggested fix:**  
Check that the note's owner matches the signed-in user's ID before returning the note.

## 3. Unescaped HTML in Directory Search

**Severity:** Medium (provisional)  
**File:** `src/server.js`  
**Endpoint:** `GET /search`

**Description:**  
The search query, display names, and email addresses are inserted directly into the HTML response without visible escaping. If specially crafted input is interpreted as HTML or JavaScript, it could lead to cross-site scripting (XSS).

**Suggested fix:**  
Escape untrusted values according to their HTML context before rendering them. Prefer safe templating or DOM methods that treat user input as text.

## 4. Predictable Session Tokens

**Severity:** High (provisional)  
**File:** `src/web.js`  
**Functions:** `makeSessionToken()` and `getUserFromRequest()`

**Description:**  
The session token is created by Base64URL-encoding the username and a fixed string. When processing the cookie, the application decodes the token and looks up the username without verifying a signature or checking a server-side session. This may allow someone to create a cookie for a known username and impersonate that user.

**Suggested fix:**  
Use cryptographically random session identifiers, validate sessions on the server, and invalidate them on logout.

---

**Note:** These findings are based on source-code review. Runtime exploitability and the final severity of each issue should be confirmed through local testing.