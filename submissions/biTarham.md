

Security Review Findings: Source Code Analysis



This report documents the security vulnerabilities identified during the source code review of the OSPC recruitment application.



Finding 1: Insecure Direct Object References (IDOR) on Notes Endpoint



• Severity: High

• Location: src/server.js (Lines 44-51)

• Route: GET /api/notes/:id



Description



The application checks if a user is logged in before fetching a note, but it fails to check if the logged-in user actually owns that note. It simply takes the ID from the URL path, finds the note, and serves it to the requester.



Evidence



javascript

if (method === "GET" \&\& url.pathname.startsWith("/api/notes/")) {

&#x20; const user = getUserFromRequest(req);

&#x20; if (!user) return json(res, 401, { error: "sign in required" }); // Only checks if logged in

&#x20; const id = Number(url.pathname.split("/").pop());

&#x20; const note = notes.find(item => item.id === id); // Fetches note purely by ID without ownership verification

&#x20; if (!note) return json(res, 404, { error: "note not found" });

&#x20; return json(res, 200, { id: note.id, title: note.title, body: note.body });

}

Use code with caution.

Local Demonstration: Log in as user alex. On the dashboard, your note URL might say /api/notes/1. Manually change the URL in your browser address bar to /api/notes/2 (which belongs to sam). The app will successfully display Sam’s private note data to Alex.



Impact



Any authenticated user can read the personal notes of every other user registered in the system by guessing or iterating through numeric note IDs.



Recommendation



Modify the lookup logic to verify that the note's owner ID matches the authenticated user's ID before returning the response data:

javascript

const note = notes.find(item => item.id === id \&\& item.owner === user.id);

Use code with caution.



Finding 2: Mass Assignment (Prototype Pollution / Privilege Escalation)



• Severity: Critical

• Location: src/server.js (Lines 61–68)

• Route: POST /api/profile



Description



The profile update endpoint blindly copies all properties from the user-supplied JSON body directly into the active user session object using Object.assign(). It lacks an allowlist filtering mechanism to restrict which fields a user is permitted to update.



Evidence



javascript

if (method === "POST" \&\& url.pathname === "/api/api/profile") { // (Route handling logic)

&#x20; ...

&#x20; if (!changes || typeof changes !== "object" || Array.isArray(changes)) return json(res, 400, ...);

&#x20; Object.assign(user, changes); // Vulnerable line: copies everything including internal properties like "role"

Use code with caution.



Impact



A regular user can escalate their account privileges to an administrator role by explicitly sending a payload specifying {"role": "admin"}. This allows them to bypass the check on line 74 (user.role !== "admin") and successfully extract the training flag from the /admin dashboard.



Recommendation



Explicitly assign only permitted properties instead of copying the raw input object directly:

javascript

if (changes.displayName) {

&#x20; user.displayName = changes.displayName;

}

Use code with caution.



Finding 3: Reflected Cross-Site Scripting (XSS)



• Severity: Medium

• Location: src/server.js (Lines 78-83)

• Route: GET /search



Description



The search endpoint accepts a user query parameter (q), incorporates it directly into the HTML output template literal strings, and displays it to the client browser without performing any context-aware HTML escaping or sanitization.



Evidence



javascript

const query = url.searchParams.get("q") || "";

...

return send(res, 200, page("Directory search", `... <input name="q" value="${query}"> ... <h2>Results for: ${query}</h2> ...`));

Use code with caution.



Impact



An attacker can craft a malicious URL containing a JavaScript payload (e.g., /search?q=<script>alert(document.cookie)</script>). If another user visits this link, the script will execute within the context of their session, potentially compromising data or leaking authentication tokens.



Recommendation



Pass user-supplied input parameters through a sanitation helper function to convert dangerous characters (<, >, ", ', \&) into safe HTML entities before embedding them into templates.



Finding 4: Insecure Storage of User Credentials



• Severity: High

• Location: Reference to src/data.js via imports

• Route: System Architecture / Data Model



Description



The application reads login parameters directly from an object structure where passwords are stored in clear, plaintext format. During the authentication step on line 30, it compares the credentials using basic plaintext string match verification.



Evidence



javascript

const user = users.find(item => item.username === body.get("username") \&\& item.password === body.get("password"));

Use code with caution.



Impact



If an attacker obtains local file read capabilities or access to the codebase backup structure, all user credentials are compromised immediately. There is no cryptographic barrier protecting the passwords.



Recommendation



Passwords should never be stored in plaintext. They must be securely transformed using a robust, dedicated cryptographic hashing algorithm (such as Argon2id or bcrypt) combined with unique salts before storage and verification.



Finding 5: Weak Session Token Generation



• Severity: High

• Location: src/server.js (Line 32) and reference to src/web.js

• Route: POST /login



Description



Upon successful login, the server generates a session cookie utilizing a custom utility function (makeSessionToken(user.username)). Because this relies directly on the predictable string structure of the input username, the tokens are trivial to construct.



Evidence



javascript

return send(res, 302, "", "text/plain; charset=utf-8", { "Set-Cookie": `sid=${makeSessionToken(user.username)}; Path=/; SameSite=Lax`, Location: "/dashboard" });

Use code with caution.



Impact



An attacker does not need to compromise a password to hijack an active account. They can simply predict or format the value of a valid token string for another target user (like admin) and manually inject it into their browser cookies to impersonate them.



Recommendation



Use standard cryptographically secure pseudo-random number generators (CSPRNG), such as Node's native crypto.randomUUID() or crypto.randomBytes(), to create long, high-entropy, unpredictable session identifiers.

