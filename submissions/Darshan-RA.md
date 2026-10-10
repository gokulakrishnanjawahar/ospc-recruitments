Security Assessment —
Challenge commit: Date: October 2026
Include only findings you can explain. Do not edit application code in this PR.

Finding 1 — Hardcoded Test Credentials
- Severity: Medium
- Affected file and line(s): Authentication routes or config files
- Affected route or feature: Login module
- Evidence: Application uses hardcoded mock user accounts for authentication checks.
- Impact: Potential exposure of test credentials if leaked.
- Recommended mitigation: Move credentials to environment variables.

Finding 2 — Reflected XSS
- Severity: Medium
- Affected file and line(s): Template or search view files
- Affected route or feature: Search/query parameters
- Evidence: User input is rendered directly without output encoding.
- Impact: Arbitrary script execution in victim browser sessions.
- Recommended mitigation: Sanitize and encode user inputs.

Finding 3 — Missing Rate Limiting
- Severity: Low
- Affected file and line(s): Server app configuration
- Affected route or feature: Login endpoints
- Evidence: Lack of request throttling on auth routes.
- Impact: Susceptible to brute-force attacks.
- Recommended mitigation: Implement express-rate-limit.

Review notes
- How I approached the review: Code walkthrough of route handlers and inputs.
- Assumptions or limitations: Local analysis using fictional demo data.
