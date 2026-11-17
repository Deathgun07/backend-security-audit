# app-a = OWASP Juice Shop @ 266448a — ground truth from its own `vuln-code-snippet` annotations (server side only)
Frontend-only coding challenges excluded (out of scope for a backend audit): adminSection, scoreBoard, tokenSale, web3Sandbox, localXss, restfulXss, xssBonus.
| ID | Vulnerability (challenges) | Location |
|---|---|---|
| A1 | SQL injection in login (loginAdmin, loginBender, loginJim) | routes/login.ts:34 |
| A2 | SQL injection in product search (unionSqlInjection, dbSchema) | routes/search.ts:23 |
| A3 | NoSQL injection in review update (noSqlReviews) | routes/updateProductReviews.ts:18-20 |
| A4 | Review update without author/ownership check (forgedReview) | routes/updateProductReviews.ts:16-18 |
| A5 | Open redirect allow-list bypass via `includes` (redirect, redirectCryptoCurrency) | lib/insecurity.ts:136 |
| A6 | Weak password hashing / no password policy (weakPassword) | models/user.ts:73 |
| A7 | Passkey signature not verified (passkeySignature) | routes/passkey.ts:222 |
| A8 | Passkey credential overwrite (passkeyCredentialOverwrite) | routes/passkey.ts:142 |
| A9 | Chatbot: LLM-controlled coupon discount without server-side bound (chatbotPromptInjection, chatbotGreedyInjection) | routes/chat.ts:180-185 |
| A10 | Access log directory listing and download (accessLogDisclosure) | server.ts:306-308 |
| A11 | /ftp directory listing (directoryListing) | server.ts:294-295 |
| A12 | /metrics exposed without auth (exposedMetrics) | server.ts:771 |
| A13 | PUT /api/Products/:id without authorization (changeProduct) | server.ts:402 |
| A14 | Register as admin: role mass assignment on user creation (registerAdmin) | server.ts:550 |
| A15 | Reset-password rate limit bypass via X-Forwarded-For (resetPasswordMorty) | server.ts:378 |
Scoring unit: A1–A15 (15 distinct root causes).
