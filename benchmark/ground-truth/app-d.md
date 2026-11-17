# app-d ground truth (written by us, NOT independent)
| ID | Vulnerability | Location |
|---|---|---|
| D1 | orders table without RLS | supabase/migrations/20250301000000_schema.sql:21-27 |
| D2 | profiles UPDATE policy owner-scoped but role/credits columns writable (privilege escalation, free credits) | schema.sql:9-10 (+ columns 4-5) |
| D3 | messages SELECT using (true): any user reads all private messages | schema.sql:36 |
| D4 | policy based on user_metadata (user-editable) | schema.sql:39-40 |
| D5 | transfer_credits SECURITY DEFINER, no search_path, no auth check, callable via RPC (steal credits) | schema.sql:42-47 |
| D6 | invoices bucket public | schema.sql:58 |
| D7 | /api/admin/export: getSession only + no admin role check, service role dumps all orders/addresses | app/api/admin/export/route.ts:5-9 |
| D8 | cancelOrder IDOR: service role update without ownership filter | app/orders/actions.ts:9 |
| D9 | service role key exposed through next.config.js `env` (latent: inlined only where client code reads it; initially overstated as a confirmed leak) | next.config.js:5 |
Secure on purpose (false-positive checks): notes table + policy, /api/notes (getUser + zod + RLS client), my_notes (invoker + search_path), order_stats view (security_invoker), myOrders (service role but filtered by user.id), avatars bucket public (avatars are public by nature: acceptable as Info/Low), lib/supabase/admin.ts server-only.
