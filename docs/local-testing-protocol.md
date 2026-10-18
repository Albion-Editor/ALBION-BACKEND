# Albion Proxy - Local Testing Protocol
# Phase 1: Backend Proxy Core - End-to-End Verification

This guide verifies the complete proxy pipeline:
**Auth → Cap Check → LiteLLM Routing → Supabase Logging**

---

## Prerequisites

- Node.js installed (v16+)
- Python 3.8+ installed (for LiteLLM)
- A Supabase project with:
  - `subscriptions` table (columns: `user_id`, `tier`, `cycle_start`, `status`)
  - `usage_logs` table (columns: `user_id`, `model`, `prompt_tokens`, `completion_tokens`, `actual_cost`, `session_id`, `timestamp`)
  - An RPC function `get_current_cycle_usage(p_user_id, p_cycle_start)` returning total tokens used
- A DeepInfra account with API key
- A Together AI account with API key (for failover testing)

---

## A. Infrastructure Startup

Open **three** separate terminal windows.

### Terminal 1: Configure Environment
```powershell
cd albion-proxy
Copy-Item .env.example .env
# Edit .env with your real values:
# notepad .env
```

Fill in these values in `.env`:
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...your-service-role-key
PORT=3000
ALLOWED_ORIGINS=*
LITELLM_BASE_URL=http://localhost:4000
LITELLM_MASTER_KEY=sk-albion-proxy-key-CHANGE-ME-IN-PROD
DEEPINFRA_API_KEY=your-deepinfra-api-key
TOGETHER_API_KEY=your-together-api-key
DATABASE_URL=postgresql://user:pass@host:5432/litellm_db
```

### Terminal 2: Start LiteLLM Proxy
```powershell
cd albion-proxy
pip install "litellm[proxy]"
litellm --config litellm_config.yaml --port 4000
```
**Expected output:** `LiteLLM Proxy running on port 4000`

### Terminal 3: Start Albion Proxy
```powershell
cd albion-proxy
node server.js
```
**Expected output:**
```
Albion Proxy running on port 3000
LiteLLM target: http://localhost:4000
CORS origins: *
```

---

## B. Test 1: Auth Rejection (401 — No Token)

This verifies the `authenticate()` middleware blocks requests without a valid JWT.

```powershell
curl -X POST http://localhost:3000/chat -H "Content-Type: application/json" -d "{`"messages`":[{`"role`":`"user`",`"content`":`"test`"}]}"
```

**Expected curl response:**
```json
{"error":"Invalid token"}
```

**Expected server.js console:** (nothing logged — rejected before routing)

---

## C. Test 2: Auth Rejection (401 — Invalid Token)

```powershell
curl -X POST http://localhost:3000/chat -H "Content-Type: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" -d "{`"messages`":[{`"role`":`"user`",`"content`":`"test`"}]}"
```

**Expected curl response:**
```json
{"error":"Invalid token"}
```

**Expected server.js console:**
```
[AUTH] Unexpected error: <Supabase error message about invalid JWT>
```

This proves: even with a structurally valid JWT, Supabase rejects it because it wasn't signed by your project's secret.

---

## D. Test 3: Health Check (No Auth Required)

```powershell
curl http://localhost:3000/health
```

**Expected response:**
```json
{"status":"ok","service":"albion-proxy","timestamp":"2026-09-02T16:30:00.000Z"}
```

This verifies Express is running and responding.

---

## E. Test 4: Full End-to-End (Requires Valid Supabase JWT)

### Step 1: Get a Valid Test JWT

Option A — Use Supabase Dashboard:
1. Go to your Supabase project → **Authentication** → **Users**
2. Create a test user (e.g., `testuser@albion.dev` / password `TestPass123!`)
3. Use the Supabase client to sign in and get the JWT:

```javascript
// Run this in Node.js (one-off script)
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient('YOUR_SUPABASE_URL', 'YOUR_SUPABASE_ANON_KEY');

async function getTestToken() {
  const { data, error } = await supabase.auth.signInWithPassword({
    email: 'testuser@albion.dev',
    password: 'TestPass123!'
  });
  if (error) { console.error(error); return; }
  console.log('JWT Token:', data.session.access_token);
  console.log('User ID:', data.user.id);
}
getTestToken();
```

Save the token — you'll use it in the curl commands below.

Option B — Use Supabase SQL Editor to create test subscription data:
```sql
-- Insert a test subscription for your test user
INSERT INTO subscriptions (user_id, tier, cycle_start, status)
VALUES ('<USER_ID_FROM_ABOVE>', 'starter', NOW(), 'active');
```

### Step 2: Run the Full Pipeline Test

Replace `<YOUR_JWT>` with the real token from Step 1:

```powershell
curl -X POST http://localhost:3000/chat `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer <YOUR_JWT>" `
  -d "{`"messages`":[{`"role`":`"user`",`"content`":`"Hello from Albion. Reply with exactly: Albion proxy working.`"}],`"model_preference`":`"deepseek-v4-flash`",`"estimated_tokens`":500,`"session_id`":`"test-session-1`"}"
```

**Expected curl response (success):**
```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "model": "deepseek-ai/DeepSeek-V4-Flash",
  "choices": [
    {
      "message": {
        "role": "assistant",
        "content": "Albion proxy working."
      }
    }
  ],
  "usage": {
    "prompt_tokens": 25,
    "completion_tokens": 5,
    "total_tokens": 30
  }
}
```

**Expected server.js console (success):**
```
[No errors — clean pass through authenticate() and checkCapBeforeRoute()]
```

**Expected curl response (if LiteLLM is down):**
```json
{"error":"Provider unavailable. Retrying...","retry_after":2000}
```

---

## F. Test 5: Cap Enforcement

### Setup: Max out the test user's usage
In Supabase SQL Editor, insert fake usage to exceed the starter cap (5M tokens):
```sql
INSERT INTO usage_logs (user_id, model, prompt_tokens, completion_tokens, actual_cost, session_id, timestamp)
VALUES ('<USER_ID>', 'deepseek-v4-flash', 4999000, 0, 0, 'cap-test', NOW());
```

### Run the test
```powershell
curl -X POST http://localhost:3000/chat `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer <YOUR_JWT>" `
  -d "{`"messages`":[{`"role`":`"user`",`"content`":`"test cap enforcement`"}],`"model_preference`":`"deepseek-v4-pro`",`"estimated_tokens`":5000,`"session_id`":`"cap-test-2`"}"
```

**Expected server.js console:**
```
[CAP] User <USER_ID> (starter) would exceed cap: 4999000 + 5000 > 5000000. Forcing flash_only.
```

**Expected behavior:** Even though the user requested `deepseek-v4-pro`, the proxy silently downgrades to `deepseek-v4-flash` because `4999000 + 5000 > 5000000`.

### Cleanup
```sql
DELETE FROM usage_logs WHERE session_id = 'cap-test';
```

---

## G. Supabase Dashboard Verification

After running Test 4 (full end-to-end), verify usage was logged:

1. Go to Supabase Dashboard → **Table Editor** → `usage_logs`
2. You should see a new row with:
   - `user_id`: matches your test user
   - `model`: `deepseek-v4-flash`
   - `prompt_tokens`: matches the response's `usage.prompt_tokens`
   - `completion_tokens`: matches the response's `usage.completion_tokens`
   - `session_id`: `test-session-1`
   - `timestamp`: within the last few minutes

**If the row is missing:** Check `server.js` console for `[USAGE] Failed to log usage` errors. Common causes:
- `usage_logs` table doesn't exist → create it
- Column name mismatch → verify schema matches the `insert()` call
- RLS policies blocking service role → disable RLS on `usage_logs` for now

---

## Test Results Summary

| Test | What It Verifies | Expected Result |
|------|-----------------|-----------------|
| Test 1 | No token → 401 | `{"error":"Invalid token"}` |
| Test 2 | Invalid token → 401 | `{"error":"Invalid token"}` |
| Test 3 | Health endpoint | `{"status":"ok",...}` |
| Test 4 | Full pipeline | AI response + usage logged |
| Test 5 | Cap enforcement | Silent downgrade to flash |

All 5 tests must pass before Phase 1 is considered complete.
