# Albion Cline Proxy Configuration

To wire the embedded Cline extension to the Albion Backend Proxy, add the following JSON to your VSCodium `settings.json` (File > Preferences > Settings > search "settings.json" or press `Ctrl+,` and click the `{}` icon in the top right).

```json
{
  "cline.apiProvider": "openai",
  "cline.openAiBaseUrl": "http://localhost:3000/chat",
  "cline.openAiApiKey": "YOUR_SUPABASE_JWT_TOKEN_HERE",
  "cline.openAiModelId": "deepseek-v4-flash",
  "albion.proxyUrl": "http://localhost:3000",
  "albion.apiKey": "YOUR_SUPABASE_JWT_TOKEN_HERE"
}
```

## How This Works

1. `cline.apiProvider: "openai"` tells Cline to use the OpenAI-compatible API format.
2. `cline.openAiBaseUrl` points Cline to our Node.js proxy's `/chat` endpoint.
3. `cline.openAiApiKey` injects the Supabase JWT, which our proxy's `authenticate()` middleware will validate.
4. `cline.openAiModelId` sets the default model. The proxy will override this based on the Task Classifier and token caps.
5. The `albion.*` settings are declared in our extension's `package.json` for future UI integration.

## Request Flow

```
Cline Extension
  │
  │  POST http://localhost:3000/chat
  │  Headers: Authorization: Bearer <Supabase JWT>
  │  Body: { model: "deepseek-v4-flash", messages: [...] }
  │
  ▼
Albion Proxy (server.js, port 3000)
  │
  ├─ 1. authenticate() → Validates JWT via Supabase
  ├─ 2. checkCapBeforeRoute() → Enforces tier token limits
  ├─ 3. Determines targetModel (may override based on cap/task)
  │
  │  POST http://localhost:4000/chat/completions
  │  Headers: Authorization: Bearer <LiteLLM Master Key>
  │  Body: { model: targetModel, messages: [...], metadata: {...} }
  │
  ▼
LiteLLM Proxy (port 4000)
  │
  ├─ Routes to DeepInfra (primary)
  ├─ Falls back to Together AI on failure
  └─ Tracks spend per request
```

## Testing the Connection

### Prerequisites
1. Ensure the proxy is running: `node server.js` (in `albion-proxy/`)
2. Ensure LiteLLM is running: `litellm --config litellm_config.yaml --port 4000`

### Steps
1. Open the extracted `VSCodium.exe` portable build.
2. Open Settings (`Ctrl+,`) → click the `{}` icon (top right) to open `settings.json`.
3. Paste the JSON snippet above (replace `YOUR_SUPABASE_JWT_TOKEN_HERE` with a valid test token).
4. Save and reload the window (`Ctrl+Shift+P` → "Reload Window").
5. Open the Cline panel (right sidebar, Cline icon).
6. Type: "Hello, are you connected to the Albion proxy?"
7. Check the `albion-proxy` terminal. You should see:
   - `[AUTH] User authenticated: <user-id>`
   - `[CAP] Tier check passed for user <user-id>`
   - The response routed successfully through LiteLLM → DeepInfra.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Cline shows "Invalid API key" | JWT expired or malformed | Get a fresh JWT from Supabase auth |
| 401 from proxy | `cline.openAiApiKey` not set | Add your JWT to `settings.json` |
| 502 from proxy | LiteLLM not running | Start LiteLLM: `litellm --config litellm_config.yaml --port 4000` |
| "Connection refused" | Proxy not running | Start proxy: `node server.js` |
| Cap forced to flash_only | No active subscription in Supabase | Create a test subscription row in `subscriptions` table |
