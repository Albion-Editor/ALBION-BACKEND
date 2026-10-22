# Albion Free Tier Policy

## Allowance

- **200,000 tokens lifetime, per user.**
- The allowance is a one-time grant. It does **not** reset daily, weekly, monthly, or per billing cycle.
- When the allowance is exhausted the account is locked out of AI requests until the user upgrades.

## Provider routing

- The free tier uses **one primary provider only**: DeepInfra or OpenRouter.
- `FREE_TIER_PROVIDER` selects the provider explicitly. If it is unset, the proxy prefers DeepInfra when `DEEPINFRA_API_KEY` exists, otherwise OpenRouter.
- There is **no Groq routing**, no key rotation, and no cross-provider fallback.
- A provider failure returns **HTTP 503**. It does not consume the user's lifetime tokens because the pending reservation is released.

## Token accounting

- Usage lives in Supabase `user_token_usage` and is updated through atomic RPCs:
  - `albion_reserve_free_tier_tokens`
  - `albion_commit_free_tier_tokens`
  - `albion_release_free_tier_tokens`
- The proxy reserves an estimated token count **before** calling the provider, commits actual usage afterwards, and releases the reservation on failure. Parallel requests therefore cannot bypass the cap.
- Streaming requests request `stream_options.include_usage = true` and commit the final usage chunk. If the provider omits usage, the proxy falls back to a deterministic character-based estimate.

## Responses

| Condition | Status | Body |
| --- | --- | --- |
| Allowance available | `200` | Normal provider response |
| Lifetime cap reached (pre-flight or reservation) | `402` | `Free tier lifetime limit reached (200k tokens). Please upgrade to continue.` |
| Provider unavailable / accounting unavailable | `503` | Provider or accounting error message |

`402` responses use `code: "free_tier_lifetime_limit_reached"` so clients can show the upgrade lockout without parsing prose.

## Pricing reference

DeepSeek V4.1 Flash:

- Input: **$0.07 / 1M tokens**
- Output: **$0.50 / 1M tokens**
- Blended: **$0.156 / 1M tokens**
- Exchange rate used for display: **₦1,370 / $1**

At the full 200k lifetime allowance the blended cost is approximately **$0.0312**.
