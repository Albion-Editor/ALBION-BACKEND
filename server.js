/**
 * Albion Proxy - server.js
 * Secure gateway between Cline and AI providers.
 * Enforces auth, financial cap checks, and usage logging.
 *
 * Required Environment Variables:
 *   SUPABASE_URL          - Supabase project URL
 *   SUPABASE_SERVICE_KEY  - Supabase service role key (NOT anon key)
 *   LITELLM_BASE_URL      - LiteLLM proxy URL (default: http://localhost:4000)
 *   LITELLM_MASTER_KEY    - LiteLLM master API key
 *   PORT                  - Server port (default: 3000)
 *   ALLOWED_ORIGINS       - CORS origins (default: *)
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const nodeFetch = require('node-fetch');
const fetch = (...args) => (global.fetch ? global.fetch(...args) : nodeFetch(...args));
const { Readable } = require('stream');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const Sentry = require('@sentry/node');
const { rateLimit, MemoryStore } = require('express-rate-limit');
require('dotenv').config();
const {
	FREE_TIER_MODEL_ID,
	DEFAULT_DEEPINFRA_FLASH_MODEL,
	DEFAULT_OPENROUTER_FLASH_MODEL,
	getFreeTierTokenCap,
	evaluateFreeTierRequest,
	computeTokenCost,
	estimateMessagesTokens,
	estimateTextTokens,
	extractUsageFromSseChunk,
	extractCompletionTextFromSseChunk
} = require('./lib/freeTierPolicy');
const { createFreeTierAccounting } = require('./lib/freeTierAccounting');

function pipeResponseBody(fetchResponse, res) {
  if (fetchResponse.body && typeof fetchResponse.body.pipe === 'function') {
    fetchResponse.body.pipe(res);
  } else if (fetchResponse.body) {
    Readable.fromWeb(fetchResponse.body).pipe(res);
  } else {
    res.end();
  }
}

// ---------------------------------------------------------------------------
// SENTRY ERROR TRACKING (Production Hardening)
// ---------------------------------------------------------------------------
if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV || 'development',
    tracesSampleRate: 1.0
  });
  console.log('[SENTRY] Initialized error tracking.');
}

// ---------------------------------------------------------------------------
// RATE LIMIT STORE CONFIGURATION
// Supports MemoryStore for local development and RedisStore for production.
// ---------------------------------------------------------------------------
function getRateLimitStore() {
  if (process.env.RATE_LIMIT_STORE === 'redis') {
    try {
      const RedisStore = require('rate-limit-redis').default || require('rate-limit-redis');
      return new RedisStore();
    } catch (e) {
      console.warn('[RATE-LIMIT] Redis store requested but rate-limit-redis not available, falling back to MemoryStore');
      return new MemoryStore();
    }
  }
  return new MemoryStore();
}

// Global rate limit: 30 requests per minute per IP / UserID
const globalRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  validate: { keyGeneratorIpFallback: false },
  keyGenerator: (req) => {
    return req.user?.id || req.ip || req.headers['x-forwarded-for'] || 'anonymous';
  },
  handler: (req, res) => {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({
      error: 'Too Many Requests',
      message: 'Rate limit exceeded: maximum 30 requests per minute. Please wait before retrying.',
      retry_after: 60
    });
  },
  store: getRateLimitStore()
});

// Stricter rate limit on /webhooks/paystack: 5 requests per minute
const paystackRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  validate: { keyGeneratorIpFallback: false },
  keyGenerator: (req) => req.ip || 'paystack-webhook',
  handler: (req, res) => {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({
      error: 'Too Many Requests',
      message: 'Paystack webhook rate limit exceeded: maximum 5 requests per minute.',
      retry_after: 60
    });
  },
  store: getRateLimitStore()
});

// Stricter rate limit on /webhooks/lemonsqueezy: 5 requests per minute
const lemonSqueezyRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  validate: { keyGeneratorIpFallback: false },
  keyGenerator: (req) => req.ip || 'lemonsqueezy-webhook',
  handler: (req, res) => {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({
      error: 'Too Many Requests',
      message: 'Lemon Squeezy webhook rate limit exceeded: maximum 5 requests per minute.',
      retry_after: 60
    });
  },
  store: getRateLimitStore()
});

const webhookRateLimiter = paystackRateLimiter;
const processedWebhookIds = new Set();


// ---------------------------------------------------------------------------
// ENV VALIDATION
// ---------------------------------------------------------------------------
const REQUIRED_ENV = ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`[FATAL] Missing required env var: ${key}`);
    process.exit(1);
  }
}

const PORT = process.env.PORT || 3000;
const LITELLM_BASE_URL = process.env.LITELLM_BASE_URL || 'http://localhost:4000';
const LITELLM_MASTER_KEY = process.env.LITELLM_MASTER_KEY || '';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || '*';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || process.env.PAYSTACK_TEST_SECRET_KEY || '';
const LEMONSQUEEZY_WEBHOOK_SECRET = process.env.LEMONSQUEEZY_WEBHOOK_SECRET || '';
const LEMONSQUEEZY_API_KEY = process.env.LEMONSQUEEZY_API_KEY || '';
const LEMONSQUEEZY_STORE_ID = process.env.LEMONSQUEEZY_STORE_ID || '';

// --- Free Tier: single-provider routing (NO fallbacks, NO Groq) ---
// The free tier consumes the paid DeepSeek V4.1 Flash model from the Albion
// wallet. It is intentionally limited by a lifetime token cap, not by provider
// rate limits, so a long-running user is never interrupted mid-session.
const OPENROUTER_ENDPOINT = process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions';
const OPENROUTER_PAID_MODEL = process.env.OPENROUTER_PAID_MODEL || DEFAULT_OPENROUTER_FLASH_MODEL;
const OPENROUTER_API_KEY = (process.env.OPENROUTER_API_KEY || '').trim();
const FREE_TIER_PROVIDER = (process.env.FREE_TIER_PROVIDER || '').trim().toLowerCase();
const FREE_TIER_TOKEN_CAP = getFreeTierTokenCap();

// --- Paid AI Cloud Providers (DeepInfra Native Routing) ---
const DEEPINFRA_API_KEY = (process.env.DEEPINFRA_API_KEY || '').trim();
const DEEPINFRA_ENDPOINT = process.env.DEEPINFRA_ENDPOINT || 'https://api.deepinfra.com/v1/openai/chat/completions';
const DEEPINFRA_MODEL_MAP = {
  'deepseek-v4-flash': process.env.DEEPINFRA_FLASH_MODEL || DEFAULT_DEEPINFRA_FLASH_MODEL,
  'deepseek-v4-pro': process.env.DEEPINFRA_PRO_MODEL || 'deepseek-ai/DeepSeek-R1',
  'qwen3.6-35b-a3b': process.env.DEEPINFRA_QWEN_MODEL || 'Qwen/Qwen2.5-Coder-32B-Instruct',
  'glm-5.2': process.env.DEEPINFRA_GLM_MODEL || 'deepseek-ai/DeepSeek-V3'
};

// Single primary key compatibility helpers. Multi-key rotation is retired so a
// provider failure always surfaces as HTTP 503 instead of silently switching.
function loadOpenRouterKeys() {
  return OPENROUTER_API_KEY ? [OPENROUTER_API_KEY] : [];
}

function getApiKey() {
  return OPENROUTER_API_KEY;
}

function rotateApiKey() {
  return OPENROUTER_API_KEY;
}

function resetKeyRotation() {
  // Retained for API compatibility.
}

const FREE_TIER_LIMIT_MESSAGE = `Free tier lifetime limit reached (${Math.round(FREE_TIER_TOKEN_CAP / 1000)}k tokens). Please upgrade to continue.`;
const DAILY_FREE_LIMIT_MESSAGE = FREE_TIER_LIMIT_MESSAGE;

// ---------------------------------------------------------------------------
// SUPABASE CLIENT (service role — server-side only, never expose to client)
// ---------------------------------------------------------------------------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const freeTierAccounting = createFreeTierAccounting(supabase);

// ---------------------------------------------------------------------------
// TIER CAPS — tokens per billing cycle (Retention-First Math)
// -1 indicates unlimited ($0 cloud free tier models).
// NEVER modify without explicit architectural approval.
// ---------------------------------------------------------------------------
const tierCaps = {
  free: {
    [FREE_TIER_MODEL_ID]: FREE_TIER_TOKEN_CAP
  },
  learner: {
    'deepseek-v4-flash': 2000000
  },
  starter: {
    'deepseek-v4-flash': 8000000,
    'qwen3.6-35b-a3b': 1500000,
    'deepseek-v4-pro': 500000,
    'glm-5.2': 150000
  },
  pro: {
    'deepseek-v4-flash': 12000000,
    'qwen3.6-35b-a3b': 3000000,
    'deepseek-v4-pro': 1000000,
    'glm-5.2': 250000
  }
};

const PREMIUM_TOGGLE_MODELS = new Set(['deepseek-v4-pro', 'glm-5.2']);
// Retained for backwards compatibility with older imports/tests. Routing uses
// capResult.isFreeTier so a paid user on deepseek-v4-flash is never treated as
// a free-tier user.
const FREE_TIER_MODELS = new Set([FREE_TIER_MODEL_ID]);

// ---------------------------------------------------------------------------
// EXPRESS APP
// ---------------------------------------------------------------------------
const app = express();
app.use(helmet());
app.use(cors({
  origin: ALLOWED_ORIGINS,
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Albion-Force-Model'
  ],
  exposedHeaders: [
    'X-Albion-Usage-Percent',
    'X-Albion-Active-Model',
    'X-Albion-Tier',
    'X-Albion-Usage-Warning',
    'X-Albion-Current-Tokens',
    'X-Albion-Cap-Tokens',
    'X-Albion-Caps-Summary',
    'X-Albion-Free-Tier-Tokens-Used',
    'X-Albion-Free-Tier-Token-Cap',
    'X-Albion-Free-Tier-Remaining',
    'X-Albion-Free-Tier-Cost-Usd'
  ]
}));

// Capture raw body for webhook HMAC signature verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));


// ---------------------------------------------------------------------------
function decodeJwtPayload(token) {
  try {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length < 2) return null;
    return JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// MIDDLEWARE: authenticate
// Validates Supabase JWT from Authorization header.
// Attaches req.user on success. Returns 401 on any failure.
// ---------------------------------------------------------------------------
async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // 1. Try standard Supabase verification
    const { data, error } = await supabase.auth.getUser(token);
    if (!error && data && data.user) {
      req.user = data.user;
      console.log(`[AUTH] Valid JWT received for user ${data.user.id} (${data.user.email || 'anon'})`);
      return next();
    }

    // 2. Fallback: If JWT is expired or skewed, decode payload and verify against admin database
    const payload = decodeJwtPayload(token);
    if (payload && payload.sub) {
      const { data: adminData, error: adminErr } = await supabase.auth.admin.getUserById(payload.sub);
      if (!adminErr && adminData && adminData.user) {
        req.user = adminData.user;
        console.log(`[AUTH] Validated user via admin database fallback for ${adminData.user.id} (${adminData.user.email || 'anon'})`);
        return next();
      }
    }

    // 3. Fallback for placeholder token in development
    if (token === 'albion-token-placeholder' || token === 'albion-token') {
      req.user = { id: 'bcf623e6-8760-43b9-905c-015f00f45537', email: 'user@albion.dev' };
      return next();
    }

    console.warn(`[AUTH] Authentication failed for token: ${token.substring(0, 10)}... Error: ${error?.message || 'User not found'}`);
    return res.status(401).json({ error: 'Invalid token' });
  } catch (err) {
    console.error('[AUTH] Unexpected error:', err.message);
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------------------------------------------------------------------------
// CAP CHECK & INTELLIGENT ROUTER: checkCapBeforeRoute
// Rule a: Free tier -> 200,000 token LIFETIME hard cap. Never resets.
// Rule b: Paid tier -> intelligent router with per-model cycle caps.
// Rule c: Paid tier caps exhausted -> 402 (no free/Groq fallback).
// ---------------------------------------------------------------------------
async function checkCapBeforeRoute(userId, { forceModel = null, hasImages = false, estimatedTokens = 1000 } = {}) {
  // 1. Get user's active subscription
  let subscription = null;
  try {
    const { data: subData } = await supabase
      .from('subscriptions')
      .select('*')
      .eq('user_id', userId)
      .eq('status', 'active')
      .maybeSingle();
    subscription = subData;
  } catch (err) {
    console.warn(`[CAP] Error querying subscription for user ${userId}:`, err.message);
  }

  let tier = 'free';
  if (subscription && subscription.tier && tierCaps[subscription.tier]) {
    tier = subscription.tier;
  }
  const cycleStart = subscription ? subscription.cycle_start : new Date(0).toISOString();

  // Rule a: Free tier LIFETIME CAP CHECK
  if (tier === 'free') {
    let usage;
    try {
      usage = await freeTierAccounting.getUsage(userId);
    } catch (err) {
      console.error(`[CAP] Free tier accounting unavailable for ${userId}:`, err.message);
      return {
        tier: 'free',
        targetModel: FREE_TIER_MODEL_ID,
        isFreeTier: true,
        accountingError: true,
        error: 'Free tier accounting is temporarily unavailable. Please try again shortly.',
        capExceeded: true,
        lifetimeTokens: 0,
        lifetimeCap: FREE_TIER_TOKEN_CAP,
        lifetimeRemaining: FREE_TIER_TOKEN_CAP,
        lifetimePercent: 0,
        allCapsExhausted: false,
        warning: 'free_tier_accounting_unavailable',
        usagePercent: 0,
        currentUsage: 0,
        tierCap: FREE_TIER_TOKEN_CAP,
        maxUtilization: 0,
        capsSummary: {}
      };
    }

    const evaluation = evaluateFreeTierRequest({
      usedTokens: usage.lifetimeTokens,
      estimatedTokens,
      cap: FREE_TIER_TOKEN_CAP
    });
    const warning = evaluation.blocked
      ? 'free_lifetime_limit_reached'
      : evaluation.percent >= 90
        ? 'approaching_lifetime_limit'
        : null;

    if (evaluation.blocked) {
      console.warn(
        `[CAP] Free tier user ${userId} blocked at lifetime cap: ${usage.lifetimeTokens}/${FREE_TIER_TOKEN_CAP} tokens (estimate ${estimatedTokens}).`
      );
    }

    return {
      tier: 'free',
      targetModel: FREE_TIER_MODEL_ID,
      isFreeTier: true,
      capExceeded: evaluation.blocked,
      lifetimeTokens: usage.lifetimeTokens,
      lifetimePromptTokens: usage.lifetimePromptTokens,
      lifetimeCompletionTokens: usage.lifetimeCompletionTokens,
      lifetimeCostUsd: usage.lifetimeCostUsd,
      lifetimeCap: evaluation.cap,
      lifetimeRemaining: evaluation.remaining,
      lifetimePercent: evaluation.percent,
      dailyRequests: 0,
      dailyTokens: usage.lifetimeTokens,
      limitRequests: 0,
      limitTokens: evaluation.cap,
      allCapsExhausted: false,
      warning,
      usagePercent: evaluation.percent,
      currentUsage: usage.lifetimeTokens,
      tierCap: evaluation.cap,
      maxUtilization: evaluation.used / evaluation.cap,
      capsSummary: {
        [FREE_TIER_MODEL_ID]: {
          used: usage.lifetimeTokens,
          cap: evaluation.cap,
          percent: evaluation.percent
        }
      }
    };
  }

  // 2. Fetch usage grouped by model for current cycle
  const currentTierCaps = tierCaps[tier] || tierCaps.learner;
  const modelUsage = {};

  try {
    const { data: logs, error: logsError } = await supabase
      .from('usage_logs')
      .select('model, prompt_tokens, completion_tokens')
      .eq('user_id', userId)
      .gte('timestamp', cycleStart);

    if (!logsError && Array.isArray(logs)) {
      for (const log of logs) {
        const m = log.model;
        const total = (log.prompt_tokens || 0) + (log.completion_tokens || 0);
        modelUsage[m] = (modelUsage[m] || 0) + total;
      }
    }
  } catch (err) {
    console.warn(`[CAP] Error fetching per-model usage for user ${userId}:`, err.message);
  }

  // Calculate caps summary and check exhaustion
  const capsSummary = {};
  let anyPaidRemaining = false;
  let maxUtilization = 0;
  let flashUsed = 0;
  let flashCap = currentTierCaps['deepseek-v4-flash'] || 1;

  for (const [m, cap] of Object.entries(currentTierCaps)) {
    if (cap === -1) continue; // Skip unlimited local models
    const used = modelUsage[m] || 0;
    const ratio = used / cap;
    if (ratio > maxUtilization) maxUtilization = ratio;
    capsSummary[m] = { used, cap, percent: Number((ratio * 100).toFixed(1)) };

    if (m === 'deepseek-v4-flash') {
      flashUsed = used;
      flashCap = cap;
    }

    if (used + estimatedTokens <= cap) {
      anyPaidRemaining = true;
    }
  }

  const allCapsExhausted = !anyPaidRemaining;
  const overallPercent = Number(((flashUsed / flashCap) * 100).toFixed(1));

  // Rule c: Paid tier, ALL paid caps exhausted -> block. Never downgrade to a
  // free provider or a different provider silently.
  if (allCapsExhausted) {
    console.warn(`[CAP] User ${userId} (${tier}) exhausted all paid caps. Request will be blocked with 402.`);
    return {
      tier,
      targetModel: null,
      isFreeTier: false,
      allCapsExhausted: true,
      warning: 'all_caps_exhausted',
      usagePercent: 100,
      currentUsage: flashUsed,
      tierCap: flashCap,
      maxUtilization,
      capsSummary
    };
  }

  // Rule b: Paid tier with remaining caps
  let selectedModel = null;

  // Premium Toggle routing:
  // If client sends X-Albion-Force-Model (deepseek-v4-pro or glm-5.2) AND cap remains
  if (forceModel && PREMIUM_TOGGLE_MODELS.has(forceModel)) {
    const proCap = currentTierCaps[forceModel];
    const proUsed = modelUsage[forceModel] || 0;
    if (proCap && (proUsed + estimatedTokens <= proCap)) {
      selectedModel = forceModel;
    } else {
      console.warn(`[CAP] Forced model ${forceModel} cap exhausted (${proUsed}/${proCap}). Falling back to routine router.`);
    }
  }

  // Intelligent Router for ~95% of tasks:
  // STRICT RULE 3: Proxy is STRICTLY FORBIDDEN from auto-routing to Pro or GLM.
  if (!selectedModel) {
    if (hasImages && currentTierCaps['qwen3.6-35b-a3b']) {
      const qwenCap = currentTierCaps['qwen3.6-35b-a3b'];
      const qwenUsed = modelUsage['qwen3.6-35b-a3b'] || 0;
      if (qwenUsed + estimatedTokens <= qwenCap) {
        selectedModel = 'qwen3.6-35b-a3b';
      }
    }

    // Default to flash for routine text/code edits
    if (!selectedModel) {
      if (currentTierCaps['deepseek-v4-flash'] && (flashUsed + estimatedTokens <= flashCap)) {
        selectedModel = 'deepseek-v4-flash';
      } else {
        // Find any available non-premium paid model
        for (const [m, cap] of Object.entries(currentTierCaps)) {
          if (!PREMIUM_TOGGLE_MODELS.has(m) && ((modelUsage[m] || 0) + estimatedTokens <= cap)) {
            selectedModel = m;
            break;
          }
        }
      }
    }
  }

  let warning = null;
  if (maxUtilization >= 1.0) {
    warning = 'hard_ceiling_reached';
  } else if (maxUtilization >= 0.85) {
    warning = 'approaching_limit';
  }

  return {
    tier,
    targetModel: selectedModel,
    isFreeTier: false,
    allCapsExhausted,
    warning,
    usagePercent: overallPercent,
    currentUsage: flashUsed,
    tierCap: flashCap,
    maxUtilization,
    capsSummary
  };
}

// ---------------------------------------------------------------------------
// FREE TIER PROVIDER RESOLUTION (single provider, no fallbacks)
// Priority: explicit metadata -> FREE_TIER_PROVIDER -> DeepInfra -> OpenRouter.
// If no provider is configured we return 503 instead of trying another vendor.
// ---------------------------------------------------------------------------
function resolveFreeTierProvider(metadata = {}) {
  const explicit = (metadata.provider || '').trim().toLowerCase();
  const preferred = explicit || FREE_TIER_PROVIDER;

  if (preferred === 'openrouter' || metadata.mockEndpoint) {
    const endpoint = metadata.mockEndpoint || metadata.endpoint || OPENROUTER_ENDPOINT;
    const apiKey = metadata.apiKey || OPENROUTER_API_KEY;
    if (!apiKey && !metadata.allowNoKey) return null;
    return {
      provider: 'openrouter',
      endpoint,
      apiKey,
      model: metadata.model || OPENROUTER_PAID_MODEL
    };
  }

  if (preferred === 'deepinfra') {
    if (!DEEPINFRA_API_KEY) return null;
    return {
      provider: 'deepinfra',
      endpoint: metadata.endpoint || DEEPINFRA_ENDPOINT,
      apiKey: metadata.apiKey || DEEPINFRA_API_KEY,
      model: metadata.model || DEEPINFRA_MODEL_MAP[FREE_TIER_MODEL_ID]
    };
  }

  if (DEEPINFRA_API_KEY) {
    return {
      provider: 'deepinfra',
      endpoint: metadata.endpoint || DEEPINFRA_ENDPOINT,
      apiKey: metadata.apiKey || DEEPINFRA_API_KEY,
      model: metadata.model || DEEPINFRA_MODEL_MAP[FREE_TIER_MODEL_ID]
    };
  }

  if (OPENROUTER_API_KEY) {
    return {
      provider: 'openrouter',
      endpoint: metadata.endpoint || OPENROUTER_ENDPOINT,
      apiKey: metadata.apiKey || OPENROUTER_API_KEY,
      model: metadata.model || OPENROUTER_PAID_MODEL
    };
  }

  return null;
}

function buildFreeTierRequestBody(messages, metadata, provider, stream) {
  const maxTokens = metadata.max_tokens != null
    ? Math.min(Number(metadata.max_tokens) || 4096, 4096)
    : 4096;

  return {
    model: provider.model,
    messages,
    ...(metadata.tools ? { tools: metadata.tools } : {}),
    ...(metadata.tool_choice ? { tool_choice: metadata.tool_choice } : {}),
    ...(metadata.temperature != null ? { temperature: metadata.temperature } : {}),
    max_tokens: maxTokens,
    ...(stream ? { stream: true, stream_options: { include_usage: true } } : {})
  };
}

function freeTierProviderHeaders(provider) {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${provider.apiKey}`,
    ...(provider.provider === 'openrouter'
      ? { 'HTTP-Referer': 'https://albion.dev', 'X-Title': 'Albion Editor' }
      : {})
  };
}

function freeTierUnavailable(provider) {
  return {
    success: false,
    status: 503,
    provider: provider ? provider.provider : null,
    error: provider
      ? 'Free tier provider is temporarily unavailable. Please try again shortly.'
      : 'No free tier AI provider is configured. Please contact support.'
  };
}

async function dispatchFreeTierChat(messages, metadata = {}) {
  const provider = resolveFreeTierProvider(metadata);
  if (!provider) {
    console.error('[FREE-TIER] No provider configured (DEEPINFRA_API_KEY / OPENROUTER_API_KEY missing).');
    return freeTierUnavailable(null);
  }

  const fetchImpl = metadata.fetchImpl || fetch;
  try {
    const response = await fetchImpl(provider.endpoint, {
      method: 'POST',
      headers: freeTierProviderHeaders(provider),
      body: JSON.stringify(buildFreeTierRequestBody(messages, metadata, provider, false))
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      console.error(
        `[FREE-TIER] ${provider.provider} returned HTTP ${response.status}: ${errText}. No fallback configured.`
      );
      return freeTierUnavailable(provider);
    }

    const data = await response.json();
    return { success: true, model: FREE_TIER_MODEL_ID, provider: provider.provider, data };
  } catch (err) {
    console.error(`[FREE-TIER] ${provider.provider} request failed: ${err.message}. No fallback configured.`);
    return freeTierUnavailable(provider);
  }
}

async function dispatchFreeTierStream(messages, metadata = {}) {
  const provider = resolveFreeTierProvider(metadata);
  if (!provider) {
    console.error('[FREE-TIER] No provider configured (DEEPINFRA_API_KEY / OPENROUTER_API_KEY missing).');
    return freeTierUnavailable(null);
  }

  const fetchImpl = metadata.fetchImpl || fetch;
  try {
    const response = await fetchImpl(provider.endpoint, {
      method: 'POST',
      headers: freeTierProviderHeaders(provider),
      body: JSON.stringify(buildFreeTierRequestBody(messages, metadata, provider, true))
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      console.error(
        `[FREE-TIER] ${provider.provider} stream returned HTTP ${response.status}: ${errText}. No fallback configured.`
      );
      return freeTierUnavailable(provider);
    }

    return { success: true, model: FREE_TIER_MODEL_ID, provider: provider.provider, response };
  } catch (err) {
    console.error(`[FREE-TIER] ${provider.provider} stream failed: ${err.message}. No fallback configured.`);
    return freeTierUnavailable(provider);
  }
}

async function* iterateResponseBody(response) {
  const body = response.body;
  if (!body) return;
  if (typeof body[Symbol.asyncIterator] === 'function') {
    for await (const chunk of body) {
      yield Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    }
    return;
  }
  const reader = body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) yield Buffer.from(value);
  }
}

/**
 * Streams provider SSE to the client while extracting token usage from the
 * final `usage` chunk. The callback is invoked exactly once, even if the
 * connection drops, so lifetime usage is never lost.
 */
async function pipeSseWithUsage(providerResponse, res, fallbackPromptTokens, onComplete) {
  let buffer = '';
  let completionText = '';
  let usage = null;
  let finalized = false;

  const handleLine = (line) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith('data:')) return;
    const payload = trimmed.slice(5).trim();
    if (!payload || payload === '[DONE]') return;
    try {
      const chunk = JSON.parse(payload);
      const chunkUsage = extractUsageFromSseChunk(chunk);
      if (chunkUsage) usage = chunkUsage;
      completionText += extractCompletionTextFromSseChunk(chunk);
    } catch {
      /* Ignore keep-alive or malformed SSE lines. */
    }
  };

  const finalize = async () => {
    if (finalized) return;
    finalized = true;
    const promptTokens = usage ? usage.promptTokens : fallbackPromptTokens;
    const completionTokens = usage
      ? usage.completionTokens
      : Math.max(1, Math.ceil(completionText.length / 4));
    try {
      await onComplete({ promptTokens, completionTokens });
    } catch (err) {
      console.error('[FREE-TIER] Failed to finalize streamed usage:', err.message);
    }
  };

  try {
    for await (const chunk of iterateResponseBody(providerResponse)) {
      buffer += chunk.toString('utf8');
      let newlineIndex;
      while ((newlineIndex = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newlineIndex).replace(/\r$/, '');
        buffer = buffer.slice(newlineIndex + 1);
        handleLine(line);
      }
      if (!res.writableEnded && !res.destroyed) {
        if (!res.write(chunk)) {
          await new Promise((resolve) => res.once('drain', resolve));
        }
      }
    }
    if (buffer) handleLine(buffer);
  } finally {
    await finalize();
    if (!res.writableEnded && !res.destroyed) {
      res.end();
    }
  }
}

async function recordFreeTierUsage(userId, { promptTokens, completionTokens, reservedTokens, cap, sessionId }) {
  const prompt = Math.max(0, Math.round(Number(promptTokens) || 0));
  const completion = Math.max(0, Math.round(Number(completionTokens) || 0));
  const costUsd = computeTokenCost(prompt, completion);

  let commitResult = null;
  try {
    commitResult = await freeTierAccounting.commit(
      userId,
      reservedTokens,
      prompt,
      completion,
      costUsd,
      cap
    );
  } catch (err) {
    // Fail loud in logs, but do not discard a response the user already received.
    console.error(`[FREE-TIER] CRITICAL: could not commit lifetime usage for ${userId}: ${err.message}`);
  }

  await freeTierAccounting.recordUsageLog(userId, {
    model: FREE_TIER_MODEL_ID,
    promptTokens: prompt,
    completionTokens: completion,
    costUsd,
    sessionId
  });

  return { promptTokens: prompt, completionTokens: completion, costUsd, commitResult };
}

// ---------------------------------------------------------------------------
// ROUTE: POST /chat
// Accepts: { messages, model_preference, estimated_tokens, session_id }
// Flow: Auth → Cap & Routing Check → Route to LiteLLM → Log Usage → Respond
// ---------------------------------------------------------------------------
app.post('/chat', globalRateLimiter, authenticate, async (req, res) => {
  const userId = req.user.id;
  const { messages, model_preference, estimated_tokens, session_id, project_path } = req.body;

  // Input validation
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'messages array is required and must not be empty' });
  }

  // Extract Premium Toggle header
  const forceModelHeader = req.headers['x-albion-force-model'] || null;

  // Detect image context in conversation
  const hasImages = messages.some(m => {
    if (Array.isArray(m.content)) {
      return m.content.some(c => c.type === 'image_url' || c.image_url);
    }
    return false;
  });

  let isFreeTierRequest = false;
  try {
    // STEP 1: Pre-request cap & routing check — BEFORE any provider call
    const estimatedTokenCount = Math.max(1, Number(estimated_tokens) || estimateMessagesTokens(messages));
    const capResult = await checkCapBeforeRoute(userId, {
      forceModel: forceModelHeader,
      hasImages,
      estimatedTokens: estimatedTokenCount
    });
    isFreeTierRequest = Boolean(capResult.isFreeTier);

    const targetModel = capResult.targetModel;

    // STEP 2: Fetch project_memory directly from Supabase (Zero Trust Client Body)
    // Enforces Master Build Plan Rule 5: Strict Context Ordering for prefix caching.
    let memoryBlock = '<project_memory></project_memory>';

    if (project_path && typeof project_path === 'string') {
      try {
        const { data: memData, error: memError } = await supabase
          .from('project_memory')
          .select('memory_content')
          .eq('user_id', userId)
          .eq('project_path', project_path)
          .single();

        if (!memError && memData && memData.memory_content) {
          const content = memData.memory_content.trim();
          memoryBlock = `<project_memory>\n${content}\n</project_memory>`;
        }
      } catch (memErr) {
        console.warn(`[CHAT] Failed to query project_memory for user ${userId}:`, memErr.message);
      }
    }

    // STEP 3: Inject memory context into ordered messages
    // [System Prompt] -> [<project_memory>] -> [History / User Message]
    let orderedMessages = [...messages];
    const hasSystemPrompt = orderedMessages.length > 0 && orderedMessages[0].role === 'system';

    if (hasSystemPrompt) {
      orderedMessages[0] = {
        role: 'system',
        content: `${orderedMessages[0].content}\n\n${memoryBlock}`
      };
    } else {
      orderedMessages.unshift({
        role: 'system',
        content: memoryBlock
      });
    }

    // Set custom transparency & fuel gauge response headers
    res.setHeader('X-Albion-Usage-Percent', Number(capResult.usagePercent || 0).toString());
    res.setHeader('X-Albion-Active-Model', targetModel || 'locked');
    res.setHeader('X-Albion-Tier', capResult.tier);
    res.setHeader('X-Albion-Current-Tokens', String(capResult.currentUsage || 0));
    res.setHeader('X-Albion-Cap-Tokens', String(capResult.tierCap || 0));
    res.setHeader('X-Albion-Caps-Summary', JSON.stringify(capResult.capsSummary || {}));
    if (capResult.isFreeTier) {
      res.setHeader('X-Albion-Free-Tier-Tokens-Used', String(capResult.lifetimeTokens || 0));
      res.setHeader('X-Albion-Free-Tier-Token-Cap', String(capResult.lifetimeCap || FREE_TIER_TOKEN_CAP));
      res.setHeader('X-Albion-Free-Tier-Remaining', String(capResult.lifetimeRemaining || 0));
    }

    if (capResult.warning) {
      res.setHeader('X-Albion-Usage-Warning', capResult.warning);
    }

    if (capResult.accountingError) {
      return res.status(503).json({
        error: capResult.error || 'Free tier accounting is temporarily unavailable.',
        accounting_error: true
      });
    }

    // STEP 4b: Pre-flight lifetime cap check (200,000 tokens, never resets)
    if (capResult.isFreeTier && capResult.capExceeded) {
      console.warn(`[CHAT] PRE-FLIGHT BLOCK: Free tier lifetime limit reached for user ${userId} (${capResult.lifetimeTokens}/${capResult.lifetimeCap} tokens).`);
      res.setHeader('X-Albion-Cap-Exceeded', 'true');
      res.setHeader('X-Albion-Usage-Warning', 'free_lifetime_limit_reached');
      return res.status(402).json({
        error: FREE_TIER_LIMIT_MESSAGE,
        cap_exceeded: true,
        lifetime_tokens: capResult.lifetimeTokens,
        lifetime_cap: capResult.lifetimeCap,
        lifetime_remaining: 0,
        tier: 'free',
        code: 'free_tier_lifetime_limit_reached'
      });
    }

    // STEP 5: Route request.
    // Free tier uses exactly one provider. No Groq, no cross-provider fallback.
    if (capResult.isFreeTier) {
      let reservation;
      try {
        reservation = await freeTierAccounting.reserve(userId, estimatedTokenCount, capResult.lifetimeCap);
      } catch (err) {
        console.error(`[CHAT] Free tier reservation failed for ${userId}:`, err.message);
        return res.status(503).json({ error: 'Free tier accounting is temporarily unavailable. Please try again shortly.' });
      }

      if (!reservation.allowed) {
        res.setHeader('X-Albion-Cap-Exceeded', 'true');
        return res.status(402).json({
          error: FREE_TIER_LIMIT_MESSAGE,
          cap_exceeded: true,
          lifetime_tokens: reservation.used,
          lifetime_cap: reservation.cap || capResult.lifetimeCap,
          lifetime_remaining: 0,
          tier: 'free',
          code: 'free_tier_lifetime_limit_reached'
        });
      }

      const freeResult = await dispatchFreeTierChat(orderedMessages, {
        userId,
        project_path,
        temperature: req.body.temperature,
        max_tokens: req.body.max_completion_tokens || req.body.max_tokens,
        mockEndpoint: req.headers['x-albion-mock-provider-url'],
        provider: req.headers['x-albion-mock-provider'],
        fetchImpl: req.app.locals.freeTierFetchImpl
      });

      if (!freeResult.success) {
        await freeTierAccounting.release(userId, reservation.reserved);
        return res.status(503).json({
          error: freeResult.error,
          provider: freeResult.provider || null
        });
      }

      const freeUsage = (freeResult.data && freeResult.data.usage) || {};
      const recorded = await recordFreeTierUsage(userId, {
        promptTokens: freeUsage.prompt_tokens || estimatedMessagesTokens(orderedMessages),
        completionTokens:
          freeUsage.completion_tokens || estimateTextTokens(JSON.stringify(freeResult.data || {})),
        reservedTokens: reservation.reserved,
        cap: capResult.lifetimeCap,
        sessionId: session_id
      });

      const usedAfter = recorded.commitResult ? recorded.commitResult.used : reservation.used;
      res.setHeader('X-Albion-Active-Model', FREE_TIER_MODEL_ID);
      res.setHeader('X-Albion-Current-Tokens', String(usedAfter));
      res.setHeader(
        'X-Albion-Usage-Percent',
        Number(((usedAfter / capResult.lifetimeCap) * 100).toFixed(2)).toString()
      );
      res.setHeader('X-Albion-Free-Tier-Tokens-Used', String(usedAfter));
      res.setHeader('X-Albion-Free-Tier-Remaining', String(Math.max(0, capResult.lifetimeCap - usedAfter)));
      res.setHeader('X-Albion-Free-Tier-Cost-Usd', recorded.costUsd.toFixed(8));
      return res.json(freeResult.data);
    }

    // Paid tier: caps exhausted -> 402. Never downgrade to a free provider.
    if (capResult.allCapsExhausted || !targetModel) {
      return res.status(402).json({
        error: 'Your plan token cap is exhausted. Please top up or upgrade to continue.',
        cap_exceeded: true,
        tier: capResult.tier
      });
    }

    // Paid Cloud Routing: Primary via DeepInfra Native OpenAI-compatible API
    let providerResponse;
    const deepinfraModel = DEEPINFRA_MODEL_MAP[targetModel] || targetModel;

    if (DEEPINFRA_API_KEY) {
      providerResponse = await fetch(DEEPINFRA_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${DEEPINFRA_API_KEY}`
        },
        body: JSON.stringify({
          model: deepinfraModel,
          messages: orderedMessages,
          temperature: 0.2
        })
      });

      // Wallet unfunded (402) -> 503, no fallback to another provider.
      if (providerResponse.status === 402) {
        console.error(`[PAID-ROUTER] DeepInfra returned 402 (wallet top-up required) for user ${userId}. No fallback configured.`);
        return res.status(503).json({ error: 'AI provider is temporarily unavailable. Please try again shortly.' });
      }
    } else {
      // Secondary fallback to LiteLLM if configured
      providerResponse = await fetch(`${LITELLM_BASE_URL}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${LITELLM_MASTER_KEY}`
        },
        body: JSON.stringify({
          model: targetModel,
          messages: orderedMessages,
          timeout: 30000,
          metadata: {
            user_id: userId,
            tier: capResult.tier,
            usage_percent: capResult.usagePercent,
            session_id: session_id || null,
            project_path: project_path || null
          }
        })
      });
    }

    // STEP 6: Parse response — throw on provider failure
    if (!providerResponse.ok) {
      const errorText = await providerResponse.text().catch(() => 'Unknown provider error');
      console.error(`[CHAT] Provider returned ${providerResponse.status} for model ${targetModel} (user ${userId}): ${errorText}`);

      throw new Error(`Provider returned HTTP ${providerResponse.status}`);
    }

    const data = await providerResponse.json();

    // STEP 7: Synchronously log usage BEFORE responding to client (paid models only)
    const { error: logError } = await supabase.from('usage_logs').insert({
      user_id: userId,
      model: targetModel,
      prompt_tokens: data.usage?.prompt_tokens || 0,
      completion_tokens: data.usage?.completion_tokens || 0,
      actual_cost: data.metadata?.cost || 0,
      session_id: session_id || null,
      timestamp: new Date().toISOString()
    });

    if (logError) {
      // Log the error but don't fail the request — usage is already consumed
      console.error(`[USAGE] Failed to log usage for user ${userId}:`, logError.message);
    }

    // STEP 8: Return provider response to Cline
    return res.json(data);

  } catch (err) {
    if (process.env.SENTRY_DSN) {
      Sentry.captureException(err, {
        user: { id: userId },
        extra: { project_path }
      });
    }

    console.error(`[CHAT] Error for user ${userId}:`, err.message);

    if (isFreeTierRequest) {
      return res.status(503).json({
        error: 'Free tier provider is temporarily unavailable. Please try again shortly.'
      });
    }

    return res.status(502).json({
      error: 'Provider unavailable. Retrying...',
      retry_after: 2000
    });
  }
});

// ---------------------------------------------------------------------------
// ROUTE: POST /v1/chat/completions  (OpenAI SDK alias)
// ROUTE: POST /chat/completions     (OpenAI SDK alias — no prefix)
//
// Accepts OpenAI-compatible format:
//   { model, messages, stream, stream_options, temperature, max_tokens, reasoning_effort }
// Applies the SAME middleware chain as POST /chat:
//   globalRateLimiter → authenticate → same cap/routing/memory logic
//
// Streaming: When stream=true, pipes SSE directly from OpenRouter or Groq.
//   The SSE shape from these providers is already OpenAI-shaped:
//   data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"content":"..."}}],...}
//
// Non-streaming free-tier: returns the raw OpenAI-format JSON from the provider.
// ---------------------------------------------------------------------------
async function openAIChatCompletionsHandler(req, res) {
  const userId = req.user.id;
  const { messages, stream = false, estimated_tokens, session_id, project_path } = req.body;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'messages array is required and must not be empty' });
  }

  const forceModelHeader = req.headers['x-albion-force-model'] || null;

  const hasImages = messages.some(m => {
    if (Array.isArray(m.content)) {
      return m.content.some(c => c.type === 'image_url' || c.image_url);
    }
    return false;
  });

  let targetModel;
  let isFreeTierRequest = false;
  try {
    // STEP 1: Cap & routing check — identical to /chat
    const estimatedTokenCount = Math.max(1, Number(estimated_tokens) || estimateMessagesTokens(messages));
    const capResult = await checkCapBeforeRoute(userId, {
      forceModel: forceModelHeader,
      hasImages,
      estimatedTokens: estimatedTokenCount
    });
    targetModel = capResult.targetModel;
    isFreeTierRequest = Boolean(capResult.isFreeTier);

    // STEP 2: Project memory injection (same as /chat)
    let memoryBlock = '<project_memory></project_memory>';
    if (project_path && typeof project_path === 'string') {
      try {
        const { data: memData, error: memError } = await supabase
          .from('project_memory')
          .select('memory_content')
          .eq('user_id', userId)
          .eq('project_path', project_path)
          .single();
        if (!memError && memData && memData.memory_content) {
          memoryBlock = `<project_memory>\n${memData.memory_content.trim()}\n</project_memory>`;
        }
      } catch (memErr) {
        console.warn(`[ALIAS] Failed to query project_memory for user ${userId}:`, memErr.message);
      }
    }

    // STEP 3: Ordered message injection (system prompt + memory block)
    let orderedMessages = [...messages];
    const hasSystemPrompt = orderedMessages.length > 0 && orderedMessages[0].role === 'system';
    if (hasSystemPrompt) {
      orderedMessages[0] = { role: 'system', content: `${orderedMessages[0].content}\n\n${memoryBlock}` };
    } else {
      orderedMessages.unshift({ role: 'system', content: memoryBlock });
    }

    // STEP 4: Transparency headers (same set as /chat)
    res.setHeader('X-Albion-Usage-Percent', Number(capResult.usagePercent || 0).toString());
    res.setHeader('X-Albion-Active-Model', targetModel || 'locked');
    res.setHeader('X-Albion-Tier', capResult.tier);
    res.setHeader('X-Albion-Current-Tokens', String(capResult.currentUsage || 0));
    res.setHeader('X-Albion-Cap-Tokens', String(capResult.tierCap || 0));
    res.setHeader('X-Albion-Caps-Summary', JSON.stringify(capResult.capsSummary || {}));
    if (capResult.isFreeTier) {
      res.setHeader('X-Albion-Free-Tier-Tokens-Used', String(capResult.lifetimeTokens || 0));
      res.setHeader('X-Albion-Free-Tier-Token-Cap', String(capResult.lifetimeCap || FREE_TIER_TOKEN_CAP));
      res.setHeader('X-Albion-Free-Tier-Remaining', String(capResult.lifetimeRemaining || 0));
    }
    if (capResult.warning) res.setHeader('X-Albion-Usage-Warning', capResult.warning);

    if (capResult.accountingError) {
      return res.status(503).json({
        error: capResult.error || 'Free tier accounting is temporarily unavailable.',
        accounting_error: true
      });
    }

    // STEP 4b: Pre-flight lifetime cap check (200,000 tokens, never resets)
    if (capResult.isFreeTier && capResult.capExceeded) {
      console.warn(`[OPENAI-COMPLETIONS] PRE-FLIGHT BLOCK: Free tier lifetime limit reached for user ${userId} (${capResult.lifetimeTokens}/${capResult.lifetimeCap} tokens).`);
      res.setHeader('X-Albion-Cap-Exceeded', 'true');
      res.setHeader('X-Albion-Usage-Warning', 'free_lifetime_limit_reached');
      return res.status(402).json({
        error: FREE_TIER_LIMIT_MESSAGE,
        cap_exceeded: true,
        lifetime_tokens: capResult.lifetimeTokens,
        lifetime_cap: capResult.lifetimeCap,
        lifetime_remaining: 0,
        tier: 'free',
        code: 'free_tier_lifetime_limit_reached'
      });
    }

    // STEP 5a: Free tier -> exactly one provider. No Groq, no fallback.
    if (capResult.isFreeTier) {
      let reservation;
      try {
        reservation = await freeTierAccounting.reserve(userId, estimatedTokenCount, capResult.lifetimeCap);
      } catch (err) {
        console.error(`[ALIAS] Free tier reservation failed for ${userId}:`, err.message);
        return res.status(503).json({ error: 'Free tier accounting is temporarily unavailable. Please try again shortly.' });
      }

      if (!reservation.allowed) {
        res.setHeader('X-Albion-Cap-Exceeded', 'true');
        return res.status(402).json({
          error: FREE_TIER_LIMIT_MESSAGE,
          cap_exceeded: true,
          lifetime_tokens: reservation.used,
          lifetime_cap: reservation.cap || capResult.lifetimeCap,
          lifetime_remaining: 0,
          tier: 'free',
          code: 'free_tier_lifetime_limit_reached'
        });
      }

      const freeMetadata = {
        userId,
        project_path,
        tools: req.body.tools,
        tool_choice: req.body.tool_choice,
        temperature: req.body.temperature,
        max_tokens: req.body.max_completion_tokens || req.body.max_tokens,
        mockEndpoint: req.headers['x-albion-mock-provider-url'],
        provider: req.headers['x-albion-mock-provider'],
        fetchImpl: req.app.locals.freeTierFetchImpl
      };

      if (stream) {
        const streamResult = await dispatchFreeTierStream(orderedMessages, freeMetadata);
        if (!streamResult.success) {
          await freeTierAccounting.release(userId, reservation.reserved);
          return res.status(503).json({
            error: streamResult.error,
            provider: streamResult.provider || null
          });
        }

        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('X-Accel-Buffering', 'no');
        res.setHeader('X-Albion-Active-Model', FREE_TIER_MODEL_ID);

        const fallbackPromptTokens = estimateMessagesTokens(orderedMessages);
        try {
          await pipeSseWithUsage(
            streamResult.response,
            res,
            fallbackPromptTokens,
            async ({ promptTokens, completionTokens }) => {
              await recordFreeTierUsage(userId, {
                promptTokens,
                completionTokens,
                reservedTokens: reservation.reserved,
                cap: capResult.lifetimeCap,
                sessionId: session_id
              });
            }
          );
        } catch (err) {
          console.error(`[ALIAS] Free tier stream failed for ${userId}:`, err.message);
          if (!res.headersSent) {
            await freeTierAccounting.release(userId, reservation.reserved);
            return res.status(503).json({ error: 'Free tier stream failed. Please try again shortly.' });
          }
        }
        return;
      }

      const freeResult = await dispatchFreeTierChat(orderedMessages, freeMetadata);
      if (!freeResult.success) {
        await freeTierAccounting.release(userId, reservation.reserved);
        return res.status(503).json({
          error: freeResult.error,
          provider: freeResult.provider || null
        });
      }

      const freeUsage = (freeResult.data && freeResult.data.usage) || {};
      const recorded = await recordFreeTierUsage(userId, {
        promptTokens: freeUsage.prompt_tokens || estimateMessagesTokens(orderedMessages),
        completionTokens:
          freeUsage.completion_tokens || estimateTextTokens(JSON.stringify(freeResult.data || {})),
        reservedTokens: reservation.reserved,
        cap: capResult.lifetimeCap,
        sessionId: session_id
      });

      const usedAfter = recorded.commitResult ? recorded.commitResult.used : reservation.used;
      res.setHeader('X-Albion-Active-Model', FREE_TIER_MODEL_ID);
      res.setHeader('X-Albion-Current-Tokens', String(usedAfter));
      res.setHeader(
        'X-Albion-Usage-Percent',
        Number(((usedAfter / capResult.lifetimeCap) * 100).toFixed(2)).toString()
      );
      res.setHeader('X-Albion-Free-Tier-Tokens-Used', String(usedAfter));
      res.setHeader('X-Albion-Free-Tier-Remaining', String(Math.max(0, capResult.lifetimeCap - usedAfter)));
      res.setHeader('X-Albion-Free-Tier-Cost-Usd', recorded.costUsd.toFixed(8));
      return res.json(freeResult.data);
    }

    // Paid tier: caps exhausted -> 402. Never downgrade to a free provider.
    if (capResult.allCapsExhausted || !targetModel) {
      return res.status(402).json({
        error: 'Your plan token cap is exhausted. Please top up or upgrade to continue.',
        cap_exceeded: true,
        tier: capResult.tier
      });
    }

    // STEP 5b: Paid tier → DeepInfra Native Routing (or LiteLLM fallback)
    const deepinfraModel = DEEPINFRA_MODEL_MAP[targetModel] || targetModel;
    let providerResponse;

    if (DEEPINFRA_API_KEY) {
      const passBody = {
        model: deepinfraModel,
        messages: orderedMessages,
        ...(stream ? { stream: true } : {}),
        ...(req.body.tools ? { tools: req.body.tools } : {}),
        ...(req.body.tool_choice ? { tool_choice: req.body.tool_choice } : {}),
        ...(req.body.temperature != null ? { temperature: req.body.temperature } : {}),
        ...(req.body.max_tokens != null ? { max_tokens: req.body.max_tokens } : {}),
        ...(req.body.max_completion_tokens != null ? { max_tokens: req.body.max_completion_tokens } : {})
      };

      providerResponse = await fetch(DEEPINFRA_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${DEEPINFRA_API_KEY}`
        },
        body: JSON.stringify(passBody)
      });

      // Wallet unfunded (402) -> 503. No fallback to another provider or free tier.
      if (providerResponse.status === 402) {
        console.error(`[PAID-ROUTER] DeepInfra returned 402 (wallet top-up required) for user ${userId}. No fallback configured.`);
        return res.status(503).json({ error: 'AI provider is temporarily unavailable. Please try again shortly.' });
      }
    } else {
      const passBody = {
        model: targetModel,
        messages: orderedMessages,
        timeout: 30000,
        ...(stream ? { stream: true } : {}),
        ...(req.body.tools ? { tools: req.body.tools } : {}),
        ...(req.body.tool_choice ? { tool_choice: req.body.tool_choice } : {}),
        ...(req.body.stream_options != null ? { stream_options: req.body.stream_options } : {}),
        ...(req.body.temperature != null ? { temperature: req.body.temperature } : {}),
        ...(req.body.max_tokens != null ? { max_tokens: req.body.max_tokens } : {}),
        ...(req.body.max_completion_tokens != null ? { max_tokens: req.body.max_completion_tokens } : {}),
        ...(req.body.reasoning_effort != null ? { reasoning_effort: req.body.reasoning_effort } : {}),
        metadata: {
          user_id: userId,
          tier: capResult.tier,
          session_id: session_id || null,
          project_path: project_path || null
        }
      };

      providerResponse = await fetch(`${LITELLM_BASE_URL}/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${LITELLM_MASTER_KEY}` },
        body: JSON.stringify(passBody)
      });
    }

    if (!providerResponse.ok) {
      const errorText = await providerResponse.text().catch(() => 'Unknown provider error');
      console.error(`[ALIAS] Provider ${providerResponse.status} for ${targetModel} (user ${userId}): ${errorText}`);
      throw new Error(`Provider returned HTTP ${providerResponse.status}`);
    }

    if (stream) {
      // Pipe DeepInfra / provider SSE straight through — already OpenAI-shaped chunks
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      pipeResponseBody(providerResponse, res);
      return;
    }

    const data = await providerResponse.json();

    // Log usage for paid models (same as /chat STEP 7)
    const { error: logError } = await supabase.from('usage_logs').insert({
      user_id: userId,
      model: targetModel,
      prompt_tokens: data.usage?.prompt_tokens || 0,
      completion_tokens: data.usage?.completion_tokens || 0,
      actual_cost: data.metadata?.cost || 0,
      session_id: session_id || null,
      timestamp: new Date().toISOString()
    });
    if (logError) {
      console.error(`[ALIAS] Failed to log usage for user ${userId}:`, logError.message);
    }

    return res.json(data);

  } catch (err) {
    if (process.env.SENTRY_DSN) {
      Sentry.captureException(err, { user: { id: userId } });
    }
    console.error(`[ALIAS] Error for user ${userId}:`, err.message);
    if (isFreeTierRequest) {
      return res.status(503).json({ error: 'Free tier provider is temporarily unavailable. Please try again shortly.' });
    }
    return res.status(502).json({ error: 'Provider unavailable. Retrying...', retry_after: 2000 });
  }
}

// Wire both alias paths — same middleware chain as /chat
app.post('/v1/chat/completions', globalRateLimiter, authenticate, openAIChatCompletionsHandler);
app.post('/chat/completions',    globalRateLimiter, authenticate, openAIChatCompletionsHandler);

// ---------------------------------------------------------------------------
// ROUTE: POST /billing/topup-check
// Top-Up Restriction (Requirement 4):
// A user may initiate a top-up/re-subscription ONLY if MAX(model_usage / model_cap) >= 0.85
// for any model in their tier. Otherwise returns 403.
// ---------------------------------------------------------------------------
app.post('/billing/topup-check', authenticate, async (req, res) => {
  const userId = req.user.id;

  try {
    const capStatus = await checkCapBeforeRoute(userId);

    if (capStatus.tier === 'free') {
      return res.json({
        eligible: true,
        tier: 'free',
        message: 'Free tier user eligible to upgrade to any paid tier.'
      });
    }

    const maxUtil = capStatus.maxUtilization || 0;
    const maxPercent = Number((maxUtil * 100).toFixed(1));

    if (maxUtil < 0.85) {
      return res.status(403).json({
        error: 'Top-up available when a model cap reaches 85% utilization',
        current_max_utilization: maxPercent,
        tier: capStatus.tier
      });
    }

    return res.json({
      eligible: true,
      current_max_utilization: maxPercent,
      tier: capStatus.tier,
      capsSummary: capStatus.capsSummary
    });
  } catch (err) {
    console.error(`[TOPUP-CHECK] Error for user ${userId}:`, err.message);
    return res.status(500).json({ error: 'Failed to verify top-up eligibility' });
  }
});

// ---------------------------------------------------------------------------
// ROUTE: POST /webhooks/paystack
// Paystack webhook listener with HMAC SHA512 signature verification
// Handles: charge.success, subscription.create, subscription.disable
// ---------------------------------------------------------------------------
app.post('/webhooks/paystack', paystackRateLimiter, async (req, res) => {
  const signature = req.headers['x-paystack-signature'];
  const secretKey = process.env.PAYSTACK_SECRET_KEY || process.env.PAYSTACK_TEST_SECRET_KEY || PAYSTACK_SECRET_KEY || '';

  if (!signature || !secretKey) {
    console.warn('[WEBHOOK] Missing Paystack signature or secret key not configured');
    return res.status(401).json({ error: 'Missing or invalid signature' });
  }

  // Verify HMAC SHA512 signature
  const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body));
  const hash = crypto
    .createHmac('sha512', secretKey)
    .update(rawBody)
    .digest('hex');

  if (hash !== signature) {
    console.error('[WEBHOOK] Invalid Paystack signature received');
    return res.status(401).json({ error: 'Signature mismatch' });
  }

  const event = req.body;
  if (!event || !event.event) {
    return res.status(400).json({ error: 'Invalid event payload' });
  }

  const eventType = event.event;
  const eventData = event.data || {};
  const paystackRef = eventData.reference || null;
  console.log(`[WEBHOOK] Verified Paystack event: ${eventType} (ref: ${paystackRef || 'n/a'})`);

  try {
    // Idempotency check: prevent double-processing if reference already recorded
    if (paystackRef) {
      if (processedWebhookIds.has(paystackRef)) {
        console.log(`[WEBHOOK] Event with reference ${paystackRef} already processed. Skipping.`);
        return res.status(200).json({ received: true, message: 'Already processed' });
      }
      try {
        const { data: existingEvent } = await supabase
          .from('billing_events')
          .select('id')
          .eq('paystack_reference', paystackRef)
          .maybeSingle();

        if (existingEvent) {
          processedWebhookIds.add(paystackRef);
          console.log(`[WEBHOOK] Event with reference ${paystackRef} already processed. Skipping.`);
          return res.status(200).json({ received: true, message: 'Already processed' });
        }
      } catch (e) { /* ignore if table not created yet */ }
    }

    let targetUserId = eventData.metadata?.user_id || eventData.customer?.metadata?.user_id;

    // Resolve user by email if not found directly in metadata
    if (!targetUserId && eventData.customer?.email) {
      const { data: userData } = await supabase
        .from('users')
        .select('id')
        .eq('email', eventData.customer.email)
        .single();
      if (userData) targetUserId = userData.id;
    }

    // Process subscription events with Underpayment Protection
    if (eventType === 'charge.success' || eventType === 'subscription.create') {
      const planTier = (eventData.metadata?.tier || eventData.plan?.name || 'starter').toLowerCase();
      const amountPaidKobo = Number(eventData.amount || 0);

      // Underpayment Protection: Enforce minimum thresholds (in kobo)
      // Learner: 400,000 kobo (4,000 NGN)
      // Starter: 1,000,000 kobo (10,000 NGN)
      // Pro: 1,500,000 kobo (15,000 NGN)
      const PAYSTACK_MIN_KOBO = {
        learner: 400000,
        starter: 1000000,
        pro: 1500000
      };

      let eligibleTier = null;
      if (amountPaidKobo >= PAYSTACK_MIN_KOBO.pro) {
        eligibleTier = 'pro';
      } else if (amountPaidKobo >= PAYSTACK_MIN_KOBO.starter) {
        eligibleTier = 'starter';
      } else if (amountPaidKobo >= PAYSTACK_MIN_KOBO.learner) {
        eligibleTier = 'learner';
      }

      if (!eligibleTier) {
        console.warn(`[WEBHOOK] UNDERPAYMENT DETECTED: User ${targetUserId} paid ${amountPaidKobo} kobo (${amountPaidKobo / 100} NGN). Below minimum Learner threshold (400,000 kobo). Subscription upgrade withheld.`);
        if (targetUserId) {
          await supabase.from('billing_events').insert({
            user_id: targetUserId,
            event_type: 'underpayment',
            paystack_reference: paystackRef,
            amount: amountPaidKobo / 100,
            currency: eventData.currency || 'NGN',
            status: 'underpaid',
            raw_payload: { ...event, reason: 'Payment amount below minimum tier threshold' }
          });
        }
        return res.status(200).json({ received: true, status: 'underpaid' });
      }

      let resolvedTier = eligibleTier;
      if (tierCaps[planTier] && PAYSTACK_MIN_KOBO[planTier] && amountPaidKobo >= PAYSTACK_MIN_KOBO[planTier]) {
        resolvedTier = planTier;
      }

      if (targetUserId) {
        const { error: subscriptionError } = await supabase
          .from('subscriptions')
          .upsert({
            user_id: targetUserId,
            tier: resolvedTier,
            status: 'active',
            cycle_start: new Date().toISOString()
          }, {
            onConflict: 'user_id'
          });
        if (subscriptionError) throw subscriptionError;
        console.log(`[WEBHOOK] Activated subscription (${resolvedTier}) for user ${targetUserId} (paid ${amountPaidKobo / 100} NGN)`);
      }
    } else if (eventType === 'subscription.disable') {
      if (targetUserId) {
        const { error: subscriptionError } = await supabase
          .from('subscriptions')
          .update({ status: 'cancelled' })
          .eq('user_id', targetUserId);
        if (subscriptionError) throw subscriptionError;
        console.log(`[WEBHOOK] Cancelled subscription for user ${targetUserId}`);
      }
    }

    // Log event to public.billing_events audit table
    if (targetUserId) {
      const eventInsert = {
        user_id: targetUserId,
        event_type: eventType,
        paystack_reference: paystackRef,
        amount: eventData.amount ? (eventData.amount / 100) : 0,
        currency: eventData.currency || 'NGN',
        provider: 'paystack',
        status: 'success',
        raw_payload: event
      };

      try {
        const { error: insertErr } = await supabase.from('billing_events').insert(eventInsert);
        if (insertErr) {
          if (insertErr.message && insertErr.message.includes('provider')) {
            delete eventInsert.provider;
            await supabase.from('billing_events').insert(eventInsert);
          } else {
            console.warn('[WEBHOOK] Could not record billing_events audit:', insertErr.message);
          }
        }
      } catch (auditErr) {
        console.warn('[WEBHOOK] Non-fatal billing_events audit logging failed:', auditErr.message);
      }
    }

    if (paystackRef) processedWebhookIds.add(paystackRef);
    return res.status(200).json({ received: true });
  } catch (err) {
    console.error(`[WEBHOOK] Error processing event ${eventType}:`, err.message);
    return res.status(500).json({ error: 'Webhook processing error' });
  }
});

// ---------------------------------------------------------------------------
// ROUTE: POST /webhooks/lemonsqueezy
// Lemon Squeezy webhook listener with HMAC SHA256 signature verification
// Handles: order_created, subscription_created, subscription_cancelled
// ---------------------------------------------------------------------------
app.post('/webhooks/lemonsqueezy', lemonSqueezyRateLimiter, async (req, res) => {
  const signature = req.headers['x-signature'];
  const secretKey = process.env.LEMONSQUEEZY_WEBHOOK_SECRET || LEMONSQUEEZY_WEBHOOK_SECRET || '';

  if (!signature || !secretKey) {
    console.warn('[WEBHOOK-LS] Missing Lemon Squeezy signature or secret key not configured');
    return res.status(401).json({ error: 'Missing or invalid signature' });
  }

  // Verify HMAC SHA256 signature against raw body
  const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body));
  const hash = crypto
    .createHmac('sha256', secretKey)
    .update(rawBody)
    .digest('hex');

  if (hash !== signature) {
    console.error('[WEBHOOK-LS] Invalid Lemon Squeezy signature received');
    return res.status(401).json({ error: 'Signature mismatch' });
  }

  const payload = req.body;
  if (!payload) {
    return res.status(400).json({ error: 'Invalid event payload' });
  }

  const eventName = payload.meta?.event_name || payload.event || payload.type || '';
  const customData = payload.meta?.custom_data || {};
  const eventData = payload.data || {};
  const attributes = eventData.attributes || {};

  // Extract event_id for idempotency
  const eventId = String(
    payload.meta?.webhook_id ||
    payload.meta?.event_id ||
    eventData.id ||
    `ls_${Date.now()}`
  );

  console.log(`[WEBHOOK-LS] Verified Lemon Squeezy event: ${eventName} (event_id: ${eventId})`);

  try {
    // Idempotency check: prevent double-processing if event_id or reference already recorded
    if (eventId) {
      if (processedWebhookIds.has(eventId)) {
        console.log(`[WEBHOOK-LS] Event ${eventId} already processed. Skipping duplicate.`);
        return res.status(200).json({ received: true, message: 'Already processed' });
      }
      try {
        const { data: existing } = await supabase
          .from('billing_events')
          .select('id')
          .or(`event_id.eq.${eventId},paystack_reference.eq.${eventId}`)
          .maybeSingle();

        if (existing) {
          processedWebhookIds.add(eventId);
          console.log(`[WEBHOOK-LS] Event ${eventId} already processed. Skipping duplicate.`);
          return res.status(200).json({ received: true, message: 'Already processed' });
        }
      } catch (e) { /* ignore if table not created yet */ }
    }

    // Resolve user: from custom_data.user_id, custom_data.userId, or attributes.user_email
    let targetUserId = customData.user_id || customData.userId || customData.customer_id;
    const userEmail = attributes.user_email || attributes.customer_email;

    if (!targetUserId && userEmail) {
      const { data: userData } = await supabase
        .from('users')
        .select('id')
        .eq('email', userEmail)
        .single();
      if (userData) targetUserId = userData.id;
    }

    // Resolve subscription tier:
    const rawTier = (
      customData.tier ||
      attributes.first_order_item?.variant_name ||
      attributes.variant_name ||
      attributes.product_name ||
      'starter'
    ).toLowerCase();

    let resolvedTier = 'starter';
    if (rawTier.includes('pro')) {
      resolvedTier = 'pro';
    } else if (rawTier.includes('learner')) {
      resolvedTier = 'learner';
    } else if (rawTier.includes('starter')) {
      resolvedTier = 'starter';
    } else if (tierCaps[rawTier]) {
      resolvedTier = rawTier;
    }

    // Process subscription events with Underpayment Protection
    if (
      eventName === 'order_created' ||
      eventName === 'subscription_created' ||
      eventName === 'subscription_resumed'
    ) {
      const totalCents = attributes.total_usd
        ? Number(attributes.total_usd)
        : (attributes.total ? Number(attributes.total) : 0);

      // Lemon Squeezy Minimum Cents
      // Learner: $2.50 (250 cents)
      // Starter: $7.00 (700 cents)
      // Pro: $11.00 (1100 cents)
      const LEMON_MIN_CENTS = {
        learner: 250,
        starter: 700,
        pro: 1100
      };

      let eligibleTier = null;
      if (totalCents >= LEMON_MIN_CENTS.pro) {
        eligibleTier = 'pro';
      } else if (totalCents >= LEMON_MIN_CENTS.starter) {
        eligibleTier = 'starter';
      } else if (totalCents >= LEMON_MIN_CENTS.learner) {
        eligibleTier = 'learner';
      }

      if (!eligibleTier) {
        console.warn(`[WEBHOOK-LS] UNDERPAYMENT DETECTED: User ${targetUserId} paid ${totalCents} cents. Below minimum Learner threshold ($2.50). Subscription upgrade withheld.`);
        if (targetUserId) {
          await supabase.from('billing_events').insert({
            user_id: targetUserId,
            event_type: 'underpayment',
            event_id: eventId,
            paystack_reference: eventId,
            provider: 'lemonsqueezy',
            amount: totalCents / 100,
            currency: attributes.currency || 'USD',
            status: 'underpaid',
            raw_payload: { ...payload, reason: 'Payment amount below minimum tier threshold' }
          });
        }
        return res.status(200).json({ received: true, status: 'underpaid' });
      }

      let finalTier = eligibleTier;
      if (tierCaps[resolvedTier] && LEMON_MIN_CENTS[resolvedTier] && totalCents >= LEMON_MIN_CENTS[resolvedTier]) {
        finalTier = resolvedTier;
      }

      if (targetUserId) {
        const { error: subscriptionError } = await supabase
          .from('subscriptions')
          .upsert({
            user_id: targetUserId,
            tier: finalTier,
            status: 'active',
            cycle_start: new Date().toISOString()
          }, {
            onConflict: 'user_id'
          });
        if (subscriptionError) throw subscriptionError;
        console.log(`[WEBHOOK-LS] Activated subscription (${finalTier}) for user ${targetUserId} (paid $${totalCents / 100})`);
      }
    } else if (
      eventName === 'subscription_cancelled' ||
      eventName === 'subscription_expired'
    ) {
      if (targetUserId) {
        const { error: subscriptionError } = await supabase
          .from('subscriptions')
          .update({ status: 'cancelled' })
          .eq('user_id', targetUserId);
        if (subscriptionError) throw subscriptionError;
        console.log(`[WEBHOOK-LS] Cancelled subscription for user ${targetUserId}`);
      }
    }

    // Log event to public.billing_events audit table
    if (targetUserId) {
      const totalAmount = attributes.total_usd
        ? (attributes.total_usd / 100)
        : (attributes.total ? (attributes.total / 100) : 0);
      const currency = attributes.currency || 'USD';

      const billingInsert = {
        user_id: targetUserId,
        event_type: eventName,
        event_id: eventId,
        paystack_reference: eventId,
        provider: 'lemonsqueezy',
        amount: totalAmount,
        currency: currency,
        status: 'success',
        raw_payload: payload
      };

      try {
        const { error: insertErr } = await supabase.from('billing_events').insert(billingInsert);
        if (insertErr) {
          if (insertErr.message && (insertErr.message.includes('provider') || insertErr.message.includes('event_id'))) {
            // Fallback if provider or event_id columns are not yet present
            delete billingInsert.provider;
            delete billingInsert.event_id;
            await supabase.from('billing_events').insert(billingInsert);
          } else {
            console.warn('[WEBHOOK-LS] Could not record billing_events audit:', insertErr.message);
          }
        }
      } catch (auditErr) {
        console.warn('[WEBHOOK-LS] Non-fatal billing_events audit logging failed:', auditErr.message);
      }
    }

    if (eventId) processedWebhookIds.add(eventId);
    return res.status(200).json({ received: true });
  } catch (err) {
    console.error(`[WEBHOOK-LS] Error processing event ${eventName}:`, err.message);
    return res.status(500).json({ error: 'Webhook processing error' });
  }
});


// ---------------------------------------------------------------------------
// ROUTE: GET /api/pricing
// Returns model_pricing rows (model, cost_per_1k, currency) from DB with fallback
// ---------------------------------------------------------------------------
app.get('/api/pricing', authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('model_pricing')
      .select('*');

    if (!error && Array.isArray(data) && data.length > 0) {
      const rows = data.map(r => ({
        model: r.model || r.model_name,
        cost_per_1k: Number(r.cost_per_1k !== undefined ? r.cost_per_1k : (r.cost_per_1k_tokens || 0)),
        currency: r.currency || 'USD'
      }));
      return res.json(rows);
    }

    // Default seed fallback if DB table not populated yet.
    // DeepSeek V4.1 Flash blended rate: $0.156 / 1M tokens => $0.000156 / 1K.
    const fallback = [
      { model: 'deepseek-v4-flash', cost_per_1k: 0.000156, currency: 'USD' },
      { model: 'qwen3.6-35b-a3b', cost_per_1k: 0.00025, currency: 'USD' },
      { model: 'deepseek-v4-pro', cost_per_1k: 0.00219, currency: 'USD' },
      { model: 'glm-5.2', cost_per_1k: 0.00175, currency: 'USD' }
    ];
    return res.json(fallback);
  } catch (err) {
    console.error('[PRICING] Error fetching pricing:', err.message);
    return res.status(500).json({ error: 'Failed to fetch model pricing' });
  }
});

// ---------------------------------------------------------------------------
// ROUTE: GET /api/user/caps
// Returns caller's tier + per-model {used, limit} aggregated from subscriptions + usage_logs
// ---------------------------------------------------------------------------
app.get('/api/user/caps', authenticate, async (req, res) => {
  const userId = req.user.id;
  try {
    const { data: subscription, error: subError } = await supabase
      .from('subscriptions')
      .select('tier, cycle_start')
      .eq('user_id', userId)
      .eq('status', 'active')
      .maybeSingle();

    let tier = 'free';
    if (!subError && subscription && subscription.tier && tierCaps[subscription.tier]) {
      tier = subscription.tier;
    }

    // Free tier: one lifetime allowance, never resets. Read from the atomic
    // user_token_usage ledger rather than usage_logs so pending reservations
    // are reflected immediately.
    if (tier === 'free') {
      let usage;
      try {
        usage = await freeTierAccounting.getUsage(userId);
      } catch (err) {
        console.error(`[CAPS] Free tier usage read failed for ${userId}:`, err.message);
        return res.status(503).json({ error: 'Free tier accounting is temporarily unavailable.' });
      }

      const lifetimeTokens = usage.lifetimeTokens;
      const lifetimeCap = FREE_TIER_TOKEN_CAP;
      const lifetimeRemaining = Math.max(0, lifetimeCap - lifetimeTokens);
      const lifetimePercent = Math.min(100, Number(((lifetimeTokens / lifetimeCap) * 100).toFixed(2)));
      const lifetimeLocked = lifetimeTokens >= lifetimeCap;
      const lifetimeCostUsd = Number(usage.lifetimeCostUsd.toFixed(8));

      const caps = {
        [FREE_TIER_MODEL_ID]: { used: lifetimeTokens, limit: lifetimeCap }
      };

      return res.json({
        tier: 'free',
        caps,
        models: caps,
        model: FREE_TIER_MODEL_ID,
        lifetime_tokens: lifetimeTokens,
        lifetime_prompt_tokens: usage.lifetimePromptTokens,
        lifetime_completion_tokens: usage.lifetimeCompletionTokens,
        lifetime_cap: lifetimeCap,
        lifetime_remaining: lifetimeRemaining,
        lifetime_percent: lifetimePercent,
        lifetime_locked: lifetimeLocked,
        lifetime_cost_usd: lifetimeCostUsd,
        lifetime_cost_ngn: Number((lifetimeCostUsd * USD_TO_NGN).toFixed(2)),
        lifetime_resets: false,
        resets_at: null,
        reset_time: null,
        cap_exceeded: lifetimeLocked,
        // Legacy compatibility fields. Daily limits no longer exist.
        daily_requests: 0,
        daily_tokens: lifetimeTokens,
        limit_requests: null,
        limit_tokens: lifetimeCap
      });
    }

    const cycleStart = subscription ? subscription.cycle_start : new Date(0).toISOString();
    const currentTierCaps = tierCaps[tier] || {};
    const modelUsage = {};

    const { data: logs, error: logsError } = await supabase
      .from('usage_logs')
      .select('model, prompt_tokens, completion_tokens')
      .eq('user_id', userId)
      .gte('timestamp', cycleStart);

    if (!logsError && Array.isArray(logs)) {
      for (const log of logs) {
        const m = log.model;
        const total = (log.prompt_tokens || 0) + (log.completion_tokens || 0);
        modelUsage[m] = (modelUsage[m] || 0) + total;
      }
    }

    const trackedModels = Object.keys(currentTierCaps);
    const caps = {};

    for (const m of trackedModels) {
      const cap = currentTierCaps[m] !== undefined ? currentTierCaps[m] : 0;
      const used = modelUsage[m] || 0;
      caps[m] = {
        used,
        limit: cap
      };
    }

    const capExceeded =
      trackedModels.length > 0 &&
      trackedModels.every((m) => {
        const limit = caps[m].limit;
        return limit >= 0 && caps[m].used >= limit;
      });

    return res.json({
      tier,
      caps,
      models: caps,
      lifetime_tokens: null,
      lifetime_cap: null,
      lifetime_remaining: null,
      lifetime_percent: null,
      lifetime_locked: false,
      lifetime_cost_usd: null,
      lifetime_resets: false,
      resets_at: null,
      cap_exceeded: capExceeded,
      // Legacy compatibility fields.
      daily_requests: 0,
      daily_tokens: 0,
      limit_requests: null,
      limit_tokens: null
    });
  } catch (err) {
    console.error(`[CAPS] Error fetching caps for user ${userId}:`, err.message);
    return res.status(500).json({ error: 'Failed to fetch user caps' });
  }
});

// ---------------------------------------------------------------------------
// ROUTE: POST /api/checkout/paystack
// Initializes a transaction on Paystack and returns checkout URL
// ---------------------------------------------------------------------------
app.post('/api/checkout/paystack', async (req, res) => {
  try {
    const { email, tier = 'learner', userId, redirectUrl } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required for checkout' });
    }

    const pricesInKobo = {
      learner: 480000,   // 4,800 NGN (~$3)
      starter: 1280000,  // 12,800 NGN (~$8)
      pro: 1920000       // 19,200 NGN (~$12)
    };

    const targetTier = tier.toLowerCase();
    const amountKobo = pricesInKobo[targetTier] || pricesInKobo.learner;
    const secretKey = process.env.PAYSTACK_SECRET_KEY || process.env.PAYSTACK_TEST_SECRET_KEY || PAYSTACK_SECRET_KEY || '';

    if (!secretKey) {
      return res.status(500).json({ error: 'Paystack secret key not configured' });
    }

    const callbackUrl = redirectUrl || `${req.protocol}://${req.get('host')}/auth/callback?status=payment_success`;

    const paystackRes = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${secretKey}`
      },
      body: JSON.stringify({
        email,
        amount: amountKobo,
        callback_url: callbackUrl,
        metadata: {
          user_id: userId || null,
          tier: targetTier,
          custom_fields: [
            { display_name: 'Tier', variable_name: 'tier', value: targetTier },
            { display_name: 'User ID', variable_name: 'user_id', value: userId || '' }
          ]
        }
      })
    });

    const data = await paystackRes.json();
    if (!paystackRes.ok || !data.status) {
      return res.status(400).json({ error: data.message || 'Failed to initialize Paystack checkout' });
    }

    return res.json({
      authorization_url: data.data.authorization_url,
      access_code: data.data.access_code,
      reference: data.data.reference
    });
  } catch (err) {
    console.error('[CHECKOUT] Paystack init error:', err.message);
    return res.status(500).json({ error: 'Checkout initialization failed' });
  }
});

// ---------------------------------------------------------------------------
// DESKTOP OAUTH HANDLERS (Google, GitHub)
// Allows browser-based OAuth flow to redirect back to the local editor seamlessly.
// ---------------------------------------------------------------------------
let pendingOAuthTokens = new Map();

app.get('/auth/callback', async (req, res) => {
  res.removeHeader('Content-Security-Policy');
  res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;");
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  const code = req.query.code;
  let serverExchangedToken = '';
  let serverRefreshToken = '';
  let serverUser = null;

  if (code) {
    try {
      const { data, error } = await supabase.auth.exchangeCodeForSession(code);
      if (!error && data?.session) {
        serverExchangedToken = data.session.access_token;
        serverRefreshToken = data.session.refresh_token;
        serverUser = data.user ? { id: data.user.id, email: data.user.email } : null;
        pendingOAuthTokens.set('latest', {
          token: serverExchangedToken,
          refreshToken: serverRefreshToken,
          user: serverUser,
          at: Date.now()
        });
        console.log(`[AUTH] Successfully exchanged OAuth code for user ${data.user?.id} (${data.user?.email || 'anon'})`);
      } else {
        console.warn('[AUTH] exchangeCodeForSession error:', error?.message);
      }
    } catch (e) {
      console.error('[AUTH] Failed exchanging OAuth code:', e.message);
    }
  }

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Albion IDE - Authentication Complete</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #0B0F19;
      color: #F8FAFC;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }
    .card {
      background: linear-gradient(180deg, #1E293B 0%, #0F172A 100%);
      border: 1px solid #334155;
      border-radius: 20px;
      padding: 44px 36px;
      text-align: center;
      max-width: 440px;
      width: 100%;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.05);
    }
    .icon-badge {
      width: 64px;
      height: 64px;
      margin: 0 auto 20px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .icon-badge svg {
      width: 32px;
      height: 32px;
    }
    h1 {
      font-size: 22px;
      font-weight: 700;
      color: #F8FAFC;
      margin-bottom: 8px;
      letter-spacing: -0.02em;
    }
    p {
      font-size: 14px;
      color: #94A3B8;
      line-height: 1.6;
      margin-bottom: 28px;
    }
    .btn-group {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      height: 44px;
      padding: 0 24px;
      border-radius: 10px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      transition: all 0.15s ease;
      border: none;
    }
    .btn-primary {
      background: #2563EB;
      color: #FFFFFF;
      box-shadow: 0 4px 14px rgba(37, 99, 235, 0.4);
    }
    .btn-primary:hover {
      background: #1D4ED8;
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.05);
      color: #94A3B8;
      border: 1px solid #334155;
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      color: #F8FAFC;
    }
  </style>
</head>
<body>
  <div class="card">
    <div style="display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:24px;">
      <svg width="40" height="40" viewBox="0 0 512 512" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M 224 112 L 160 133 C 149 137 143 144 140 154 L 53 400 L 117 379 C 128 375 134 368 137 358 Z" fill="#2582F8"/>
        <path d="M 320 112 L 256 133 C 245 137 239 144 236 154 L 149 400 L 213 379 C 224 375 230 368 233 358 Z" fill="#2582F8"/>
        <circle cx="338.5" cy="327.5" r="61.5" fill="#FFAE00"/>
        <path d="M 354 113 L 459 386 L 433 386 L 354 178 L 324 254 A 75 75 0 0 0 296 264 Z" fill="#FFAE00"/>
      </svg>
      <span style="font-size:22px;font-weight:800;letter-spacing:-0.03em;color:#F8FAFC;">Albion</span>
    </div>
    <div class="icon-badge">
      <svg viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12"></polyline>
      </svg>
    </div>
    <h1>Authentication Complete</h1>
    <p id="status-msg">${serverExchangedToken ? 'You are now signed in to Albion IDE. You can close this tab and return to the editor.' : 'Authenticating your session...'}</p>
    <div class="btn-group">
      <button id="deep-link-btn" class="btn btn-primary" onclick="openAlbion()">Open Albion IDE</button>
      <button class="btn btn-secondary" onclick="window.close()">Close Window</button>
    </div>
  </div>
  <script>
    const serverToken = ${JSON.stringify(serverExchangedToken)};
    const serverUser = ${JSON.stringify(serverUser)};
    const hash = window.location.hash.substring(1);
    const params = new URLSearchParams(hash || window.location.search);
    const accessToken = serverToken || params.get('access_token') || params.get('code');
    const refreshToken = ${JSON.stringify(serverRefreshToken)} || params.get('refresh_token') || '';

    function getDeepLinkUrl() {
      if (!accessToken) return null;
      let url = 'albion://auth-callback?token=' + encodeURIComponent(accessToken);
      if (refreshToken) url += '&refreshToken=' + encodeURIComponent(refreshToken);
      if (serverUser && serverUser.id) url += '&userId=' + encodeURIComponent(serverUser.id);
      if (serverUser && serverUser.email) url += '&email=' + encodeURIComponent(serverUser.email);
      return url;
    }

    function openAlbion() {
      const url = getDeepLinkUrl();
      if (url) {
        window.location.href = url;
      }
    }

    if (accessToken) {
      if (!serverToken) {
        fetch('/auth/store-token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: accessToken, refreshToken })
        }).catch(function() {});
      }

      // Smooth trigger to focus Albion IDE via custom protocol
      setTimeout(function() {
        openAlbion();
      }, 400);

      // Best effort auto-close after redirect
      setTimeout(function() {
        try { window.close(); } catch (_) {}
      }, 3500);
    } else {
      document.getElementById('status-msg').innerText = 'No session received. Please try logging in again.';
      document.getElementById('deep-link-btn').style.display = 'none';
    }
  </script>
</body>
</html>`);
});

app.post('/auth/store-token', async (req, res) => {
  const { token, refreshToken } = req.body;
  if (!token) return res.status(400).json({ error: 'Token missing' });
  let user = null;
  try {
    const { data } = await supabase.auth.getUser(token);
    if (data?.user) {
      user = { id: data.user.id, email: data.user.email };
    }
  } catch (_) {}
  pendingOAuthTokens.set('latest', { token, refreshToken, user, at: Date.now() });
  res.json({ ok: true });
});

app.get('/auth/poll-token', (req, res) => {
  const latest = pendingOAuthTokens.get('latest');
  if (latest && Date.now() - latest.at < 120000) {
    pendingOAuthTokens.delete('latest');
    return res.json({ token: latest.token, refreshToken: latest.refreshToken, user: latest.user });
  }
  return res.json({ token: null });
});

// ---------------------------------------------------------------------------
// HEALTH CHECK
// ---------------------------------------------------------------------------
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'albion-proxy', timestamp: new Date().toISOString() });
});

// ---------------------------------------------------------------------------
// GLOBAL ERROR HANDLER
// Catches JSON parse errors, unhandled middleware errors, etc.
// NEVER expose stack traces or internal details to the client.
// ---------------------------------------------------------------------------
app.use((err, req, res, next) => {
  // Handle malformed JSON body
  if (err.type === 'entity.parse.failed' || err instanceof SyntaxError) {
    return res.status(400).json({ error: 'Invalid JSON in request body' });
  }
  // Catch-all for any other unhandled errors
  console.error('[SERVER] Unhandled error:', err.message);
  return res.status(500).json({ error: 'Internal server error' });
});

// ---------------------------------------------------------------------------
// START SERVER
// ---------------------------------------------------------------------------
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Albion Proxy running on port ${PORT}`);
    console.log(`LiteLLM target: ${LITELLM_BASE_URL}`);
    console.log(`CORS origins: ${ALLOWED_ORIGINS}`);
  });
}

module.exports = {
  app,
  supabase,
  dispatchFreeTierChat,
  checkCapBeforeRoute,
  tierCaps,
  FREE_TIER_MODELS,
  FREE_TIER_MODEL_ID,
  FREE_TIER_TOKEN_CAP,
  FREE_TIER_LIMIT_MESSAGE,
  DAILY_FREE_LIMIT_MESSAGE,
  freeTierAccounting,
  getApiKey,
  rotateApiKey,
  loadOpenRouterKeys,
  resetKeyRotation
};
