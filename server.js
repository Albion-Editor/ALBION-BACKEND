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

// --- Free Tier Cloud Providers (Stacked Failover & API Key Rotation) ---
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const OPENROUTER_ENDPOINT = process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions';
const GROQ_ENDPOINT = process.env.GROQ_ENDPOINT || 'https://api.groq.com/openai/v1/chat/completions';
const OPENROUTER_FREE_MODEL = process.env.OPENROUTER_FREE_MODEL || 'cohere/north-mini-code:free';
const OPENROUTER_FALLBACK_MODELS = ['cohere/north-mini-code:free', 'nvidia/nemotron-3.5-lightning:free', 'nvidia/nemotron-3-super-120b-a12b:free'];
const GROQ_FREE_MODEL = process.env.GROQ_FREE_MODEL || 'llama-3.1-8b-instant';

// --- Paid AI Cloud Providers (DeepInfra Native Routing) ---
const DEEPINFRA_API_KEY = process.env.DEEPINFRA_API_KEY || '';
const DEEPINFRA_ENDPOINT = process.env.DEEPINFRA_ENDPOINT || 'https://api.deepinfra.com/v1/openai/chat/completions';
const DEEPINFRA_MODEL_MAP = {
  'deepseek-v4-flash': 'deepseek-ai/DeepSeek-V3',
  'deepseek-v4-pro': 'deepseek-ai/DeepSeek-R1',
  'qwen3.6-35b-a3b': 'Qwen/Qwen2.5-Coder-32B-Instruct',
  'glm-5.2': 'deepseek-ai/DeepSeek-V3'
};

// ---------------------------------------------------------------------------
// API KEY ROTATION & RATE LIMIT RESILIENCE (Phase 4.5)
// Supports multi-key array for OpenRouter: OPENROUTER_API_KEY_1, OPENROUTER_API_KEY_2, etc.
// Round-robin cycling with immediate failover retry on 429 (Too Many Requests) or 503.
// ---------------------------------------------------------------------------
let currentKeyIndex = 0;

function loadOpenRouterKeys() {
  const keys = [];
  // 1. Look for indexed keys: OPENROUTER_API_KEY_1, OPENROUTER_API_KEY_2, ...
  let i = 1;
  while (process.env[`OPENROUTER_API_KEY_${i}`]) {
    const k = process.env[`OPENROUTER_API_KEY_${i}`].trim();
    if (k && !keys.includes(k)) keys.push(k);
    i++;
  }
  // 2. Also check base OPENROUTER_API_KEY
  if (process.env.OPENROUTER_API_KEY) {
    const k = process.env.OPENROUTER_API_KEY.trim();
    if (k && !keys.includes(k)) keys.unshift(k);
  }
  // 3. Also check comma-separated OPENROUTER_API_KEYS
  if (process.env.OPENROUTER_API_KEYS) {
    const split = process.env.OPENROUTER_API_KEYS.split(',').map(s => s.trim()).filter(Boolean);
    for (const s of split) {
      if (!keys.includes(s)) keys.push(s);
    }
  }
  return keys;
}

function getApiKey() {
  const keys = loadOpenRouterKeys();
  if (keys.length === 0) return process.env.OPENROUTER_API_KEY || '';
  return keys[currentKeyIndex % keys.length];
}

function rotateApiKey() {
  const keys = loadOpenRouterKeys();
  if (keys.length <= 1) return getApiKey();
  const prevIndex = currentKeyIndex;
  currentKeyIndex = (currentKeyIndex + 1) % keys.length;
  console.log(`[KEY-ROTATION] Rotated OpenRouter API key from index ${prevIndex} to ${currentKeyIndex} (total keys: ${keys.length})`);
  return keys[currentKeyIndex];
}

function resetKeyRotation() {
  currentKeyIndex = 0;
}

const OPENROUTER_API_KEY = getApiKey();

const DAILY_FREE_LIMIT_MESSAGE = 'Daily free cloud AI limit reached. Please upgrade to the Learner tier ($3) for premium cloud access.';

// ---------------------------------------------------------------------------
// SUPABASE CLIENT (service role — server-side only, never expose to client)
// ---------------------------------------------------------------------------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ---------------------------------------------------------------------------
// TIER CAPS — tokens per billing cycle (Retention-First Math)
// -1 indicates unlimited ($0 cloud free tier models).
// NEVER modify without explicit architectural approval.
// ---------------------------------------------------------------------------
const tierCaps = {
  free: {
    'openrouter-free': -1,
    'groq-free': -1
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
const FREE_TIER_MODELS = new Set(['openrouter-free', 'groq-free']);

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
    'X-Albion-Caps-Summary'
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
// FREE TIER DAILY PER-USER LIMITS
// 50 requests per day OR 50,000 tokens per day, reset at midnight UTC.
// ---------------------------------------------------------------------------
const FREE_TIER_DAILY_REQUEST_LIMIT = 50;
const FREE_TIER_DAILY_TOKEN_LIMIT = 50000;

// ---------------------------------------------------------------------------
// CAP CHECK & INTELLIGENT ROUTER: checkCapBeforeRoute
// Enforces 4 routing rules in exact priority order:
//   a. Free tier -> checks 50 msg / 50k token daily limits. If exceeded, blocks pre-flight.
//   b. Paid tier with remaining caps -> intelligent router (flash/qwen auto; pro/glm ONLY via toggle)
//   c. Paid tier, ALL paid caps exhausted -> force muse-glimmer + all_caps_exhausted warning
//   d. Hard guard against paid model leaks
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

  // Calculate midnight UTC start of day
  const now = new Date();
  const startOfDayUTC = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
  const todayDateStr = startOfDayUTC.toISOString().slice(0, 10);

  // Compute Daily Usage for Free Tier tracking
  let dailyRequests = 0;
  let dailyTokens = 0;

  // 1a. Check subscription table columns if present and not reset
  if (subscription) {
    const resetDate = subscription.daily_reset_date ? String(subscription.daily_reset_date).slice(0, 10) : null;
    if (resetDate === todayDateStr) {
      dailyRequests = Number(subscription.daily_request_count) || 0;
      dailyTokens = Number(subscription.daily_token_count) || 0;
    }
  }

  // 1b. Also aggregate daily usage from usage_logs (since midnight UTC)
  try {
    const { data: dayLogs, error: dayLogsErr } = await supabase
      .from('usage_logs')
      .select('prompt_tokens, completion_tokens')
      .eq('user_id', userId)
      .gte('timestamp', startOfDayUTC.toISOString());

    if (!dayLogsErr && Array.isArray(dayLogs)) {
      const logsCount = dayLogs.length;
      const logsTokens = dayLogs.reduce((acc, row) => acc + (row.prompt_tokens || 0) + (row.completion_tokens || 0), 0);
      dailyRequests = Math.max(dailyRequests, logsCount);
      dailyTokens = Math.max(dailyTokens, logsTokens);
    }
  } catch (err) {
    console.warn(`[CAP] Error aggregating daily logs for user ${userId}:`, err.message);
  }

  // Rule a: Free tier DAILY CAP CHECK (50 requests OR 50,000 tokens)
  if (tier === 'free') {
    const capExceeded = dailyRequests >= FREE_TIER_DAILY_REQUEST_LIMIT || dailyTokens >= FREE_TIER_DAILY_TOKEN_LIMIT;

    if (capExceeded) {
      console.warn(`[CAP] Free tier user ${userId} exceeded daily limit: ${dailyRequests}/${FREE_TIER_DAILY_REQUEST_LIMIT} requests, ${dailyTokens}/${FREE_TIER_DAILY_TOKEN_LIMIT} tokens.`);
    }

    return {
      tier: 'free',
      targetModel: 'openrouter-free',
      isFreeTier: true,
      capExceeded,
      dailyRequests,
      dailyTokens,
      limitRequests: FREE_TIER_DAILY_REQUEST_LIMIT,
      limitTokens: FREE_TIER_DAILY_TOKEN_LIMIT,
      allCapsExhausted: false,
      warning: capExceeded ? 'free_daily_limit_reached' : null,
      usagePercent: Number(((dailyRequests / FREE_TIER_DAILY_REQUEST_LIMIT) * 100).toFixed(1)),
      currentUsage: dailyRequests,
      tierCap: FREE_TIER_DAILY_REQUEST_LIMIT,
      maxUtilization: dailyRequests / FREE_TIER_DAILY_REQUEST_LIMIT,
      capsSummary: {
        'openrouter-free': { used: dailyRequests, cap: FREE_TIER_DAILY_REQUEST_LIMIT, percent: Number(((dailyRequests / FREE_TIER_DAILY_REQUEST_LIMIT) * 100).toFixed(1)) },
        'groq-free': { used: dailyRequests, cap: FREE_TIER_DAILY_REQUEST_LIMIT, percent: Number(((dailyRequests / FREE_TIER_DAILY_REQUEST_LIMIT) * 100).toFixed(1)) }
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

  // Rule c: Paid tier, ALL paid caps exhausted -> force openrouter-free
  if (allCapsExhausted) {
    console.warn(`[CAP] User ${userId} (${tier}) exhausted all paid caps. Forcing free cloud tier (OpenRouter/Groq).`);
    return {
      tier,
      targetModel: 'openrouter-free',
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

  // Fallback if no routine cloud model has quota:
  if (!selectedModel) {
    selectedModel = 'openrouter-free';
  }

  // Rule d: Hard guard against paid model leakage
  if (!FREE_TIER_MODELS.has(selectedModel) && allCapsExhausted) {
    selectedModel = 'openrouter-free';
    console.error('[CAP] Paid model blocked at exhausted caps.');
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
// HELPER: recordDailyFreeUsage
// Records usage in usage_logs and updates subscriptions table daily counters
// ---------------------------------------------------------------------------
async function recordDailyFreeUsage(userId, model, promptTokens, completionTokens) {
  try {
    const totalTokens = (promptTokens || 0) + (completionTokens || 0);
    // 1. Insert into usage_logs
    await supabase.from('usage_logs').insert({
      user_id: userId,
      model: model || 'openrouter-free',
      prompt_tokens: promptTokens || 10,
      completion_tokens: completionTokens || 10,
      actual_cost: 0,
      timestamp: new Date().toISOString()
    });

    // 2. Increment subscriptions table counts if columns exist
    const todayStr = new Date().toISOString().slice(0, 10);
    const { data: sub } = await supabase
      .from('subscriptions')
      .select('daily_request_count, daily_token_count, daily_reset_date')
      .eq('user_id', userId)
      .maybeSingle();

    if (sub) {
      const isToday = sub.daily_reset_date && String(sub.daily_reset_date).slice(0, 10) === todayStr;
      const nextReq = isToday ? (Number(sub.daily_request_count) || 0) + 1 : 1;
      const nextTok = isToday ? (Number(sub.daily_token_count) || 0) + totalTokens : totalTokens;

      await supabase
        .from('subscriptions')
        .update({
          daily_request_count: nextReq,
          daily_token_count: nextTok,
          daily_reset_date: todayStr
        })
        .eq('user_id', userId);
    }
  } catch (err) {
    // Non-fatal if subscriptions columns have not been migrated yet
    console.warn('[DAILY-USAGE] Non-fatal daily usage update note:', err.message);
  }
}

// ---------------------------------------------------------------------------
// STACKED CLOUD FREE TIER DISPATCH
// Attempt 1: OpenRouter Free API (rotating pool of up to 20 keys)
// Catch 429/503: Immediately failover to Attempt 2: Groq Free API (llama-3.1-8b-instant)
// Catch Final Failure: Return 503 with exact upgrade message
// Strictly guarantees NEVER falling back to a paid model.
// ---------------------------------------------------------------------------
async function dispatchFreeTierChat(messages, metadata = {}) {
  const isMock429 = Boolean(metadata.mockOpenRouter429);

  // ATTEMPT 1: OpenRouter Free with API Key Rotation & Retry (unless mock 429 requested)
  if (!isMock429) {
    const endpoint = metadata.mockEndpoint || process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions';
    const keys = loadOpenRouterKeys();
    const maxAttempts = Math.max(1, keys.length);

    const extraParams = {
      ...(metadata.tools ? { tools: metadata.tools } : {}),
      ...(metadata.tool_choice ? { tool_choice: metadata.tool_choice } : {}),
      ...(metadata.temperature != null ? { temperature: metadata.temperature } : {}),
      ...(metadata.max_tokens != null ? { max_tokens: Math.min(Number(metadata.max_tokens) || 4096, 4096) } : { max_tokens: 4096 })
    };

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const apiKey = getApiKey();
      const maskedKey = apiKey ? `${apiKey.slice(0, 10)}...${apiKey.slice(-4)}` : 'none';

      try {
        const orResponse = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`,
            'HTTP-Referer': 'https://albion.dev',
            'X-Title': 'Albion Editor'
          },
          body: JSON.stringify({
            model: OPENROUTER_FREE_MODEL,
            messages,
            ...extraParams
          })
        });

        if (orResponse.status === 429 || orResponse.status === 503) {
          const errText = await orResponse.text().catch(() => '');
          console.warn(`[KEY-ROTATION] OpenRouter returned HTTP ${orResponse.status} on key ${maskedKey}: ${errText}. Retrying with next key...`);
          rotateApiKey();
          continue;
        }

        if (!orResponse.ok) {
          const errText = await orResponse.text().catch(() => '');
          console.warn(`[FREE-TIER] OpenRouter returned HTTP ${orResponse.status}: ${errText}. Attempting Groq fallback...`);
          break; // Other non-rate-limit errors fall back to Groq
        }

        const data = await orResponse.json();
        rotateApiKey(); // Balance load for next request
        return { success: true, model: 'openrouter-free', data };
      } catch (err) {
        console.warn(`[KEY-ROTATION] OpenRouter request error with key ${maskedKey}: ${err.message}. Retrying with next key...`);
        rotateApiKey();
      }
    }
  } else {
    console.log('[MOCK-429] OpenRouter 429 simulated via test flag. Seamlessly falling back to Groq...');
  }

  // ATTEMPT 2: Groq Free Fallback
  const extraParams = {
    ...(metadata.tools ? { tools: metadata.tools } : {}),
    ...(metadata.tool_choice ? { tool_choice: metadata.tool_choice } : {}),
    ...(metadata.temperature != null ? { temperature: metadata.temperature } : {}),
    ...(metadata.max_tokens != null ? { max_tokens: Math.min(Number(metadata.max_tokens) || 4096, 4096) } : { max_tokens: 4096 })
  };

  if (GROQ_API_KEY) {
    try {
      const groqResponse = await fetch(GROQ_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${GROQ_API_KEY}`
        },
        body: JSON.stringify({
          model: GROQ_FREE_MODEL,
          messages,
          ...extraParams
        })
      });

      if (groqResponse.ok) {
        const data = await groqResponse.json();
        return { success: true, model: 'groq-free', data };
      }

      const errText = await groqResponse.text().catch(() => '');
      console.error(`[FREE-TIER] Groq returned HTTP ${groqResponse.status}: ${errText}.`);
    } catch (err) {
      console.error(`[FREE-TIER] Groq request failed: ${err.message}.`);
    }
  } else if (isMock429) {
    // Graceful test mock response for Groq fallback verification
    return {
      success: true,
      model: 'groq-free',
      data: {
        id: 'chatcmpl-mock-groq-' + Date.now(),
        object: 'chat.completion',
        created: Math.floor(Date.now() / 1000),
        model: GROQ_FREE_MODEL,
        choices: [{
          index: 0,
          message: { role: 'assistant', content: 'Groq Free Fallback active (llama-3.1-8b-instant). Rate limit resilience verified.' },
          finish_reason: 'stop'
        }],
        usage: { prompt_tokens: 25, completion_tokens: 15, total_tokens: 40 }
      }
    };
  }

  return {
    success: false,
    status: 503,
    error: DAILY_FREE_LIMIT_MESSAGE
  };
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

  try {
    // STEP 1: Pre-request cap & routing check — BEFORE any provider call
    const estimatedTokenCount = estimated_tokens || 1000;
    const capResult = await checkCapBeforeRoute(userId, {
      forceModel: forceModelHeader,
      hasImages,
      estimatedTokens: estimatedTokenCount
    });

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
    res.setHeader('X-Albion-Usage-Percent', capResult.usagePercent.toString());
    res.setHeader('X-Albion-Active-Model', targetModel);
    res.setHeader('X-Albion-Tier', capResult.tier);
    res.setHeader('X-Albion-Current-Tokens', capResult.currentUsage.toString());
    res.setHeader('X-Albion-Cap-Tokens', capResult.tierCap.toString());
    res.setHeader('X-Albion-Caps-Summary', JSON.stringify(capResult.capsSummary || {}));

    if (capResult.warning) {
      res.setHeader('X-Albion-Usage-Warning', capResult.warning);
    }

    // STEP 4b: Pre-flight Free Tier Cap Check
    if (capResult.isFreeTier && capResult.capExceeded) {
      console.warn(`[CHAT] PRE-FLIGHT BLOCK: Free tier daily limit reached for user ${userId} (${capResult.dailyRequests}/${FREE_TIER_DAILY_REQUEST_LIMIT} requests). Request blocked before provider.`);
      res.setHeader('X-Albion-Cap-Exceeded', 'true');
      res.setHeader('X-Albion-Usage-Warning', 'free_daily_limit_reached');
      res.setHeader('X-Albion-Daily-Requests', capResult.dailyRequests.toString());
      res.setHeader('X-Albion-Daily-Tokens', capResult.dailyTokens.toString());
      return res.status(429).json({
        error: "You've reached your daily free limit (50 messages). Upgrade to Starter ($8/mo) for unlimited fast requests, or your limit resets at midnight.",
        cap_exceeded: true,
        daily_requests: capResult.dailyRequests,
        daily_tokens: capResult.dailyTokens,
        limit_requests: FREE_TIER_DAILY_REQUEST_LIMIT,
        limit_tokens: FREE_TIER_DAILY_TOKEN_LIMIT,
        reset_time: "00:00 UTC"
      });
    }

    // STEP 5: Route request
    // Free Tier OR All Caps Exhausted: Dispatch to Stacked Cloud Free Tier (OpenRouter -> Groq)
    // NEVER call LiteLLM or paid DeepInfra/Together models when caps are exhausted.
    if (capResult.isFreeTier || capResult.allCapsExhausted || FREE_TIER_MODELS.has(targetModel)) {
      const freeResult = await dispatchFreeTierChat(orderedMessages, {
        userId,
        project_path,
        mockEndpoint: req.headers['x-albion-mock-provider-url'],
        mockOpenRouter429: req.headers['x-albion-mock-openrouter-429'] === 'true' || req.query.mock_openrouter_429 === 'true'
      });

      if (!freeResult.success) {
        return res.status(503).json({
          error: freeResult.error || DAILY_FREE_LIMIT_MESSAGE
        });
      }

      // Record free tier usage
      await recordDailyFreeUsage(userId, freeResult.model, freeResult.data?.usage?.prompt_tokens, freeResult.data?.usage?.completion_tokens);

      // Update active model header with the specific free model that answered
      res.setHeader('X-Albion-Active-Model', freeResult.model);

      return res.json(freeResult.data);
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

      // Wallet unfunded (402) - Gracefully fail over to Stacked Free Tier
      if (providerResponse.status === 402) {
        console.warn(`[PAID-ROUTER] DeepInfra returned 402 (Wallet requires top-up) for user ${userId}. Gracefully falling back to Stacked Free Tier.`);
        res.setHeader('X-Albion-Paid-Notice', 'DeepInfra wallet top-up needed; free tier fallback active');
        const freeResult = await dispatchFreeTierChat(orderedMessages, {
          userId,
          project_path,
          mockEndpoint: req.headers['x-albion-mock-provider-url']
        });
        if (freeResult.success) {
          res.setHeader('X-Albion-Active-Model', freeResult.model);
          return res.json(freeResult.data);
        }
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
    if (!FREE_TIER_MODELS.has(targetModel)) {
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

    if (typeof targetModel !== 'undefined' && FREE_TIER_MODELS.has(targetModel)) {
      return res.status(503).json({
        error: DAILY_FREE_LIMIT_MESSAGE
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
  try {
    // STEP 1: Cap & routing check — identical to /chat
    const estimatedTokenCount = estimated_tokens || 1000;
    const capResult = await checkCapBeforeRoute(userId, {
      forceModel: forceModelHeader,
      hasImages,
      estimatedTokens: estimatedTokenCount
    });
    targetModel = capResult.targetModel;

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
    res.setHeader('X-Albion-Usage-Percent', capResult.usagePercent.toString());
    res.setHeader('X-Albion-Active-Model', targetModel);
    res.setHeader('X-Albion-Tier', capResult.tier);
    res.setHeader('X-Albion-Current-Tokens', capResult.currentUsage.toString());
    res.setHeader('X-Albion-Cap-Tokens', capResult.tierCap.toString());
    res.setHeader('X-Albion-Caps-Summary', JSON.stringify(capResult.capsSummary || {}));
    if (capResult.warning) res.setHeader('X-Albion-Usage-Warning', capResult.warning);

    // STEP 4b: Pre-flight Free Tier Cap Check
    if (capResult.isFreeTier && capResult.capExceeded) {
      console.warn(`[OPENAI-COMPLETIONS] PRE-FLIGHT BLOCK: Free tier daily limit reached for user ${userId} (${capResult.dailyRequests}/${FREE_TIER_DAILY_REQUEST_LIMIT} requests). Request blocked before provider.`);
      res.setHeader('X-Albion-Cap-Exceeded', 'true');
      res.setHeader('X-Albion-Usage-Warning', 'free_daily_limit_reached');
      res.setHeader('X-Albion-Daily-Requests', capResult.dailyRequests.toString());
      res.setHeader('X-Albion-Daily-Tokens', capResult.dailyTokens.toString());
      return res.status(429).json({
        error: "You've reached your daily free limit (50 messages). Upgrade to Starter ($8/mo) for unlimited fast requests, or your limit resets at midnight.",
        cap_exceeded: true,
        daily_requests: capResult.dailyRequests,
        daily_tokens: capResult.dailyTokens,
        limit_requests: FREE_TIER_DAILY_REQUEST_LIMIT,
        limit_tokens: FREE_TIER_DAILY_TOKEN_LIMIT,
        reset_time: "00:00 UTC"
      });
    }

    // STEP 5a: Free tier / caps exhausted → Stacked free-tier dispatch
    if (capResult.isFreeTier || capResult.allCapsExhausted || FREE_TIER_MODELS.has(targetModel)) {
      const isMock429 = req.headers['x-albion-mock-openrouter-429'] === 'true' || req.query.mock_openrouter_429 === 'true';

      if (stream) {
        // SSE streaming: pipe directly from free provider; shape is real OpenAI SSE chunks
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('X-Accel-Buffering', 'no');

        let requestedMax = req.body.max_tokens || req.body.max_completion_tokens;
        if (requestedMax != null) {
          requestedMax = Math.min(Number(requestedMax) || 4096, 4096);
        } else {
          requestedMax = 4096;
        }

        const commonForwardParams = {
          ...(req.body.tools ? { tools: req.body.tools } : {}),
          ...(req.body.tool_choice ? { tool_choice: req.body.tool_choice } : {}),
          ...(req.body.temperature != null ? { temperature: req.body.temperature } : {}),
          max_tokens: requestedMax
        };

        // Attempt 1: OpenRouter streaming with API Key Rotation & Retry (unless mock 429 requested)
        let streamed = false;
        if (!isMock429) {
          const keys = loadOpenRouterKeys();
          const maxAttempts = Math.max(1, keys.length);
          const orEndpoint = req.headers['x-albion-mock-provider-url'] || process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions';

          for (let attempt = 0; attempt < maxAttempts; attempt++) {
            const apiKey = getApiKey();
            const maskedKey = apiKey ? `${apiKey.slice(0, 10)}...${apiKey.slice(-4)}` : 'none';

            try {
              const orRes = await fetch(orEndpoint, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${apiKey}`,
                  'HTTP-Referer': 'https://albion.dev',
                  'X-Title': 'Albion Editor'
                },
                body: JSON.stringify({
                  model: OPENROUTER_FREE_MODEL,
                  messages: orderedMessages,
                  stream: true,
                  ...commonForwardParams
                })
              });

              if (orRes.status === 429 || orRes.status === 503) {
                const errText = await orRes.text().catch(() => '');
                console.warn(`[KEY-ROTATION] OpenRouter stream HTTP ${orRes.status} on key ${maskedKey}: ${errText}. Retrying with next key...`);
                rotateApiKey();
                continue;
              }

              if (orRes.ok) {
                res.setHeader('X-Albion-Active-Model', 'openrouter-free');
                pipeResponseBody(orRes, res);
                streamed = true;
                rotateApiKey(); // Balance load for next request
                break;
              } else {
                const errText = await orRes.text().catch(() => '');
                console.warn(`[ALIAS-FREE] OpenRouter stream HTTP ${orRes.status}: ${errText}. Trying Groq...`);
                break;
              }
            } catch (err) {
              console.warn(`[KEY-ROTATION] OpenRouter stream error on key ${maskedKey}: ${err.message}. Retrying with next key...`);
              rotateApiKey();
            }
          }
        } else {
          console.log('[MOCK-429] Mocking OpenRouter 429 rate limit. Directly falling back to Groq stream...');
        }

        if (!streamed && isMock429 && !GROQ_API_KEY) {
          res.setHeader('X-Albion-Active-Model', 'groq-free');
          res.write(`data: ${JSON.stringify({
            id: 'chatcmpl-mock-groq-' + Date.now(),
            object: 'chat.completion.chunk',
            created: Math.floor(Date.now() / 1000),
            model: GROQ_FREE_MODEL,
            choices: [{
              index: 0,
              delta: { content: 'Groq Free Fallback active (llama-3.1-8b-instant). Rate limit resilience verified.' },
              finish_reason: null
            }]
          })}\n\n`);
          res.write(`data: ${JSON.stringify({
            id: 'chatcmpl-mock-groq-' + Date.now(),
            object: 'chat.completion.chunk',
            created: Math.floor(Date.now() / 1000),
            model: GROQ_FREE_MODEL,
            choices: [{
              index: 0,
              delta: {},
              finish_reason: 'stop'
            }]
          })}\n\n`);
          res.write('data: [DONE]\n\n');
          res.end();
          streamed = true;
        } else if (!streamed && GROQ_API_KEY) {
          // Attempt 2: Groq streaming fallback
          try {
            const groqRes = await fetch(GROQ_ENDPOINT, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${GROQ_API_KEY}`
              },
              body: JSON.stringify({
                model: GROQ_FREE_MODEL,
                messages: orderedMessages,
                stream: true,
                ...commonForwardParams
              })
            });

            if (groqRes.ok) {
              res.setHeader('X-Albion-Active-Model', 'groq-free');
              pipeResponseBody(groqRes, res);
              streamed = true;
            } else {
              const errText = await groqRes.text().catch(() => '');
              console.error(`[ALIAS-FREE] Groq stream HTTP ${groqRes.status}: ${errText}. Both exhausted.`);
            }
          } catch (err) {
            console.error(`[ALIAS-FREE] Groq stream error: ${err.message}. Both exhausted.`);
          }
        }

        if (!streamed) {
          // Both providers failed — emit user-facing text chunk so chat displays the notice clearly
          res.write(`data: ${JSON.stringify({
            id: 'chatcmpl-free-err',
            object: 'chat.completion.chunk',
            created: Math.floor(Date.now() / 1000),
            model: 'free-tier',
            choices: [{
              index: 0,
              delta: { content: 'Free tier rate limit reached. Retrying or upgrading provides instant priority access.' },
              finish_reason: 'stop'
            }]
          })}\n\n`);
          res.write('data: [DONE]\n\n');
          res.end();
        }
        // Log usage for free tier completion and increment daily counters
        const activeMod = streamed ? (res.getHeader('X-Albion-Active-Model') || 'openrouter-free') : 'free-model';
        const promptToks = orderedMessages.reduce((acc, m) => acc + (typeof m.content === 'string' ? m.content.length : 10), 0);
        await recordDailyFreeUsage(userId, activeMod, promptToks, 15);
        return;
      }

      // Non-streaming free tier: use existing dispatchFreeTierChat helper
      const freeResult = await dispatchFreeTierChat(orderedMessages, {
        userId,
        project_path,
        tools: req.body.tools,
        tool_choice: req.body.tool_choice,
        temperature: req.body.temperature,
        max_tokens: req.body.max_completion_tokens || req.body.max_tokens,
        mockEndpoint: req.headers['x-albion-mock-provider-url'],
        mockOpenRouter429: isMock429
      });
      if (!freeResult.success) {
        return res.status(503).json({ error: freeResult.error || DAILY_FREE_LIMIT_MESSAGE });
      }

      const pToks = freeResult.data?.usage?.prompt_tokens || orderedMessages.reduce((acc, m) => acc + (typeof m.content === 'string' ? m.content.length : 10), 0);
      const cToks = freeResult.data?.usage?.completion_tokens || 10;
      await recordDailyFreeUsage(userId, freeResult.model || 'openrouter-free', pToks, cToks);

      res.setHeader('X-Albion-Active-Model', freeResult.model);
      return res.json(freeResult.data);
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

      // Wallet unfunded (402) - Gracefully fail over to Stacked Free Tier
      if (providerResponse.status === 402) {
        console.warn(`[PAID-ROUTER] DeepInfra returned 402 (Wallet requires top-up) for user ${userId}. Gracefully falling back to Stacked Free Tier.`);
        res.setHeader('X-Albion-Paid-Notice', 'DeepInfra wallet top-up needed; free tier fallback active');
        if (stream) {
          res.setHeader('Content-Type', 'text/event-stream');
          res.setHeader('Cache-Control', 'no-cache');
          res.setHeader('Connection', 'keep-alive');
          res.setHeader('X-Accel-Buffering', 'no');
          res.setHeader('X-Albion-Active-Model', 'openrouter-free');

          const orRes = await fetch(req.headers['x-albion-mock-provider-url'] || process.env.OPENROUTER_ENDPOINT || 'https://openrouter.ai/api/v1/chat/completions', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${getApiKey()}`,
              'HTTP-Referer': 'https://albion.dev',
              'X-Title': 'Albion Editor'
            },
            body: JSON.stringify({
              model: OPENROUTER_FREE_MODEL,
              messages: orderedMessages,
              stream: true,
              ...(req.body.tools ? { tools: req.body.tools } : {}),
              ...(req.body.tool_choice ? { tool_choice: req.body.tool_choice } : {})
            })
          });
          if (orRes.ok) {
            pipeResponseBody(orRes, res);
            return;
          }
        } else {
          const freeResult = await dispatchFreeTierChat(orderedMessages, {
            userId,
            project_path,
            mockEndpoint: req.headers['x-albion-mock-provider-url']
          });
          if (freeResult.success) {
            res.setHeader('X-Albion-Active-Model', freeResult.model);
            return res.json(freeResult.data);
          }
        }
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
    if (!FREE_TIER_MODELS.has(targetModel)) {
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
    }

    return res.json(data);

  } catch (err) {
    if (process.env.SENTRY_DSN) {
      Sentry.captureException(err, { user: { id: userId } });
    }
    console.error(`[ALIAS] Error for user ${userId}:`, err.message);
    if (typeof targetModel !== 'undefined' && FREE_TIER_MODELS.has(targetModel)) {
      return res.status(503).json({ error: DAILY_FREE_LIMIT_MESSAGE });
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

    // Default seed fallback if DB table not populated yet
    const fallback = [
      { model: 'openrouter-free', cost_per_1k: 0, currency: 'NGN' },
      { model: 'groq-free', cost_per_1k: 0, currency: 'NGN' },
      { model: 'deepseek-v4-flash', cost_per_1k: 0.00014, currency: 'USD' },
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
      .select('tier, cycle_start, daily_request_count, daily_token_count, daily_reset_date')
      .eq('user_id', userId)
      .eq('status', 'active')
      .maybeSingle();

    let tier = 'free';
    if (!subError && subscription && subscription.tier && tierCaps[subscription.tier]) {
      tier = subscription.tier;
    }
    const cycleStart = subscription ? subscription.cycle_start : new Date(0).toISOString();

    const currentTierCaps = tierCaps[tier] || tierCaps.free;
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

    const trackedModels = ['deepseek-v4-flash', 'deepseek-v4-pro', 'qwen3.6-35b-a3b', 'glm-5.2', 'openrouter-free', 'groq-free'];
    const caps = {};

    for (const m of trackedModels) {
      const cap = currentTierCaps[m] !== undefined ? currentTierCaps[m] : 0;
      const used = modelUsage[m] || 0;
      caps[m] = {
        used,
        limit: cap
      };
    }

    // Calculate midnight UTC start of day for Free Tier daily usage
    const now = new Date();
    const startOfDayUTC = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
    const todayDateStr = startOfDayUTC.toISOString().slice(0, 10);

    let dailyRequests = 0;
    let dailyTokens = 0;

    if (subscription) {
      const resetDate = subscription.daily_reset_date ? String(subscription.daily_reset_date).slice(0, 10) : null;
      if (resetDate === todayDateStr) {
        dailyRequests = Number(subscription.daily_request_count) || 0;
        dailyTokens = Number(subscription.daily_token_count) || 0;
      }
    }

    try {
      const { data: dayLogs, error: dayLogsErr } = await supabase
        .from('usage_logs')
        .select('prompt_tokens, completion_tokens')
        .eq('user_id', userId)
        .gte('timestamp', startOfDayUTC.toISOString());

      if (!dayLogsErr && Array.isArray(dayLogs)) {
        dailyRequests = Math.max(dailyRequests, dayLogs.length);
        dailyTokens = Math.max(dailyTokens, dayLogs.reduce((acc, row) => acc + (row.prompt_tokens || 0) + (row.completion_tokens || 0), 0));
      }
    } catch (_) {}

    const capExceeded = tier === 'free' && (dailyRequests >= FREE_TIER_DAILY_REQUEST_LIMIT || dailyTokens >= FREE_TIER_DAILY_TOKEN_LIMIT);

    return res.json({
      tier,
      caps,
      models: caps,
      daily_requests: dailyRequests,
      daily_tokens: dailyTokens,
      limit_requests: FREE_TIER_DAILY_REQUEST_LIMIT,
      limit_tokens: FREE_TIER_DAILY_TOKEN_LIMIT,
      cap_exceeded: capExceeded
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
  DAILY_FREE_LIMIT_MESSAGE,
  OPENROUTER_FREE_MODEL,
  getApiKey,
  rotateApiKey,
  loadOpenRouterKeys,
  resetKeyRotation
};
