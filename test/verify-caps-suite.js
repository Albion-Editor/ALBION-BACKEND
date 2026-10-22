'use strict';

/**
 * Manual integration verification for the 200k lifetime free tier.
 *
 * Requires a running proxy and a real Supabase-backed test user. This file is
 * intentionally NOT part of `npm test` (which runs test/*.test.js).
 */

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:3000';
const TEST_TOKEN = process.env.TEST_TOKEN || '';

async function request(path, options = {}) {
  const response = await fetch(`${PROXY_URL}${path}`, {
    ...options,
    headers: {
      ...(options.headers || {}),
      ...(TEST_TOKEN ? { Authorization: `Bearer ${TEST_TOKEN}` } : {})
    }
  });
  return response;
}

async function runVerification() {
  if (!TEST_TOKEN) {
    console.error('Set TEST_TOKEN (and optionally PROXY_URL) before running this suite.');
    process.exit(1);
  }

  const health = await request('/health');
  console.log('[health]', health.status, await health.json());

  const capsBefore = await request('/api/user/caps');
  const before = await capsBefore.json();
  console.log('[caps before]', before.status, {
    tier: before.tier,
    lifetime_tokens: before.lifetime_tokens,
    lifetime_cap: before.lifetime_cap,
    lifetime_locked: before.lifetime_locked
  });

  const chat = await request('/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messages: [{ role: 'user', content: 'Reply with the single word: ok' }],
      stream: false
    })
  });
  console.log('[chat]', chat.status, {
    model: chat.headers.get('x-albion-active-model'),
    lifetime_used: chat.headers.get('x-albion-free-tier-tokens-used'),
    cap: chat.headers.get('x-albion-free-tier-token-cap')
  });
  const chatBody = await chat.json();
  console.log('[chat body]', chatBody.error || chatBody?.choices?.[0]?.message?.content);

  const capsAfterResponse = await request('/api/user/caps');
  const after = await capsAfterResponse.json();
  console.log('[caps after]', after.status, {
    lifetime_tokens: after.lifetime_tokens,
    lifetime_remaining: after.lifetime_remaining,
    lifetime_percent: after.lifetime_percent,
    lifetime_cost_usd: after.lifetime_cost_usd
  });

  if (after.lifetime_locked) {
    const lockedChat = await request('/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages: [{ role: 'user', content: 'Should be blocked' }],
        stream: false
      })
    });
    const lockedBody = await lockedChat.json();
    console.log('[locked chat]', lockedChat.status, lockedBody.error, lockedBody.code);
    if (lockedChat.status !== 402) {
      throw new Error('Expected HTTP 402 for a locked free-tier user');
    }
  }

  console.log('Lifetime free tier verification complete.');
}

runVerification().catch((err) => {
  console.error(err);
  process.exit(1);
});
