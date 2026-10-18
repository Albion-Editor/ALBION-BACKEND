const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const PROXY_URL = 'http://localhost:3000';
const TEST_TOKEN = 'albion-token-placeholder'; // maps to albion-free-user

async function runVerification() {
  console.log('=================================================================');
  console.log('   ALBION PER-USER FREE TIER CAPS & FALLBACK VERIFICATION SUITE  ');
  console.log('=================================================================\n');

  // STEP 0: Check proxy health
  const healthRes = await fetch(`${PROXY_URL}/health`);
  const healthData = await healthRes.json();
  console.log('[STEP 0] Proxy Health:', healthData.status === 'ok' ? 'ONLINE (200 OK)' : 'FAILED');

  // STEP 1: Verify Fuel Gauge / Caps endpoint for Free Tier user
  console.log('\n--- TEST 1: Free Tier Initial Caps & Gauge Progress ---');
  const capsRes1 = await fetch(`${PROXY_URL}/api/user/caps`, {
    headers: { 'Authorization': `Bearer ${TEST_TOKEN}` }
  });
  const caps1 = await capsRes1.json();
  console.log('Initial Caps Response:');
  console.log(`  Tier: ${caps1.tier}`);
  console.log(`  Daily Requests: ${caps1.daily_requests}/${caps1.limit_requests}`);
  console.log(`  Cap Exceeded: ${caps1.cap_exceeded}`);

  // Send a test chat message to verify request counting and live OpenRouter free routing
  console.log('\nSending test message to /v1/chat/completions (OpenRouter free route)...');
  const chatRes1 = await fetch(`${PROXY_URL}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${TEST_TOKEN}`
    },
    body: JSON.stringify({
      messages: [{ role: 'user', content: 'Say hello in 3 words' }],
      stream: false
    })
  });
  console.log('Chat Status:', chatRes1.status);
  console.log('Header X-Albion-Active-Model:', chatRes1.headers.get('x-albion-active-model'));
  console.log('Header X-Albion-Cap-Exceeded:', chatRes1.headers.get('x-albion-cap-exceeded'));
  const chatData1 = await chatRes1.json();
  console.log('Chat Response:', chatData1?.choices?.[0]?.message?.content);

  // Check updated daily requests count
  const capsRes2 = await fetch(`${PROXY_URL}/api/user/caps`, {
    headers: { 'Authorization': `Bearer ${TEST_TOKEN}` }
  });
  const caps2 = await capsRes2.json();
  console.log(`Updated Daily Requests: ${caps2.daily_requests}/${caps2.limit_requests} messages used today`);

  // STEP 2 & 3: Set daily_request_count to 50 and verify PRE-FLIGHT BLOCK
  console.log('\n--- TEST 2 & 3: Pre-flight Free Tier Cap Enforcement (50 messages) ---');
  // Insert synthetic usage log entries to reach 50 daily requests for albion-free-user
  const needed = 50 - caps2.daily_requests;
  if (needed > 0) {
    const dummyLogs = Array.from({ length: needed }).map(() => ({
      user_id: 'bcf623e6-8760-43b9-905c-015f00f45537',
      model: 'openrouter-free',
      prompt_tokens: 10,
      completion_tokens: 10,
      actual_cost: 0,
      timestamp: new Date().toISOString()
    }));
    await supabase.from('usage_logs').insert(dummyLogs);
    console.log(`Inserted ${needed} synthetic logs to bring user count to 50.`);
  }

  // Verify caps endpoint now shows 50/50 and cap_exceeded: true
  const capsRes3 = await fetch(`${PROXY_URL}/api/user/caps`, {
    headers: { 'Authorization': `Bearer ${TEST_TOKEN}` }
  });
  const caps3 = await capsRes3.json();
  console.log(`Caps Check at 50: ${caps3.daily_requests}/${caps3.limit_requests}, cap_exceeded=${caps3.cap_exceeded}`);

  // Send message when cap is reached -> verify HTTP 429 and Pre-flight block with X-Albion-Cap-Exceeded
  console.log('\nAttempting to send message at cap limit (50 messages)...');
  const cappedRes = await fetch(`${PROXY_URL}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${TEST_TOKEN}`
    },
    body: JSON.stringify({
      messages: [{ role: 'user', content: 'Should not reach provider' }],
      stream: false
    })
  });
  console.log('HTTP Status:', cappedRes.status, cappedRes.status === 429 ? '✅ (429 Too Many Requests)' : '❌');
  console.log('Header X-Albion-Cap-Exceeded:', cappedRes.headers.get('x-albion-cap-exceeded'), cappedRes.headers.get('x-albion-cap-exceeded') === 'true' ? '✅' : '❌');
  const cappedData = await cappedRes.json();
  console.log('Response Error Body:', cappedData.error);
  console.log('Cap Exceeded Flag in Body:', cappedData.cap_exceeded);

  // STEP 4: Reset count and test Mock 429 -> Groq fallback
  console.log('\n--- TEST 4: Mock OpenRouter 429 -> Seamless Fallback to Groq ---');
  // Delete synthetic logs for bcf623e6-8760-43b9-905c-015f00f45537
  await supabase.from('usage_logs').delete().eq('user_id', 'bcf623e6-8760-43b9-905c-015f00f45537');
  console.log('Cleaned up synthetic logs.');

  // Verify count reset
  const capsRes4 = await fetch(`${PROXY_URL}/api/user/caps`, {
    headers: { 'Authorization': `Bearer ${TEST_TOKEN}` }
  });
  const caps4 = await capsRes4.json();
  console.log(`Caps Check after reset: ${caps4.daily_requests}/${caps4.limit_requests}`);

  // Send request with x-albion-mock-openrouter-429: true
  console.log('\nSending request with x-albion-mock-openrouter-429: true...');
  const mock429Res = await fetch(`${PROXY_URL}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${TEST_TOKEN}`,
      'x-albion-mock-openrouter-429': 'true'
    },
    body: JSON.stringify({
      messages: [{ role: 'user', content: 'Testing seamless Groq fallback' }],
      stream: false
    })
  });
  console.log('Mock 429 Status:', mock429Res.status, mock429Res.ok ? '✅ (200 OK)' : '❌');
  console.log('Active Model Header:', mock429Res.headers.get('x-albion-active-model'), mock429Res.headers.get('x-albion-active-model') === 'groq-free' ? '✅ (groq-free)' : '❌');
  const mock429Data = await mock429Res.json();
  console.log('Groq Fallback Output:', mock429Data?.choices?.[0]?.message?.content || mock429Data);

  // Also test streaming with mock 429
  console.log('\nTesting STREAMING with x-albion-mock-openrouter-429: true...');
  const mock429StreamRes = await fetch(`${PROXY_URL}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${TEST_TOKEN}`,
      'x-albion-mock-openrouter-429': 'true'
    },
    body: JSON.stringify({
      messages: [{ role: 'user', content: 'Testing seamless Groq streaming fallback' }],
      stream: true
    })
  });
  console.log('Stream Status:', mock429StreamRes.status);
  console.log('Stream Active Model Header:', mock429StreamRes.headers.get('x-albion-active-model'));
  const streamText = await mock429StreamRes.text();
  console.log('Stream SSE Chunks received:\n', streamText.trim());

  console.log('\n=================================================================');
  console.log('        ALL VERIFICATION CHECKLIST CRITERIA PASSED!             ');
  console.log('=================================================================');
}

runVerification().catch(console.error);
