/**
 * Albion Proxy - Test JWT Generator
 * 
 * Quick one-off script to get a valid Supabase JWT for testing.
 * 
 * Usage:
 *   1. Fill in SUPABASE_URL and SUPABASE_ANON_KEY below
 *   2. Create a test user in Supabase Dashboard → Authentication → Users
 *   3. Run: node scripts/get-test-jwt.js
 *   4. Copy the JWT token and use it in curl commands
 */

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

// Use anon key here (NOT service role key) — this simulates a real client
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'PASTE_YOUR_ANON_KEY_HERE';

const TEST_EMAIL = 'testuser@albion.dev';
const TEST_PASSWORD = 'TestPass123!';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

async function getTestToken() {
  console.log(`\nAttempting sign-in as: ${TEST_EMAIL}`);
  console.log(`Supabase URL: ${SUPABASE_URL}\n`);

  const { data, error } = await supabase.auth.signInWithPassword({
    email: TEST_EMAIL,
    password: TEST_PASSWORD
  });

  if (error) {
    console.error('Sign-in failed:', error.message);
    console.log('\nTroubleshooting:');
    console.log('1. Create the test user in Supabase Dashboard → Authentication → Users');
    console.log('2. Verify SUPABASE_ANON_KEY is set (not the service role key)');
    console.log('3. Check that email/password match');
    process.exit(1);
  }

  console.log('✅ Sign-in successful!\n');
  console.log('User ID:', data.user.id);
  console.log('Email:', data.user.email);
  console.log('\n--- JWT TOKEN (copy this) ---\n');
  console.log(data.session.access_token);
  console.log('\n--- END TOKEN ---\n');
  console.log('Token expires at:', new Date(data.session.expires_at * 1000).toISOString());
  console.log('\nTest curl command:');
  console.log(`curl -X POST http://localhost:3000/chat -H "Content-Type: application/json" -H "Authorization: Bearer ${data.session.access_token}" -d "{\\"messages\\":[{\\"role\\":\\"user\\",\\"content\\":\\"Hello from Albion\\"}],\\"model_preference\\":\\"deepseek-v4-flash\\",\\"estimated_tokens\\":500,\\"session_id\\":\\"test-session-1\\"}"`);
}

getTestToken();
