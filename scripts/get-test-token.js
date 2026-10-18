// Force Node.js to use Cloudflare DNS to bypass local resolution failures
process.env.NODE_OPTIONS = '--dns-result-order=ipv4first';
const { setDefaultResultOrder } = require('dns');
try { setDefaultResultOrder('ipv4first'); } catch(e) {} // Safe fallback for older Node

// albion-proxy/scripts/get-test-token.js
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

async function getTestToken() {
  // Attempt to sign in with password
  const { data, error } = await supabase.auth.signInWithPassword({
    email: 'test@albion.dev',
    password: '123456'
  });

  if (error) {
    console.error('❌ Auth failed:', error.message);
    
    // If user doesn't exist, create them automatically
    if (error.message.includes('Invalid login credentials')) {
      console.log('\n🔧 Creating test user...');
      const { data: newUser, error: createError } = await supabase.auth.admin.createUser({
        email: 'test@albion.dev',
        password: '123456',
        email_confirm: true // Auto-confirm so no email verification needed
      });
      
      if (createError) {
        console.error('Failed to create user:', createError.message);
        return;
      }
      
      console.log('✅ Test user created! Retrying sign-in...\n');
      // Retry sign-in after creation
      const retry = await supabase.auth.signInWithPassword({
        email: 'test@albion.dev',
        password: '123456'
      });
      
      if (retry.error) {
        console.error('Still failing:', retry.error.message);
        return;
      }
      
      console.log('✅ VALID TEST JWT:\n');
      console.log(retry.data.session.access_token);
      return;
    }
    return;
  }

  console.log('\n✅ VALID TEST JWT:\n');
  console.log(data.session.access_token);
  console.log('\nCopy this entire string into your curl -H "Authorization: Bearer <TOKEN>"\n');
}

getTestToken();
