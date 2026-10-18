require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SERVICE_KEY
);

async function getTestToken() {
  // Sign in with the test user you created in Auth > Users
  const { data, error } = await supabase.auth.signInWithPassword({
    email: 'test@albion.dev',
    password: 'password123' // Use the password you set when creating the user
  });

  if (error) {
    console.error('Auth failed:', error.message);
    console.log('Tip: Create this user first in Supabase Dashboard > Authentication > Users');
    return;
  }

  console.log('\n✅ VALID TEST JWT:\n');
  console.log(data.session.access_token);
  console.log('\nCopy this entire string into your curl -H "Authorization: Bearer <TOKEN>"\n');
}

getTestToken();
