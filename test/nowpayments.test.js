const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

test('NOWPayments IPN signature verification logic', () => {
  const secret = 'test_ipn_secret_12345';
  const payload = {
    payment_id: 12345678,
    payment_status: 'finished',
    pay_address: '0x1234...',
    price_amount: 8,
    price_currency: 'usd',
    actually_paid: 8,
    pay_currency: 'usdttrc20',
    order_id: 'user_abc123_starter'
  };

  // 1. Generate signature according to NOWPayments docs (sort keys alphabetically)
  const sortedPayload = JSON.stringify(payload, Object.keys(payload).sort());
  const hmac = crypto.createHmac('sha512', secret).update(sortedPayload).digest('hex');

  // 2. Verify with matching secret
  const checkPayload = JSON.stringify(payload, Object.keys(payload).sort());
  const checkHmac = crypto.createHmac('sha512', secret).update(checkPayload).digest('hex');
  const valid = crypto.timingSafeEqual(Buffer.from(hmac, 'hex'), Buffer.from(checkHmac, 'hex'));
  assert.equal(valid, true, 'Valid signature must match');

  // 3. Verify with wrong secret fails
  const wrongHmac = crypto.createHmac('sha512', 'wrong_secret').update(checkPayload).digest('hex');
  const invalid = crypto.timingSafeEqual(Buffer.from(hmac, 'hex'), Buffer.from(wrongHmac, 'hex'));
  assert.equal(invalid, false, 'Mismatched signature must fail');

  // 4. Order ID parsing
  const orderId = payload.order_id;
  const lastUnderscore = orderId.lastIndexOf('_');
  const userId = orderId.slice(0, lastUnderscore);
  const planTier = orderId.slice(lastUnderscore + 1);
  assert.equal(userId, 'user_abc123');
  assert.equal(planTier, 'starter');
});
