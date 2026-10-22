'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createFreeTierAccounting } = require('../lib/freeTierAccounting');

function fakeSupabase(overrides = {}) {
	const calls = [];
	return {
		calls,
		from(table) {
			calls.push({ type: 'from', table });
			return {
				select() { return this; },
				eq() { return this; },
				async maybeSingle() {
					return { data: overrides.row || null, error: overrides.readError || null };
				},
				async insert(row) {
					calls.push({ type: 'insert', table, row });
					return { error: overrides.insertError || null };
				}
			};
		},
		async rpc(name, args) {
			calls.push({ type: 'rpc', name, args });
			if (overrides.rpcError) return { data: null, error: { message: overrides.rpcError } };
			if (name === 'albion_reserve_free_tier_tokens') {
				return { data: overrides.reserve || [{ allowed: true, used: 1200, previous_used: 1000, cap: 200000, remaining: 198800 }], error: null };
			}
			if (name === 'albion_commit_free_tier_tokens') {
				return { data: overrides.commit || [{ used: 1100, cap: 200000, remaining: 198900, over_cap: false }], error: null };
			}
			return { data: null, error: null };
		}
	};
}

test('reserve maps the atomic RPC response', async () => {
	const supabase = fakeSupabase();
	const accounting = createFreeTierAccounting(supabase);
	const result = await accounting.reserve('user-1', 200, 200000);

	assert.equal(result.allowed, true);
	assert.equal(result.used, 1200);
	assert.equal(result.previousUsed, 1000);
	assert.equal(result.reserved, 200);
	assert.equal(result.cap, 200000);
	assert.equal(result.remaining, 198800);

	const rpc = supabase.calls.find((c) => c.type === 'rpc');
	assert.equal(rpc.name, 'albion_reserve_free_tier_tokens');
	assert.deepEqual(rpc.args, { p_user_id: 'user-1', p_estimate: 200, p_cap: 200000 });
});

test('reserve surfaces a held reservation as not allowed', async () => {
	const supabase = fakeSupabase({
		reserve: [{ allowed: false, used: 200000, previous_used: 199500, cap: 200000, remaining: 0 }]
	});
	const accounting = createFreeTierAccounting(supabase);
	const result = await accounting.reserve('user-1', 500, 200000);

	assert.equal(result.allowed, false);
	assert.equal(result.used, 200000);
	assert.equal(result.remaining, 0);
});

test('commit sends real prompt/completion/cost values', async () => {
	const supabase = fakeSupabase();
	const accounting = createFreeTierAccounting(supabase);
	const result = await accounting.commit('user-1', 500, 300, 100, 0.0001, 200000);

	assert.deepEqual(result, { used: 1100, cap: 200000, remaining: 198900, overCap: false });
	const rpc = supabase.calls.find((c) => c.type === 'rpc');
	assert.deepEqual(rpc.args, {
		p_user_id: 'user-1',
		p_reserved: 500,
		p_prompt_tokens: 300,
		p_completion_tokens: 100,
		p_cost_usd: 0.0001,
		p_cap: 200000
	});
});

test('release is a no-op for zero tokens', async () => {
	const supabase = fakeSupabase();
	const accounting = createFreeTierAccounting(supabase);
	await accounting.release('user-1', 0);
	assert.equal(supabase.calls.filter((c) => c.type === 'rpc').length, 0);
});

test('read errors are surfaced so callers can return 503', async () => {
	const supabase = fakeSupabase({ readError: { message: 'relation missing' } });
	const accounting = createFreeTierAccounting(supabase);
	await assert.rejects(() => accounting.getUsage('user-1'), /relation missing/);
});
