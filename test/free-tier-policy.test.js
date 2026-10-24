'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
	DEFAULT_FREE_TIER_TOKEN_CAP,
	FREE_TIER_MODEL_ID,
	evaluateFreeTierRequest,
	computeTokenCost,
	estimateMessagesTokens,
	estimateTextTokens,
	extractUsageFromSseChunk,
	extractCompletionTextFromSseChunk,
	getFreeTierLimitMessage
} = require('../lib/freeTierPolicy');

test('free tier default cap is a 100k lifetime allowance', () => {
	assert.equal(DEFAULT_FREE_TIER_TOKEN_CAP, 100000);
	assert.equal(FREE_TIER_MODEL_ID, 'qwen/qwen3-coder-30b-a3b-instruct');
});

test('99k used + 2k estimated is blocked with 402', () => {
	const result = evaluateFreeTierRequest({ usedTokens: 99000, estimatedTokens: 2000 });
	assert.equal(result.allowed, false);
	assert.equal(result.blocked, true);
	assert.equal(result.status, 402);
	assert.equal(result.reason, 'free_tier_lifetime_limit_reached');
	assert.equal(result.remaining, 1000);
	assert.equal(result.message, 'Free tier lifetime limit reached (100k tokens). Please upgrade to continue.');
});

test('99k used + 1k estimated is allowed', () => {
	const result = evaluateFreeTierRequest({ usedTokens: 99000, estimatedTokens: 1000 });
	assert.equal(result.allowed, true);
	assert.equal(result.blocked, false);
	assert.equal(result.status, 200);
	assert.equal(result.remaining, 1000);
});

test('exhausted lifetime usage is permanently locked', () => {
	const result = evaluateFreeTierRequest({ usedTokens: 100000, estimatedTokens: 0 });
	assert.equal(result.blocked, true);
	assert.equal(result.locked, true);
	assert.equal(result.remaining, 0);
	assert.equal(result.status, 402);
});

test('per-token cost uses $0.07/M input and $0.50/M output', () => {
	assert.equal(computeTokenCost(1000000, 0), 0.07);
	assert.equal(computeTokenCost(0, 1000000), 0.5);
	assert.equal(computeTokenCost(1000, 1000), 0.00057);
});

test('token estimation is deterministic and non-zero', () => {
	assert.equal(estimateTextTokens('abcd'), 1);
	assert.equal(estimateTextTokens('abcde'), 2);
	assert.ok(estimateMessagesTokens([{ role: 'user', content: 'hello world' }]) > 0);
});

test('SSE usage and completion text are extracted from OpenAI chunks', () => {
	const chunk = {
		choices: [{ delta: { content: 'hello' } }],
		usage: { prompt_tokens: 12, completion_tokens: 3 }
	};
	assert.deepEqual(extractUsageFromSseChunk(chunk), { promptTokens: 12, completionTokens: 3 });
	assert.equal(extractCompletionTextFromSseChunk(chunk), 'hello');
	assert.equal(extractUsageFromSseChunk({ choices: [] }), null);
});

test('limit message reflects custom caps', () => {
	assert.match(getFreeTierLimitMessage(250000), /250k tokens/);
});
