'use strict';

/**
 * Albion Free Tier Policy
 *
 * The free tier is a one-time, lifetime allowance. It does not reset monthly,
 * weekly, or daily. Once a user exhausts the lifetime cap they are locked out
 * of AI requests until they upgrade.
 */

const DEFAULT_FREE_TIER_TOKEN_CAP = 200000;
const FREE_TIER_MODEL_ID = 'deepseek-v4-flash';
const FREE_TIER_DISPLAY_NAME = 'DeepSeek V4.1 Flash';
const DEFAULT_DEEPINFRA_FLASH_MODEL = 'deepseek-ai/DeepSeek-V4.1-Flash';
const DEFAULT_OPENROUTER_FLASH_MODEL = 'deepseek/deepseek-v4.1-flash-1017';

// Published DeepSeek V4.1 Flash rates (USD per 1M tokens).
const INPUT_COST_PER_MILLION_USD = 0.07;
const OUTPUT_COST_PER_MILLION_USD = 0.5;
const BLENDED_COST_PER_MILLION_USD = 0.156;
const USD_TO_NGN = 1370;

function getFreeTierTokenCap(env = process.env) {
	const parsed = Number(env.FREE_TIER_TOKEN_CAP);
	if (Number.isFinite(parsed) && parsed > 0) {
		return Math.floor(parsed);
	}
	return DEFAULT_FREE_TIER_TOKEN_CAP;
}

function getFreeTierLimitMessage(cap) {
	const thousands = Math.round(cap / 1000);
	return `Free tier lifetime limit reached (${thousands}k tokens). Please upgrade to continue.`;
}

/**
 * Pure, deterministic decision used by the proxy before forwarding a request.
 * `estimatedTokens` is added to the lifetime usage so a parallel request cannot
 * sneak in a final oversized payload at the boundary.
 */
function evaluateFreeTierRequest({ usedTokens, estimatedTokens = 0, cap } = {}) {
	const limit = Math.max(1, Math.floor(Number(cap) || getFreeTierTokenCap()));
	const used = Math.max(0, Math.floor(Number(usedTokens) || 0));
	const estimate = Math.max(0, Math.floor(Number(estimatedTokens) || 0));
	const remaining = Math.max(0, limit - used);
	const locked = used >= limit;
	const allowed = !locked && used + estimate <= limit;
	const percent = Math.min(100, Number(((used / limit) * 100).toFixed(2)));

	return {
		allowed,
		blocked: !allowed || used >= limit,
		reason: allowed ? null : 'free_tier_lifetime_limit_reached',
		status: allowed ? 200 : 402,
		used,
		estimated: estimate,
		cap: limit,
		remaining,
		required: used + estimate,
		percent,
		locked,
		message: allowed ? null : getFreeTierLimitMessage(limit)
	};
}

function computeTokenCost(promptTokens, completionTokens) {
	const prompt = Math.max(0, Number(promptTokens) || 0);
	const completion = Math.max(0, Number(completionTokens) || 0);
	const cost =
		(prompt * INPUT_COST_PER_MILLION_USD + completion * OUTPUT_COST_PER_MILLION_USD) / 1000000;
	return Number(cost.toFixed(8));
}

function estimateTextTokens(text) {
	if (!text) {
		return 1;
	}
	return Math.max(1, Math.ceil(String(text).length / 4));
}

function estimateMessagesTokens(messages) {
	if (!Array.isArray(messages) || messages.length === 0) {
		return 1;
	}
	let total = 0;
	for (const message of messages) {
		const content = message && message.content;
		if (typeof content === 'string') {
			total += estimateTextTokens(content);
		} else if (Array.isArray(content)) {
			for (const part of content) {
				if (part && typeof part.text === 'string') {
					total += estimateTextTokens(part.text);
				}
			}
		}
		total += 4; // role / message framing overhead
	}
	return Math.max(1, total);
}

function extractUsageFromSseChunk(chunk) {
	if (!chunk || typeof chunk !== 'object' || !chunk.usage) {
		return null;
	}
	return {
		promptTokens: Math.max(0, Number(chunk.usage.prompt_tokens) || 0),
		completionTokens: Math.max(0, Number(chunk.usage.completion_tokens) || 0)
	};
}

function extractCompletionTextFromSseChunk(chunk) {
	if (!chunk || typeof chunk !== 'object' || !Array.isArray(chunk.choices)) {
		return '';
	}
	let text = '';
	for (const choice of chunk.choices) {
		const delta = choice && choice.delta;
		if (delta && typeof delta.content === 'string') {
			text += delta.content;
		}
	}
	return text;
}

module.exports = {
	DEFAULT_FREE_TIER_TOKEN_CAP,
	FREE_TIER_MODEL_ID,
	FREE_TIER_DISPLAY_NAME,
	DEFAULT_DEEPINFRA_FLASH_MODEL,
	DEFAULT_OPENROUTER_FLASH_MODEL,
	INPUT_COST_PER_MILLION_USD,
	OUTPUT_COST_PER_MILLION_USD,
	BLENDED_COST_PER_MILLION_USD,
	USD_TO_NGN,
	getFreeTierTokenCap,
	getFreeTierLimitMessage,
	evaluateFreeTierRequest,
	computeTokenCost,
	estimateTextTokens,
	estimateMessagesTokens,
	extractUsageFromSseChunk,
	extractCompletionTextFromSseChunk
};
