'use strict';

/**
 * Atomic free-tier accounting backed by Supabase RPC functions.
 *
 * Required migration: supabase/migrations/20261022000000_free_tier_lifetime_tokens.sql
 *
 * The proxy reserves estimated tokens atomically before contacting a provider,
 * then commits the real usage afterwards. A failed provider call releases the
 * reservation. This prevents parallel requests from bypassing the lifetime cap.
 */

function normalizeUsageRow(row) {
	return {
		lifetimeTokens: Math.max(0, Number(row && row.lifetime_tokens) || 0),
		lifetimePromptTokens: Math.max(0, Number(row && row.lifetime_prompt_tokens) || 0),
		lifetimeCompletionTokens: Math.max(0, Number(row && row.lifetime_completion_tokens) || 0),
		lifetimeCostUsd: Math.max(0, Number(row && row.lifetime_cost_usd) || 0)
	};
}

function normalizeReservation(data) {
	const row = Array.isArray(data) ? data[0] : data;
	const used = Math.max(0, Number(row && row.used) || 0);
	const previousUsed = Math.max(0, Number(row && row.previous_used) || 0);
	return {
		allowed: !row || row.allowed !== false,
		used,
		previousUsed,
		reserved: Math.max(0, used - previousUsed),
		cap: Math.max(0, Number(row && row.cap) || 0),
		remaining: Math.max(0, Number(row && row.remaining) || 0)
	};
}

function normalizeCommit(data) {
	const row = Array.isArray(data) ? data[0] : data;
	return {
		used: Math.max(0, Number(row && row.used) || 0),
		cap: Math.max(0, Number(row && row.cap) || 0),
		remaining: Math.max(0, Number(row && row.remaining) || 0),
		overCap: Boolean(row && row.over_cap)
	};
}

function createFreeTierAccounting(supabase, options = {}) {
	const table = options.table || 'user_token_usage';
	const logger = options.logger || console;

	async function getUsage(userId) {
		const { data, error } = await supabase
			.from(table)
			.select('lifetime_tokens, lifetime_prompt_tokens, lifetime_completion_tokens, lifetime_cost_usd')
			.eq('user_id', userId)
			.maybeSingle();

		if (error) {
			throw new Error(`[FREE-TIER] Could not read ${table}: ${error.message}`);
		}
		return normalizeUsageRow(data);
	}

	async function reserve(userId, estimatedTokens, cap) {
		const { data, error } = await supabase.rpc('albion_reserve_free_tier_tokens', {
			p_user_id: userId,
			p_estimate: Math.max(0, Math.floor(Number(estimatedTokens) || 0)),
			p_cap: Math.max(1, Math.floor(Number(cap) || 0))
		});

		if (error) {
			throw new Error(`[FREE-TIER] Could not reserve tokens: ${error.message}`);
		}
		return normalizeReservation(data);
	}

	async function commit(userId, reservedTokens, promptTokens, completionTokens, costUsd, cap) {
		const { data, error } = await supabase.rpc('albion_commit_free_tier_tokens', {
			p_user_id: userId,
			p_reserved: Math.max(0, Math.floor(Number(reservedTokens) || 0)),
			p_prompt_tokens: Math.max(0, Math.floor(Number(promptTokens) || 0)),
			p_completion_tokens: Math.max(0, Math.floor(Number(completionTokens) || 0)),
			p_cost_usd: Math.max(0, Number(costUsd) || 0),
			p_cap: Math.max(1, Math.floor(Number(cap) || 0))
		});

		if (error) {
			throw new Error(`[FREE-TIER] Could not commit tokens: ${error.message}`);
		}
		return normalizeCommit(data);
	}

	async function release(userId, reservedTokens) {
		const tokens = Math.max(0, Math.floor(Number(reservedTokens) || 0));
		if (tokens === 0) {
			return;
		}
		const { error } = await supabase.rpc('albion_release_free_tier_tokens', {
			p_user_id: userId,
			p_reserved: tokens
		});
		if (error) {
			logger.warn(`[FREE-TIER] Could not release ${tokens} reserved tokens: ${error.message}`);
		}
	}

	async function recordUsageLog(userId, fields = {}) {
		const { error } = await supabase.from('usage_logs').insert({
			user_id: userId,
			model: fields.model || 'deepseek-v4-flash',
			prompt_tokens: Math.max(0, Math.floor(Number(fields.promptTokens) || 0)),
			completion_tokens: Math.max(0, Math.floor(Number(fields.completionTokens) || 0)),
			actual_cost: Math.max(0, Number(fields.costUsd) || 0),
			session_id: fields.sessionId || null,
			timestamp: new Date().toISOString()
		});
		if (error) {
			logger.error(`[FREE-TIER] Failed to write usage_logs for ${userId}: ${error.message}`);
		}
	}

	return { getUsage, reserve, commit, release, recordUsageLog };
}

module.exports = { createFreeTierAccounting, normalizeUsageRow, normalizeReservation, normalizeCommit };
