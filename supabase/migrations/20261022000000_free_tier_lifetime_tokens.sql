-- Albion Free Tier: 200,000 token LIFETIME hard cap
-- This migration adds the atomic accounting table and RPC functions used by
-- albion-proxy. The cap is lifetime-only: there is no daily/monthly reset.
--
-- Apply with: supabase db push

create table if not exists public.user_token_usage (
	user_id uuid primary key references auth.users (id) on delete cascade,
	lifetime_tokens bigint not null default 0 check (lifetime_tokens >= 0),
	lifetime_prompt_tokens bigint not null default 0 check (lifetime_prompt_tokens >= 0),
	lifetime_completion_tokens bigint not null default 0 check (lifetime_completion_tokens >= 0),
	lifetime_cost_usd numeric(16, 8) not null default 0 check (lifetime_cost_usd >= 0),
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

alter table public.user_token_usage enable row level security;

-- The proxy uses the service-role key. Owners may read their own usage; no
-- client-side writes are allowed.
drop policy if exists "user_token_usage_select_own" on public.user_token_usage;
create policy "user_token_usage_select_own"
	on public.user_token_usage
	for select
	using (auth.uid() = user_id);

create index if not exists user_token_usage_updated_at_idx
	on public.user_token_usage (updated_at desc);

-- Reserve estimated tokens before a provider request.
-- Returns allowed=false when used + estimate would exceed the lifetime cap.
-- The row lock makes this safe against parallel requests.
create or replace function public.albion_reserve_free_tier_tokens(
	p_user_id uuid,
	p_estimate bigint,
	p_cap bigint
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
	v_used bigint;
	v_estimate bigint := greatest(coalesce(p_estimate, 0), 0);
	v_cap bigint := greatest(coalesce(p_cap, 200000), 1);
begin
	insert into public.user_token_usage (user_id)
	values (p_user_id)
	on conflict (user_id) do nothing;

	select lifetime_tokens
	into v_used
	from public.user_token_usage
	where user_id = p_user_id
	for update;

	if v_used + v_estimate > v_cap then
		return jsonb_build_object(
			'allowed', false,
			'used', v_used,
			'previous_used', v_used,
			'cap', v_cap,
			'remaining', greatest(v_cap - v_used, 0)
		);
	end if;

	update public.user_token_usage
	set lifetime_tokens = lifetime_tokens + v_estimate,
		updated_at = now()
	where user_id = p_user_id;

	return jsonb_build_object(
		'allowed', true,
		'used', v_used + v_estimate,
		'previous_used', v_used,
		'cap', v_cap,
		'remaining', greatest(v_cap - (v_used + v_estimate), 0)
	);
end;
$$;

-- Commit real usage. The reservation is replaced by the actual token count.
-- The resulting lifetime total is clamped to the cap.
create or replace function public.albion_commit_free_tier_tokens(
	p_user_id uuid,
	p_reserved bigint,
	p_prompt_tokens bigint,
	p_completion_tokens bigint,
	p_cost_usd numeric,
	p_cap bigint
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
	v_used bigint;
	v_reserved bigint := greatest(coalesce(p_reserved, 0), 0);
	v_prompt bigint := greatest(coalesce(p_prompt_tokens, 0), 0);
	v_completion bigint := greatest(coalesce(p_completion_tokens, 0), 0);
	v_actual bigint := v_prompt + v_completion;
	v_delta bigint := v_actual - v_reserved;
	v_cap bigint := greatest(coalesce(p_cap, 200000), 1);
	v_next bigint;
begin
	insert into public.user_token_usage (user_id)
	values (p_user_id)
	on conflict (user_id) do nothing;

	select lifetime_tokens
	into v_used
	from public.user_token_usage
	where user_id = p_user_id
	for update;

	v_next := greatest(0, least(v_cap, v_used + v_delta));

	update public.user_token_usage
	set lifetime_tokens = v_next,
		lifetime_prompt_tokens = lifetime_prompt_tokens + v_prompt,
		lifetime_completion_tokens = lifetime_completion_tokens + v_completion,
		lifetime_cost_usd = lifetime_cost_usd + greatest(coalesce(p_cost_usd, 0), 0),
		updated_at = now()
	where user_id = p_user_id;

	return jsonb_build_object(
		'used', v_next,
		'cap', v_cap,
		'remaining', greatest(v_cap - v_next, 0),
		'over_cap', v_next >= v_cap
	);
end;
$$;

-- Release a reservation when the provider request failed before any tokens
-- were consumed.
create or replace function public.albion_release_free_tier_tokens(
	p_user_id uuid,
	p_reserved bigint
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
	v_reserved bigint := greatest(coalesce(p_reserved, 0), 0);
	v_used bigint;
begin
	update public.user_token_usage
	set lifetime_tokens = greatest(lifetime_tokens - v_reserved, 0),
		updated_at = now()
	where user_id = p_user_id
	returning lifetime_tokens into v_used;

	return jsonb_build_object('used', coalesce(v_used, 0));
end;
$$;

revoke all on function public.albion_reserve_free_tier_tokens(uuid, bigint, bigint) from public;
revoke all on function public.albion_commit_free_tier_tokens(uuid, bigint, bigint, bigint, numeric, bigint) from public;
revoke all on function public.albion_release_free_tier_tokens(uuid, bigint) from public;

grant execute on function public.albion_reserve_free_tier_tokens(uuid, bigint, bigint) to service_role;
grant execute on function public.albion_commit_free_tier_tokens(uuid, bigint, bigint, bigint, numeric, bigint) to service_role;
grant execute on function public.albion_release_free_tier_tokens(uuid, bigint) to service_role;
