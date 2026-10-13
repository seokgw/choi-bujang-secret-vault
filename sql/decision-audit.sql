-- Apply in the Supabase project referenced by production SUPABASE_URL.
-- Server-generated audit metadata only; do not store bodies, JWTs, IDs of users/devices or memo text.
create table if not exists vault_api.decision_audit (
  request_id uuid primary key,
  evaluated_at timestamptz not null default now(),
  decision text not null check (decision in ('allow','deny','step_up')),
  reason_code text not null check (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  rule_ids jsonb not null check (jsonb_typeof(rule_ids) = 'array'),
  source text not null check (source = 'decision_fixture_api')
);
revoke all on table vault_api.decision_audit from public, anon, authenticated;
grant usage on schema vault_api to service_role;
grant select, insert on table vault_api.decision_audit to service_role;
alter table vault_api.decision_audit enable row level security;
-- Only Supabase's server-side service role bypasses RLS. No anon/auth policies.
-- Never expose SUPABASE_SECRET_KEY to a browser or commit it to GitHub.
