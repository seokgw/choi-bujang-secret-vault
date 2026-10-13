begin;

create table vault_api.resource_roles (
  app_origin text not null,
  issuer text not null,
  user_id uuid not null,
  resource_id text not null check (resource_id = 'notices'),
  role text not null check (role = 'instructor'),
  primary key (app_origin, issuer, user_id, resource_id)
);

create table vault_api.training_notices (
  id integer generated always as identity primary key,
  title text not null check (char_length(title) between 1 and 200),
  content text not null check (char_length(content) between 1 and 10000)
);

alter table vault_api.resource_roles enable row level security;
alter table vault_api.training_notices enable row level security;
revoke all on table vault_api.resource_roles, vault_api.training_notices from public, anon, authenticated;
revoke all on sequence vault_api.training_notices_id_seq from public, anon, authenticated;
grant select on table vault_api.resource_roles to service_role;
-- PostgreSQL row locks require UPDATE privilege on at least one column.
grant update (role) on table vault_api.resource_roles to service_role;
grant select, update on table vault_api.training_notices to service_role;

create function vault_api.update_training_notice(
  p_app_origin text, p_issuer text, p_user_id uuid,
  p_id integer, p_title text, p_content text
) returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  updated_notice jsonb;
begin
  -- Hold the role row until this transaction completes: revocation cannot race the edit.
  perform 1 from vault_api.resource_roles
    where app_origin = p_app_origin and issuer = p_issuer and user_id = p_user_id
      and resource_id = 'notices' and role = 'instructor'
    for share;
  if not found then
    return jsonb_build_object('error', 'instructor_required');
  end if;
  update vault_api.training_notices set title = p_title, content = p_content
    where id = p_id
    returning jsonb_build_object('id', id, 'title', title, 'content', content)
      into updated_notice;
  if not found then return jsonb_build_object('error', 'not_found'); end if;
  return jsonb_build_object('notice', updated_notice);
end;
$$;
revoke all on function vault_api.update_training_notice(text, text, uuid, integer, text, text)
  from public, anon, authenticated;
grant execute on function vault_api.update_training_notice(text, text, uuid, integer, text, text)
  to service_role;
notify pgrst, 'reload schema';
commit;
