-- Откат миграции 26: возвращает определения из миграции 25 и убирает привязку к пулам.
drop function if exists bls_proxy_manager.next_available_in_scoped(text, text[]);
drop function if exists bls_proxy_manager.acquire_proxies_scoped(text, integer, integer, text, text, text[], boolean, text[]);
drop function if exists bls_proxy_manager.admin_purpose_pools(text);
drop function if exists bls_proxy_manager.admin_bot_client_set_pools(uuid, text[]);
drop function if exists bls_proxy_manager.admin_bot_client_create(text, text, text, text, text[]);
drop function if exists bls_proxy_manager.bot_tokens_active();
drop function if exists bls_proxy_manager.admin_bot_clients_list();
drop function if exists bls_proxy_manager.bot_pools_validate(text, text[]);
alter table bls_proxy_manager.bot_clients drop constraint if exists bot_clients_pools_chk;
alter table bls_proxy_manager.bot_clients drop column if exists pools;

create function bls_proxy_manager.admin_bot_clients_list()
returns table (id uuid, purpose text, name text, hint text, enabled boolean, created_at timestamptz, last_used_at timestamptz)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select c.id, c.purpose, c.name, c.token_hint, c.enabled, c.created_at, c.last_used_at
      from bot_clients c order by c.purpose, c.name
$$;
create function bls_proxy_manager.admin_bot_client_create(
    p_purpose text, p_name text, p_token_hash text, p_hint text)
returns uuid
language sql volatile security definer set search_path = bls_proxy_manager, pg_temp
as $$
    insert into bot_clients (purpose, name, token_hash, token_hint)
    values (p_purpose, p_name, p_token_hash, p_hint)
    returning id
$$;
create function bls_proxy_manager.bot_tokens_active()
returns table (token_hash text, purpose text, name text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$ select c.token_hash, c.purpose, c.name from bot_clients c where c.enabled $$;

revoke all on function bls_proxy_manager.admin_bot_clients_list() from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_bot_client_create(text, text, text, text) from public, anon, authenticated;
revoke all on function bls_proxy_manager.bot_tokens_active() from public, anon, authenticated;
grant execute on function bls_proxy_manager.admin_bot_clients_list() to bls_admin;
grant execute on function bls_proxy_manager.admin_bot_client_create(text, text, text, text) to bls_admin;
grant execute on function bls_proxy_manager.bot_tokens_active() to bls_reporter, bls_issuer;
