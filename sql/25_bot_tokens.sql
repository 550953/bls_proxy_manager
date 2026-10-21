-- 25: токены ботов в базе, управление из дашборда (без правки env на хостинге).
-- В базе лежит только SHA-256 хеш токена и последние 4 символа для узнавания. Сам токен виден один раз при создании.
-- Токены из env (BLS_BOT_TOKEN, BLS_BOT_TOKEN_VISAGLOBAL, BLS_BOT_CLIENTS_*) продолжают работать как раньше.
-- Откат: 25_ROLLBACK.sql. Проверка: 25_test.sql.
set local lock_timeout = '5s';

create table if not exists bls_proxy_manager.bot_clients (
    id           uuid primary key default gen_random_uuid(),
    purpose      text not null check (purpose in ('bls', 'visaglobal')),
    name         text not null check (name ~ '^[A-Za-z0-9._-]{1,40}$'),
    token_hash   text not null unique,
    token_hint   text not null,
    enabled      boolean not null default true,
    created_at   timestamptz not null default now(),
    last_used_at timestamptz,
    unique (purpose, name)
);
alter table bls_proxy_manager.bot_clients enable row level security;
revoke all on table bls_proxy_manager.bot_clients from public, anon, authenticated;

-- список для дашборда (хеш не отдаётся)
create or replace function bls_proxy_manager.admin_bot_clients_list()
returns table (id uuid, purpose text, name text, hint text, enabled boolean, created_at timestamptz, last_used_at timestamptz)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select c.id, c.purpose, c.name, c.token_hint, c.enabled, c.created_at, c.last_used_at
      from bot_clients c order by c.purpose, c.name
$$;

-- создать клиента: хеш считает сервис, токен в базу не попадает
create or replace function bls_proxy_manager.admin_bot_client_create(
    p_purpose text, p_name text, p_token_hash text, p_hint text)
returns uuid
language sql volatile security definer set search_path = bls_proxy_manager, pg_temp
as $$
    insert into bot_clients (purpose, name, token_hash, token_hint)
    values (p_purpose, p_name, p_token_hash, p_hint)
    returning id
$$;

create or replace function bls_proxy_manager.admin_bot_client_set_enabled(p_id uuid, p_enabled boolean)
returns integer
language sql volatile security definer set search_path = bls_proxy_manager, pg_temp
as $$
    with u as (update bot_clients set enabled = p_enabled where id = p_id returning 1)
    select count(*)::integer from u
$$;

create or replace function bls_proxy_manager.admin_bot_client_delete(p_id uuid)
returns integer
language sql volatile security definer set search_path = bls_proxy_manager, pg_temp
as $$
    with d as (delete from bot_clients where id = p_id returning 1)
    select count(*)::integer from d
$$;

-- для сервиса: действующие токены (только включённые)
create or replace function bls_proxy_manager.bot_tokens_active()
returns table (token_hash text, purpose text, name text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$ select c.token_hash, c.purpose, c.name from bot_clients c where c.enabled $$;

-- отметка «последний раз использован» не чаще раза в минуту
create or replace function bls_proxy_manager.bot_token_touch(p_token_hash text)
returns void
language sql volatile security definer set search_path = bls_proxy_manager, pg_temp
as $$
    update bot_clients set last_used_at = now()
     where token_hash = p_token_hash and (last_used_at is null or last_used_at < now() - interval '1 minute')
$$;

revoke all on function bls_proxy_manager.admin_bot_clients_list() from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_bot_client_create(text, text, text, text) from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_bot_client_set_enabled(uuid, boolean) from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_bot_client_delete(uuid) from public, anon, authenticated;
revoke all on function bls_proxy_manager.bot_tokens_active() from public, anon, authenticated;
revoke all on function bls_proxy_manager.bot_token_touch(text) from public, anon, authenticated;

grant execute on function bls_proxy_manager.admin_bot_clients_list() to bls_admin;
grant execute on function bls_proxy_manager.admin_bot_client_create(text, text, text, text) to bls_admin;
grant execute on function bls_proxy_manager.admin_bot_client_set_enabled(uuid, boolean) to bls_admin;
grant execute on function bls_proxy_manager.admin_bot_client_delete(uuid) to bls_admin;
grant execute on function bls_proxy_manager.bot_tokens_active() to bls_reporter, bls_issuer;
grant execute on function bls_proxy_manager.bot_token_touch(text) to bls_reporter, bls_issuer;
