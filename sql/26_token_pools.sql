-- 26: привязка токена клиента к пулам. pools = NULL: токен видит все пулы своей цели (как раньше);
-- pools = {'A','B'}: /acquire выдаёт прокси только из этих пулов (proxies.pool). Остальное (кулдауны, карантин,
-- вердикты) не меняется. Токены из env и старые токены без списка работают как раньше.
-- Существующие acquire_proxies / next_available_in не трогаются: сервис вызывает обёртки *_scoped.
-- Откат: 26_ROLLBACK.sql. Проверка: 26_test.sql.
set local lock_timeout = '5s';

alter table bls_proxy_manager.bot_clients add column if not exists pools text[];
do $$ begin
    if not exists (select 1 from pg_constraint where conname = 'bot_clients_pools_chk') then
        alter table bls_proxy_manager.bot_clients
            add constraint bot_clients_pools_chk check (pools is null or cardinality(pools) between 1 and 50);
    end if;
end $$;

-- проверка и нормализация списка пулов: NULL остаётся NULL, пустой список и неизвестный пул — ошибка
create or replace function bls_proxy_manager.bot_pools_validate(p_purpose text, p_pools text[])
returns text[]
language plpgsql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare v text[]; bad text;
begin
    if p_pools is null then return null; end if;
    select array_agg(distinct btrim(x) order by btrim(x)) into v
      from unnest(p_pools) x where btrim(coalesce(x, '')) <> '';
    if v is null then
        raise exception 'pools: пустой список (для всех пулов передайте NULL)' using errcode = '22023';
    end if;
    select x into bad from unnest(v) x
     where not exists (select 1 from proxies p where p.pool = x and p_purpose = any (p.purposes)) limit 1;
    if bad is not null then
        raise exception 'pools: пул "%" не найден среди прокси цели %', bad, p_purpose using errcode = '22023';
    end if;
    return v;
end $$;

-- список клиентов для дашборда (+ pools)
drop function if exists bls_proxy_manager.admin_bot_clients_list();
create function bls_proxy_manager.admin_bot_clients_list()
returns table (id uuid, purpose text, name text, hint text, enabled boolean, created_at timestamptz,
               last_used_at timestamptz, pools text[])
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select c.id, c.purpose, c.name, c.token_hint, c.enabled, c.created_at, c.last_used_at, c.pools
      from bot_clients c order by c.purpose, c.name
$$;

-- действующие токены для сервиса (+ pools)
drop function if exists bls_proxy_manager.bot_tokens_active();
create function bls_proxy_manager.bot_tokens_active()
returns table (token_hash text, purpose text, name text, pools text[])
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$ select c.token_hash, c.purpose, c.name, c.pools from bot_clients c where c.enabled $$;

-- создание клиента: четыре старых аргумента + необязательный список пулов
drop function if exists bls_proxy_manager.admin_bot_client_create(text, text, text, text);
drop function if exists bls_proxy_manager.admin_bot_client_create(text, text, text, text, text[]);
create function bls_proxy_manager.admin_bot_client_create(
    p_purpose text, p_name text, p_token_hash text, p_hint text, p_pools text[] default null)
returns uuid
language plpgsql volatile security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare v_id uuid;
begin
    insert into bot_clients (purpose, name, token_hash, token_hint, pools)
    values (p_purpose, p_name, p_token_hash, p_hint, bot_pools_validate(p_purpose, p_pools))
    returning id into v_id;
    return v_id;
end $$;

-- сменить пулы клиента (NULL = все пулы цели)
create or replace function bls_proxy_manager.admin_bot_client_set_pools(p_id uuid, p_pools text[])
returns integer
language plpgsql volatile security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare v_purpose text; n integer;
begin
    select purpose into v_purpose from bot_clients where id = p_id;
    if v_purpose is null then return 0; end if;
    update bot_clients set pools = bot_pools_validate(v_purpose, p_pools) where id = p_id;
    get diagnostics n = row_count;
    return n;
end $$;

-- какие пулы можно назначить для цели
create or replace function bls_proxy_manager.admin_purpose_pools(p_purpose text)
returns table (pool text, proxies bigint, enabled bigint)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select p.pool, count(*), count(*) filter (where p.enabled)
      from proxies p
     where p.pool is not null and p_purpose = any (p.purposes)
     group by p.pool order by p.pool
$$;

-- выдача только из разрешённых пулов: обёртка над acquire_proxies, лишние прокси попадают в exclude
create or replace function bls_proxy_manager.acquire_proxies_scoped(
    p_account_id  text,
    p_count       integer,
    p_ttl_seconds integer,
    p_purpose     text,
    p_client_id   text,
    p_exclude     text[],
    p_replace     boolean,
    p_pools       text[]
) returns table (
    lease_id uuid, proxy_id text, scheme text, host text, port integer,
    username text, password text, expires_at timestamptz
)
language sql volatile security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select * from bls_proxy_manager.acquire_proxies(
        p_account_id, p_count, p_ttl_seconds, p_purpose, p_client_id,
        coalesce(p_exclude, '{}') || coalesce(
            array(select p.id from proxies p
                   where p_purpose = any (p.purposes)
                     and (p_pools is not null)
                     and (p.pool is null or not (p.pool = any (p_pools)))),
            '{}'),
        p_replace)
$$;

-- «через сколько появится свободный прокси» только по разрешённым пулам
create or replace function bls_proxy_manager.next_available_in_scoped(p_purpose text, p_pools text[])
returns integer
language plpgsql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare v_at timestamptz;
begin
    if p_pools is null then return next_available_in(p_purpose); end if;
    if coalesce(p_purpose, 'bls') = 'bls' then
        select min(greatest(
                   ps.free_at,
                   coalesce(ps.quarantined_until, '-infinity'::timestamptz),
                   case when coalesce(u.n, 0) >= p.max_leases then u.min_exp else '-infinity'::timestamptz end))
          into v_at
          from proxies p
          join proxy_state ps on ps.proxy_id = p.id
          left join (select l.proxy_id, count(*) n, min(l.expires_at) min_exp
                       from leases l where l.released_at is null and l.expires_at > now()
                      group by l.proxy_id) u on u.proxy_id = p.id
         where p.enabled and p_purpose = any (p.purposes) and p.pool = any (p_pools);
    else
        select min(greatest(
                   coalesce(ps.free_at, now()),
                   coalesce(ps.quarantined_until, '-infinity'::timestamptz),
                   case when coalesce(u.n, 0) >= p.max_leases then u.min_exp else '-infinity'::timestamptz end))
          into v_at
          from proxies p
          left join proxy_purpose_state ps on ps.proxy_id = p.id and ps.purpose = p_purpose
          left join (select l.proxy_id, count(*) n, min(l.expires_at) min_exp
                       from leases l where l.released_at is null and l.expires_at > now()
                      group by l.proxy_id) u on u.proxy_id = p.id
         where p.enabled and p_purpose = any (p.purposes) and p.pool = any (p_pools);
    end if;
    if v_at is null then return 60; end if;
    return least(3600, greatest(1, ceil(extract(epoch from (v_at - now())))::integer));
end $$;

revoke all on function bls_proxy_manager.bot_pools_validate(text, text[]) from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_bot_clients_list() from public, anon, authenticated;
revoke all on function bls_proxy_manager.bot_tokens_active() from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_bot_client_create(text, text, text, text, text[]) from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_bot_client_set_pools(uuid, text[]) from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_purpose_pools(text) from public, anon, authenticated;
revoke all on function bls_proxy_manager.acquire_proxies_scoped(text, integer, integer, text, text, text[], boolean, text[]) from public, anon, authenticated;
revoke all on function bls_proxy_manager.next_available_in_scoped(text, text[]) from public, anon, authenticated;

grant execute on function bls_proxy_manager.admin_bot_clients_list() to bls_admin;
grant execute on function bls_proxy_manager.admin_bot_client_create(text, text, text, text, text[]) to bls_admin;
grant execute on function bls_proxy_manager.admin_bot_client_set_pools(uuid, text[]) to bls_admin;
grant execute on function bls_proxy_manager.admin_purpose_pools(text) to bls_admin;
grant execute on function bls_proxy_manager.bot_tokens_active() to bls_reporter, bls_issuer;
grant execute on function bls_proxy_manager.acquire_proxies_scoped(text, integer, integer, text, text, text[], boolean, text[]) to bls_issuer;
grant execute on function bls_proxy_manager.next_available_in_scoped(text, text[]) to bls_issuer;
