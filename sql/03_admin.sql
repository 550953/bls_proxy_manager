-- =============================================================================
-- Админ-роль для дашборда. Накатывать ПОСЛЕ 00_full_install.sql. Идемпотентно.
-- bls_admin не имеет прав на таблицы: только функции ниже. Пароли прокси
-- наружу не отдаются никогда (только флаг has_password).
-- После: alter role bls_admin password '<длинный-случайный>';
-- =============================================================================

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'bls_admin') then
        create role bls_admin login noinherit nosuperuser nocreatedb nocreaterole nobypassrls;
    end if;
end $$;

alter role bls_admin connection limit 5;
alter role bls_admin set statement_timeout = '15s';
alter role bls_admin set idle_in_transaction_session_timeout = '15s';

set search_path = bls_proxy_manager, pg_temp;

-- Массовое добавление/обновление. Ключ совпадения — (host, port).
-- item: {id?, scheme, host, port, username?, password?, kind, pool, max_leases}
create or replace function admin_upsert_proxies(p_items jsonb) returns jsonb
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    it    jsonb;
    v_id  text;
    v_host text;
    v_port integer;
    v_ins integer := 0;
    v_upd integer := 0;
begin
    if p_items is null or jsonb_typeof(p_items) <> 'array' then
        raise exception 'array expected';
    end if;
    if jsonb_array_length(p_items) > 2000 then
        raise exception 'too many items';
    end if;

    for it in select e from jsonb_array_elements(p_items) e loop
        v_host := btrim(it->>'host');
        v_port := (it->>'port')::integer;
        if v_host is null or v_host = '' or v_port is null then
            raise exception 'host/port required';
        end if;

        select id into v_id from proxies where host = v_host and port = v_port limit 1;

        if v_id is null then
            v_id := coalesce(nullif(it->>'id', ''), v_host || ':' || v_port);
            insert into proxies(id, scheme, host, port, kind, pool, max_leases)
            values (v_id,
                    coalesce(it->>'scheme', 'socks5'), v_host, v_port,
                    coalesce(it->>'kind', 'shared'), nullif(it->>'pool', ''),
                    coalesce((it->>'max_leases')::integer, 1));
            v_ins := v_ins + 1;
        else
            update proxies
               set scheme     = coalesce(it->>'scheme', scheme),
                   kind       = coalesce(it->>'kind', kind),
                   pool       = coalesce(nullif(it->>'pool', ''), pool),
                   max_leases = coalesce((it->>'max_leases')::integer, max_leases)
             where id = v_id;
            v_upd := v_upd + 1;
        end if;

        if (it->>'username') is not null or (it->>'password') is not null then
            insert into proxy_credentials(proxy_id, username, password)
            values (v_id, it->>'username', it->>'password')
            on conflict (proxy_id) do update
               set username = excluded.username, password = excluded.password;
        end if;
    end loop;

    return jsonb_build_object('inserted', v_ins, 'updated', v_upd);
end $$;

create or replace function admin_list_proxies()
returns table (
    id text, scheme text, host text, port integer, kind text, pool text,
    max_leases integer, enabled boolean, username text, has_password boolean,
    quarantined_until timestamptz, quarantine_reason text, free_at timestamptz,
    consecutive_failures integer, probe_failures integer,
    last_ok_at timestamptz, last_error_at timestamptz,
    last_probe_ok boolean, last_latency_ms integer,
    active_leases integer, accounts text[]
)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select p.id, p.scheme, p.host, p.port, p.kind, p.pool,
           p.max_leases, p.enabled, cr.username, (coalesce(cr.password, '') <> ''),
           ps.quarantined_until, ps.quarantine_reason, ps.free_at,
           ps.consecutive_failures, ps.probe_failures,
           ps.last_ok_at, ps.last_error_at,
           ps.last_probe_ok, ps.last_latency_ms,
           coalesce(u.n, 0), u.accts
      from proxies p
      join proxy_state ps on ps.proxy_id = p.id
      left join proxy_credentials cr on cr.proxy_id = p.id
      left join (select l.proxy_id, count(*)::integer n, array_agg(l.account_id order by l.account_id) accts
                   from leases l where l.released_at is null and l.expires_at > now()
                  group by l.proxy_id) u on u.proxy_id = p.id
     order by p.pool nulls last, p.id
$$;

create or replace function admin_active_leases()
returns table (lease_id uuid, proxy_id text, account_id text, purpose text,
               acquired_at timestamptz, expires_at timestamptz)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select l.id, l.proxy_id, l.account_id, l.purpose, l.acquired_at, l.expires_at
      from leases l
     where l.released_at is null and l.expires_at > now()
     order by l.account_id
$$;

create or replace function admin_recent_events(p_limit integer default 100)
returns table (created_at timestamptz, proxy_id text, account_id text,
               event_type text, error_code text, phase text, detail text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select e.created_at, e.proxy_id, e.account_id, e.event_type, e.error_code, e.phase, e.detail::text
      from proxy_events e
     order by e.id desc
     limit least(greatest(coalesce(p_limit, 100), 1), 500)
$$;

create or replace function admin_set_enabled(p_ids text[], p_enabled boolean) returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare n integer;
begin
    update proxies set enabled = p_enabled where id = any (p_ids);
    get diagnostics n = row_count;
    if not p_enabled then
        update leases set released_at = now(), release_reason = 'admin_disabled'
         where proxy_id = any (p_ids) and released_at is null;
    end if;
    return n;
end $$;

create or replace function admin_delete_proxies(p_ids text[]) returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare n integer;
begin
    delete from proxies where id = any (p_ids);
    get diagnostics n = row_count;
    return n;
end $$;

create or replace function admin_clear_quarantine(p_ids text[]) returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare n integer;
begin
    update proxy_state
       set quarantined_until = null, quarantine_reason = null, quarantine_level = 0,
           consecutive_failures = 0, probe_failures = 0, free_at = now(), updated_at = now()
     where proxy_id = any (p_ids);
    get diagnostics n = row_count;
    return n;
end $$;

-- ---- права: закрыть от public/anon/authenticated, выдать bls_admin ----------
do $$
declare r text;
begin
    foreach r in array array['anon','authenticated'] loop
        if exists (select 1 from pg_roles where rolname = r) then
            execute format('revoke all on all functions in schema bls_proxy_manager from %I', r);
        end if;
    end loop;
end $$;
revoke all on all functions in schema bls_proxy_manager from public;
revoke all on all functions in schema bls_proxy_manager from bls_admin;

grant usage on schema bls_proxy_manager to bls_admin;
grant select on v_pool_summary to bls_admin;
grant execute on function admin_upsert_proxies(jsonb)          to bls_admin;
grant execute on function admin_list_proxies()                 to bls_admin;
grant execute on function admin_active_leases()                to bls_admin;
grant execute on function admin_recent_events(integer)         to bls_admin;
grant execute on function admin_set_enabled(text[], boolean)   to bls_admin;
grant execute on function admin_delete_proxies(text[])         to bls_admin;
grant execute on function admin_clear_quarantine(text[])       to bls_admin;

reset search_path;

-- Проверка: должно вернуть 7 строк (admin_*), execute только у bls_admin
select p.proname, p.proacl
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'bls_proxy_manager' and p.proname like 'admin\_%'
 order by 1;
