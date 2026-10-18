-- =============================================================================
-- 14_purpose_admin.sql — данные дашборда по цели (VisaGlobal) + график BLS без чужих аренд.
-- Накатывать ПОСЛЕ 13_visaglobal_purpose.sql. Безопасно запускать повторно.
-- Меняет: admin_upsert_proxies (разрешает purposes 'visaglobal') и admin_event_stats (BLS-график
-- считает только аренды BLS и сбои OCR). Остальное — новые функции admin_purpose_*.
-- =============================================================================
set search_path = bls_proxy_manager, pg_temp;

-- ---------- 1. Прокси цели (та же форма, что admin_list_proxies) ----------
create or replace function bls_proxy_manager.admin_purpose_proxies(p_purpose text)
returns table (
    id text, scheme text, host text, port integer, kind text, pool text, purposes text[],
    max_leases integer, enabled boolean, username text, has_password boolean,
    quarantined_until timestamptz, quarantine_reason text, free_at timestamptz,
    consecutive_failures integer, probe_failures integer,
    last_ok_at timestamptz, last_error_at timestamptz,
    last_probe_ok boolean, last_latency_ms integer,
    active_leases integer, accounts text[],
    fault_count integer, quarantine_runs integer, cooldown_reason text,
    auto_disabled boolean, disabled_reason text, last_fault_code text, fault_verdict text
)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select p.id, p.scheme, p.host, p.port, p.kind, p.pool, p.purposes,
           p.max_leases, p.enabled, cr.username, (coalesce(cr.password, '') <> ''),
           -- карантин цели; общий карантин пробера («прокси не отвечает») тоже виден
           case when gs.quarantine_reason = 'probe failures' and gs.quarantined_until > now()
                     and (pp.quarantined_until is null or gs.quarantined_until > pp.quarantined_until)
                then gs.quarantined_until else pp.quarantined_until end,
           case when gs.quarantine_reason = 'probe failures' and gs.quarantined_until > now()
                     and (pp.quarantined_until is null or gs.quarantined_until > pp.quarantined_until)
                then gs.quarantine_reason else pp.quarantine_reason end,
           coalesce(pp.free_at, now()),
           coalesce(pp.consecutive_failures, 0), gs.probe_failures,
           pp.last_ok_at, pp.last_error_at,
           gs.last_probe_ok, gs.last_latency_ms,
           coalesce(u.n, 0), u.accts,
           coalesce(pp.fault_count, 0), 0, pp.cooldown_reason,
           gs.auto_disabled, gs.disabled_reason, pp.last_fault_code, null::text
      from proxies p
      join proxy_state gs on gs.proxy_id = p.id
      left join proxy_purpose_state pp on pp.proxy_id = p.id and pp.purpose = p_purpose
      left join proxy_credentials cr on cr.proxy_id = p.id
      left join (select l.proxy_id, count(*)::integer n, array_agg(l.account_id order by l.account_id) accts
                   from leases l where l.released_at is null and l.expires_at > now()
                  group by l.proxy_id) u on u.proxy_id = p.id
     where p_purpose = any (p.purposes)
     order by p.pool nulls last, p.id
$$;

-- ---------- 2. Сводка по пулам цели (та же форма, что v_pool_summary) ----------
create or replace function bls_proxy_manager.admin_purpose_summary(p_purpose text)
returns table (kind text, pool text, enabled bigint, quarantined bigint, cooling bigint,
               "full" bigint, available bigint)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    with st as (
        select p.kind, coalesce(p.pool, '-') as pool, p.enabled, p.max_leases,
               greatest(coalesce(pp.quarantined_until, '-infinity'::timestamptz),
                        case when gs.quarantine_reason = 'probe failures'
                             then coalesce(gs.quarantined_until, '-infinity'::timestamptz)
                             else '-infinity'::timestamptz end) as q_until,
               coalesce(pp.free_at, now()) as free_at,
               coalesce(u.n, 0) as n
          from proxies p
          join proxy_state gs on gs.proxy_id = p.id
          left join proxy_purpose_state pp on pp.proxy_id = p.id and pp.purpose = p_purpose
          left join (select l.proxy_id, count(*) n from leases l
                      where l.released_at is null and l.expires_at > now() group by l.proxy_id) u on u.proxy_id = p.id
         where p_purpose = any (p.purposes)
    )
    select kind, pool,
           count(*) filter (where enabled),
           count(*) filter (where enabled and q_until > now()),
           count(*) filter (where enabled and q_until <= now() and free_at > now()),
           count(*) filter (where enabled and n >= max_leases),
           count(*) filter (where enabled and q_until <= now() and free_at <= now() and n < max_leases)
      from st
     group by kind, pool
     order by 1, 2
$$;

-- ---------- 3. Аренды и события цели ----------
create or replace function bls_proxy_manager.admin_purpose_leases(p_purpose text)
returns table (lease_id uuid, proxy_id text, account_id text, purpose text,
               acquired_at timestamptz, expires_at timestamptz)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select l.id, l.proxy_id, l.account_id, l.purpose, l.acquired_at, l.expires_at
      from leases l
     where l.released_at is null and l.expires_at > now() and l.purpose = p_purpose
     order by l.account_id
$$;

create or replace function bls_proxy_manager.admin_purpose_events(p_purpose text, p_limit integer default 100)
returns table (created_at timestamptz, proxy_id text, account_id text,
               event_type text, error_code text, phase text, detail text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select e.created_at, e.proxy_id, e.account_id, e.event_type, e.error_code, e.phase, e.detail::text
      from proxy_events e
      left join leases l on l.id = e.lease_id
     where l.purpose = p_purpose or e.detail->>'purpose' = p_purpose
     order by e.id desc
     limit least(greatest(coalesce(p_limit, 100), 1), 500)
$$;

-- ---------- 4. Настройки цели (белый список) ----------
create or replace function bls_proxy_manager.admin_purpose_get_settings(p_purpose text)
returns table (key text, value text, note text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select k.key,
           pcfg_int(p_purpose, k.key, 0)::text,
           (select s.note from purpose_settings s where s.purpose = p_purpose and s.key = k.key)
      from unnest(array['cooldown_ok_s','cooldown_ban_s','cooldown_error_s','consec_fail_quarantine',
                        'quarantine_min','cooldown_proxy_fault_s','fault_cooldown2_s','fault_disable_count',
                        'fault_quarantine_min','repeat_fault_window_min']) as k(key)
$$;

create or replace function bls_proxy_manager.admin_purpose_set_setting(p_purpose text, p_key text, p_value text)
returns void language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
begin
    if p_purpose is null or p_purpose !~ '^[a-z0-9_]{2,30}$' or p_purpose = 'bls' then
        raise exception 'bad purpose %', p_purpose;
    end if;
    if p_key not in ('cooldown_ok_s','cooldown_ban_s','cooldown_error_s','consec_fail_quarantine',
                     'quarantine_min','cooldown_proxy_fault_s','fault_cooldown2_s','fault_disable_count',
                     'fault_quarantine_min','repeat_fault_window_min') then
        raise exception 'key not allowed: %', p_key;
    end if;
    if p_value !~ '^[0-9]{1,6}$' then raise exception 'integer 0..999999 expected'; end if;
    insert into purpose_settings(purpose, key, value) values (p_purpose, p_key, to_jsonb(p_value::integer))
    on conflict (purpose, key) do update set value = excluded.value;
end $$;

-- ---------- 5. Снять карантин и кулдаун цели у выбранных прокси ----------
create or replace function bls_proxy_manager.admin_purpose_clear_quarantine(p_purpose text, p_ids text[])
returns integer language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare n integer;
begin
    update proxy_purpose_state
       set quarantined_until = null, quarantine_reason = null, cooldown_reason = null, free_at = now(),
           consecutive_failures = 0, fault_count = 0, fault_first_at = null, updated_at = now()
     where purpose = p_purpose and proxy_id = any (p_ids);
    get diagnostics n = row_count;
    return n;
end $$;

-- ---------- 6. График цели ----------
create or replace function bls_proxy_manager.admin_purpose_event_stats(p_purpose text, p_hours integer default 24)
returns table (bucket timestamptz, ok bigint, err bigint)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    with prm as (
        select least(greatest(coalesce(p_hours, 24), 1), 336) as h,
               (select nullif(s.value #>> '{}', '')::timestamptz from settings s where s.key = 'stats_since') as since
    ), unit as (
        select h, since,
               case when h <= 72 then 'hour' else 'day' end as u,
               case when h <= 72 then interval '1 hour' else interval '1 day' end as step
          from prm
    ), g as (
        select generate_series(
                   date_trunc(u.u, greatest(now() - make_interval(hours => u.h), coalesce(u.since, '-infinity'::timestamptz))),
                   date_trunc(u.u, now()), u.step) as b,
               u.step, u.since
          from unit u
    ), ev as (
        select e.id, e.created_at, e.event_type, e.error_code, e.lease_id
          from proxy_events e
          join leases l on l.id = e.lease_id
         where l.purpose = p_purpose and e.event_type in ('released', 'error')
           and e.created_at > now() - make_interval(hours => (select h from prm))
    )
    select g.b as bucket,
           count(ev.id) filter (where ev.event_type = 'released' and ev.error_code is null) as ok,
           count(distinct ev.lease_id::text || '|' || ev.error_code)
               filter (where ev.event_type = 'error'
                         and ev.error_code = any (pcfg_codes(p_purpose, 'proxy_error_codes'))) as err
      from g
      left join ev on ev.created_at >= greatest(g.b, coalesce(g.since, '-infinity'::timestamptz))
                  and ev.created_at < g.b + g.step
     group by g.b
     order by g.b
$$;

-- BLS-график: аренды других целей сюда не попадают (события OCR без аренды остаются)
create or replace function bls_proxy_manager.admin_event_stats(p_hours integer default 24)
returns table (bucket timestamptz, ok bigint, err bigint)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    with prm as (
        select least(greatest(coalesce(p_hours, 24), 1), 336) as h,
               (select nullif(s.value #>> '{}', '')::timestamptz from settings s where s.key = 'stats_since') as since
    ), unit as (
        select h, since,
               case when h <= 72 then 'hour' else 'day' end as u,
               case when h <= 72 then interval '1 hour' else interval '1 day' end as step
          from prm
    ), g as (
        select generate_series(
                   date_trunc(u.u, greatest(now() - make_interval(hours => u.h), coalesce(u.since, '-infinity'::timestamptz))),
                   date_trunc(u.u, now()), u.step) as b,
               u.step, u.since
          from unit u
    ), ev as (
        select e.id, e.created_at, e.event_type, e.error_code, e.lease_id
          from proxy_events e
          left join leases l on l.id = e.lease_id
         where e.event_type in ('released', 'error', 'ocr_fail', 'ocr_geo')
           and (e.lease_id is null or l.purpose = 'bls')
           and e.created_at > now() - make_interval(hours => (select h from prm))
    )
    select g.b as bucket,
           count(ev.id) filter (where ev.event_type = 'released' and ev.error_code is null) as ok,
           count(distinct ev.lease_id::text || '|' || ev.error_code)
               filter (where ev.event_type = 'error' and ev.lease_id is not null
                         and ev.error_code = any (cfg_codes('proxy_error_codes')))
         + count(ev.id) filter (where ev.event_type in ('ocr_fail', 'ocr_geo')) as err
      from g
      left join ev on ev.created_at >= greatest(g.b, coalesce(g.since, '-infinity'::timestamptz))
                  and ev.created_at < g.b + g.step
     group by g.b
     order by g.b
$$;

-- ---------- 7. Добавление прокси с purposes ∋ 'visaglobal' ----------
create or replace function bls_proxy_manager.admin_upsert_proxies(p_items jsonb) returns jsonb
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    it     jsonb;
    v_id   text;
    v_host text;
    v_port integer;
    v_purp text[];
    v_ins  integer := 0;
    v_upd  integer := 0;
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

        v_purp := null;
        if jsonb_typeof(it->'purposes') = 'array' then
            select array_agg(distinct x order by x) into v_purp
              from jsonb_array_elements_text(it->'purposes') x
             where x in ('bls', 'ocr', 'visaglobal');
        end if;

        select id into v_id from proxies where host = v_host and port = v_port limit 1;

        if v_id is null then
            v_id := coalesce(nullif(it->>'id', ''), v_host || ':' || v_port);
            insert into proxies(id, scheme, host, port, kind, pool, max_leases, purposes)
            values (v_id,
                    coalesce(it->>'scheme', 'socks5'), v_host, v_port,
                    coalesce(it->>'kind', 'shared'), nullif(it->>'pool', ''),
                    coalesce((it->>'max_leases')::integer, 1),
                    coalesce(v_purp, '{bls}'::text[]));
            v_ins := v_ins + 1;
        else
            update proxies
               set scheme     = coalesce(it->>'scheme', scheme),
                   kind       = coalesce(it->>'kind', kind),
                   pool       = coalesce(nullif(it->>'pool', ''), pool),
                   max_leases = coalesce((it->>'max_leases')::integer, max_leases),
                   purposes   = coalesce(v_purp, purposes)
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

-- ---------- 8. Права ----------
revoke all on function bls_proxy_manager.admin_purpose_proxies(text)                 from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_purpose_summary(text)                 from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_purpose_leases(text)                  from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_purpose_events(text,integer)          from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_purpose_get_settings(text)            from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_purpose_set_setting(text,text,text)   from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_purpose_clear_quarantine(text,text[]) from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_purpose_event_stats(text,integer)     from public, anon, authenticated;
grant execute on function bls_proxy_manager.admin_purpose_proxies(text)                 to bls_admin;
grant execute on function bls_proxy_manager.admin_purpose_summary(text)                 to bls_admin;
grant execute on function bls_proxy_manager.admin_purpose_leases(text)                  to bls_admin;
grant execute on function bls_proxy_manager.admin_purpose_events(text,integer)          to bls_admin;
grant execute on function bls_proxy_manager.admin_purpose_get_settings(text)            to bls_admin;
grant execute on function bls_proxy_manager.admin_purpose_set_setting(text,text,text)   to bls_admin;
grant execute on function bls_proxy_manager.admin_purpose_clear_quarantine(text,text[]) to bls_admin;
grant execute on function bls_proxy_manager.admin_purpose_event_stats(text,integer)     to bls_admin;
grant execute on function bls_proxy_manager.admin_event_stats(integer)                  to bls_admin;
grant execute on function bls_proxy_manager.admin_upsert_proxies(jsonb)                 to bls_admin;
reset search_path;
