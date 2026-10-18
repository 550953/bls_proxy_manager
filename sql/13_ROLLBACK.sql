-- 13_ROLLBACK.sql — вернуть пять функций к состоянию до 13 (с 12_dedupe_only). Таблицы и данные не удаляются.
-- Полное удаление (необязательно): drop table bls_proxy_manager.proxy_purpose_state, bls_proxy_manager.purpose_settings cascade;
set search_path = bls_proxy_manager, pg_temp;

create or replace function bls_proxy_manager.acquire_proxies(
    p_account_id  text,
    p_count       integer default 1,
    p_ttl_seconds integer default 300,
    p_purpose     text    default 'bls',
    p_client_id   text    default null,
    p_exclude     text[]  default '{}',
    p_replace     boolean default true
) returns table (
    lease_id uuid, proxy_id text, scheme text, host text, port integer,
    username text, password text, expires_at timestamptz
)
language plpgsql security definer
set search_path = bls_proxy_manager, pg_temp
as $$
#variable_conflict use_column
declare
    v_ttl   integer := least(greatest(coalesce(p_ttl_seconds, 300), 30), 3600);
    v_count integer := least(greatest(coalesce(p_count, 1), 1), 5);
    v_bad   text[]  := cfg_codes('proxy_error_codes');
begin
    if p_account_id is null or length(p_account_id) = 0 then
        raise exception 'account_id required';
    end if;

    -- выдача сериализована: при 10–50 ботах это дёшево и исключает гонки за слот
    perform pg_advisory_xact_lock(hashtext('bls_proxy_acquire'));

    update leases l set released_at = now(), release_reason = 'expired'
     where l.released_at is null and l.expires_at <= now();

    if p_replace then
        update leases l set released_at = now(), release_reason = 'replaced'
         where l.account_id = p_account_id and l.purpose = p_purpose and l.released_at is null;
    end if;

    return query
    with cand as (
        select p.id
          from proxies p
          join proxy_state ps on ps.proxy_id = p.id
          left join (select l.proxy_id, count(*) n from leases l
                      where l.released_at is null group by l.proxy_id) u on u.proxy_id = p.id
         where p.enabled
           and p_purpose = any (p.purposes)
           and not (p.id = any (coalesce(p_exclude, '{}')))
           and (ps.quarantined_until is null or ps.quarantined_until <= now())
           and ps.free_at <= now()
           and coalesce(u.n, 0) < p.max_leases
         order by
           -- 1) прокси, на которых у ЭТОГО аккаунта недавно были прокси-ошибки — в конец
           exists (select 1 from proxy_events e
                    where e.account_id = p_account_id and e.proxy_id = p.id
                      and e.event_type = 'error' and e.created_at > now() - interval '1 hour'
                      and e.error_code = any (v_bad)),
           -- 2) «липкость»: где у аккаунта был успешный цикл последним
           (select max(e.created_at) from proxy_events e
             where e.account_id = p_account_id and e.proxy_id = p.id
               and e.event_type = 'cycle_ok' and e.created_at > now() - interval '24 hours') desc nulls last,
           -- 3) давно не использовавшиеся
           ps.last_used_at asc nulls first,
           random()
         limit v_count
    ), ins as (
        insert into leases (proxy_id, account_id, client_id, purpose, expires_at)
        select c.id, p_account_id, p_client_id, p_purpose, now() + make_interval(secs => v_ttl)
          from cand c
        returning leases.id, leases.proxy_id, leases.expires_at
    ), upd as (
        update proxy_state s set last_used_at = now(), updated_at = now()
          from ins where s.proxy_id = ins.proxy_id
        returning s.proxy_id
    )
    select ins.id, p.id, p.scheme, p.host, p.port, cr.username, cr.password, ins.expires_at
      from ins
      join proxies p on p.id = ins.proxy_id
      left join proxy_credentials cr on cr.proxy_id = p.id;
end $$;

create or replace function bls_proxy_manager.next_available_in(p_purpose text default 'bls') returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare v_at timestamptz;
begin
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
     where p.enabled and p_purpose = any (p.purposes);

    if v_at is null then return 60; end if;
    return least(3600, greatest(1, ceil(extract(epoch from (v_at - now())))::integer));
end $$;

create or replace function bls_proxy_manager.release_lease(
    p_lease_id   uuid,
    p_reason     text  default 'released',
    p_error_code text  default null,
    p_phase      text  default null,
    p_detail     jsonb default '{}'::jsonb
) returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare l leases%rowtype;
begin
    select * into l from leases where id = p_lease_id for update;
    if not found or l.released_at is not null then return; end if;   -- идемпотентно

    if p_error_code is not null then
        perform report_event(p_lease_id, 'error', p_error_code, p_phase, null, p_detail);
    end if;

    update leases set released_at = now(), release_reason = left(coalesce(p_reason,'released'), 100)
     where id = p_lease_id;

    update proxy_state
       set free_at = greatest(free_at, now() + make_interval(secs => cfg_int('cooldown_ok_s', 0))),
           updated_at = now()
     where proxy_id = l.proxy_id;

    insert into proxy_events(lease_id, proxy_id, account_id, event_type, error_code, phase, detail)
    values (l.id, l.proxy_id, l.account_id, 'released', p_error_code, p_phase,
            jsonb_build_object('reason', p_reason) || coalesce(p_detail, '{}'::jsonb));
end $$;

create or replace function bls_proxy_manager.evaluate_cross_account_health() returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    v_ids     text[];
    v_enabled integer;
    v_thr     integer;
    v_id      text;
begin
    select array_agg(x.proxy_id) into v_ids from (
        select e.proxy_id
          from proxy_events e
          join proxy_state ps on ps.proxy_id = e.proxy_id
         where e.event_type = 'error'
           and e.created_at > now() - make_interval(mins => cfg_int('xacct_window_min', 15))
           and e.error_code = any (cfg_codes('proxy_error_codes'))
           and (ps.quarantined_until is null or ps.quarantined_until <= now())
         group by e.proxy_id
        having count(*) >= cfg_int('xacct_min_errors', 3)
           and count(distinct e.account_id) >= cfg_int('xacct_min_accounts', 2)
    ) x;

    if v_ids is null then return 0; end if;

    select count(*) into v_enabled from proxies where enabled;
    v_thr := greatest(cfg_int('global_wave_min_proxies', 3),
                      ceil(v_enabled * cfg_int('global_wave_share_pct', 50) / 100.0)::integer);

    if cardinality(v_ids) >= v_thr then
        if not exists (select 1 from proxy_events
                        where event_type = 'global_wave' and created_at > now() - interval '10 minutes') then
            insert into proxy_events(event_type, detail)
            values ('global_wave', jsonb_build_object('flagged', v_ids, 'threshold', v_thr));
        end if;
        return 0;
    end if;

    foreach v_id in array v_ids loop
        perform quarantine_proxy(v_id, 'cross-account errors');
    end loop;
    return cardinality(v_ids);
end $$;

create or replace function bls_proxy_manager.report_event(
    p_lease_id   uuid,
    p_event_type text,
    p_error_code text    default null,
    p_phase      text    default null,
    p_latency_ms integer default null,
    p_detail     jsonb   default '{}'::jsonb
) returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    l       leases%rowtype;
    v_cons  integer;
    v_cool  integer;
    v_id    bigint;
    v_dup   boolean := false;
begin
    if p_event_type not in ('cycle_ok','error') then
        raise exception 'bad event_type %', p_event_type;
    end if;
    select * into l from leases where id = p_lease_id;
    if not found then raise exception 'unknown lease %', p_lease_id; end if;

    insert into proxy_events(lease_id, proxy_id, account_id, event_type, error_code, phase, latency_ms, detail)
    values (l.id, l.proxy_id, l.account_id, p_event_type, p_error_code, p_phase, p_latency_ms,
            coalesce(p_detail, '{}'::jsonb))
    returning id into v_id;

    -- тот же код по той же аренде за последнюю минуту = повтор (report + release)
    if p_event_type = 'error' and p_error_code is not null then
        select exists (
            select 1 from proxy_events e
             where e.lease_id = l.id and e.event_type = 'error'
               and e.error_code = p_error_code and e.id < v_id
               and e.created_at > now() - interval '60 seconds'
        ) into v_dup;
    end if;

    if p_event_type = 'cycle_ok' then
        update proxy_state
           set consecutive_failures = 0,
               fault_count = 0,
               fault_first_at = null,
               last_ok_at = now(),
               quarantine_level = case when quarantined_until is null
                                         or quarantined_until < now() - interval '1 hour'
                                       then 0 else quarantine_level end,
               updated_at = now()
         where proxy_id = l.proxy_id;

    elsif v_dup then
        null;  -- повтор: только журнал

    elsif p_error_code = any (cfg_codes('proxy_fault_codes')) then
        perform apply_proxy_fault(l.proxy_id, p_error_code);

    elsif p_error_code = any (cfg_codes('proxy_error_codes')) then
        v_cool := case when p_error_code = any (cfg_codes('ban_error_codes'))
                       then cfg_int('cooldown_ban_s', 900)
                       else cfg_int('cooldown_error_s', 120) end;
        update proxy_state
           set consecutive_failures = consecutive_failures + 1,
               last_error_at = now(),
               free_at = greatest(free_at, now() + make_interval(secs => v_cool)),
               cooldown_reason = p_error_code || ' (кулдаун)',
               updated_at = now()
         where proxy_id = l.proxy_id
        returning consecutive_failures into v_cons;

        if v_cons >= cfg_int('consec_fail_quarantine', 5) then
            perform quarantine_proxy(l.proxy_id, 'consecutive errors, last: ' || p_error_code);
        end if;
    end if;
    -- прочие ошибки (BLS_NO_SLOTS, логин, Selenium, CDP...) только логируются
end $$;

revoke all on function bls_proxy_manager.report_event(uuid,text,text,text,integer,jsonb) from public, anon, authenticated;
grant execute on function bls_proxy_manager.acquire_proxies(text,integer,integer,text,text,text[],boolean) to bls_issuer;
grant execute on function bls_proxy_manager.next_available_in(text) to bls_issuer;
grant execute on function bls_proxy_manager.release_lease(uuid,text,text,text,jsonb) to bls_reporter;
grant execute on function bls_proxy_manager.report_event(uuid,text,text,text,integer,jsonb) to bls_reporter;
grant execute on function bls_proxy_manager.evaluate_cross_account_health() to bls_issuer;
reset search_path;
