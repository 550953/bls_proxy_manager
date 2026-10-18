-- =============================================================================
-- 13_visaglobal_purpose.sql — V1: выдача прокси для VisaGlobal со своими кулдаунами.
-- Накатывать после 05, 06, 08, 12 (и 11). Откат: 13_ROLLBACK.sql.
--
-- Идея: ветка «для других целей». Всё, что относится к purpose='bls', работает прежним
-- кодом; для purpose<>'bls' (visaglobal и т.д.) свои кулдауны, бан-кулдауны, карантин по
-- ошибкам и ступени сбоев в таблице proxy_purpose_state. Кулдаун BLS не морозит IP для
-- VisaGlobal и наоборот.
--
-- Что общее: proxies.enabled (в т.ч. «выключено» на 3-й ступени BLS), карантин пробера
-- («probe failures»), лимит max_leases (один IP не выдаётся двум целям одновременно).
-- Чего пока нет (V2/V3): строка VisaGlobal в дашборде, проверка «прощения» по
-- visa.vfsglobal.com, выключение 3-й ступени только по цели.
-- =============================================================================
set search_path = bls_proxy_manager, pg_temp;

-- ---------- 1. Настройки по целям (запасной вариант — общие settings) ----------
create table if not exists bls_proxy_manager.purpose_settings (
    purpose text  not null,
    key     text  not null,
    value   jsonb not null,
    note    text,
    primary key (purpose, key)
);

create or replace function bls_proxy_manager.pcfg_int(p_purpose text, p_key text, p_default integer)
returns integer language sql stable set search_path = bls_proxy_manager, pg_temp as $$
    select coalesce(
        (select (s.value #>> '{}')::integer from purpose_settings s where s.purpose = p_purpose and s.key = p_key),
        cfg_int(p_key, p_default))
$$;

create or replace function bls_proxy_manager.pcfg_codes(p_purpose text, p_key text)
returns text[] language sql stable set search_path = bls_proxy_manager, pg_temp as $$
    select coalesce(
        (select array(select jsonb_array_elements_text(s.value))
           from purpose_settings s where s.purpose = p_purpose and s.key = p_key),
        cfg_codes(p_key))
$$;

insert into bls_proxy_manager.purpose_settings(purpose, key, value, note) values
 ('visaglobal', 'cooldown_ok_s',            '300',  'кулдаун после обычного release, сек'),
 ('visaglobal', 'cooldown_ban_s',           '900',  'кулдаун после 403/429, сек'),
 ('visaglobal', 'cooldown_error_s',         '120',  'кулдаун после прочих прокси-ошибок, сек'),
 ('visaglobal', 'consec_fail_quarantine',   '5',    'ошибок подряд -> карантин'),
 ('visaglobal', 'quarantine_min',           '30',   'карантин по ошибкам подряд, мин'),
 ('visaglobal', 'cooldown_proxy_fault_s',   '600',  '1-й сбой прокси: кулдаун, сек'),
 ('visaglobal', 'fault_cooldown2_s',        '3600', '2-й сбой прокси: кулдаун, сек'),
 ('visaglobal', 'fault_disable_count',      '3',    'сбой №N в окне -> карантин fault_quarantine_min'),
 ('visaglobal', 'fault_quarantine_min',     '240',  '3-й сбой: карантин, мин'),
 ('visaglobal', 'repeat_fault_window_min',  '300',  'окно подсчёта сбоев, мин')
on conflict (purpose, key) do nothing;

-- ---------- 2. Состояние прокси по цели -------------------------------------
create table if not exists bls_proxy_manager.proxy_purpose_state (
    proxy_id             text not null references bls_proxy_manager.proxies(id) on delete cascade,
    purpose              text not null,
    free_at              timestamptz not null default now(),
    quarantined_until    timestamptz,
    quarantine_reason    text,
    cooldown_reason      text,
    consecutive_failures integer not null default 0,
    fault_count          integer not null default 0,
    fault_first_at       timestamptz,
    last_fault_at        timestamptz,
    last_fault_code      text,
    last_used_at         timestamptz,
    last_ok_at           timestamptz,
    last_error_at        timestamptz,
    updated_at           timestamptz not null default now(),
    primary key (proxy_id, purpose)
);

-- ---------- 3. Ошибка по аренде другой цели ---------------------------------
create or replace function bls_proxy_manager.purpose_apply_error(p_proxy_id text, p_purpose text, p_code text)
returns void language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    s       proxy_purpose_state%rowtype;
    v_cnt   integer;
    v_first timestamptz;
    v_cd    integer;
    v_cons  integer;
    v_win   integer := pcfg_int(p_purpose, 'repeat_fault_window_min', 300);
    v_dis   integer := greatest(2, pcfg_int(p_purpose, 'fault_disable_count', 3));
begin
    insert into proxy_purpose_state(proxy_id, purpose) values (p_proxy_id, p_purpose)
    on conflict do nothing;
    select * into s from proxy_purpose_state where proxy_id = p_proxy_id and purpose = p_purpose for update;

    if p_code = any (pcfg_codes(p_purpose, 'proxy_fault_codes')) then
        -- прокси сам не пропускает трафик: ступени 10 мин -> 60 мин -> карантин
        if s.last_fault_at is not null and s.last_fault_at > now() - interval '20 seconds' then return; end if;
        if s.quarantined_until is not null and s.quarantined_until > now() then return; end if;

        if s.fault_first_at is null or s.fault_first_at < now() - make_interval(mins => v_win) then
            v_cnt := 1;  v_first := now();
        else
            v_cnt := s.fault_count + 1;  v_first := s.fault_first_at;
        end if;

        if v_cnt >= v_dis then
            update proxy_purpose_state
               set quarantined_until = now() + make_interval(mins => pcfg_int(p_purpose, 'fault_quarantine_min', 240)),
                   quarantine_reason = 'сбой №' || v_cnt || ' в окне, last: ' || p_code,
                   fault_count = v_cnt, fault_first_at = v_first,
                   last_fault_at = now(), last_fault_code = p_code,
                   last_error_at = now(), updated_at = now()
             where proxy_id = p_proxy_id and purpose = p_purpose;
            insert into proxy_events(proxy_id, event_type, error_code, detail)
            values (p_proxy_id, 'quarantined', p_code,
                    jsonb_build_object('purpose', p_purpose, 'reason', 'fault ladder', 'step', v_cnt));
        else
            v_cd := case when v_cnt <= 1 then pcfg_int(p_purpose, 'cooldown_proxy_fault_s', 600)
                         else pcfg_int(p_purpose, 'fault_cooldown2_s', 3600) end;
            update proxy_purpose_state
               set free_at = greatest(free_at, now() + make_interval(secs => v_cd)),
                   cooldown_reason = p_code || ' · сбой ' || v_cnt || '/' || v_dis || ' (кулдаун ' || (v_cd / 60) || ' мин)',
                   fault_count = v_cnt, fault_first_at = v_first,
                   last_fault_at = now(), last_fault_code = p_code,
                   last_error_at = now(), updated_at = now()
             where proxy_id = p_proxy_id and purpose = p_purpose;
        end if;
        insert into proxy_events(proxy_id, event_type, error_code, detail)
        values (p_proxy_id, 'fault_step', p_code,
                jsonb_build_object('purpose', p_purpose, 'step', v_cnt, 'of', v_dis));

    elsif p_code = any (pcfg_codes(p_purpose, 'proxy_error_codes')) then
        -- 403/429 и прочее: кулдаун, а при серии ошибок подряд — карантин
        v_cd := case when p_code = any (pcfg_codes(p_purpose, 'ban_error_codes'))
                     then pcfg_int(p_purpose, 'cooldown_ban_s', 900)
                     else pcfg_int(p_purpose, 'cooldown_error_s', 120) end;
        update proxy_purpose_state
           set consecutive_failures = consecutive_failures + 1,
               last_error_at = now(),
               free_at = greatest(free_at, now() + make_interval(secs => v_cd)),
               cooldown_reason = p_code || ' (кулдаун)',
               updated_at = now()
         where proxy_id = p_proxy_id and purpose = p_purpose
        returning consecutive_failures into v_cons;

        if v_cons >= pcfg_int(p_purpose, 'consec_fail_quarantine', 5) then
            update proxy_purpose_state
               set quarantined_until = now() + make_interval(mins => pcfg_int(p_purpose, 'quarantine_min', 30)),
                   quarantine_reason = 'consecutive errors, last: ' || p_code,
                   consecutive_failures = 0, updated_at = now()
             where proxy_id = p_proxy_id and purpose = p_purpose;
            insert into proxy_events(proxy_id, event_type, error_code, detail)
            values (p_proxy_id, 'quarantined', p_code,
                    jsonb_build_object('purpose', p_purpose, 'reason', 'consecutive errors'));
        end if;
    end if;
    -- прочие ошибки только в журнале
end $$;

-- ---------- 4. Выдача для другой цели ---------------------------------------
create or replace function bls_proxy_manager.acquire_proxies_purpose(
    p_account_id  text,
    p_count       integer,
    p_ttl_seconds integer,
    p_purpose     text,
    p_client_id   text,
    p_exclude     text[],
    p_replace     boolean
) returns table (
    lease_id uuid, proxy_id text, scheme text, host text, port integer,
    username text, password text, expires_at timestamptz
)
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
#variable_conflict use_column
declare
    v_bad text[] := pcfg_codes(p_purpose, 'proxy_error_codes');
begin
    -- тот же замок, что у BLS: max_leases общий для всех целей
    perform pg_advisory_xact_lock(hashtext('bls_proxy_acquire'));

    update leases l set released_at = now(), release_reason = 'expired'
     where l.released_at is null and l.expires_at <= now();

    if p_replace then
        update leases l set released_at = now(), release_reason = 'replaced'
         where l.account_id = p_account_id and l.purpose = p_purpose and l.released_at is null;
    end if;

    insert into proxy_purpose_state(proxy_id, purpose)
    select p.id, p_purpose from proxies p
     where p.enabled and p_purpose = any (p.purposes)
    on conflict do nothing;

    return query
    with cand as (
        select p.id
          from proxies p
          join proxy_purpose_state ps on ps.proxy_id = p.id and ps.purpose = p_purpose
          join proxy_state gs on gs.proxy_id = p.id
          left join (select l.proxy_id, count(*) n from leases l
                      where l.released_at is null group by l.proxy_id) u on u.proxy_id = p.id
         where p.enabled
           and p_purpose = any (p.purposes)
           and not (p.id = any (coalesce(p_exclude, '{}')))
           -- общий карантин: только пробер («прокси вообще не отвечает»)
           and (gs.quarantined_until is null or gs.quarantined_until <= now()
                or gs.quarantine_reason is distinct from 'probe failures')
           -- карантин и кулдаун именно этой цели
           and (ps.quarantined_until is null or ps.quarantined_until <= now())
           and ps.free_at <= now()
           and coalesce(u.n, 0) < p.max_leases
         order by
           exists (select 1 from proxy_events e
                    where e.account_id = p_account_id and e.proxy_id = p.id
                      and e.event_type = 'error' and e.created_at > now() - interval '1 hour'
                      and e.error_code = any (v_bad)),
           ps.last_used_at asc nulls first,
           random()
         limit p_count
    ), ins as (
        insert into leases (proxy_id, account_id, client_id, purpose, expires_at)
        select c.id, p_account_id, p_client_id, p_purpose, now() + make_interval(secs => p_ttl_seconds)
          from cand c
        returning leases.id, leases.proxy_id, leases.expires_at
    ), upd as (
        update proxy_purpose_state s set last_used_at = now(), updated_at = now()
          from ins where s.proxy_id = ins.proxy_id and s.purpose = p_purpose
        returning s.proxy_id
    )
    select ins.id, p.id, p.scheme, p.host, p.port, cr.username, cr.password, ins.expires_at
      from ins
      join proxies p on p.id = ins.proxy_id
      left join proxy_credentials cr on cr.proxy_id = p.id;
end $$;

create or replace function bls_proxy_manager.next_available_in_purpose(p_purpose text) returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare v_at timestamptz;
begin
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
     where p.enabled and p_purpose = any (p.purposes);

    if v_at is null then return 60; end if;
    return least(3600, greatest(1, ceil(extract(epoch from (v_at - now())))::integer));
end $$;

-- ---------- 5. Подправленные существующие функции (вставки помечены комментариями) ----------
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

    -- другие цели (visaglobal и т.п.): своя выдача и своё состояние; путь BLS ниже не меняется
    if coalesce(p_purpose, 'bls') <> 'bls' then
        return query select * from acquire_proxies_purpose(
            p_account_id, v_count, v_ttl, p_purpose, p_client_id, p_exclude, p_replace);
        return;
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
    if coalesce(p_purpose, 'bls') <> 'bls' then
        return next_available_in_purpose(p_purpose);
    end if;
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

    if l.purpose = 'bls' then
        update proxy_state
           set free_at = greatest(free_at, now() + make_interval(secs => cfg_int('cooldown_ok_s', 0))),
               updated_at = now()
         where proxy_id = l.proxy_id;
    else
        -- кулдаун только для этой цели: BLS-состояние прокси не трогаем
        insert into proxy_purpose_state(proxy_id, purpose) values (l.proxy_id, l.purpose)
        on conflict do nothing;
        update proxy_purpose_state
           set free_at = greatest(free_at, now() + make_interval(secs => pcfg_int(l.purpose, 'cooldown_ok_s', 0))),
               updated_at = now()
         where proxy_id = l.proxy_id and purpose = l.purpose;
    end if;

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
           and not exists (select 1 from leases l where l.id = e.lease_id and l.purpose <> 'bls')
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

    -- другие цели (visaglobal и т.п.): своё состояние, BLS не трогаем
    if l.purpose <> 'bls' then
        if p_event_type = 'cycle_ok' then
            insert into proxy_purpose_state(proxy_id, purpose) values (l.proxy_id, l.purpose)
            on conflict do nothing;
            update proxy_purpose_state
               set consecutive_failures = 0, fault_count = 0, fault_first_at = null,
                   last_ok_at = now(), updated_at = now()
             where proxy_id = l.proxy_id and purpose = l.purpose;
        elsif p_error_code is not null and not v_dup then
            perform purpose_apply_error(l.proxy_id, l.purpose, p_error_code);
        end if;
        return;
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

-- ---------- 6. Наблюдение и сброс -------------------------------------------
create or replace view bls_proxy_manager.v_purpose_status as
select ps.purpose, coalesce(p.pool, '-') as pool, p.id as proxy_id, p.enabled,
       case when not p.enabled then 'выключен'
            when ps.quarantined_until > now() then 'карантин'
            when exists (select 1 from bls_proxy_manager.leases l
                          where l.proxy_id = p.id and l.released_at is null and l.expires_at > now()) then 'занят'
            when ps.free_at > now() then 'кулдаун'
            else 'свободен' end as status,
       ps.free_at, ps.quarantined_until, ps.quarantine_reason, ps.cooldown_reason,
       ps.consecutive_failures, ps.fault_count, ps.last_ok_at, ps.last_used_at
  from bls_proxy_manager.proxy_purpose_state ps
  join bls_proxy_manager.proxies p on p.id = ps.proxy_id;

-- Создать недостающие строки состояния и обнулить кулдауны/карантины ЭТОЙ цели.
create or replace function bls_proxy_manager.admin_purpose_reset(p_purpose text) returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare n integer;
begin
    insert into proxy_purpose_state(proxy_id, purpose)
    select p.id, p_purpose from proxies p where p_purpose = any (p.purposes)
    on conflict do nothing;
    update proxy_purpose_state
       set free_at = now(), quarantined_until = null, quarantine_reason = null, cooldown_reason = null,
           consecutive_failures = 0, fault_count = 0, fault_first_at = null, updated_at = now()
     where purpose = p_purpose;
    get diagnostics n = row_count;
    insert into proxy_events(event_type, detail)
    values ('pool_run_reset', jsonb_build_object('purpose', p_purpose, 'source', 'admin_purpose_reset'));
    return n;
end $$;

-- ---------- 7. Права ---------------------------------------------------------
revoke all on function bls_proxy_manager.pcfg_int(text,text,integer)  from public, anon, authenticated;
revoke all on function bls_proxy_manager.pcfg_codes(text,text)        from public, anon, authenticated;
revoke all on function bls_proxy_manager.purpose_apply_error(text,text,text) from public, anon, authenticated;
revoke all on function bls_proxy_manager.acquire_proxies_purpose(text,integer,integer,text,text,text[],boolean) from public, anon, authenticated;
revoke all on function bls_proxy_manager.next_available_in_purpose(text) from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_purpose_reset(text)    from public, anon, authenticated;
revoke all on bls_proxy_manager.proxy_purpose_state from public, anon, authenticated;
revoke all on bls_proxy_manager.purpose_settings    from public, anon, authenticated;
revoke all on bls_proxy_manager.v_purpose_status    from public, anon, authenticated;
grant execute on function bls_proxy_manager.admin_purpose_reset(text) to bls_admin;
grant execute on function bls_proxy_manager.acquire_proxies(text,integer,integer,text,text,text[],boolean) to bls_issuer;
grant execute on function bls_proxy_manager.next_available_in(text) to bls_issuer;
grant execute on function bls_proxy_manager.release_lease(uuid,text,text,text,jsonb) to bls_reporter;
grant execute on function bls_proxy_manager.report_event(uuid,text,text,text,integer,jsonb) to bls_reporter;
grant execute on function bls_proxy_manager.evaluate_cross_account_health() to bls_issuer;

reset search_path;

-- ---------- Как включить VisaGlobal на прокси (пример: 30 прокси пула) ----------
-- update bls_proxy_manager.proxies
--    set purposes = (select array_agg(distinct x order by x) from unnest(purposes || array['visaglobal']) x)
--  where id in (select id from bls_proxy_manager.proxies
--                where pool = 'Proxysoxy_17.10.2026_100' and 'bls' = any(purposes) order by random() limit 30);
-- select bls_proxy_manager.admin_purpose_reset('visaglobal');   -- создаст строки состояния
-- select status, count(*) from bls_proxy_manager.v_purpose_status where purpose = 'visaglobal' group by 1;
