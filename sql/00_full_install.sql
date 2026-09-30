-- =============================================================================
-- bls_proxy_manager — ПОЛНАЯ УСТАНОВКА ОДНИМ ФАЙЛОМ (Supabase / Postgres 15+)
--
-- Что внутри:
--   1. Роли bls_issuer / bls_reporter / bls_prober (без паролей)
--   2. Таблицы: proxies, proxy_credentials, proxy_state, probe_targets,
--      proxy_probe_stats, leases, proxy_events, settings
--   3. Функции (все SECURITY DEFINER, search_path зафиксирован):
--      acquire_proxies, next_available_in, renew_lease, report_event,
--      release_lease, close_expired_leases, evaluate_cross_account_health,
--      record_probe, select_probe_target, probe_batch
--   4. View v_pool_summary
--   5. RLS: включён на ВСЕХ таблицах, политик для anon/authenticated нет = deny.
--   6. Права: сначала revoke всего у public/anon/authenticated, затем точечные grant.
--
-- Запуск: SQL Editor -> вставить целиком -> Run. Идемпотентно (кроме смены
-- типов возврата функций: тогда drop schema ... cascade и накатить заново).
-- После: задать пароли ролям (внизу) и добавить прокси (внизу, шаблон).
-- НЕ добавляй схему bls_proxy_manager в "Exposed schemas" (Settings -> API).
-- =============================================================================

-- drop schema if exists bls_proxy_manager cascade;   -- чистая переустановка

create schema if not exists bls_proxy_manager;

-- ============================ 1. РОЛИ ========================================
do $$
declare r text;
begin
    foreach r in array array['bls_issuer','bls_reporter','bls_prober'] loop
        if not exists (select 1 from pg_roles where rolname = r) then
            execute format('create role %I login noinherit nosuperuser nocreatedb nocreaterole nobypassrls', r);
        end if;
    end loop;
end $$;

alter role bls_issuer   connection limit 10;
alter role bls_reporter connection limit 10;
alter role bls_prober   connection limit 10;
alter role bls_issuer   set statement_timeout = '10s';
alter role bls_reporter set statement_timeout = '10s';
alter role bls_prober   set statement_timeout = '15s';
alter role bls_issuer   set idle_in_transaction_session_timeout = '15s';
alter role bls_reporter set idle_in_transaction_session_timeout = '15s';
alter role bls_prober   set idle_in_transaction_session_timeout = '30s';

-- ============================ 2. ТАБЛИЦЫ =====================================
set search_path = bls_proxy_manager, pg_temp;

create table if not exists probe_targets (
    id              integer generated always as identity primary key,
    url             text not null unique,
    expected_status integer not null default 200,
    enabled         boolean not null default true,
    created_at      timestamptz not null default now()
);

create table if not exists proxies (
    id          text primary key,                              -- 'proxy6-01', 'megafon-msk-2'
    scheme      text not null default 'http'
                check (scheme in ('http','https','socks5','socks5h')),
    host        text not null,
    port        integer not null check (port between 1 and 65535),
    kind        text not null default 'shared'
                check (kind in ('shared','dedicated','mobile')),
    pool        text,                                          -- логическая группа (proxy6-shared-1 и т.п.)
    purposes    text[] not null default '{bls}',
    max_leases  integer not null default 1 check (max_leases >= 1),  -- одновременных аренд
    enabled     boolean not null default true,
    note        text,
    created_at  timestamptz not null default now()
);

-- Пароли отдельно: эту таблицу не читает никто, кроме security definer функций.
create table if not exists proxy_credentials (
    proxy_id  text primary key references proxies(id) on delete cascade,
    username  text,
    password  text
);

create table if not exists proxy_state (
    proxy_id             text primary key references proxies(id) on delete cascade,
    free_at              timestamptz not null default now(),   -- кулдаун: раньше не выдаём
    quarantined_until    timestamptz,
    quarantine_reason    text,
    quarantine_level     integer not null default 0,           -- эскалация 5,10,20... мин
    consecutive_failures integer not null default 0,           -- ошибки ботов подряд
    probe_failures       integer not null default 0,           -- ошибки пробера подряд
    last_used_at         timestamptz,
    last_ok_at           timestamptz,
    last_error_at        timestamptz,
    last_probe_at        timestamptz,
    last_probe_ok        boolean,
    last_latency_ms      integer,
    probe_target_id      integer references probe_targets(id) on delete set null,
    updated_at           timestamptz not null default now()
);

create table if not exists proxy_probe_stats (
    proxy_id         text not null references proxies(id) on delete cascade,
    target_id        integer not null references probe_targets(id) on delete cascade,
    ok_count         integer not null default 0,
    fail_count       integer not null default 0,
    consecutive_fail integer not null default 0,
    ewma_latency_ms  real,
    last_ok          boolean,
    last_probed_at   timestamptz,
    primary key (proxy_id, target_id)
);

create table if not exists leases (
    id             uuid primary key default gen_random_uuid(),
    proxy_id       text not null references proxies(id) on delete cascade,
    account_id     text not null,
    client_id      text,
    purpose        text not null,
    acquired_at    timestamptz not null default now(),
    expires_at     timestamptz not null,
    released_at    timestamptz,
    release_reason text
);
create index if not exists leases_active_proxy   on leases (proxy_id)   where released_at is null;
create index if not exists leases_active_account on leases (account_id, purpose) where released_at is null;
create index if not exists leases_active_expiry  on leases (expires_at) where released_at is null;

create table if not exists proxy_events (
    id         bigint generated always as identity primary key,
    created_at timestamptz not null default now(),
    lease_id   uuid,
    proxy_id   text,
    account_id text,
    event_type text not null,      -- cycle_ok | error | released | quarantined | global_wave
    error_code text,
    phase      text,
    latency_ms integer,
    detail     jsonb not null default '{}'::jsonb
);
create index if not exists proxy_events_proxy   on proxy_events (proxy_id, created_at desc);
create index if not exists proxy_events_account on proxy_events (account_id, proxy_id, created_at desc);
create index if not exists proxy_events_time    on proxy_events (created_at);

create table if not exists settings (
    key   text primary key,
    value jsonb not null,
    note  text
);

-- state-строка создаётся автоматически при добавлении прокси
create or replace function proxies_after_insert() returns trigger
language plpgsql set search_path = bls_proxy_manager, pg_temp as $$
begin
    insert into proxy_state(proxy_id) values (new.id) on conflict do nothing;
    return new;
end $$;

drop trigger if exists trg_proxies_after_insert on proxies;
create trigger trg_proxies_after_insert after insert on proxies
    for each row execute function proxies_after_insert();

insert into proxy_state(proxy_id) select id from proxies on conflict do nothing;

-- ============================ 3. НАСТРОЙКИ / СИДЫ ============================
insert into settings(key, value, note) values
 ('cooldown_ok_s',            '0',    'пауза прокси после нормального release'),
 ('cooldown_error_s',         '120',  'пауза после ошибки прокси-класса'),
 ('cooldown_ban_s',           '900',  'пауза после 403/429'),
 ('proxy_error_codes',        '["HTTP_403","HTTP_429","PROXY_CONNECT_FAILED","PROXY_TIMEOUT","ERR_PROXY_CONNECTION_FAILED","ERR_TUNNEL_CONNECTION_FAILED"]',
                              'ошибки, которые считаются виной прокси. LOGIN_PASSWORD_NOT_FOUND, SELENIUM_*, CDP_* сюда НЕ входят. Сверь имена с кодами бота!'),
 ('ban_error_codes',         '["HTTP_403","HTTP_429"]', 'подмножество: длинный кулдаун'),
 ('xacct_window_min',         '15',   'окно кросс-аккаунтной оценки'),
 ('xacct_min_accounts',       '2',    'мин. разных аккаунтов с ошибками на одном прокси'),
 ('xacct_min_errors',         '3',    'мин. ошибок на прокси в окне'),
 ('global_wave_min_proxies',  '3',    'если столько прокси «виноваты» одновременно...'),
 ('global_wave_share_pct',    '50',   '...и это >= % включённых прокси -> общее событие (WAF/IP), карантин не ставим'),
 ('consec_fail_quarantine',   '5',    'ошибок подряд без cycle_ok -> карантин'),
 ('probe_fail_quarantine',    '3',    'провалов пробера подряд -> карантин'),
 ('quarantine_base_min',      '5',    'база карантина, удваивается по уровню'),
 ('quarantine_max_min',       '240',  'потолок карантина'),
 ('probe_interval_min',       '5',    'как часто пинговать один прокси'),
 ('events_retention_days',    '14',   'хранение proxy_events')
on conflict (key) do nothing;

-- Нейтральные таргеты. Пинговать сам сайт BLS не стоит — лишний шанс бана IP.
insert into probe_targets(url, expected_status) values
 ('https://www.gstatic.com/generate_204', 204),
 ('https://connectivitycheck.gstatic.com/generate_204', 204),
 ('https://www.cloudflare.com/cdn-cgi/trace', 200)
on conflict (url) do nothing;

-- ============================ 4. ВНУТРЕННИЕ ХЕЛПЕРЫ ===========================
create or replace function cfg_int(p_key text, p_default integer) returns integer
language sql stable set search_path = bls_proxy_manager, pg_temp as $$
    select coalesce((select (s.value #>> '{}')::integer from settings s where s.key = p_key), p_default)
$$;

create or replace function cfg_codes(p_key text) returns text[]
language sql stable set search_path = bls_proxy_manager, pg_temp as $$
    select coalesce(
        (select array(select jsonb_array_elements_text(s.value)) from settings s where s.key = p_key),
        '{}'::text[])
$$;

create or replace function quarantine_proxy(p_proxy_id text, p_reason text) returns void
language plpgsql set search_path = bls_proxy_manager, pg_temp as $$
declare v_done integer;
begin
    update proxy_state
       set quarantined_until = now() + make_interval(mins =>
               least(cfg_int('quarantine_max_min', 240),
                     cfg_int('quarantine_base_min', 5) * power(2, least(quarantine_level, 10))::integer)),
           quarantine_reason = p_reason,
           quarantine_level  = quarantine_level + 1,
           consecutive_failures = 0,
           probe_failures = 0,
           updated_at = now()
     where proxy_id = p_proxy_id
       and (quarantined_until is null or quarantined_until <= now());
    get diagnostics v_done = row_count;
    if v_done > 0 then
        insert into proxy_events(proxy_id, event_type, detail)
        values (p_proxy_id, 'quarantined', jsonb_build_object('reason', p_reason));
    end if;
end $$;

-- ============================ 5. ВЫДАЧА ======================================
create or replace function acquire_proxies(
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

-- Через сколько секунд появится хоть один подходящий прокси (для retry_after_seconds)
create or replace function next_available_in(p_purpose text default 'bls') returns integer
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

create or replace function renew_lease(p_lease_id uuid, p_ttl_seconds integer default 300)
returns timestamptz
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare v timestamptz;
begin
    update leases l
       set expires_at = now() + make_interval(secs => least(greatest(coalesce(p_ttl_seconds,300),30),3600))
     where l.id = p_lease_id and l.released_at is null and l.expires_at > now()
    returning l.expires_at into v;
    return v;   -- null -> сервис отдаёт 409
end $$;

-- ============================ 6. ФИДБЕК ОТ БОТОВ =============================
create or replace function report_event(
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
    l      leases%rowtype;
    v_cons integer;
    v_cool integer;
begin
    if p_event_type not in ('cycle_ok','error') then
        raise exception 'bad event_type %', p_event_type;
    end if;
    select * into l from leases where id = p_lease_id;
    if not found then raise exception 'unknown lease %', p_lease_id; end if;

    insert into proxy_events(lease_id, proxy_id, account_id, event_type, error_code, phase, latency_ms, detail)
    values (l.id, l.proxy_id, l.account_id, p_event_type, p_error_code, p_phase, p_latency_ms,
            coalesce(p_detail, '{}'::jsonb));

    if p_event_type = 'cycle_ok' then
        update proxy_state
           set consecutive_failures = 0,
               last_ok_at = now(),
               quarantine_level = case when quarantined_until is null
                                         or quarantined_until < now() - interval '1 hour'
                                       then 0 else quarantine_level end,
               updated_at = now()
         where proxy_id = l.proxy_id;

    elsif p_error_code = any (cfg_codes('proxy_error_codes')) then
        v_cool := case when p_error_code = any (cfg_codes('ban_error_codes'))
                       then cfg_int('cooldown_ban_s', 900)
                       else cfg_int('cooldown_error_s', 120) end;
        update proxy_state
           set consecutive_failures = consecutive_failures + 1,
               last_error_at = now(),
               free_at = greatest(free_at, now() + make_interval(secs => v_cool)),
               updated_at = now()
         where proxy_id = l.proxy_id
        returning consecutive_failures into v_cons;

        if v_cons >= cfg_int('consec_fail_quarantine', 5) then
            perform quarantine_proxy(l.proxy_id, 'consecutive errors, last: ' || p_error_code);
        end if;
    end if;
    -- прочие ошибки (логин, Selenium, CDP...) только логируются: прокси не виноват
end $$;

create or replace function release_lease(
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

-- ============================ 7. КРОН ========================================
create or replace function close_expired_leases() returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare n integer;
begin
    with c as (
        update leases l set released_at = now(), release_reason = 'expired'
         where l.released_at is null and l.expires_at <= now()
        returning 1)
    select count(*) into n from c;

    delete from proxy_events
     where created_at < now() - make_interval(days => cfg_int('events_retention_days', 14));
    delete from leases
     where released_at is not null and released_at < now() - interval '30 days';
    return n;
end $$;

-- Карантин, если один и тот же прокси ловит прокси-ошибки от НЕСКОЛЬКИХ аккаунтов.
-- Если «виноватых» сразу слишком много — это общее событие (WAF/IP-волна 403), а не
-- поломка прокси: карантин не ставим, пишем global_wave.
create or replace function evaluate_cross_account_health() returns integer
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

-- ============================ 8. ПРОБЕР ======================================
create or replace function probe_batch(p_limit integer default 20)
returns table (
    proxy_id text, scheme text, host text, port integer,
    username text, password text,
    bound_target integer, candidate_ids integer[]
)
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
#variable_conflict use_column
begin
    return query
    select p.id, p.scheme, p.host, p.port, cr.username, cr.password,
           ps.probe_target_id,
           case when ps.probe_target_id is null then
               (select array_agg(pt.id) from (
                   select t.id from probe_targets t where t.enabled order by random() limit 3) pt)
           end
      from proxies p
      join proxy_state ps on ps.proxy_id = p.id
      left join proxy_credentials cr on cr.proxy_id = p.id
     where p.enabled
       and (ps.quarantined_until is null or ps.quarantined_until <= now())
       and (ps.last_probe_at is null
            or ps.last_probe_at < now() - make_interval(mins => cfg_int('probe_interval_min', 5)))
     order by ps.last_probe_at asc nulls first
     limit greatest(1, least(coalesce(p_limit, 20), 50));
end $$;

create or replace function record_probe(
    p_proxy_id text, p_target_id integer, p_ok boolean, p_latency_ms integer
) returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    v_consec       integer;
    v_target_down  boolean;
    v_pf           integer;
begin
    insert into proxy_probe_stats as s
           (proxy_id, target_id, ok_count, fail_count, consecutive_fail, ewma_latency_ms, last_ok, last_probed_at)
    values (p_proxy_id, p_target_id,
            case when p_ok then 1 else 0 end,
            case when p_ok then 0 else 1 end,
            case when p_ok then 0 else 1 end,
            case when p_ok then p_latency_ms end,
            p_ok, now())
    on conflict (proxy_id, target_id) do update set
        ok_count         = s.ok_count   + case when p_ok then 1 else 0 end,
        fail_count       = s.fail_count + case when p_ok then 0 else 1 end,
        consecutive_fail = case when p_ok then 0 else s.consecutive_fail + 1 end,
        ewma_latency_ms  = case when p_ok and p_latency_ms is not null
                                then coalesce(s.ewma_latency_ms * 0.7 + p_latency_ms * 0.3, p_latency_ms)
                                else s.ewma_latency_ms end,
        last_ok          = p_ok,
        last_probed_at   = now()
    returning s.consecutive_fail into v_consec;

    -- если сам таргет лежит (фейлится на >=3 других прокси за 5 мин) — вины прокси нет
    v_target_down := (not p_ok) and (
        select count(*) from proxy_probe_stats o
         where o.target_id = p_target_id and o.proxy_id <> p_proxy_id
           and o.last_ok = false and o.last_probed_at > now() - interval '5 minutes') >= 3;

    update proxy_state
       set last_probe_at   = now(),
           last_probe_ok   = p_ok,
           last_latency_ms = case when p_ok and p_latency_ms is not null then p_latency_ms else last_latency_ms end,
           probe_failures  = case when p_ok then 0
                                  when v_target_down then probe_failures
                                  else probe_failures + 1 end,
           -- привязанный таргет начал падать -> отвязать, пусть выберется заново
           probe_target_id = case when not p_ok and v_consec >= 2 and probe_target_id = p_target_id
                                  then null else probe_target_id end,
           updated_at      = now()
     where proxy_id = p_proxy_id
    returning probe_failures into v_pf;

    if v_pf >= cfg_int('probe_fail_quarantine', 3) then
        perform quarantine_proxy(p_proxy_id, 'probe failures');
    end if;
end $$;

-- Лучший таргет для прокси: живой с минимальной сглаженной задержкой
create or replace function select_probe_target(p_proxy_id text) returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare v integer;
begin
    select s.target_id into v
      from proxy_probe_stats s
      join probe_targets t on t.id = s.target_id and t.enabled
     where s.proxy_id = p_proxy_id and s.ok_count > 0 and s.last_ok
     order by s.ewma_latency_ms asc nulls last
     limit 1;

    update proxy_state set probe_target_id = v, updated_at = now() where proxy_id = p_proxy_id;
    return v;
end $$;

-- ============================ 9. VIEW ========================================
-- Владелец-view (security definer по умолчанию): issuer читает сводку без прав на таблицы.
create or replace view v_pool_summary as
select p.kind,
       coalesce(p.pool, '-') as pool,
       count(*) filter (where p.enabled) as enabled,
       count(*) filter (where p.enabled and ps.quarantined_until > now()) as quarantined,
       count(*) filter (where p.enabled and (ps.quarantined_until is null or ps.quarantined_until <= now())
                          and ps.free_at > now()) as cooling,
       count(*) filter (where p.enabled and coalesce(u.n,0) >= p.max_leases) as full,
       count(*) filter (where p.enabled and (ps.quarantined_until is null or ps.quarantined_until <= now())
                          and ps.free_at <= now() and coalesce(u.n,0) < p.max_leases) as available
  from proxies p
  join proxy_state ps on ps.proxy_id = p.id
  left join (select l.proxy_id, count(*) n from leases l
              where l.released_at is null and l.expires_at > now() group by l.proxy_id) u on u.proxy_id = p.id
 group by p.kind, coalesce(p.pool, '-');

-- ============================ 10. RLS ========================================
-- Включаем везде. Политик для anon/authenticated нет -> доступа нет даже при утечке
-- grant'а. Владелец (postgres) и SECURITY DEFINER функции RLS обходят.
alter table probe_targets     enable row level security;
alter table proxies           enable row level security;
alter table proxy_credentials enable row level security;
alter table proxy_state       enable row level security;
alter table proxy_probe_stats enable row level security;
alter table leases            enable row level security;
alter table proxy_events      enable row level security;
alter table settings          enable row level security;

-- Единственный прямой доступ к таблице: пробер читает список таргетов (кэш в сервисе)
drop policy if exists prober_read_targets on probe_targets;
create policy prober_read_targets on probe_targets
    for select to bls_prober using (enabled);

-- ============================ 11. ПРАВА ======================================
-- Сначала снимаем всё (в т.ч. дефолтные грант'ы Supabase для anon/authenticated),
-- потом выдаём минимум.
do $$
declare r text;
begin
    foreach r in array array['anon','authenticated'] loop
        if exists (select 1 from pg_roles where rolname = r) then
            execute format('revoke all on schema bls_proxy_manager from %I', r);
            execute format('revoke all on all tables    in schema bls_proxy_manager from %I', r);
            execute format('revoke all on all sequences in schema bls_proxy_manager from %I', r);
            execute format('revoke all on all functions in schema bls_proxy_manager from %I', r);
        end if;
    end loop;
end $$;

revoke all on schema bls_proxy_manager from public;
revoke all on all tables    in schema bls_proxy_manager from public;
revoke all on all sequences in schema bls_proxy_manager from public;
revoke all on all functions in schema bls_proxy_manager from public;

revoke all on schema bls_proxy_manager from bls_issuer, bls_reporter, bls_prober;
revoke all on all tables    in schema bls_proxy_manager from bls_issuer, bls_reporter, bls_prober;
revoke all on all sequences in schema bls_proxy_manager from bls_issuer, bls_reporter, bls_prober;
revoke all on all functions in schema bls_proxy_manager from bls_issuer, bls_reporter, bls_prober;

alter default privileges in schema bls_proxy_manager revoke execute on functions from public;

grant usage on schema bls_proxy_manager to bls_issuer, bls_reporter, bls_prober;

-- issuer: выдача + продление + /health + крон
grant execute on function acquire_proxies(text,integer,integer,text,text,text[],boolean) to bls_issuer;
grant execute on function next_available_in(text)                                       to bls_issuer;
grant execute on function renew_lease(uuid,integer)                                     to bls_issuer;
grant execute on function close_expired_leases()                                        to bls_issuer;
grant execute on function evaluate_cross_account_health()                               to bls_issuer;
grant select  on v_pool_summary                                                         to bls_issuer;

-- reporter: только фидбек по уже выданному lease_id
grant execute on function report_event(uuid,text,text,text,integer,jsonb)               to bls_reporter;
grant execute on function release_lease(uuid,text,text,text,jsonb)                      to bls_reporter;

-- prober: пароли только через probe_batch(); таблицы — только probe_targets (+RLS-политика)
grant execute on function probe_batch(integer)                                          to bls_prober;
grant execute on function record_probe(text,integer,boolean,integer)                    to bls_prober;
grant execute on function select_probe_target(text)                                     to bls_prober;
grant select  on probe_targets                                                          to bls_prober;

-- ============================ 12. ПОСЛЕ ЗАПУСКА ===============================
-- 12.1 Пароли ролям (сгенерируй длинные случайные, храни в .env сервиса):
--   alter role bls_issuer   password '...';
--   alter role bls_reporter password '...';
--   alter role bls_prober   password '...';
--
-- 12.2 Добавить прокси (пример):
--   insert into bls_proxy_manager.proxies(id, scheme, host, port, kind, pool, max_leases)
--   values ('proxy6-01','http','1.2.3.4',8000,'shared','proxy6-shared-1',1);
--   insert into bls_proxy_manager.proxy_credentials(proxy_id, username, password)
--   values ('proxy6-01','user','pass');
--   -- мобильный: kind='mobile', max_leases=1
--
-- 12.3 Быстрая проверка выдачи:
--   select * from bls_proxy_manager.acquire_proxies('acc01');
--   select * from bls_proxy_manager.v_pool_summary;

reset search_path;

-- Итог: RLS должен быть true у всех таблиц схемы
select c.relname as table_name, c.relrowsecurity as rls_enabled
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'bls_proxy_manager' and c.relkind = 'r'
 order by 1;
