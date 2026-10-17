-- =============================================================================
-- 05_fault_ladder.sql — ступени наказания для битых прокси + проверка BLS
-- Схема: bls_proxy_manager (все имена ниже с префиксом схемы, ничего не уедет в public).
-- Куда: Supabase -> SQL Editor -> вставить целиком -> Run. Безопасно запускать повторно.
-- 04_proxy_fault.sql ПРОПУСТИТЬ: этот файл его полностью заменяет.
--
-- Лестница при PROXY_CONNECT_FAILED / PROXY_TIMEOUT / ERR_*:
--   1-й сбой           -> кулдаун 10 мин  (cooldown_proxy_fault_s = 600)
--   2-й сбой в окне    -> карантин 60 мин (fault_quarantine_min)
--   2-й карантин за    -> enabled=false (auto_disabled) до рестарта сервиса пула
--   запуск пула           или до ручного «Включить»
-- Проверка BLS: сразу после сбоя сервис делает TCP-CONNECT через этот прокси на
-- appointment.blsspainrussia.ru:443 (без логина и без TLS). Прошёл или сам BLS лежит
-- -> наказание откатывается (прокси «прощён»). Не прошёл, а BLS с сервера доступен
-- -> прокси признан мёртвым, наказание остаётся.
-- =============================================================================

do $$
begin
    if not exists (select 1 from pg_namespace where nspname = 'bls_proxy_manager') then
        raise exception 'Схема bls_proxy_manager не найдена — сначала накатите 00_full_install.sql';
    end if;
end $$;

set search_path = bls_proxy_manager, pg_temp;

-- ---------- 1. Колонки -------------------------------------------------------
alter table bls_proxy_manager.proxy_state
    add column if not exists fault_count      integer     not null default 0,
    add column if not exists fault_first_at   timestamptz,
    add column if not exists quarantine_runs  integer     not null default 0,   -- карантинов за запуск пула
    add column if not exists cooldown_reason  text,
    add column if not exists last_fault_at    timestamptz,
    add column if not exists last_fault_code  text,
    add column if not exists fault_verdict    text,                              -- null=ждёт проверки | proxy_dead | site_down | transient
    add column if not exists fault_snapshot   jsonb,
    add column if not exists auto_disabled    boolean     not null default false,
    add column if not exists disabled_reason  text;

-- ---------- 2. Настройки -----------------------------------------------------
-- Эти ключи задаём принудительно (в т.ч. перебиваем 3600 из 04):
insert into bls_proxy_manager.settings(key, value, note) values
 ('cooldown_proxy_fault_s',          '600',  '1-й сбой прокси: кулдаун, сек'),
 ('fault_quarantine_min',            '60',   '2-й сбой в окне: карантин, мин'),
 ('repeat_fault_window_min',         '180',  'окно подсчёта сбоев одного прокси, мин'),
 ('repeat_fault_count',              '2',    'сбой №N в окне -> карантин'),
 ('fault_disable_after_quarantines', '2',    'N-й карантин за запуск пула -> выключено (enabled=false)'),
 ('fault_soft_cooldown_s',           '60',   'кулдаун после «прощения» (BLS TCP прошёл / сайт лежит), сек'),
 ('site_check_enabled',              '1',    '1 = после сбоя проверять TCP до BLS, 0 = не проверять'),
 ('proxy_fault_codes',
  '["PROXY_CONNECT_FAILED","PROXY_TIMEOUT","ERR_PROXY_CONNECTION_FAILED","ERR_TUNNEL_CONNECTION_FAILED"]',
  'коды «прокси сам не пропускает трафик»')
on conflict (key) do update set value = excluded.value, note = excluded.note;

-- proxy_fault_codes должны входить в proxy_error_codes
update bls_proxy_manager.settings
   set value = (select to_jsonb(array(
                  select distinct c from jsonb_array_elements_text(
                      settings.value || '["PROXY_CONNECT_FAILED","PROXY_TIMEOUT","ERR_PROXY_CONNECTION_FAILED","ERR_TUNNEL_CONNECTION_FAILED"]'::jsonb) c
                  order by c)))
 where key = 'proxy_error_codes';

-- ---------- 3. Ступени -------------------------------------------------------
create or replace function bls_proxy_manager.apply_proxy_fault(p_proxy_id text, p_code text) returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    s       proxy_state%rowtype;
    v_snap  jsonb;
    v_cnt   integer;
    v_first timestamptz;
    v_win   integer := cfg_int('repeat_fault_window_min', 180);
begin
    select * into s from proxy_state where proxy_id = p_proxy_id for update;
    if not found then return; end if;

    -- тот же сбой пришёл дважды подряд (report + release одной аренды) — не эскалируем
    if s.last_fault_at is not null and s.last_fault_at > now() - interval '20 seconds' then return; end if;
    -- уже в карантине — ничего не добавляем
    if s.quarantined_until is not null and s.quarantined_until > now() then return; end if;

    v_snap := jsonb_build_object(
        'fault_count',       s.fault_count,
        'fault_first_at',    s.fault_first_at,
        'quarantine_runs',   s.quarantine_runs,
        'quarantined_until', s.quarantined_until,
        'quarantine_reason', s.quarantine_reason,
        'cooldown_reason',   s.cooldown_reason,
        'free_at',           s.free_at);

    if s.fault_first_at is null or s.fault_first_at < now() - make_interval(mins => v_win) then
        v_cnt := 1;  v_first := now();
    else
        v_cnt := s.fault_count + 1;  v_first := s.fault_first_at;
    end if;

    if v_cnt < cfg_int('repeat_fault_count', 2) then
        -- ступень 1: кулдаун
        update proxy_state
           set free_at          = greatest(free_at, now() + make_interval(secs => cfg_int('cooldown_proxy_fault_s', 600))),
               cooldown_reason  = p_code || ' · сбой ' || v_cnt || ' (кулдаун)',
               fault_count      = v_cnt,
               fault_first_at   = v_first,
               last_fault_at    = now(),
               last_fault_code  = p_code,
               fault_verdict    = null,
               fault_snapshot   = v_snap,
               last_error_at    = now(),
               updated_at       = now()
         where proxy_id = p_proxy_id;

    elsif s.quarantine_runs + 1 >= cfg_int('fault_disable_after_quarantines', 2) then
        -- ступень 3: выключено до рестарта пула
        update proxies set enabled = false where id = p_proxy_id;
        update leases set released_at = now(), release_reason = 'auto_disabled'
         where proxy_id = p_proxy_id and released_at is null;
        update proxy_state
           set quarantine_runs  = quarantine_runs + 1,
               fault_count      = 0,
               fault_first_at   = null,
               auto_disabled    = true,
               disabled_reason  = 'карантин №' || (quarantine_runs + 1) || ' за запуск, last: ' || p_code,
               last_fault_at    = now(),
               last_fault_code  = p_code,
               fault_verdict    = null,
               fault_snapshot   = v_snap,
               last_error_at    = now(),
               updated_at       = now()
         where proxy_id = p_proxy_id;
        insert into proxy_events(proxy_id, event_type, error_code, detail)
        values (p_proxy_id, 'auto_disabled', p_code, jsonb_build_object('quarantine_runs', s.quarantine_runs + 1));

    else
        -- ступень 2: карантин
        update proxy_state
           set quarantined_until = now() + make_interval(mins => cfg_int('fault_quarantine_min', 60)),
               quarantine_reason = 'сбой x' || v_cnt || ' в окне, last: ' || p_code,
               quarantine_runs   = quarantine_runs + 1,
               fault_count       = 0,
               fault_first_at    = null,
               consecutive_failures = 0,
               probe_failures    = 0,
               last_fault_at     = now(),
               last_fault_code   = p_code,
               fault_verdict     = null,
               fault_snapshot    = v_snap,
               last_error_at     = now(),
               updated_at        = now()
         where proxy_id = p_proxy_id;
        insert into proxy_events(proxy_id, event_type, error_code, detail)
        values (p_proxy_id, 'quarantined', p_code,
                jsonb_build_object('reason', 'proxy fault x' || v_cnt, 'quarantine_runs', s.quarantine_runs + 1));
    end if;
end $$;

-- ---------- 4. report_event: сбои прокси идут через лестницу ----------------
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
               fault_count = 0,
               fault_first_at = null,
               last_ok_at = now(),
               quarantine_level = case when quarantined_until is null
                                         or quarantined_until < now() - interval '1 hour'
                                       then 0 else quarantine_level end,
               updated_at = now()
         where proxy_id = l.proxy_id;

    elsif p_error_code = any (cfg_codes('proxy_fault_codes')) then
        -- прокси сам не пропускает трафик: лестница кулдаун -> карантин -> выключено
        perform apply_proxy_fault(l.proxy_id, p_error_code);

    elsif p_error_code = any (cfg_codes('proxy_error_codes')) then
        -- 403/429 и прочее прокси-класса: как раньше
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
    -- прочие ошибки (логин, Selenium, CDP...) только логируются
end $$;

-- ---------- 5. Проверка BLS после сбоя --------------------------------------
-- какой прокси проверять по аренде (reporter знает только lease_id)
create or replace function bls_proxy_manager.lease_proxy(p_lease_id uuid) returns text
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$ select proxy_id from leases where id = p_lease_id $$;

-- данные прокси для проверки: только если сбой свежий и вердикта ещё нет
create or replace function bls_proxy_manager.fault_probe_job(p_proxy_id text)
returns table (proxy_id text, scheme text, host text, port integer, username text, password text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select p.id, p.scheme, p.host, p.port, cr.username, cr.password
      from proxies p
      join proxy_state ps on ps.proxy_id = p.id
      left join proxy_credentials cr on cr.proxy_id = p.id
     where p.id = p_proxy_id
       and ps.last_fault_at > now() - interval '5 minutes'
       and ps.fault_verdict is null
       and cfg_int('site_check_enabled', 1) = 1
$$;

create or replace function bls_proxy_manager.fault_verdict(p_proxy_id text, p_verdict text, p_detail jsonb default '{}'::jsonb)
returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    s    proxy_state%rowtype;
    snap jsonb;
begin
    if p_verdict not in ('proxy_dead','site_down','transient') then
        raise exception 'bad verdict %', p_verdict;
    end if;
    select * into s from proxy_state where proxy_id = p_proxy_id for update;
    if not found or s.fault_verdict is not null
       or s.last_fault_at is null or s.last_fault_at < now() - interval '10 minutes' then
        return;
    end if;
    snap := s.fault_snapshot;

    if p_verdict = 'proxy_dead' or snap is null then
        update proxy_state set fault_verdict = 'proxy_dead', updated_at = now() where proxy_id = p_proxy_id;
        insert into proxy_events(proxy_id, event_type, error_code, detail)
        values (p_proxy_id, 'fault_confirmed', s.last_fault_code, coalesce(p_detail, '{}'::jsonb));
        return;
    end if;

    -- «простить»: вернуть счётчики/карантин к состоянию до сбоя, короткая пауза
    update proxy_state
       set fault_count       = coalesce((snap->>'fault_count')::integer, 0),
           fault_first_at    = (snap->>'fault_first_at')::timestamptz,
           quarantine_runs   = coalesce((snap->>'quarantine_runs')::integer, 0),
           quarantined_until = (snap->>'quarantined_until')::timestamptz,
           quarantine_reason = snap->>'quarantine_reason',
           free_at           = now() + make_interval(secs => cfg_int('fault_soft_cooldown_s', 60)),
           cooldown_reason   = case p_verdict when 'site_down' then 'BLS недоступен — прощён'
                                              else 'TCP до BLS прошёл — прощён' end,
           auto_disabled     = false,
           disabled_reason   = null,
           fault_verdict     = p_verdict,
           updated_at        = now()
     where proxy_id = p_proxy_id;
    if s.auto_disabled then
        update proxies set enabled = true where id = p_proxy_id;
    end if;
    insert into proxy_events(proxy_id, event_type, error_code, detail)
    values (p_proxy_id, 'fault_forgiven', s.last_fault_code,
            jsonb_build_object('verdict', p_verdict) || coalesce(p_detail, '{}'::jsonb));
end $$;

-- ---------- 6. Рестарт пула: сброс ступеней ----------------------------------
create or replace function bls_proxy_manager.admin_reset_run() returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare n integer;
begin
    update proxies p set enabled = true
      from proxy_state s where s.proxy_id = p.id and s.auto_disabled;
    get diagnostics n = row_count;
    update proxy_state
       set quarantine_runs = 0, fault_count = 0, fault_first_at = null,
           auto_disabled = false, disabled_reason = null, updated_at = now()
     where quarantine_runs > 0 or fault_count > 0 or auto_disabled;
    insert into proxy_events(event_type, detail)
    values ('pool_run_reset', jsonb_build_object('re_enabled', n));
    return n;
end $$;

-- ---------- 7. Админ-функции (дашборд) ---------------------------------------
create or replace function bls_proxy_manager.admin_set_enabled(p_ids text[], p_enabled boolean) returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare n integer;
begin
    update proxies set enabled = p_enabled where id = any (p_ids);
    get diagnostics n = row_count;
    if p_enabled then
        update proxy_state set auto_disabled = false, disabled_reason = null,
               quarantine_runs = 0, fault_count = 0, fault_first_at = null, updated_at = now()
         where proxy_id = any (p_ids);
    else
        update leases set released_at = now(), release_reason = 'admin_disabled'
         where proxy_id = any (p_ids) and released_at is null;
    end if;
    return n;
end $$;

create or replace function bls_proxy_manager.admin_clear_quarantine(p_ids text[]) returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare n integer;
begin
    update proxy_state
       set quarantined_until = null, quarantine_reason = null, quarantine_level = 0,
           consecutive_failures = 0, probe_failures = 0, free_at = now(),
           fault_count = 0, fault_first_at = null, quarantine_runs = 0,
           cooldown_reason = null, updated_at = now()
     where proxy_id = any (p_ids);
    get diagnostics n = row_count;
    return n;
end $$;

-- тип возврата меняется -> drop (права вернём ниже)
drop function if exists bls_proxy_manager.admin_list_proxies();
create function bls_proxy_manager.admin_list_proxies()
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
           ps.quarantined_until, ps.quarantine_reason, ps.free_at,
           ps.consecutive_failures, ps.probe_failures,
           ps.last_ok_at, ps.last_error_at,
           ps.last_probe_ok, ps.last_latency_ms,
           coalesce(u.n, 0), u.accts,
           ps.fault_count, ps.quarantine_runs, ps.cooldown_reason,
           ps.auto_disabled, ps.disabled_reason, ps.last_fault_code, ps.fault_verdict
      from proxies p
      join proxy_state ps on ps.proxy_id = p.id
      left join proxy_credentials cr on cr.proxy_id = p.id
      left join (select l.proxy_id, count(*)::integer n, array_agg(l.account_id order by l.account_id) accts
                   from leases l where l.released_at is null and l.expires_at > now()
                  group by l.proxy_id) u on u.proxy_id = p.id
     order by p.pool nulls last, p.id
$$;

-- настройки для дашборда (белый список ключей)
create or replace function bls_proxy_manager.admin_get_settings() returns table (key text, value text, note text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select s.key, s.value #>> '{}', s.note from settings s
     where s.key in ('cooldown_ok_s','cooldown_proxy_fault_s','fault_quarantine_min',
                     'repeat_fault_count','repeat_fault_window_min','fault_disable_after_quarantines',
                     'fault_soft_cooldown_s','site_check_enabled')
     order by s.key
$$;

create or replace function bls_proxy_manager.admin_set_setting(p_key text, p_value text) returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
begin
    if p_key not in ('cooldown_ok_s','cooldown_proxy_fault_s','fault_quarantine_min',
                     'repeat_fault_count','repeat_fault_window_min','fault_disable_after_quarantines',
                     'fault_soft_cooldown_s','site_check_enabled') then
        raise exception 'key not allowed: %', p_key;
    end if;
    if p_value !~ '^[0-9]{1,6}$' then raise exception 'integer 0..999999 expected'; end if;
    update settings set value = to_jsonb(p_value::integer) where key = p_key;
    if not found then raise exception 'unknown key %', p_key; end if;
end $$;

-- ---------- 8. Права ---------------------------------------------------------
revoke all on function bls_proxy_manager.apply_proxy_fault(text,text)            from public, anon, authenticated;
revoke all on function bls_proxy_manager.lease_proxy(uuid)                       from public, anon, authenticated;
revoke all on function bls_proxy_manager.fault_probe_job(text)                   from public, anon, authenticated;
revoke all on function bls_proxy_manager.fault_verdict(text,text,jsonb)          from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_reset_run()                       from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_list_proxies()                    from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_get_settings()                    from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_set_setting(text,text)            from public, anon, authenticated;

grant execute on function bls_proxy_manager.lease_proxy(uuid)                    to bls_reporter;
grant execute on function bls_proxy_manager.fault_probe_job(text)                to bls_prober;
grant execute on function bls_proxy_manager.fault_verdict(text,text,jsonb)       to bls_prober;
grant execute on function bls_proxy_manager.admin_list_proxies()                 to bls_admin;
grant execute on function bls_proxy_manager.admin_reset_run()                    to bls_admin;
grant execute on function bls_proxy_manager.admin_get_settings()                 to bls_admin;
grant execute on function bls_proxy_manager.admin_set_setting(text,text)         to bls_admin;

reset search_path;

-- ---------- 9. Проверка (должна вернуть 8 настроек и 10 новых колонок) -------
select key, value #>> '{}' as value from bls_proxy_manager.settings
 where key in ('cooldown_proxy_fault_s','fault_quarantine_min','repeat_fault_window_min','repeat_fault_count',
               'fault_disable_after_quarantines','fault_soft_cooldown_s','site_check_enabled','cooldown_ok_s')
 order by 1;
select count(*) as new_columns from information_schema.columns
 where table_schema = 'bls_proxy_manager' and table_name = 'proxy_state'
   and column_name in ('fault_count','fault_first_at','quarantine_runs','cooldown_reason','last_fault_at',
                       'last_fault_code','fault_verdict','fault_snapshot','auto_disabled','disabled_reason');
