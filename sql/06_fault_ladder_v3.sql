-- =============================================================================
-- 06_fault_ladder_v3.sql — лестница "вариант А" (3 ступени) + усиленная проверка BLS
-- Накатывать ПОСЛЕ 05_fault_ladder.sql. Безопасно запускать повторно.
--
--   1-й сбой в окне -> кулдаун 10 мин   (cooldown_proxy_fault_s)
--   2-й сбой в окне -> кулдаун 60 мин   (fault_cooldown2_s)       [карантин больше не используется]
--   3-й сбой в окне -> выключено (auto_disabled) до «Сбросить ступени» / «Включить»
--
-- После КАЖДОГО сбоя сервис пула сам делает TCP-CONNECT до BLS через этот прокси:
--   на ступенях 2 и 3 — до site_check_attempts попыток с паузой (ловим короткие сбои ДЦ);
--   прошёл (transient) или BLS недоступен напрямую (site_down) -> ступень откатывается («прощён»);
--   не прошёл, а BLS напрямую открывается (proxy_dead) -> наказание остаётся.
-- Карантин пробера (probe failures) и 403/429 не затронуты.
-- =============================================================================
do $$ begin
    if not exists (select 1 from information_schema.columns
                    where table_schema='bls_proxy_manager' and table_name='proxy_state' and column_name='fault_snapshot') then
        raise exception 'Сначала накатите 05_fault_ladder.sql';
    end if;
end $$;

set search_path = bls_proxy_manager, pg_temp;

-- ---------- 1. Настройки ----------------------------------------------------
insert into bls_proxy_manager.settings(key, value, note) values
 ('fault_cooldown2_s',   '3600', '2-й сбой прокси: кулдаун, сек'),
 ('fault_disable_count', '3',    'сбой №N в окне -> выключить до сброса'),
 ('site_check_attempts', '3',    'попыток TCP до BLS на ступенях 2 и 3 (с паузой)')
on conflict (key) do nothing;

-- окно должно покрывать всю лестницу (клиент сам держит плохой прокси 60/120 мин)
update bls_proxy_manager.settings set value = to_jsonb(300) where key = 'repeat_fault_window_min';
update bls_proxy_manager.settings set note = '1-й сбой прокси: кулдаун, сек' where key = 'cooldown_proxy_fault_s';

-- ---------- 2. Ступени ------------------------------------------------------
create or replace function bls_proxy_manager.apply_proxy_fault(p_proxy_id text, p_code text) returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    s       proxy_state%rowtype;
    v_snap  jsonb;
    v_cnt   integer;
    v_first timestamptz;
    v_win   integer := cfg_int('repeat_fault_window_min', 300);
    v_dis   integer := greatest(2, cfg_int('fault_disable_count', 3));
    v_cd    integer;
begin
    select * into s from proxy_state where proxy_id = p_proxy_id for update;
    if not found then return; end if;

    -- дубль одного и того же сбоя (report + release одной аренды)
    if s.last_fault_at is not null and s.last_fault_at > now() - interval '20 seconds' then return; end if;
    -- уже выключен или в карантине пробера — ничего не добавляем
    if s.auto_disabled then return; end if;
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

    if v_cnt >= v_dis then
        -- ступень 3: выключено
        update proxies set enabled = false where id = p_proxy_id;
        update leases set released_at = now(), release_reason = 'auto_disabled'
         where proxy_id = p_proxy_id and released_at is null;
        update proxy_state
           set fault_count     = v_cnt,
               fault_first_at  = v_first,
               auto_disabled   = true,
               disabled_reason = 'сбой №' || v_cnt || ' в окне, last: ' || p_code,
               last_fault_at   = now(),
               last_fault_code = p_code,
               fault_verdict   = null,
               fault_snapshot  = v_snap,
               last_error_at   = now(),
               updated_at      = now()
         where proxy_id = p_proxy_id;
        insert into proxy_events(proxy_id, event_type, error_code, detail)
        values (p_proxy_id, 'auto_disabled', p_code, jsonb_build_object('step', v_cnt, 'of', v_dis));
        insert into proxy_events(proxy_id, event_type, error_code, detail)
        values (p_proxy_id, 'fault_step', p_code, jsonb_build_object('step', v_cnt, 'of', v_dis, 'action', 'disabled'));
    else
        -- ступени 1 и 2: кулдаун (10 мин, затем 60 мин)
        v_cd := case when v_cnt <= 1 then cfg_int('cooldown_proxy_fault_s', 600)
                     else cfg_int('fault_cooldown2_s', 3600) end;
        update proxy_state
           set free_at          = greatest(free_at, now() + make_interval(secs => v_cd)),
               cooldown_reason  = p_code || ' · сбой ' || v_cnt || '/' || v_dis || ' (кулдаун ' || (v_cd / 60) || ' мин)',
               fault_count      = v_cnt,
               fault_first_at   = v_first,
               last_fault_at    = now(),
               last_fault_code  = p_code,
               fault_verdict    = null,
               fault_snapshot   = v_snap,
               last_error_at    = now(),
               updated_at       = now()
         where proxy_id = p_proxy_id;
        insert into proxy_events(proxy_id, event_type, error_code, detail)
        values (p_proxy_id, 'fault_step', p_code,
                jsonb_build_object('step', v_cnt, 'of', v_dis, 'action', 'cooldown', 'cooldown_s', v_cd));
    end if;
end $$;

-- ---------- 3. Задание на проверку BLS: число попыток зависит от ступени ----
drop function if exists bls_proxy_manager.fault_probe_job(text);
create function bls_proxy_manager.fault_probe_job(p_proxy_id text)
returns table (proxy_id text, scheme text, host text, port integer, username text, password text,
               fault_count integer, attempts integer)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select p.id, p.scheme, p.host, p.port, cr.username, cr.password,
           ps.fault_count,
           case when ps.fault_count >= 2
                then greatest(1, least(5, cfg_int('site_check_attempts', 3)))
                else 1 end
      from proxies p
      join proxy_state ps on ps.proxy_id = p.id
      left join proxy_credentials cr on cr.proxy_id = p.id
     where p.id = p_proxy_id
       and ps.last_fault_at > now() - interval '8 minutes'
       and ps.fault_verdict is null
       and cfg_int('site_check_enabled', 1) = 1
$$;

-- ---------- 4. Админ: белый список настроек --------------------------------
create or replace function bls_proxy_manager.admin_get_settings() returns table (key text, value text, note text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select s.key, s.value #>> '{}', s.note from settings s
     where s.key in ('cooldown_ok_s','cooldown_proxy_fault_s','fault_cooldown2_s','fault_disable_count',
                     'repeat_fault_window_min','fault_soft_cooldown_s','site_check_enabled','site_check_attempts')
     order by s.key
$$;

create or replace function bls_proxy_manager.admin_set_setting(p_key text, p_value text) returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
begin
    if p_key not in ('cooldown_ok_s','cooldown_proxy_fault_s','fault_cooldown2_s','fault_disable_count',
                     'repeat_fault_window_min','fault_soft_cooldown_s','site_check_enabled','site_check_attempts') then
        raise exception 'key not allowed: %', p_key;
    end if;
    if p_value !~ '^[0-9]{1,6}$' then raise exception 'integer 0..999999 expected'; end if;
    update settings set value = to_jsonb(p_value::integer) where key = p_key;
    if not found then raise exception 'unknown key %', p_key; end if;
end $$;

-- ---------- 5. Аудит: что и почему сделала лестница -------------------------
create or replace view bls_proxy_manager.v_fault_audit as
select p.id as proxy_id, p.pool, p.enabled, ps.auto_disabled,
       ps.fault_count, ps.fault_verdict, ps.last_fault_code, ps.last_fault_at,
       ps.free_at, ps.cooldown_reason, ps.disabled_reason, ps.last_probe_ok,
       (select count(*) from proxy_events e where e.proxy_id = p.id and e.event_type = 'fault_step'      and e.created_at > now() - interval '24 hours') as steps_24h,
       (select count(*) from proxy_events e where e.proxy_id = p.id and e.event_type = 'fault_confirmed' and e.created_at > now() - interval '24 hours') as confirmed_24h,
       (select count(*) from proxy_events e where e.proxy_id = p.id and e.event_type = 'fault_forgiven'  and e.created_at > now() - interval '24 hours') as forgiven_24h
  from proxies p
  join proxy_state ps on ps.proxy_id = p.id
 where ps.last_fault_at is not null;

-- ---------- 6. Права ---------------------------------------------------------
revoke all on function bls_proxy_manager.apply_proxy_fault(text,text) from public, anon, authenticated;
revoke all on function bls_proxy_manager.fault_probe_job(text)        from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_get_settings()         from public, anon, authenticated;
revoke all on function bls_proxy_manager.admin_set_setting(text,text) from public, anon, authenticated;
grant execute on function bls_proxy_manager.fault_probe_job(text)        to bls_prober;
grant execute on function bls_proxy_manager.admin_get_settings()         to bls_admin;
grant execute on function bls_proxy_manager.admin_set_setting(text,text) to bls_admin;
revoke all on bls_proxy_manager.v_fault_audit from public, anon, authenticated;

reset search_path;

-- Проверка: 3 новых ключа + окно 300
select key, value #>> '{}' as value from bls_proxy_manager.settings
 where key in ('cooldown_proxy_fault_s','fault_cooldown2_s','fault_disable_count','repeat_fault_window_min','site_check_attempts')
 order by key;
