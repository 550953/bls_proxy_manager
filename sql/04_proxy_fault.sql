-- 04_proxy_fault.sql — миграция для УЖЕ установленной базы (Supabase SQL Editor).
-- Безопасно запускать повторно.  Свежая установка получает то же из 00_full_install.sql.
--
-- Что делает:
--  * прокси, который сам не пропускает трафик (PROXY_CONNECT_FAILED и др.), получает
--    кулдаун cooldown_proxy_fault_s (по умолчанию 1 час) и НЕ выдаётся никому;
--  * если тот же прокси сбоит ещё раз в окне repeat_fault_window_min (любые аккаунты) —
--    карантин 60 -> 120 -> 240 минут.
set search_path = bls_proxy_manager, pg_temp;

-- 1) Новые настройки (существующие значения не трогаем).
insert into settings(key, value, note) values
 ('proxy_fault_codes',        '["PROXY_CONNECT_FAILED","PROXY_TIMEOUT","ERR_PROXY_CONNECTION_FAILED","ERR_TUNNEL_CONNECTION_FAILED"]',
                              'подмножество proxy_error_codes: прокси сам не пропускает трафик (долгий кулдаун; повтор -> карантин)'),
 ('cooldown_proxy_fault_s',   '3600', 'пауза прокси после proxy_fault_codes, сек'),
 ('repeat_fault_window_min',  '180',  'окно подсчёта повторных proxy_fault_codes на одном прокси'),
 ('repeat_fault_count',       '2',    'столько ошибок в окне (от любых аккаунтов) -> карантин'),
 ('repeat_fault_quarantine_min','60', 'база карантина за повтор, удваивается по уровню (60,120,240; потолок quarantine_max_min)')
on conflict (key) do nothing;

-- 2) Коды proxy_fault_codes должны входить в proxy_error_codes (иначе сервер их игнорирует).
--    Добавляем недостающие, не затирая ваши правки списка.
update settings
   set value = (select to_jsonb(array(
                  select distinct c
                    from jsonb_array_elements_text(
                           settings.value || '["PROXY_CONNECT_FAILED","PROXY_TIMEOUT","ERR_PROXY_CONNECTION_FAILED","ERR_TUNNEL_CONNECTION_FAILED"]'::jsonb) c
                   order by c)))
 where key = 'proxy_error_codes';

-- 3) Функции.
create or replace function quarantine_proxy_min(p_proxy_id text, p_reason text, p_base_min integer) returns void
language plpgsql set search_path = bls_proxy_manager, pg_temp as $$
declare v_done integer;
begin
    update proxy_state
       set quarantined_until = now() + make_interval(mins =>
               least(cfg_int('quarantine_max_min', 240),
                     greatest(1, coalesce(p_base_min, 60)) * power(2, least(quarantine_level, 10))::integer)),
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
    v_fault boolean;
    v_rep  integer;
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
        -- «прокси сам не пропускает трафик» (SOCKS/connect/timeout) — долгая пауза
        v_fault := p_error_code = any (cfg_codes('proxy_fault_codes'));
        v_cool := case when p_error_code = any (cfg_codes('ban_error_codes'))
                       then cfg_int('cooldown_ban_s', 900)
                       when v_fault
                       then cfg_int('cooldown_proxy_fault_s', cfg_int('cooldown_error_s', 120))
                       else cfg_int('cooldown_error_s', 120) end;
        update proxy_state
           set consecutive_failures = consecutive_failures + 1,
               last_error_at = now(),
               free_at = greatest(free_at, now() + make_interval(secs => v_cool)),
               updated_at = now()
         where proxy_id = l.proxy_id
        returning consecutive_failures into v_cons;

        -- Тот же прокси сбоил повторно за короткий срок (от любых аккаунтов) — карантин.
        if v_fault then
            select count(*) into v_rep
              from proxy_events e
             where e.proxy_id = l.proxy_id
               and e.event_type = 'error'
               and e.error_code = any (cfg_codes('proxy_fault_codes'))
               and e.created_at > now() - make_interval(mins => cfg_int('repeat_fault_window_min', 180));
            if v_rep >= cfg_int('repeat_fault_count', 2) then
                perform quarantine_proxy_min(
                    l.proxy_id,
                    'repeat proxy fault x' || v_rep || ', last: ' || p_error_code,
                    cfg_int('repeat_fault_quarantine_min', 60));
            end if;
        end if;

        if v_cons >= cfg_int('consec_fail_quarantine', 5) then
            perform quarantine_proxy(l.proxy_id, 'consecutive errors, last: ' || p_error_code);
        end if;
    end if;
    -- прочие ошибки (логин, Selenium, CDP...) только логируются: прокси не виноват
end $$;

-- 4) Проверка.
select key, value from settings
 where key in ('proxy_error_codes','proxy_fault_codes','cooldown_proxy_fault_s',
               'repeat_fault_window_min','repeat_fault_count','repeat_fault_quarantine_min');
