-- 21_ROLLBACK.sql — вернуть состояние до 21_visaglobal_policy.sql (функции как в 13/00 и живой базе на 21.10.2026).
-- Таблица error_codes и колонки proxy_events.blame/verdict остаются (они ничего не ломают); удалить: см. конец файла.
begin;
-- purpose_apply_error: вернуть прежнюю реализацию (void)
drop function if exists bls_proxy_manager.purpose_apply_error(text, text, text);
alter function bls_proxy_manager.purpose_apply_error_legacy(text, text, text) rename to purpose_apply_error;

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

-- renew_lease
create or replace function bls_proxy_manager.renew_lease(p_lease_id uuid, p_ttl_seconds integer default 300)
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

-- account_needs_reset (как было)
create or replace function bls_proxy_manager.account_needs_reset(p_account_id text)
returns boolean language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    v_thr    integer := cfg_int('account_reset_count', 3);
    v_win    integer := cfg_int('account_reset_window_min', 30);
    v_anchor timestamptz;
    v_n      integer;
begin
    if v_thr <= 0 or p_account_id is null then return false; end if;
    select greatest(now() - make_interval(mins => v_win),
                    coalesce(max(e.created_at), '-infinity'::timestamptz))
      into v_anchor
      from proxy_events e
     where e.account_id = p_account_id and e.event_type in ('profile_reset', 'cycle_ok');
    select count(distinct e.proxy_id) into v_n
      from proxy_events e
     where e.account_id = p_account_id and e.event_type = 'error'
       and e.created_at > v_anchor
       and e.error_code = any (cfg_codes('account_reset_codes'));
    if v_n < v_thr then return false; end if;
    if not exists (select 1 from proxy_events e
                    where e.account_id = p_account_id and e.event_type = 'reset_requested'
                      and e.created_at > v_anchor) then
        insert into proxy_events(account_id, event_type, detail)
        values (p_account_id, 'reset_requested', jsonb_build_object('distinct_proxies', v_n));
    end if;
    return true;
end $$;

-- настройки: вернуть cooldown_ok_s как было
update bls_proxy_manager.purpose_settings set value = to_jsonb(300) where purpose='visaglobal' and key='cooldown_ok_s';
delete from bls_proxy_manager.purpose_settings
 where purpose='visaglobal' and key in ('max_lease_total_s','ip_escalate_window_min','ip_cooldown_max_s','ip_quarantine_count','ip_quarantine_accounts');
commit;
-- полное удаление (по желанию):
--   drop table bls_proxy_manager.error_codes;
--   alter table bls_proxy_manager.proxy_events drop column blame, drop column verdict;
