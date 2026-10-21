-- Откат 22: возвращает purpose_apply_error версии 21 и убирает проверку/подтверждение.
drop function if exists bls_proxy_manager.purpose_fault_verdict(text, text, text, jsonb);
drop function if exists bls_proxy_manager.purpose_fault_job(text, text);
create or replace function bls_proxy_manager.purpose_apply_error(p_proxy_id text, p_purpose text, p_code text)
returns text language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    d        error_codes%rowtype;
    s        proxy_purpose_state%rowtype;
    v_code   text := upper(btrim(coalesce(p_code, '')));
    v_win    integer := pcfg_int(p_purpose, 'ip_escalate_window_min', 120);
    v_max    integer := pcfg_int(p_purpose, 'ip_cooldown_max_s', 3600);
    v_anchor timestamptz;
    v_n      integer;
    v_acc    integer;
    v_cd     integer;
begin
    if not exists (select 1 from error_codes where purpose = p_purpose) then
        perform purpose_apply_error_legacy(p_proxy_id, p_purpose, p_code);
        return 'legacy';
    end if;

    select * into d from error_codes where purpose = p_purpose and code = v_code;
    if not found then return 'log:unknown_code'; end if;      -- неизвестный код никого не банит
    if d.cooldown_s <= 0 then return 'log:' || d.blame; end if;

    insert into proxy_purpose_state(proxy_id, purpose) values (p_proxy_id, p_purpose)
    on conflict do nothing;
    select * into s from proxy_purpose_state where proxy_id = p_proxy_id and purpose = p_purpose for update;

    if s.quarantined_until is not null and s.quarantined_until > now() then
        return 'already_quarantined';
    end if;

    -- серия: ошибки IP этой цели после последнего успеха, в окне; по разным арендам
    v_anchor := greatest(now() - make_interval(mins => v_win),
                         coalesce(s.last_ok_at, '-infinity'::timestamptz));
    select count(distinct e.lease_id), count(distinct e.account_id) into v_n, v_acc
      from proxy_events e join leases l on l.id = e.lease_id
     where e.proxy_id = p_proxy_id and l.purpose = p_purpose
       and e.event_type = 'error' and e.created_at > v_anchor
       and upper(e.error_code) = any (select c.code from error_codes c
                                       where c.purpose = p_purpose and c.cooldown_s > 0);
    v_n := greatest(coalesce(v_n, 0), 1);

    if d.quarantine_ok
       and v_n   >= pcfg_int(p_purpose, 'ip_quarantine_count', 4)
       and v_acc >= pcfg_int(p_purpose, 'ip_quarantine_accounts', 2) then
        update proxy_purpose_state
           set quarantined_until = now() + make_interval(mins => pcfg_int(p_purpose, 'quarantine_min', 30)),
               quarantine_reason = v_code || ' x' || v_n || ' (аккаунтов: ' || v_acc || ')',
               last_error_at = now(), updated_at = now()
         where proxy_id = p_proxy_id and purpose = p_purpose;
        insert into proxy_events(proxy_id, event_type, error_code, detail)
        values (p_proxy_id, 'quarantined', v_code,
                jsonb_build_object('purpose', p_purpose, 'reason', 'repeat', 'n', v_n, 'accounts', v_acc));
        return 'quarantine';
    end if;

    v_cd := least(v_max, d.cooldown_s * (1 << least(v_n - 1, 10)));
    update proxy_purpose_state
       set consecutive_failures = consecutive_failures + 1,
           last_error_at = now(),
           free_at = greatest(free_at, now() + make_interval(secs => v_cd)),
           cooldown_reason = v_code || ' (кулдаун ' || v_cd || ' с, повтор ' || v_n || ')',
           updated_at = now()
     where proxy_id = p_proxy_id and purpose = p_purpose;
    return 'cooldown:' || v_cd;
end $$;
revoke all on function bls_proxy_manager.purpose_apply_error(text, text, text) from public, anon, authenticated;
delete from bls_proxy_manager.purpose_settings where purpose='visaglobal' and key='ip_unconfirmed_cooldown_s';
alter table bls_proxy_manager.proxy_purpose_state drop column if exists fault_verdict;
alter table bls_proxy_manager.proxy_purpose_state drop column if exists fault_snapshot;
alter table bls_proxy_manager.error_codes drop column if exists needs_confirm;
alter table bls_proxy_manager.error_codes drop column if exists probe;
