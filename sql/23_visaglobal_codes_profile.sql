-- 23: VisaGlobal — блоки 1-3 ТЗ: алиасы кодов, новые коды, подтверждение по профилю, ответ клиенту.
-- Зависит от 21 и 22. Откат: 23_ROLLBACK.sql (берёт определения функций из _fn_backup_23).
set local lock_timeout = '5s';

-- Копия определений, которые меняем (для отката)
create table if not exists bls_proxy_manager._fn_backup_23 as
select p.proname, pg_get_functiondef(p.oid) as def
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'bls_proxy_manager'
   and p.proname in ('report_event', 'release_lease', 'purpose_apply_error');
revoke all on bls_proxy_manager._fn_backup_23 from public, anon, authenticated;

-- Новые коды
insert into bls_proxy_manager.error_codes(purpose, code, blame, cooldown_s, reset_profile, quarantine_ok, note, needs_confirm, probe) values
 ('visaglobal','CAPTCHA_UNSOLVED', 'site',    0,   false, false, 'Turnstile не решился: IP не трогаем', false, false),
 ('visaglobal','CAPTCHA_EXPIRED',  'site',    0,   false, false, 'токен капчи протух: IP не трогаем',   false, false),
 ('visaglobal','PROFILE_BROKEN',   'profile', 0,   true,  false, 'профиль мусорный: сброс профиля, IP не трогаем', false, false),
 ('visaglobal','VFS_EMPTY_403201', 'profile', 900, true,  false, 'пустой ответ 403201: сброс профиля, IP на подтверждение', true, false),
 ('visaglobal','AUTH_ISSUE',       'account', 0,   false, false, 'проблема аккаунта без уточнения: IP не трогаем', false, false)
on conflict (purpose, code) do nothing;

-- Алиасы: чужие и новые имена кодов -> канонические
create table if not exists bls_proxy_manager.error_aliases (
    purpose text not null,
    alias   text not null,
    code    text not null,
    primary key (purpose, alias),
    foreign key (purpose, code) references bls_proxy_manager.error_codes(purpose, code)
);
revoke all on bls_proxy_manager.error_aliases from public, anon, authenticated;
insert into bls_proxy_manager.error_aliases(purpose, alias, code) values
 ('visaglobal','PROXY_DEAD',    'NET_PROXY_DEAD'),
 ('visaglobal','PROXY_AUTH',    'NET_PROXY_AUTH'),
 ('visaglobal','IP_BLOCKED',    'CF_BLOCK'),
 ('visaglobal','SITE_ERROR',    'VFS_5XX'),
 ('visaglobal','ACCOUNT_ISSUE', 'AUTH_ISSUE')
on conflict (purpose, alias) do nothing;

create or replace function bls_proxy_manager.error_code_resolve(p_purpose text, p_code text)
returns text language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select coalesce(
        (select c.code from error_codes c
          where c.purpose = p_purpose and c.code = upper(btrim(coalesce(p_code, '')))),
        (select a.code from error_aliases a
          where a.purpose = p_purpose and a.alias = upper(btrim(coalesce(p_code, '')))),
        'UNKNOWN')
$$;
revoke all on function bls_proxy_manager.error_code_resolve(text, text) from public, anon, authenticated;

-- Применение кода к IP: повторы считаются по профилям, подтверждение = 2 чистых профиля или 2 аккаунта
create or replace function bls_proxy_manager.purpose_apply_error(p_proxy_id text, p_purpose text, p_code text)
returns text language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    d        error_codes%rowtype;
    s        proxy_purpose_state%rowtype;
    v_code   text;
    v_win    integer := pcfg_int(p_purpose, 'ip_escalate_window_min', 120);
    v_max    integer := pcfg_int(p_purpose, 'ip_cooldown_max_s', 3600);
    v_anchor timestamptz;
    v_n      integer;
    v_conf   integer;
    v_acc    integer;
    v_cd     integer;
    v_snap   jsonb;
    v_confirmed boolean;
begin
    if not exists (select 1 from error_codes where purpose = p_purpose) then
        perform purpose_apply_error_legacy(p_proxy_id, p_purpose, p_code);
        return 'legacy';
    end if;
    v_code := error_code_resolve(p_purpose, p_code);
    select * into d from error_codes where purpose = p_purpose and code = v_code;
    if not found then return 'log:unknown_code'; end if;
    if d.cooldown_s <= 0 then return 'log:' || d.blame; end if;

    insert into proxy_purpose_state(proxy_id, purpose) values (p_proxy_id, p_purpose)
    on conflict do nothing;
    select * into s from proxy_purpose_state where proxy_id = p_proxy_id and purpose = p_purpose for update;

    if s.quarantined_until is not null and s.quarantined_until > now() then
        return 'already_quarantined';
    end if;

    v_anchor := greatest(now() - make_interval(mins => v_win),
                         coalesce(s.last_ok_at, '-infinity'::timestamptz));
    select count(distinct coalesce(e.detail->>'profile_id', e.lease_id::text)),
           count(distinct coalesce(e.detail->>'profile_id', e.lease_id::text))
               filter (where coalesce(e.detail->>'profile_fresh', 'true') <> 'false'),
           count(distinct e.account_id)
      into v_n, v_conf, v_acc
      from proxy_events e join leases l on l.id = e.lease_id
     where e.proxy_id = p_proxy_id and l.purpose = p_purpose
       and e.event_type = 'error' and e.created_at > v_anchor
       and upper(e.error_code) = any (select c.code from error_codes c
                                       where c.purpose = p_purpose and c.cooldown_s > 0);
    v_n := greatest(coalesce(v_n, 0), 1);
    v_confirmed := coalesce(v_conf, 0) >= 2 or coalesce(v_acc, 0) >= 2;

    if d.probe then
        if s.fault_verdict is not null or s.last_fault_at is null or s.last_fault_at < now() - interval '8 minutes' then
            v_snap := jsonb_build_object('free_at', s.free_at, 'quarantined_until', s.quarantined_until,
                                         'quarantine_reason', s.quarantine_reason, 'cooldown_reason', s.cooldown_reason,
                                         'consecutive_failures', s.consecutive_failures);
        else
            v_snap := s.fault_snapshot;
        end if;
    end if;

    if d.quarantine_ok
       and v_n   >= pcfg_int(p_purpose, 'ip_quarantine_count', 4)
       and v_acc >= pcfg_int(p_purpose, 'ip_quarantine_accounts', 2) then
        update proxy_purpose_state
           set quarantined_until = now() + make_interval(mins => pcfg_int(p_purpose, 'quarantine_min', 30)),
               quarantine_reason = v_code || ' x' || v_n || ' (аккаунтов: ' || v_acc || ')',
               last_error_at = now(), updated_at = now(),
               fault_snapshot = case when d.probe then v_snap else fault_snapshot end,
               fault_verdict  = case when d.probe then null  else fault_verdict  end,
               last_fault_at  = case when d.probe then now() else last_fault_at  end,
               last_fault_code= case when d.probe then v_code else last_fault_code end
         where proxy_id = p_proxy_id and purpose = p_purpose;
        insert into proxy_events(proxy_id, event_type, error_code, detail)
        values (p_proxy_id, 'quarantined', v_code,
                jsonb_build_object('purpose', p_purpose, 'reason', 'repeat', 'n', v_n, 'accounts', v_acc));
        return 'quarantine';
    end if;

    if d.needs_confirm and not v_confirmed then
        v_cd := least(d.cooldown_s, pcfg_int(p_purpose, 'ip_unconfirmed_cooldown_s', 120));
    else
        v_cd := least(v_max, d.cooldown_s * (1 << least(greatest(v_n - case when d.needs_confirm then 2 else 1 end, 0), 10)));
    end if;
    update proxy_purpose_state
       set consecutive_failures = consecutive_failures + 1,
           last_error_at = now(),
           free_at = greatest(free_at, now() + make_interval(secs => v_cd)),
           cooldown_reason = v_code || ' (кулдаун ' || v_cd || ' с, профилей ' || v_n
                             || case when d.needs_confirm and not v_confirmed then ', не подтверждён' else '' end || ')',
           updated_at = now(),
           fault_snapshot = case when d.probe then v_snap else fault_snapshot end,
           fault_verdict  = case when d.probe then null  else fault_verdict  end,
           last_fault_at  = case when d.probe then now() else last_fault_at  end,
           last_fault_code= case when d.probe then v_code else last_fault_code end
     where proxy_id = p_proxy_id and purpose = p_purpose;
    return 'cooldown:' || v_cd || case when d.needs_confirm and not v_confirmed then ':unconfirmed' else '' end;
end $$;
revoke all on function bls_proxy_manager.purpose_apply_error(text, text, text) from public, anon, authenticated;

-- report_event: код приводится к каноническому (для задач со справочником), сырое значение уходит в detail.raw_code
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
    l         leases%rowtype;
    v_cons    integer;
    v_cool    integer;
    v_id      bigint;
    v_dup     boolean := false;
    v_verdict text;
    v_code    text := p_error_code;
    v_det     jsonb := coalesce(p_detail, '{}'::jsonb);
begin
    if p_event_type not in ('cycle_ok','error','info','warn') then
        raise exception 'bad event_type %', p_event_type;
    end if;
    select * into l from leases where id = p_lease_id;
    if not found then raise exception 'unknown lease %', p_lease_id; end if;

    if l.purpose <> 'bls' and p_error_code is not null
       and exists (select 1 from error_codes where purpose = l.purpose) then
        v_code := error_code_resolve(l.purpose, p_error_code);
        if upper(btrim(p_error_code)) <> v_code then
            v_det := v_det || jsonb_build_object('raw_code', p_error_code);
        end if;
    end if;

    insert into proxy_events(lease_id, proxy_id, account_id, event_type, error_code, phase, latency_ms, detail)
    values (l.id, l.proxy_id, l.account_id, p_event_type, v_code, p_phase, p_latency_ms, v_det)
    returning id into v_id;

    if p_event_type in ('info','warn') then return; end if;

    if p_event_type = 'error' and v_code is not null then
        select exists (
            select 1 from proxy_events e
             where e.lease_id = l.id and e.event_type = 'error'
               and e.error_code = v_code and e.id < v_id
               and e.created_at > now() - interval '60 seconds'
        ) into v_dup;
    end if;

    if l.purpose <> 'bls' then
        if p_event_type = 'cycle_ok' then
            insert into proxy_purpose_state(proxy_id, purpose) values (l.proxy_id, l.purpose)
            on conflict do nothing;
            update proxy_purpose_state
               set consecutive_failures = 0, fault_count = 0, fault_first_at = null,
                   last_ok_at = now(), updated_at = now()
             where proxy_id = l.proxy_id and purpose = l.purpose;
        elsif v_code is not null then
            if v_dup then
                v_verdict := 'dup';
            else
                v_verdict := purpose_apply_error(l.proxy_id, l.purpose, v_code);
            end if;
            update proxy_events
               set blame = coalesce((select c.blame from error_codes c
                                      where c.purpose = l.purpose and c.code = v_code), 'unknown'),
                   verdict = v_verdict
             where id = v_id;
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
        null;

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
end $$;

-- release_lease: в событии released тоже канонический код
create or replace function bls_proxy_manager.release_lease(
    p_lease_id   uuid,
    p_reason     text  default 'released',
    p_error_code text  default null,
    p_phase      text  default null,
    p_detail     jsonb default '{}'::jsonb
) returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    l       leases%rowtype;
    v_code  text := p_error_code;
    v_canon text;
begin
    select * into l from leases where id = p_lease_id for update;
    if not found or l.released_at is not null then return; end if;

    if v_code is null and l.purpose <> 'bls'
       and coalesce(p_detail->>'operation_status', '') = 'UNKNOWN' then
        v_code := 'UNKNOWN';
    end if;

    if v_code is not null then
        perform report_event(p_lease_id, 'error', v_code, p_phase, null, p_detail);
    end if;

    v_canon := v_code;
    if v_code is not null and l.purpose <> 'bls'
       and exists (select 1 from error_codes where purpose = l.purpose) then
        v_canon := error_code_resolve(l.purpose, v_code);
    end if;

    update leases set released_at = now(), release_reason = left(coalesce(p_reason,'released'), 100)
     where id = p_lease_id;

    if l.purpose = 'bls' then
        update proxy_state
           set free_at = greatest(free_at, now() + make_interval(secs => cfg_int('cooldown_ok_s', 0))),
               updated_at = now()
         where proxy_id = l.proxy_id;
    else
        insert into proxy_purpose_state(proxy_id, purpose) values (l.proxy_id, l.purpose)
        on conflict do nothing;
        update proxy_purpose_state
           set free_at = greatest(free_at, now() + make_interval(secs => pcfg_int(l.purpose, 'cooldown_ok_s', 0))),
               updated_at = now()
         where proxy_id = l.proxy_id and purpose = l.purpose;
    end if;

    insert into proxy_events(lease_id, proxy_id, account_id, event_type, error_code, phase, detail)
    values (l.id, l.proxy_id, l.account_id, 'released', v_canon, p_phase,
            jsonb_build_object('reason', p_reason) || coalesce(p_detail, '{}'::jsonb));
end $$;

-- Ответ клиенту: что сервер решил по последней ошибке аренды
create or replace function bls_proxy_manager.lease_verdict(p_lease_id uuid)
returns jsonb language plpgsql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    l   leases%rowtype;
    e   proxy_events%rowtype;
    d   error_codes%rowtype;
    v_cd integer := 0;
    v_next text;
    v_change boolean;
begin
    select * into l from leases where id = p_lease_id;
    if not found then
        return jsonb_build_object('verdict','unknown_lease','cooldown_s',0,'next_action','stop','change_ip',false);
    end if;
    if l.purpose = 'bls' then
        return jsonb_build_object('verdict','n/a','cooldown_s',0,'next_action','continue','change_ip',false);
    end if;
    select * into e from proxy_events
     where lease_id = p_lease_id and event_type = 'error' order by id desc limit 1;
    if not found then
        return jsonb_build_object('verdict','ok','cooldown_s',0,'next_action','continue','change_ip',false);
    end if;
    select * into d from error_codes where purpose = l.purpose and code = upper(coalesce(e.error_code, ''));
    select coalesce(greatest(0, ceil(extract(epoch from (free_at - now())))), 0)::integer into v_cd
      from proxy_purpose_state where proxy_id = l.proxy_id and purpose = l.purpose;
    v_cd := coalesce(v_cd, 0);
    v_change := coalesce(e.verdict, '') like 'cooldown%' or coalesce(e.verdict, '') in ('quarantine','already_quarantined');
    v_next := case
        when d.reset_profile                          then 'reset_profile'
        when d.blame in ('account','provider')        then 'stop'
        when d.blame in ('site','mail','unknown')     then 'retry'
        when v_change                                 then 'new_ip'
        else 'retry' end;
    return jsonb_build_object('verdict', coalesce(e.verdict, 'unknown'), 'cooldown_s', v_cd,
                              'next_action', v_next, 'change_ip', v_change,
                              'blame', coalesce(e.blame, d.blame, 'unknown'), 'code', e.error_code);
end $$;
revoke all on function bls_proxy_manager.lease_verdict(uuid) from public, anon, authenticated;
grant execute on function bls_proxy_manager.lease_verdict(uuid) to bls_reporter;
