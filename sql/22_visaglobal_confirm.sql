-- 22: VisaGlobal — подтверждение блокировок и серверная проверка прокси.
-- Применена в боевую базу 2026-10-21 (visaglobal_confirm_22). Зависит от 21.
-- ВАЖНО: итоговая версия purpose_apply_error лежит в 23_visaglobal_codes_profile.sql (она заменяет версию из 22).
alter table bls_proxy_manager.error_codes add column if not exists needs_confirm boolean not null default false;
alter table bls_proxy_manager.error_codes add column if not exists probe         boolean not null default false;
alter table bls_proxy_manager.proxy_purpose_state add column if not exists fault_verdict  text;
alter table bls_proxy_manager.proxy_purpose_state add column if not exists fault_snapshot jsonb;

update bls_proxy_manager.error_codes set needs_confirm = true
 where purpose = 'visaglobal' and code in ('CF_BLOCK','CF_RATE','VFS_429','HTTP_403','HTTP_429');
update bls_proxy_manager.error_codes set probe = true
 where purpose = 'visaglobal' and code in ('NET_PROXY_DEAD','NET_TIMEOUT','PROXY_TIMEOUT','PROXY_CONNECT_FAILED',
       'ERR_PROXY_CONNECTION_FAILED','ERR_TUNNEL_CONNECTION_FAILED','ERR_SOCKS_CONNECTION_FAILED');

insert into bls_proxy_manager.purpose_settings(purpose, key, value, note) values
 ('visaglobal','ip_unconfirmed_cooldown_s', to_jsonb(120), 'кулдаун IP при неподтверждённой блокировке (одна аренда), сек')
on conflict (purpose, key) do update set value = excluded.value, note = excluded.note;

create or replace function bls_proxy_manager.purpose_fault_job(p_proxy_id text, p_purpose text)
returns table(proxy_id text, scheme text, host text, port integer, username text, password text, code text, attempts integer)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select p.id, p.scheme, p.host, p.port, cr.username, cr.password, ps.last_fault_code,
           case when ps.consecutive_failures >= 2
                then greatest(1, least(5, cfg_int('site_check_attempts', 3))) else 1 end
      from proxies p
      join proxy_purpose_state ps on ps.proxy_id = p.id and ps.purpose = p_purpose
      left join proxy_credentials cr on cr.proxy_id = p.id
     where p.id = p_proxy_id
       and ps.last_fault_at > now() - interval '8 minutes'
       and ps.fault_verdict is null
       and cfg_int('site_check_enabled', 1) = 1
$$;

create or replace function bls_proxy_manager.purpose_fault_verdict(
    p_proxy_id text, p_purpose text, p_verdict text, p_detail jsonb default '{}'::jsonb)
returns void language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    s    proxy_purpose_state%rowtype;
    snap jsonb;
begin
    if p_verdict not in ('proxy_dead','site_down','transient') then
        raise exception 'bad verdict %', p_verdict;
    end if;
    select * into s from proxy_purpose_state where proxy_id = p_proxy_id and purpose = p_purpose for update;
    if not found or s.fault_verdict is not null
       or s.last_fault_at is null or s.last_fault_at < now() - interval '10 minutes' then
        return;
    end if;
    snap := s.fault_snapshot;

    if p_verdict = 'proxy_dead' or snap is null then
        update proxy_purpose_state set fault_verdict = 'proxy_dead', updated_at = now()
         where proxy_id = p_proxy_id and purpose = p_purpose;
        insert into proxy_events(proxy_id, event_type, error_code, detail)
        values (p_proxy_id, 'fault_confirmed', s.last_fault_code,
                jsonb_build_object('purpose', p_purpose) || coalesce(p_detail, '{}'::jsonb));
        return;
    end if;

    update proxy_purpose_state
       set free_at              = greatest(coalesce((snap->>'free_at')::timestamptz, now()),
                                           now() + make_interval(secs => cfg_int('fault_soft_cooldown_s', 60))),
           quarantined_until    = (snap->>'quarantined_until')::timestamptz,
           quarantine_reason    = snap->>'quarantine_reason',
           cooldown_reason      = 'прощён: ' || p_verdict,
           consecutive_failures = coalesce((snap->>'consecutive_failures')::integer, 0),
           fault_verdict        = p_verdict,
           updated_at           = now()
     where proxy_id = p_proxy_id and purpose = p_purpose;
    insert into proxy_events(proxy_id, event_type, error_code, detail)
    values (p_proxy_id, 'fault_forgiven', s.last_fault_code,
            jsonb_build_object('purpose', p_purpose, 'verdict', p_verdict) || coalesce(p_detail, '{}'::jsonb));
end $$;

revoke all on function bls_proxy_manager.purpose_fault_job(text, text) from public, anon, authenticated;
revoke all on function bls_proxy_manager.purpose_fault_verdict(text, text, text, jsonb) from public, anon, authenticated;
grant execute on function bls_proxy_manager.purpose_fault_job(text, text) to bls_prober;
grant execute on function bls_proxy_manager.purpose_fault_verdict(text, text, text, jsonb) to bls_prober;
