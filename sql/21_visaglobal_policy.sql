-- 21_visaglobal_policy.sql — политика ошибок VisaGlobal: справочник кодов вместо «клиент сказал — банить».
-- Запускать ПОСЛЕ 13–17. Откат: 21_ROLLBACK.sql. BLS (purpose='bls') эти правки не затрагивают,
-- кроме account_needs_reset (он дополнительно учитывает коды-«сбросы профиля» из справочника; BLS их не шлёт).
--
-- Что делает:
--  1. error_codes: код -> виновник (blame), кулдаун, «ведёт ли к сбросу профиля», «может ли привести к карантину».
--  2. purpose_apply_error: решение по справочнику. Неизвестный код = только журнал, без бана.
--     Кулдаун растёт при повторах на этом IP (x2, потолок ip_cooldown_max_s), успех (cycle_ok) обнуляет серию.
--     Карантин — только для кодов с quarantine_ok И при ошибках минимум с N разных аккаунтов (один бот не может «убить» IP).
--  3. report_event: типы info/warn (только журнал); в proxy_events пишутся blame и verdict.
--  4. release_lease: возврат с operation_status=UNKNOWN без кода больше не теряется (код UNKNOWN).
--  5. renew_lease: потолок суммарной аренды для не-BLS целей (max_lease_total_s, по умолчанию 30 мин).
--  6. account_needs_reset: учитывает коды со сбросом профиля из справочника.
--  7. cooldown_ok_s для visaglobal: 300 -> 60 (каждый штатный возврат больше не блокирует IP на 5 минут).
begin;
set local lock_timeout = '5s';

-- ---------- 1. Справочник кодов ---------------------------------------------
create table if not exists bls_proxy_manager.error_codes (
    purpose        text    not null,
    code           text    not null,
    blame          text    not null check (blame in ('ip','profile','account','site','mail','provider','unknown')),
    cooldown_s     integer not null default 0,     -- базовый кулдаун IP, 0 = только журнал
    reset_profile  boolean not null default false, -- считать для account_needs_reset (сброс профиля браузера)
    quarantine_ok  boolean not null default false, -- может ли серия привести к карантину
    note           text,
    primary key (purpose, code)
);
revoke all on bls_proxy_manager.error_codes from public, anon, authenticated;

insert into bls_proxy_manager.error_codes(purpose, code, blame, cooldown_s, reset_profile, quarantine_ok, note) values
 -- сеть / прокси
 ('visaglobal','NET_PROXY_DEAD',            'ip',       300, false, true,  'нет трафика через прокси'),
 ('visaglobal','NET_TIMEOUT',               'ip',       120, false, false, 'таймаут соединения/чтения'),
 ('visaglobal','NET_PROXY_AUTH',            'provider',   0, false, false, '407 от прокси: алерт админу, IP не трогаем'),
 -- Cloudflare
 ('visaglobal','CF_CHALLENGE_LOOP',         'profile',    0, true,  false, 'цикл капчи: сброс профиля, IP не трогаем'),
 ('visaglobal','CF_BLOCK',                  'ip',       900, true,  false, '403/1020/Access Denied'),
 ('visaglobal','CF_RATE',                   'ip',       900, false, false, '1015 / 429 на уровне CF'),
 ('visaglobal','CF_TIMEOUT',                'unknown',  120, false, false, 'скрипты CF не догрузились'),
 -- VFS
 ('visaglobal','VFS_SEC_403',               'profile',  300, true,  false, 'ограничение безопасности/сессии (403201/403203/403005/403204 в detail)'),
 ('visaglobal','VFS_429',                   'ip',       900, false, false, 'лимит запросов'),
 ('visaglobal','VFS_QUEUE',                 'site',       0, false, false, 'waiting room'),
 ('visaglobal','VFS_5XX',                   'site',       0, false, false, 'сбой сайта'),
 ('visaglobal','VFS_COMMON_ERR',            'site',       0, false, false, 'ошибка CommonSections и т.п.'),
 ('visaglobal','VFS_MAINT',                 'site',       0, false, false, 'технические работы'),
 ('visaglobal','VFS_SESSION_EXPIRED',       'profile',    0, false, false, 'сессия оборвалась: перезаход'),
 -- аккаунт / почта / капча-сервис
 ('visaglobal','AUTH_INVALID_CREDS',        'account',    0, false, false, 'неверный логин/пароль'),
 ('visaglobal','AUTH_LOCKED',               'account',    0, false, false, 'аккаунт заблокирован'),
 ('visaglobal','AUTH_NOT_ACTIVATED',        'account',    0, false, false, 'аккаунт не активирован'),
 ('visaglobal','AUTH_OTP_TIMEOUT',          'mail',       0, false, false, 'письмо/код не пришёл (смотреть OTP-брокер)'),
 ('visaglobal','SOLVER_FAIL',               'site',       0, false, false, 'сбой капча-сервиса'),
 ('visaglobal','UNKNOWN',                   'unknown',    0, false, false, 'не распознано: только журнал'),
 -- алиасы старых клиентов (прежние коды -> то же поведение, но мягче)
 ('visaglobal','HTTP_403',                  'ip',       300, true,  false, 'алиас: старый клиент (раньше бан 15 мин)'),
 ('visaglobal','HTTP_429',                  'ip',       900, false, false, 'алиас: старый клиент'),
 ('visaglobal','PROXY_TIMEOUT',             'ip',       120, false, false, 'алиас -> NET_TIMEOUT (раньше лесенка до 4 ч)'),
 ('visaglobal','PROXY_CONNECT_FAILED',      'ip',       300, false, true,  'алиас -> NET_PROXY_DEAD'),
 ('visaglobal','ERR_PROXY_CONNECTION_FAILED','ip',      300, false, true,  'алиас -> NET_PROXY_DEAD'),
 ('visaglobal','ERR_TUNNEL_CONNECTION_FAILED','ip',     300, false, true,  'алиас -> NET_PROXY_DEAD'),
 ('visaglobal','ERR_SOCKS_CONNECTION_FAILED','ip',      300, false, true,  'алиас -> NET_PROXY_DEAD')
on conflict (purpose, code) do nothing;

-- настройки цели
insert into bls_proxy_manager.purpose_settings(purpose, key, value, note) values
 ('visaglobal','cooldown_ok_s',          to_jsonb(60),   'кулдаун после штатного release, сек'),
 ('visaglobal','max_lease_total_s',      to_jsonb(1800), 'потолок суммарной аренды с учётом /renew, сек (0 = без потолка)'),
 ('visaglobal','ip_escalate_window_min', to_jsonb(120),  'окно подсчёта повторов ошибок IP, мин'),
 ('visaglobal','ip_cooldown_max_s',      to_jsonb(3600), 'максимум кулдауна IP при повторах, сек'),
 ('visaglobal','ip_quarantine_count',    to_jsonb(4),    'повторов ошибок -> карантин (если код quarantine_ok)'),
 ('visaglobal','ip_quarantine_accounts', to_jsonb(2),    'минимум разных аккаунтов среди повторов для карантина')
on conflict (purpose, key) do update set value = excluded.value, note = excluded.note;

-- ---------- 2. Колонки для разбора причин -----------------------------------
alter table bls_proxy_manager.proxy_events add column if not exists blame   text;
alter table bls_proxy_manager.proxy_events add column if not exists verdict text;

-- ---------- 3. Решение по справочнику ---------------------------------------
-- Старая реализация (лесенка сбоев) остаётся как _legacy для целей без справочника.
alter function bls_proxy_manager.purpose_apply_error(text, text, text)
    rename to purpose_apply_error_legacy;

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
revoke all on function bls_proxy_manager.purpose_apply_error_legacy(text, text, text) from public, anon, authenticated;

-- ---------- 4. report_event: info/warn, blame, verdict ----------------------
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
begin
    if p_event_type not in ('cycle_ok','error','info','warn') then
        raise exception 'bad event_type %', p_event_type;
    end if;
    select * into l from leases where id = p_lease_id;
    if not found then raise exception 'unknown lease %', p_lease_id; end if;

    insert into proxy_events(lease_id, proxy_id, account_id, event_type, error_code, phase, latency_ms, detail)
    values (l.id, l.proxy_id, l.account_id, p_event_type, p_error_code, p_phase, p_latency_ms,
            coalesce(p_detail, '{}'::jsonb))
    returning id into v_id;

    -- info/warn: только журнал, на состояние IP не влияют
    if p_event_type in ('info','warn') then return; end if;

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
        elsif p_error_code is not null then
            if v_dup then
                v_verdict := 'dup';
            else
                v_verdict := purpose_apply_error(l.proxy_id, l.purpose, p_error_code);
            end if;
            update proxy_events
               set blame = coalesce((select c.blame from error_codes c
                                      where c.purpose = l.purpose and c.code = upper(btrim(p_error_code))), 'unknown'),
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

-- ---------- 5. release_lease: возврат без кода не теряет UNKNOWN ------------
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
    l      leases%rowtype;
    v_code text := p_error_code;
begin
    select * into l from leases where id = p_lease_id for update;
    if not found or l.released_at is not null then return; end if;   -- идемпотентно

    -- не-BLS: клиент вернул аренду со статусом UNKNOWN и без кода -> фиксируем код UNKNOWN (только журнал)
    if v_code is null and l.purpose <> 'bls'
       and coalesce(p_detail->>'operation_status', '') = 'UNKNOWN' then
        v_code := 'UNKNOWN';
    end if;

    if v_code is not null then
        perform report_event(p_lease_id, 'error', v_code, p_phase, null, p_detail);
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
    values (l.id, l.proxy_id, l.account_id, 'released', v_code, p_phase,
            jsonb_build_object('reason', p_reason) || coalesce(p_detail, '{}'::jsonb));
end $$;

-- ---------- 6. renew_lease: потолок суммарной аренды (не-BLS) ---------------
create or replace function bls_proxy_manager.renew_lease(p_lease_id uuid, p_ttl_seconds integer default 300)
returns timestamptz
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    l     leases%rowtype;
    v_new timestamptz;
    v_cap integer;
    v     timestamptz;
begin
    select * into l from leases
     where id = p_lease_id and released_at is null and expires_at > now() for update;
    if not found then return null; end if;     -- null -> сервис отдаёт 409

    v_new := now() + make_interval(secs => least(greatest(coalesce(p_ttl_seconds,300),30),3600));
    if l.purpose <> 'bls' then
        v_cap := pcfg_int(l.purpose, 'max_lease_total_s', 1800);
        if v_cap > 0 then
            if l.acquired_at + make_interval(secs => v_cap) <= now() then return null; end if;
            v_new := least(v_new, l.acquired_at + make_interval(secs => v_cap));
        end if;
    end if;
    update leases set expires_at = v_new where id = p_lease_id returning expires_at into v;
    return v;
end $$;

-- ---------- 7. account_needs_reset: + коды сброса профиля из справочника ----
create or replace function bls_proxy_manager.account_needs_reset(p_account_id text)
returns boolean language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    v_thr    integer := cfg_int('account_reset_count', 3);
    v_win    integer := cfg_int('account_reset_window_min', 30);
    v_codes  text[]  := cfg_codes('account_reset_codes')
                        || coalesce(array(select c.code from error_codes c where c.reset_profile), '{}'::text[]);
    v_anchor timestamptz;
    v_n      integer;
begin
    if v_thr <= 0 or p_account_id is null then return false; end if;

    -- якорь: начало окна / последний успешный цикл / последний подтверждённый сброс.
    -- Считаем только ошибки ПОДРЯД, без cycle_ok между ними.
    select greatest(now() - make_interval(mins => v_win),
                    coalesce(max(e.created_at), '-infinity'::timestamptz))
      into v_anchor
      from proxy_events e
     where e.account_id = p_account_id and e.event_type in ('profile_reset', 'cycle_ok');

    select count(distinct e.proxy_id) into v_n
      from proxy_events e
     where e.account_id = p_account_id
       and e.event_type = 'error'
       and e.created_at > v_anchor
       and e.error_code = any (v_codes);

    if v_n < v_thr then return false; end if;

    if not exists (select 1 from proxy_events e
                    where e.account_id = p_account_id and e.event_type = 'reset_requested'
                      and e.created_at > v_anchor) then
        insert into proxy_events(account_id, event_type, detail)
        values (p_account_id, 'reset_requested', jsonb_build_object('distinct_proxies', v_n));
    end if;
    return true;
end $$;

commit;
