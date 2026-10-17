-- =============================================================================
-- 08_ocr_purpose.sql — прокси для OCR-сервиса (Gemini) рядом с BLS-кликером.
-- Накатывать ПОСЛЕ 06_fault_ladder_v3.sql (04 и 07 не нужны). Безопасно запускать повторно.
-- Откат: 08_ocr_purpose_ROLLBACK.sql.
--
-- ЧТО ДЕЛАЕТ (всё добавляется, BLS-путь не меняется):
--   * ocr_get_pool()        — снапшот живых прокси с назначением 'ocr' (для GET /ocr/pool)
--   * ocr_report_batch()    — пачка итогов от OCR (ok/fail/geo) -> кулдаун / карантин
--   * admin_upsert_proxies  — теперь понимает purposes (['bls'] | ['ocr'] | оба)
--   * admin_get/set_settings— в белый список добавлены 5 ключей ocr_*
-- НЕ ТРОГАЕТ: acquire_proxies, report_event, release_lease, apply_proxy_fault,
--             evaluate_cross_account_health, probe_*. Кликер продолжает работать как раньше:
--             он просит purpose='bls', а у OCR-прокси purposes = {ocr}.
-- =============================================================================
do $$ begin
    if not exists (select 1 from information_schema.columns
                    where table_schema='bls_proxy_manager' and table_name='proxy_state' and column_name='fault_snapshot')
       or not exists (select 1 from bls_proxy_manager.settings where key = 'fault_cooldown2_s') then
        raise exception 'Сначала накатите 05_fault_ladder.sql и 06_fault_ladder_v3.sql';
    end if;
end $$;

set search_path = bls_proxy_manager, pg_temp;

-- ---------- 1. Настройки OCR (ничего не перезаписываем) ----------------------
insert into bls_proxy_manager.settings(key, value, note) values
 ('ocr_cooldown_s',         '60',  'OCR: 1-й сбой канала, кулдаун, сек (каждый следующий x2)'),
 ('ocr_cooldown_max_s',     '900', 'OCR: потолок кулдауна, сек'),
 ('ocr_fail_quarantine',    '5',   'OCR: сбоев канала подряд -> карантин (quarantine_base_min x2 по уровню)'),
 ('ocr_geo_quarantine_min', '60',  'OCR: карантин за гео-отказ Gemini, мин (x2 по уровню, потолок quarantine_max_min)'),
 ('ocr_fault_debounce_s',   '30',  'OCR: сбои одного прокси чаще, чем раз в N сек, считаются одним')
on conflict (key) do nothing;

-- ---------- 2. Добавление прокси: purposes ----------------------------------
-- Нет purposes (или пустой/мусорный) — как раньше: новые = {bls}, существующие не меняются.
create or replace function bls_proxy_manager.admin_upsert_proxies(p_items jsonb) returns jsonb
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    it     jsonb;
    v_id   text;
    v_host text;
    v_port integer;
    v_purp text[];
    v_ins  integer := 0;
    v_upd  integer := 0;
begin
    if p_items is null or jsonb_typeof(p_items) <> 'array' then
        raise exception 'array expected';
    end if;
    if jsonb_array_length(p_items) > 2000 then
        raise exception 'too many items';
    end if;

    for it in select e from jsonb_array_elements(p_items) e loop
        v_host := btrim(it->>'host');
        v_port := (it->>'port')::integer;
        if v_host is null or v_host = '' or v_port is null then
            raise exception 'host/port required';
        end if;

        v_purp := null;
        if jsonb_typeof(it->'purposes') = 'array' then
            select array_agg(distinct x order by x) into v_purp
              from jsonb_array_elements_text(it->'purposes') x
             where x in ('bls', 'ocr');
        end if;

        select id into v_id from proxies where host = v_host and port = v_port limit 1;

        if v_id is null then
            v_id := coalesce(nullif(it->>'id', ''), v_host || ':' || v_port);
            insert into proxies(id, scheme, host, port, kind, pool, max_leases, purposes)
            values (v_id,
                    coalesce(it->>'scheme', 'socks5'), v_host, v_port,
                    coalesce(it->>'kind', 'shared'), nullif(it->>'pool', ''),
                    coalesce((it->>'max_leases')::integer, 1),
                    coalesce(v_purp, '{bls}'::text[]));
            v_ins := v_ins + 1;
        else
            update proxies
               set scheme     = coalesce(it->>'scheme', scheme),
                   kind       = coalesce(it->>'kind', kind),
                   pool       = coalesce(nullif(it->>'pool', ''), pool),
                   max_leases = coalesce((it->>'max_leases')::integer, max_leases),
                   purposes   = coalesce(v_purp, purposes)
             where id = v_id;
            v_upd := v_upd + 1;
        end if;

        if (it->>'username') is not null or (it->>'password') is not null then
            insert into proxy_credentials(proxy_id, username, password)
            values (v_id, it->>'username', it->>'password')
            on conflict (proxy_id) do update
               set username = excluded.username, password = excluded.password;
        end if;
    end loop;

    return jsonb_build_object('inserted', v_ins, 'updated', v_upd);
end $$;

-- ---------- 3. Снапшот пула для OCR -----------------------------------------
-- enabled + purposes ∋ 'ocr' + не в карантине + не в кулдауне. Лизов и глобальных локов нет.
create or replace function bls_proxy_manager.ocr_get_pool()
returns table (proxy_id text, scheme text, host text, port integer, username text, password text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select p.id, p.scheme, p.host, p.port, cr.username, cr.password
      from proxies p
      join proxy_state ps on ps.proxy_id = p.id
      left join proxy_credentials cr on cr.proxy_id = p.id
     where p.enabled
       and 'ocr' = any (p.purposes)
       and (ps.quarantined_until is null or ps.quarantined_until <= now())
       and ps.free_at <= now()
     order by p.id
     limit 500
$$;

-- ---------- 4. Итоги от OCR --------------------------------------------------
-- item: {id, ok, fail, geo} — счётчики за ~15 с. Трогаем ТОЛЬКО прокси с purposes ∋ 'ocr'.
--   geo > 0            -> карантин (Gemini: User location is not supported)
--   fail > ok          -> кулдаун 60,120,240... с (потолок ocr_cooldown_max_s); N подряд -> карантин
--   иначе ok > 0       -> счётчик подряд = 0, last_ok_at = now()
-- 429/квота ключа сюда не приходит (это не вина прокси).
create or replace function bls_proxy_manager.ocr_report_batch(p_items jsonb) returns integer
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    it     jsonb;
    v_id   text;
    v_ok   integer;
    v_fail integer;
    v_geo  integer;
    v_n    integer := 0;
    s      proxy_state%rowtype;
    v_cons integer;
    v_cd   integer;
begin
    if p_items is null or jsonb_typeof(p_items) <> 'array' then
        raise exception 'array expected';
    end if;
    if jsonb_array_length(p_items) > 500 then
        raise exception 'too many items';
    end if;

    for it in select e from jsonb_array_elements(p_items) e loop
        v_id   := it->>'id';
        v_ok   := least(greatest(coalesce((it->>'ok')::integer,   0), 0), 1000000);
        v_fail := least(greatest(coalesce((it->>'fail')::integer, 0), 0), 1000000);
        v_geo  := least(greatest(coalesce((it->>'geo')::integer,  0), 0), 1000000);

        select ps.* into s
          from proxy_state ps
          join proxies p on p.id = ps.proxy_id
         where p.id = v_id and 'ocr' = any (p.purposes)
           for update of ps;
        if not found then continue; end if;

        if v_geo > 0 then
            if s.quarantined_until is null or s.quarantined_until <= now() then
                perform quarantine_proxy_min(v_id, 'ocr: гео-отказ Gemini', cfg_int('ocr_geo_quarantine_min', 60));
                insert into proxy_events(proxy_id, event_type, error_code, detail)
                values (v_id, 'ocr_geo', 'GEMINI_GEO_BLOCK', jsonb_build_object('geo', v_geo, 'ok', v_ok));
            end if;

        elsif v_fail > v_ok then
            if (s.quarantined_until is not null and s.quarantined_until > now())
               or (s.last_error_at is not null
                   and s.last_error_at > now() - make_interval(secs => cfg_int('ocr_fault_debounce_s', 30))) then
                null;   -- уже в карантине / тот же сбой, что только что учли
            else
                v_cons := s.consecutive_failures + 1;
                v_cd := least(cfg_int('ocr_cooldown_max_s', 900),
                              cfg_int('ocr_cooldown_s', 60) * power(2, least(v_cons - 1, 10))::integer);
                update proxy_state
                   set consecutive_failures = v_cons,
                       last_error_at   = now(),
                       free_at         = greatest(free_at, now() + make_interval(secs => v_cd)),
                       cooldown_reason = 'OCR: сбой канала x' || v_cons || ' (кулдаун ' || v_cd || ' с)',
                       updated_at      = now()
                 where proxy_id = v_id;
                insert into proxy_events(proxy_id, event_type, error_code, detail)
                values (v_id, 'ocr_fail', 'OCR_PROXY_FAIL',
                        jsonb_build_object('fail', v_fail, 'ok', v_ok, 'step', v_cons, 'cooldown_s', v_cd));
                if v_cons >= cfg_int('ocr_fail_quarantine', 5) then
                    perform quarantine_proxy(v_id, 'ocr: сбои канала подряд x' || v_cons);
                end if;
            end if;

        elsif v_ok > 0 then
            update proxy_state
               set consecutive_failures = 0,
                   last_ok_at = now(),
                   quarantine_level = case when quarantined_until is null
                                             or quarantined_until < now() - interval '1 hour'
                                           then 0 else quarantine_level end,
                   updated_at = now()
             where proxy_id = v_id;
        end if;

        v_n := v_n + 1;
    end loop;
    return v_n;
end $$;

-- ---------- 5. Настройки в дашборде: белый список + ocr_* -------------------
create or replace function bls_proxy_manager.admin_get_settings() returns table (key text, value text, note text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select s.key, s.value #>> '{}', s.note from settings s
     where s.key in ('cooldown_ok_s','cooldown_proxy_fault_s','fault_cooldown2_s','fault_disable_count',
                     'repeat_fault_window_min','fault_soft_cooldown_s','site_check_enabled','site_check_attempts',
                     'ocr_cooldown_s','ocr_cooldown_max_s','ocr_fail_quarantine','ocr_geo_quarantine_min',
                     'ocr_fault_debounce_s')
     order by s.key
$$;

create or replace function bls_proxy_manager.admin_set_setting(p_key text, p_value text) returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
begin
    if p_key not in ('cooldown_ok_s','cooldown_proxy_fault_s','fault_cooldown2_s','fault_disable_count',
                     'repeat_fault_window_min','fault_soft_cooldown_s','site_check_enabled','site_check_attempts',
                     'ocr_cooldown_s','ocr_cooldown_max_s','ocr_fail_quarantine','ocr_geo_quarantine_min',
                     'ocr_fault_debounce_s') then
        raise exception 'key not allowed: %', p_key;
    end if;
    if p_value !~ '^[0-9]{1,6}$' then raise exception 'integer 0..999999 expected'; end if;
    update settings set value = to_jsonb(p_value::integer) where key = p_key;
    if not found then raise exception 'unknown key %', p_key; end if;
end $$;

-- ---------- 6. Права ---------------------------------------------------------
-- Новые роли и пароли НЕ нужны: снапшот читает bls_issuer (как acquire), итоги пишет bls_reporter (как report).
revoke all on function bls_proxy_manager.ocr_get_pool()            from public, anon, authenticated;
revoke all on function bls_proxy_manager.ocr_report_batch(jsonb)   from public, anon, authenticated;
grant execute on function bls_proxy_manager.ocr_get_pool()          to bls_issuer;
grant execute on function bls_proxy_manager.ocr_report_batch(jsonb) to bls_reporter;

reset search_path;

-- ---------- 7. Проверка: 5 ключей ocr_*, 2 новые функции ---------------------
select key, value #>> '{}' as value from bls_proxy_manager.settings where key like 'ocr\_%' order by 1;
select proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'bls_proxy_manager' and proname in ('ocr_get_pool','ocr_report_batch') order by 1;
