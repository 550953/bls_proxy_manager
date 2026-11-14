-- Тест 27: цель gmail_login. Всё в транзакции repeatable read и откатывается (rollback): боевые данные не меняются.
-- Запускать ПОСЛЕ 27_gmail_login_purpose.sql. Успех: "ВСЕ ТЕСТЫ 27 ПРОШЛИ", любой провал — exception с номером теста.
begin isolation level repeatable read;
do $t$
declare
    pid  text;
    pid2 text;
    pg   text;                    -- прокси только для gmail_login
    h0   text; h1 text;           -- хэш состояния других целей и BLS
    l    uuid;
    v    text;
    fa   timestamptz;
    fb   timestamptz;
    sec  numeric;
    n    integer;
    j    jsonb;
    cons integer;
    cd   text[] := array['60','120','240','300'];
    i    integer;
    r    record;

    -- хэш всего, что принадлежит НЕ gmail_login: состояние BLS и других целей, справочники, настройки
    fn_hash constant text := $h$
        select md5(coalesce((select string_agg(x::text, '|' order by x::text) from bls_proxy_manager.proxy_state x), '') ||
                   coalesce((select string_agg(x::text, '|' order by x::text) from bls_proxy_manager.proxy_purpose_state x where x.purpose <> 'gmail_login'), '') ||
                   coalesce((select string_agg(x::text, '|' order by x::text) from bls_proxy_manager.error_codes x where x.purpose <> 'gmail_login'), '') ||
                   coalesce((select string_agg(x::text, '|' order by x::text) from bls_proxy_manager.purpose_settings x where x.purpose <> 'gmail_login'), ''))
    $h$;
begin
    -- ---- подготовка: 2 прокси с целью gmail_login (только внутри транзакции) + прокси ТОЛЬКО для gmail_login
    select id into pid  from bls_proxy_manager.proxies where enabled order by id limit 1;
    select id into pid2 from bls_proxy_manager.proxies where enabled and id <> pid order by id limit 1;
    if pid is null or pid2 is null then raise exception 'TEST: нужно минимум 2 прокси в базе'; end if;
    update bls_proxy_manager.proxies set purposes = (select array_agg(distinct x order by x) from unnest(purposes || array['gmail_login']) x)
     where id in (pid, pid2);
    pg := 'test-gmail-only';
    insert into bls_proxy_manager.proxies(id, scheme, host, port, kind, purposes)
    values (pg, 'socks5', '192.0.2.77', 1081, 'shared', '{gmail_login}');
    insert into bls_proxy_manager.proxy_purpose_state(proxy_id, purpose) values (pid,'gmail_login'),(pid2,'gmail_login'),(pg,'gmail_login') on conflict do nothing;
    update bls_proxy_manager.proxy_purpose_state set free_at = now(), quarantined_until = null, last_ok_at = null,
           consecutive_failures = 0, last_fault_at = null, fault_verdict = null, fault_snapshot = null
     where purpose = 'gmail_login';
    delete from bls_proxy_manager.proxy_events where proxy_id in (pid, pid2, pg);

    execute fn_hash into h0;

    -- ---- T0: справочник и настройки на месте
    select count(*) into n from bls_proxy_manager.error_codes where purpose = 'gmail_login';
    if n <> 11 then raise exception 'T0: кодов gmail_login % (ожидалось 11)', n; end if;
    if (select count(*) from bls_proxy_manager.error_codes where purpose='gmail_login' and probe) <> 2 then raise exception 'T0: probe'; end if;
    if bls_proxy_manager.pcfg_int('gmail_login','ip_cooldown_max_s',0) <> 300 then raise exception 'T0: настройки'; end if;

    -- ---- T2: NET_PROXY_DEAD: 60 -> 120 -> 240 -> 300 (потолок). Один аккаунт, разные профили, разные аренды
    for i in 1..4 loop
        l := gen_random_uuid();
        insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at)
        values (l,pid,'t-acc-1','gmail_login','test',now(),now()+interval '5 min');
        perform bls_proxy_manager.report_event(l,'error','NET_PROXY_DEAD','exit_check',null,
                jsonb_build_object('profile_id','p'||i));
        select verdict into v from bls_proxy_manager.proxy_events where lease_id = l and event_type='error';
        if v <> 'cooldown:' || cd[i] then raise exception 'T2.%: verdict % (ожидалось cooldown:%)', i, v, cd[i]; end if;
        select free_at into fa from bls_proxy_manager.proxy_purpose_state where proxy_id=pid and purpose='gmail_login';
        sec := extract(epoch from (fa - now()));
        if sec < cd[i]::numeric - 3 or sec > cd[i]::numeric + 1 then raise exception 'T2.%: free_at +% с', i, sec; end if;
    end loop;
    -- пятая ошибка с ДРУГОГО аккаунта: 5 повторов, 2 аккаунта -> карантин
    l := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at)
    values (l,pid,'t-acc-2','gmail_login','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.report_event(l,'error','NET_PROXY_DEAD','exit_check',null,'{"profile_id":"p9"}');
    select verdict into v from bls_proxy_manager.proxy_events where lease_id = l and event_type='error';
    if v <> 'quarantine' then raise exception 'T2.q: verdict %', v; end if;
    if (select quarantined_until from bls_proxy_manager.proxy_purpose_state where proxy_id=pid and purpose='gmail_login') is null
       then raise exception 'T2.q: карантин не выставлен'; end if;
    -- вердикт боту
    j := bls_proxy_manager.lease_verdict(l);
    if j->>'next_action' <> 'new_ip' or (j->>'change_ip')::boolean is not true or j->>'blame' <> 'ip' then raise exception 'T2.v: %', j; end if;

    -- ---- T3: HOST_*, неизвестный код, IX/CHROME: free_at и серия не двигаются, в verdict только журнал
    for r in select unnest(array['HOST_BUSY','HOST_ERROR','NO_SUCH_CODE','IX_START_PAGE','CHROME_ERR_PAGE','UNKNOWN']) as code loop
        select free_at, consecutive_failures into fa, cons from bls_proxy_manager.proxy_purpose_state where proxy_id=pid2 and purpose='gmail_login';
        l := gen_random_uuid();
        insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at)
        values (l,pid2,'t-acc-3','gmail_login','test',now(),now()+interval '5 min');
        perform bls_proxy_manager.report_event(l,'error',r.code,'final',null,'{}');
        select verdict into v from bls_proxy_manager.proxy_events where lease_id = l and event_type='error';
        if v not like 'log:%' then raise exception 'T3 %: verdict %', r.code, v; end if;
        select free_at into fb from bls_proxy_manager.proxy_purpose_state where proxy_id=pid2 and purpose='gmail_login';
        if fb <> fa or (select consecutive_failures from bls_proxy_manager.proxy_purpose_state where proxy_id=pid2 and purpose='gmail_login') <> cons
           then raise exception 'T3 %: состояние прокси изменилось', r.code; end if;
        j := bls_proxy_manager.lease_verdict(l);
        if j->>'next_action' <> 'retry' or (j->>'change_ip')::boolean then raise exception 'T3 %: вердикт боту %', r.code, j; end if;
    end loop;
    -- сырой код сохраняется в detail.raw_code
    select detail->>'raw_code' into v from bls_proxy_manager.proxy_events where proxy_id=pid2 and error_code='UNKNOWN' and detail ? 'raw_code' limit 1;
    if v <> 'NO_SUCH_CODE' then raise exception 'T3: raw_code %', v; end if;

    -- ---- T3b: коды без штрафа IP, но с разным next_action
    for r in select * from (values ('NET_PROXY_AUTH','stop'),('GOOGLE_VERIFY','stop'),('GOOGLE_BLOCKED','stop')) x(code, act) loop
        l := gen_random_uuid();
        insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at)
        values (l,pid2,'t-acc-3','gmail_login','test',now(),now()+interval '5 min');
        perform bls_proxy_manager.report_event(l,'error',r.code,'final',null,'{}');
        j := bls_proxy_manager.lease_verdict(l);
        if j->>'next_action' <> r.act or (j->>'change_ip')::boolean then raise exception 'T3b %: %', r.code, j; end if;
    end loop;

    -- ---- T3c: капча Google на неподтверждённом IP: короткий кулдаун
    l := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at)
    values (l,pid2,'t-acc-4','gmail_login','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.report_event(l,'error','GOOGLE_CAPTCHA','final',null,'{"profile_id":"c1"}');
    select verdict into v from bls_proxy_manager.proxy_events where lease_id = l and event_type='error';
    if v <> 'cooldown:120:unconfirmed' then raise exception 'T3c: %', v; end if;

    -- ---- T4: info с фазой и задержкой попадает в журнал, состояние прокси не меняется
    select free_at, consecutive_failures into fa, cons from bls_proxy_manager.proxy_purpose_state where proxy_id=pg and purpose='gmail_login';
    l := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at)
    values (l,pg,'t-acc-5','gmail_login','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.report_event(l,'info',null,'exit_check',1234,
            '{"outcome":"slow","slot":3,"starts_in_flight":5,"lost_ms":0}');
    select phase, latency_ms, detail into r from bls_proxy_manager.proxy_events where lease_id=l and event_type='info';
    if r.phase <> 'exit_check' or r.latency_ms <> 1234 or r.detail->>'starts_in_flight' <> '5' then raise exception 'T4: %', r; end if;
    perform bls_proxy_manager.report_event(l,'warn',null,'page_load',20000,'{"outcome":"slow"}');
    select free_at into fb from bls_proxy_manager.proxy_purpose_state where proxy_id=pg and purpose='gmail_login';
    if fb <> fa or (select consecutive_failures from bls_proxy_manager.proxy_purpose_state where proxy_id=pg and purpose='gmail_login') <> cons
       then raise exception 'T4: состояние изменилось'; end if;

    -- ---- T5: release ok: пауза 30 с только у gmail_login
    perform bls_proxy_manager.release_lease(l, 'ok', null, null, '{}');
    select free_at into fb from bls_proxy_manager.proxy_purpose_state where proxy_id=pg and purpose='gmail_login';
    sec := extract(epoch from (fb - now()));
    if sec < 27 or sec > 31 then raise exception 'T5: пауза после ok % с', sec; end if;

    -- ---- T6: выдача: цель gmail_login берёт свой прокси, bls и visaglobal его не получают
    update bls_proxy_manager.proxy_purpose_state set free_at = now() where proxy_id = pg and purpose='gmail_login';
    select count(*) into n from bls_proxy_manager.acquire_proxies('t-acc-6', 1, 60, 'gmail_login', 'test', array[pid, pid2], true);
    if n <> 1 then raise exception 'T6: acquire gmail_login вернул % строк', n; end if;
    if (select purpose from bls_proxy_manager.leases where account_id='t-acc-6' order by acquired_at desc limit 1) <> 'gmail_login'
       then raise exception 'T6: аренда не gmail_login'; end if;
    -- T8: после всех операций gmail_login (ошибки, info, release, acquire) другие цели не изменились.
    -- Журнал proxy_events/leases в хэш не входит. Проверка стоит до пробной выдачи bls/visaglobal ниже: она состояние меняет.
    execute fn_hash into h1;
    if h0 is distinct from h1 then raise exception 'T8: состояние bls/visaglobal/ocr изменилось'; end if;
    if exists (select 1 from bls_proxy_manager.acquire_proxies('t-acc-7', 50, 60, 'visaglobal', 'test', null, true) where proxy_id = pg)
       then raise exception 'T6: visaglobal получил прокси gmail_login'; end if;
    if exists (select 1 from bls_proxy_manager.acquire_proxies('t-acc-8', 50, 60, 'bls', 'test', null, true) where proxy_id = pg)
       then raise exception 'T6: bls получил прокси gmail_login'; end if;

    -- ---- T7: админ-функции знают цель
    j := bls_proxy_manager.admin_upsert_proxies('[{"host":"192.0.2.78","port":1081,"purposes":["gmail_login"]}]');
    if (select purposes from bls_proxy_manager.proxies where host='192.0.2.78') <> '{gmail_login}' then raise exception 'T7: admin_upsert_proxies отбросил gmail_login'; end if;
    perform bls_proxy_manager.bot_token_touch(repeat('a', 64));
    insert into bls_proxy_manager.bot_clients(purpose, name, token_hash, token_hint) values ('gmail_login','t27',repeat('c',64),'wxyz');
    begin
        insert into bls_proxy_manager.bot_clients(purpose, name, token_hash, token_hint) values ('nope','t27',repeat('d',64),'wxyz');
        raise exception 'T7: левая цель принята в bot_clients';
    exception when check_violation then null; end;

    raise notice 'ВСЕ ТЕСТЫ 27 ПРОШЛИ';
end
$t$;
rollback;
