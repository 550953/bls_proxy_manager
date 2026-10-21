-- 21_test.sql — проверка политики VisaGlobal. Всё внутри транзакции и откатывается (rollback): боевые данные не меняются.
-- Запускать ПОСЛЕ 21_visaglobal_policy.sql. Любой провал даёт exception с описанием.
begin;
do $t$
declare
    pid  text;
    pids text[];
    f    timestamptz;
    q    timestamptz;
    sec  numeric;
    lid  uuid;
    v    text;
    n    integer;
    i    integer;

begin
    select array_agg(id) into pids from (select id from bls_proxy_manager.proxies
                                          where 'visaglobal' = any(purposes) order by id limit 3) x;
    if pids is null then raise exception 'TEST: нет прокси с целью visaglobal'; end if;
    pid := pids[1];

    insert into bls_proxy_manager.proxy_purpose_state(proxy_id, purpose) values (pid, 'visaglobal') on conflict do nothing;
    update bls_proxy_manager.proxy_purpose_state
       set free_at = now(), quarantined_until = null, last_ok_at = null, consecutive_failures = 0
     where proxy_id = pid and purpose = 'visaglobal';

    -- 1. ошибка аккаунта IP не трогает
    lid := gen_random_uuid();
    insert into bls_proxy_manager.leases(id, proxy_id, account_id, purpose, client_id, acquired_at, expires_at)
    values (lid, pid, 't-acc-1', 'visaglobal', 'test', now(), now() + interval '5 min');
    perform bls_proxy_manager.report_event(lid, 'error', 'AUTH_INVALID_CREDS', 'auth', null, '{}');
    select free_at into f from bls_proxy_manager.proxy_purpose_state where proxy_id = pid and purpose = 'visaglobal';
    if f > now() + interval '2 seconds' then raise exception 'TEST1: AUTH_* сдвинул free_at'; end if;
    select verdict into v from bls_proxy_manager.proxy_events where lease_id = lid and event_type = 'error';
    if v <> 'log:account' then raise exception 'TEST1: verdict=%', v; end if;

    -- 2. неизвестный код: только журнал
    perform bls_proxy_manager.report_event(lid, 'error', 'SOMETHING_NEW', 'x', null, '{}');
    select free_at into f from bls_proxy_manager.proxy_purpose_state where proxy_id = pid and purpose = 'visaglobal';
    if f > now() + interval '2 seconds' then raise exception 'TEST2: неизвестный код сдвинул free_at'; end if;
    select verdict into v from bls_proxy_manager.proxy_events where lease_id = lid and error_code = 'SOMETHING_NEW';
    if v <> 'log:unknown_code' then raise exception 'TEST2: verdict=%', v; end if;

    -- 3. info/warn только журнал
    perform bls_proxy_manager.report_event(lid, 'warn', 'SOLVER_SWITCHED', 'solver', null, '{}');
    select free_at into f from bls_proxy_manager.proxy_purpose_state where proxy_id = pid and purpose = 'visaglobal';
    if f > now() + interval '2 seconds' then raise exception 'TEST3: warn сдвинул free_at'; end if;

    -- 4. NET_TIMEOUT: кулдаун 120, затем растёт (240)
    lid := gen_random_uuid();
    insert into bls_proxy_manager.leases(id, proxy_id, account_id, purpose, client_id, acquired_at, expires_at)
    values (lid, pid, 't-acc-1', 'visaglobal', 'test', now(), now() + interval '5 min');
    perform bls_proxy_manager.report_event(lid, 'error', 'NET_TIMEOUT', 'network', null, '{}');
    select extract(epoch from free_at - now()) into sec from bls_proxy_manager.proxy_purpose_state where proxy_id = pid and purpose = 'visaglobal';
    if sec not between 110 and 125 then raise exception 'TEST4a: cooldown=% (ожидали ~120)', sec; end if;
    lid := gen_random_uuid();
    insert into bls_proxy_manager.leases(id, proxy_id, account_id, purpose, client_id, acquired_at, expires_at)
    values (lid, pid, 't-acc-1', 'visaglobal', 'test', now(), now() + interval '5 min');
    perform bls_proxy_manager.report_event(lid, 'error', 'NET_TIMEOUT', 'network', null, '{}');
    select extract(epoch from free_at - now()) into sec from bls_proxy_manager.proxy_purpose_state where proxy_id = pid and purpose = 'visaglobal';
    if sec not between 230 and 245 then raise exception 'TEST4b: cooldown=% (ожидали ~240)', sec; end if;

    -- 5. NET_PROXY_DEAD: один аккаунт карантин не выдаёт, второй — выдаёт
    for i in 1..2 loop
        lid := gen_random_uuid();
        insert into bls_proxy_manager.leases(id, proxy_id, account_id, purpose, client_id, acquired_at, expires_at)
        values (lid, pid, 't-acc-1', 'visaglobal', 'test', now(), now() + interval '5 min');
        perform bls_proxy_manager.report_event(lid, 'error', 'NET_PROXY_DEAD', 'network', null, '{}');
    end loop;
    select quarantined_until into q from bls_proxy_manager.proxy_purpose_state where proxy_id = pid and purpose = 'visaglobal';
    if q is not null and q > now() then raise exception 'TEST5a: один аккаунт устроил карантин'; end if;
    lid := gen_random_uuid();
    insert into bls_proxy_manager.leases(id, proxy_id, account_id, purpose, client_id, acquired_at, expires_at)
    values (lid, pid, 't-acc-2', 'visaglobal', 'test', now(), now() + interval '5 min');
    perform bls_proxy_manager.report_event(lid, 'error', 'NET_PROXY_DEAD', 'network', null, '{}');
    select quarantined_until into q from bls_proxy_manager.proxy_purpose_state where proxy_id = pid and purpose = 'visaglobal';
    if q is null or q <= now() then raise exception 'TEST5b: карантина нет после серии с двух аккаунтов'; end if;

    -- 6. успех обнуляет серию
    update bls_proxy_manager.proxy_purpose_state set quarantined_until = null, free_at = now() where proxy_id = pid and purpose = 'visaglobal';
    lid := gen_random_uuid();
    insert into bls_proxy_manager.leases(id, proxy_id, account_id, purpose, client_id, acquired_at, expires_at)
    values (lid, pid, 't-acc-1', 'visaglobal', 'test', now(), now() + interval '5 min');
    perform bls_proxy_manager.report_event(lid, 'cycle_ok', null, 'login', 123, '{}');
    perform bls_proxy_manager.report_event(lid, 'error', 'NET_TIMEOUT', 'network', null, '{}');
    select extract(epoch from free_at - now()) into sec from bls_proxy_manager.proxy_purpose_state where proxy_id = pid and purpose = 'visaglobal';
    if sec not between 110 and 125 then raise exception 'TEST6: после cycle_ok кулдаун=% (ожидали ~120)', sec; end if;

    -- 7. возврат без кода со статусом UNKNOWN фиксируется
    perform bls_proxy_manager.release_lease(lid, 'released', null, 'single_diagnostic',
                                            '{"operation_status":"UNKNOWN","operation_reason":"security_response_unconfirmed"}');
    select count(*) into n from bls_proxy_manager.proxy_events where lease_id = lid and error_code = 'UNKNOWN';
    if n < 1 then raise exception 'TEST7: UNKNOWN не записан'; end if;

    -- 8. потолок аренды: аренде 31 минута -> /renew даёт null
    lid := gen_random_uuid();
    insert into bls_proxy_manager.leases(id, proxy_id, account_id, purpose, client_id, acquired_at, expires_at)
    values (lid, pid, 't-acc-3', 'visaglobal', 'test', now() - interval '31 min', now() + interval '1 min');
    if bls_proxy_manager.renew_lease(lid, 300) is not null then raise exception 'TEST8: renew прошёл за потолком'; end if;
    lid := gen_random_uuid();
    insert into bls_proxy_manager.leases(id, proxy_id, account_id, purpose, client_id, acquired_at, expires_at)
    values (lid, pid, 't-acc-3', 'visaglobal', 'test', now() - interval '10 min', now() + interval '1 min');
    if bls_proxy_manager.renew_lease(lid, 3600) is null then raise exception 'TEST8b: renew отклонён зря'; end if;

    -- 9. CF_CHALLENGE_LOOP с трёх разных IP -> сброс профиля, IP не наказан
    if array_length(pids, 1) = 3 then
        for i in 1..3 loop
            lid := gen_random_uuid();
            insert into bls_proxy_manager.leases(id, proxy_id, account_id, purpose, client_id, acquired_at, expires_at)
            values (lid, pids[i], 't-acc-reset', 'visaglobal', 'test', now(), now() + interval '5 min');
            perform bls_proxy_manager.report_event(lid, 'error', 'CF_CHALLENGE_LOOP', 'cloudflare', null, '{}');
        end loop;
        if not bls_proxy_manager.account_needs_reset('t-acc-reset') then
            raise exception 'TEST9: сброс профиля не запрошен';
        end if;
    end if;

    raise notice 'ВСЕ ТЕСТЫ 21 ПРОШЛИ';
end
$t$;
rollback;
