-- Тест 23: идёт в транзакции и в конце откатывается (ожидаемая ошибка ALL_TESTS_PASSED_23 означает успех).
begin;
do $t$
declare
    pid text; l1 uuid; l3 uuid; l6 uuid; fa timestamptz; fb timestamptz; v text; c text; det jsonb; j jsonb;
begin
    select id into pid from bls_proxy_manager.proxies where 'visaglobal' = any(purposes) order by id limit 1;
    delete from bls_proxy_manager.proxy_events where proxy_id = pid;
    insert into bls_proxy_manager.proxy_purpose_state(proxy_id, purpose) values (pid,'visaglobal') on conflict do nothing;
    update bls_proxy_manager.proxy_purpose_state set free_at=now(), quarantined_until=null, last_ok_at=null,
        consecutive_failures=0, last_fault_at=null, fault_verdict=null, fault_snapshot=null where proxy_id=pid and purpose='visaglobal';

    -- T1: алиас ip_blocked -> CF_BLOCK, не подтверждён
    l1 := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at) values (l1,pid,'t-1','visaglobal','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.report_event(l1,'error','ip_blocked','cloudflare',null,'{"profile_id":"p1"}');
    select error_code, verdict, detail into c, v, det from bls_proxy_manager.proxy_events where lease_id=l1 and event_type='error';
    if c <> 'CF_BLOCK' or det->>'raw_code' <> 'ip_blocked' or v <> 'cooldown:120:unconfirmed' then raise exception 'T1 % % %', c, v, det; end if;

    -- T3: тот же профиль на другой аренде: не подтверждено
    l3 := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at) values (l3,pid,'t-1','visaglobal','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.report_event(l3,'error','CF_BLOCK','cloudflare',null,'{"profile_id":"p1"}');
    select verdict into v from bls_proxy_manager.proxy_events where lease_id=l3 and event_type='error';
    if v <> 'cooldown:120:unconfirmed' then raise exception 'T3 %', v; end if;

    -- T4: второй чистый профиль: подтверждено, 900 с, next_action=reset_profile
    l3 := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at) values (l3,pid,'t-1','visaglobal','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.report_event(l3,'error','CF_BLOCK','cloudflare',null,'{"profile_id":"p2"}');
    select verdict into v from bls_proxy_manager.proxy_events where lease_id=l3 and event_type='error';
    j := bls_proxy_manager.lease_verdict(l3);
    if v <> 'cooldown:900' or j->>'next_action' <> 'reset_profile' or (j->>'change_ip')::boolean is not true then raise exception 'T4 % %', v, j; end if;

    -- T7: нечистые профили не подтверждают
    delete from bls_proxy_manager.proxy_events where proxy_id = pid;
    update bls_proxy_manager.proxy_purpose_state set free_at=now() where proxy_id=pid and purpose='visaglobal';
    l3 := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at) values (l3,pid,'t-1','visaglobal','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.report_event(l3,'error','CF_BLOCK',null,null,'{"profile_id":"p5","profile_fresh":false}');
    l3 := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at) values (l3,pid,'t-1','visaglobal','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.report_event(l3,'error','CF_BLOCK',null,null,'{"profile_id":"p6","profile_fresh":false}');
    select verdict into v from bls_proxy_manager.proxy_events where lease_id=l3 and event_type='error';
    if v <> 'cooldown:120:unconfirmed' then raise exception 'T7 %', v; end if;

    -- T2: неизвестный код -> UNKNOWN, IP не трогаем
    select free_at into fa from bls_proxy_manager.proxy_purpose_state where proxy_id=pid and purpose='visaglobal';
    l6 := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at) values (l6,pid,'t-9','visaglobal','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.report_event(l6,'error','weird_code','login',null,'{}');
    select error_code, verdict, detail into c, v, det from bls_proxy_manager.proxy_events where lease_id=l6 and event_type='error';
    select free_at into fb from bls_proxy_manager.proxy_purpose_state where proxy_id=pid and purpose='visaglobal';
    if c <> 'UNKNOWN' or det->>'raw_code' <> 'weird_code' or v <> 'log:unknown' or fa <> fb then raise exception 'T2 % % %', c, v, det; end if;

    -- T5: account_issue -> AUTH_ISSUE, IP не трогаем, next_action=stop
    l6 := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at) values (l6,pid,'t-9','visaglobal','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.report_event(l6,'error','account_issue','login',null,'{}');
    select error_code, verdict into c, v from bls_proxy_manager.proxy_events where lease_id=l6 and event_type='error';
    select free_at into fb from bls_proxy_manager.proxy_purpose_state where proxy_id=pid and purpose='visaglobal';
    j := bls_proxy_manager.lease_verdict(l6);
    if c <> 'AUTH_ISSUE' or v <> 'log:account' or fa <> fb or j->>'next_action' <> 'stop' then raise exception 'T5 % % %', c, v, j; end if;

    -- T8: release с алиасом: канонический код в error и released
    l6 := gen_random_uuid();
    insert into bls_proxy_manager.leases(id,proxy_id,account_id,purpose,client_id,acquired_at,expires_at) values (l6,pid,'t-8','visaglobal','test',now(),now()+interval '5 min');
    perform bls_proxy_manager.release_lease(l6,'bad ip','proxy_dead','network','{}');
    if (select count(*) from bls_proxy_manager.proxy_events where lease_id=l6 and error_code='NET_PROXY_DEAD') <> 2 then raise exception 'T8'; end if;

    raise exception 'ALL_TESTS_PASSED_23';
end $t$;
rollback;
