-- 13_smoke_test.sql — проверка V1 на вашей БД. Ничего не оставляет: в конце специально
-- вызывается исключение, и Postgres откатывает ВСЁ (тестовые прокси, аренды, события).
-- Успех = сообщение «ТЕСТ ПРОЙДЕН». Любое другое сообщение = нашли проблему, пришлите его мне.
do $$
declare
    a text := 'test-vfs-a:1';
    b text := 'test-vfs-b:2';
    v_others text[];
    v_excl_b text[];
    v_excl_a text[];
    v_lease uuid;
    v_pid text;
    v_ok boolean;
    i integer;
begin
    insert into bls_proxy_manager.proxies(id, scheme, host, port, purposes) values
        (a, 'socks5', 'test-vfs-a', 1, '{bls,visaglobal}'),
        (b, 'socks5', 'test-vfs-b', 2, '{bls,visaglobal}');
    insert into bls_proxy_manager.proxy_state(proxy_id) values (a), (b) on conflict do nothing;

    -- все настоящие прокси исключаем из выдачи, играем только на двух тестовых
    select coalesce(array_agg(id), '{}') into v_others from bls_proxy_manager.proxies where id not in (a, b);
    v_excl_b := v_others || b;   -- доступен только A
    v_excl_a := v_others || a;   -- доступен только B

    -- T1. BLS берёт A и отпускает с 429 -> A в бан-кулдауне ДЛЯ BLS
    select lease_id, proxy_id into v_lease, v_pid
      from bls_proxy_manager.acquire_proxies('tbls', 1, 300, 'bls', 'test', v_excl_b, true);
    if v_pid is distinct from a then raise exception 'T1: BLS acquire вернул %, ожидали %', v_pid, a; end if;
    perform bls_proxy_manager.release_lease(v_lease, 'test', 'HTTP_429', 'test', '{}'::jsonb);
    select free_at > now() + interval '10 minutes' into v_ok from bls_proxy_manager.proxy_state where proxy_id = a;
    if not coalesce(v_ok, false) then raise exception 'T1: у BLS нет бан-кулдауна после 429'; end if;

    -- T2. VisaGlobal на ТОМ ЖЕ прокси A получает выдачу (кулдаун BLS его не морозит)
    select lease_id, proxy_id into v_lease, v_pid
      from bls_proxy_manager.acquire_proxies('tvfs', 1, 300, 'visaglobal', 'test', v_excl_b, true);
    if v_pid is distinct from a then raise exception 'T2: VisaGlobal не получил прокси A (вернул %)', v_pid; end if;
    perform bls_proxy_manager.release_lease(v_lease, 'test', null, 'test', '{}'::jsonb);

    -- T3. после обычного release у VisaGlobal свой кулдаун; BLS по-прежнему заморожен своим
    select proxy_id into v_pid from bls_proxy_manager.acquire_proxies('tvfs', 1, 300, 'visaglobal', 'test', v_excl_b, true);
    if v_pid is not null then raise exception 'T3: VisaGlobal получил прокси % во время своего кулдауна', v_pid; end if;
    update bls_proxy_manager.proxy_purpose_state set free_at = now() where proxy_id = a and purpose = 'visaglobal';
    select proxy_id into v_pid from bls_proxy_manager.acquire_proxies('tbls2', 1, 300, 'bls', 'test', v_excl_b, true);
    if v_pid is not null then raise exception 'T3: BLS получил прокси % во время кулдауна BLS', v_pid; end if;
    select proxy_id into v_pid from bls_proxy_manager.acquire_proxies('tvfs', 1, 300, 'visaglobal', 'test', v_excl_b, true);
    if v_pid is distinct from a then raise exception 'T3: VisaGlobal не получил A после снятия своего кулдауна'; end if;
    update bls_proxy_manager.leases set released_at = now() where released_at is null and account_id in ('tvfs','tbls2');

    -- T4. 5 ошибок 429 подряд у VisaGlobal на B -> карантин ТОЛЬКО для VisaGlobal
    for i in 1..5 loop
        select lease_id, proxy_id into v_lease, v_pid
          from bls_proxy_manager.acquire_proxies('tvfs', 1, 300, 'visaglobal', 'test', v_excl_a, true);
        if v_pid is distinct from b then raise exception 'T4: итерация %: ожидали B, получили %', i, v_pid; end if;
        perform bls_proxy_manager.release_lease(v_lease, 'test', 'HTTP_429', 'test', '{}'::jsonb);
        update bls_proxy_manager.proxy_purpose_state set free_at = now() where proxy_id = b and purpose = 'visaglobal';
    end loop;
    select quarantined_until > now() into v_ok from bls_proxy_manager.proxy_purpose_state
     where proxy_id = b and purpose = 'visaglobal';
    if not coalesce(v_ok, false) then raise exception 'T4: нет карантина VisaGlobal после 5 ошибок'; end if;
    select (quarantined_until is not null and quarantined_until > now()) or consecutive_failures <> 0 into v_ok
      from bls_proxy_manager.proxy_state where proxy_id = b;
    if coalesce(v_ok, false) then raise exception 'T4: ошибки VisaGlobal задели состояние BLS у прокси B'; end if;
    select proxy_id into v_pid from bls_proxy_manager.acquire_proxies('tvfs', 1, 300, 'visaglobal', 'test', v_excl_a, true);
    if v_pid is not null then raise exception 'T4: VisaGlobal получил B из карантина'; end if;
    select proxy_id into v_pid from bls_proxy_manager.acquire_proxies('tbls3', 1, 300, 'bls', 'test', v_excl_a, true);
    if v_pid is distinct from b then raise exception 'T4: BLS не получил B (вернул %)', v_pid; end if;
    update bls_proxy_manager.leases set released_at = now() where released_at is null and account_id = 'tbls3';

    -- T5. сбой самого прокси у VisaGlobal -> ступень 1 (кулдаун) только для VisaGlobal
    update bls_proxy_manager.proxy_purpose_state
       set quarantined_until = null, free_at = now(), consecutive_failures = 0 where proxy_id = b and purpose = 'visaglobal';
    select lease_id into v_lease
      from bls_proxy_manager.acquire_proxies('tvfs', 1, 300, 'visaglobal', 'test', v_excl_a, true);
    if v_lease is null then raise exception 'T5: не удалось взять B для проверки ступеней'; end if;
    perform bls_proxy_manager.report_event(v_lease, 'error', 'PROXY_CONNECT_FAILED', 'test', null, '{}'::jsonb);
    select fault_count = 1 and free_at > now() + interval '5 minutes' into v_ok
      from bls_proxy_manager.proxy_purpose_state where proxy_id = b and purpose = 'visaglobal';
    if not coalesce(v_ok, false) then raise exception 'T5: ступень 1 у VisaGlobal не сработала'; end if;
    select fault_count = 0 and not auto_disabled into v_ok from bls_proxy_manager.proxy_state where proxy_id = b;
    if not coalesce(v_ok, false) then raise exception 'T5: сбой VisaGlobal задел ступени BLS'; end if;

    raise exception 'ТЕСТ ПРОЙДЕН: T1–T5 ок. Все изменения откачены.';
end $$;
