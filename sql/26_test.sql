-- Проверка миграции 26. Блок заканчивается намеренной ошибкой TEST_PASSED, поэтому в базе ничего не остаётся.
-- Если вместо TEST_PASSED видите другое сообщение, проверка не прошла.
do $$
declare v_id uuid; n integer; v_cnt integer; r record; v_pool text;
begin
    -- тестовые прокси в двух пулах (visaglobal)
    insert into bls_proxy_manager.proxies(id, scheme, host, port, pool, purposes, max_leases, enabled) values
      ('t26-a1','socks5','10.26.0.1',1,'T26_A','{visaglobal}',1,true),
      ('t26-a2','socks5','10.26.0.2',1,'T26_A','{visaglobal}',1,true),
      ('t26-b1','socks5','10.26.0.3',1,'T26_B','{visaglobal}',1,true),
      ('t26-n1','socks5','10.26.0.4',1,null,'{visaglobal}',1,true);

    -- создание: все пулы / конкретные / неизвестный / пустой список
    v_id := bls_proxy_manager.admin_bot_client_create('visaglobal','t26-all',repeat('a',64),'aaaa');
    if (select pools from bls_proxy_manager.admin_bot_clients_list() where id = v_id) is not null then
        raise exception 'FAIL: по умолчанию pools должен быть NULL (все пулы)'; end if;
    begin perform bls_proxy_manager.admin_bot_client_create('visaglobal','t26-bad',repeat('b',64),'bbbb',array['NO_SUCH_POOL']);
          raise exception 'FAIL: неизвестный пул не отклонён';
    exception when invalid_parameter_value then null; end;
    begin perform bls_proxy_manager.admin_bot_client_create('visaglobal','t26-empty',repeat('c',64),'cccc',array[]::text[]);
          raise exception 'FAIL: пустой список не отклонён';
    exception when invalid_parameter_value then null; end;
    begin perform bls_proxy_manager.admin_bot_client_create('visaglobal','t26-blls',repeat('d',64),'dddd',array['ZvSDCG_other_purpose']);
          raise exception 'FAIL: пул другой цели не отклонён';
    exception when invalid_parameter_value then null; end;
    v_id := bls_proxy_manager.admin_bot_client_create('visaglobal','t26-a',repeat('e',64),'eeee',array['T26_A',' T26_A ']);
    if (select pools from bls_proxy_manager.bot_tokens_active() where name = 't26-a') <> array['T26_A'] then
        raise exception 'FAIL: pools не дошли до сервиса или не нормализованы'; end if;

    -- смена пулов
    n := bls_proxy_manager.admin_bot_client_set_pools(v_id, array['T26_A','T26_B']);
    if n <> 1 then raise exception 'FAIL: set_pools'; end if;
    n := bls_proxy_manager.admin_bot_client_set_pools(v_id, null);
    if (select pools from bls_proxy_manager.admin_bot_clients_list() where id = v_id) is not null then
        raise exception 'FAIL: сброс на все пулы'; end if;
    if bls_proxy_manager.admin_bot_client_set_pools(gen_random_uuid(), null) <> 0 then
        raise exception 'FAIL: неизвестный клиент должен дать 0'; end if;

    -- список пулов для назначения
    if (select count(*) from bls_proxy_manager.admin_purpose_pools('visaglobal') where pool in ('T26_A','T26_B')) <> 2 then
        raise exception 'FAIL: admin_purpose_pools'; end if;

    -- выдача только из пула T26_A: 20 раз подряд, всегда t26-a1 или t26-a2
    for i in 1..20 loop
        select * into r from bls_proxy_manager.acquire_proxies_scoped('t26-acc'||i, 1, 60, 'visaglobal', 'x', '{}', true, array['T26_A']) limit 1;
        if r.proxy_id is null then
            if i <= 2 then raise exception 'FAIL: из пула T26_A ничего не выдано (i=%)', i; end if;
            exit;
        end if;
        select pool into v_pool from bls_proxy_manager.proxies where id = r.proxy_id;
        if v_pool is distinct from 'T26_A' then raise exception 'FAIL: выдан прокси не из разрешённого пула: % (%)', r.proxy_id, v_pool; end if;
    end loop;
    -- два прокси в пуле заняты (max_leases = 1): третий запрос пуст, хотя в T26_B и без пула есть свободные
    select count(*) into v_cnt from bls_proxy_manager.acquire_proxies_scoped('t26-acc-extra', 1, 60, 'visaglobal', 'x', '{}', true, array['T26_A']);
    if v_cnt <> 0 then raise exception 'FAIL: пул T26_A исчерпан, а прокси выданы из чужих'; end if;
    -- без ограничения (NULL) чужие пулы доступны
    select * into r from bls_proxy_manager.acquire_proxies_scoped('t26-acc-free', 1, 60, 'visaglobal', 'x', '{}', true, null) limit 1;
    if r.proxy_id is null then raise exception 'FAIL: без ограничения прокси не выдан'; end if;
    -- пул без имени (null) доступен только токену «все пулы»
    select * into r from bls_proxy_manager.acquire_proxies_scoped('t26-acc-b', 1, 60, 'visaglobal', 'x', '{}', true, array['T26_B']) limit 1;
    if r.proxy_id <> 't26-b1' then raise exception 'FAIL: пул T26_B дал %', r.proxy_id; end if;

    -- сколько ждать: пул T26_A занят, T26_B (занят выше) — значение в разумных пределах
    n := bls_proxy_manager.next_available_in_scoped('visaglobal', array['T26_A']);
    if n < 1 or n > 3600 then raise exception 'FAIL: next_available_in_scoped=%', n; end if;
    if bls_proxy_manager.next_available_in_scoped('visaglobal', array['NO_SUCH']) <> 60 then
        raise exception 'FAIL: пустой выбор должен дать 60'; end if;

    raise exception 'TEST_PASSED';
end $$;
