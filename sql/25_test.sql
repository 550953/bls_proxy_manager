-- Проверка миграции 25. Всё выполняется внутри блока и заканчивается намеренной ошибкой TEST_PASSED,
-- поэтому в базе ничего не остаётся. Если вместо TEST_PASSED видите другое сообщение, проверка не прошла.
do $$
declare v_id uuid; n integer; v_cnt integer;
begin
    v_id := bls_proxy_manager.admin_bot_client_create('visaglobal', 'test-client', repeat('a', 64), 'abcd');
    select count(*) into v_cnt from bls_proxy_manager.bot_tokens_active() where name = 'test-client';
    if v_cnt <> 1 then raise exception 'FAIL: включённый токен не виден сервису'; end if;

    perform bls_proxy_manager.admin_bot_client_set_enabled(v_id, false);
    select count(*) into v_cnt from bls_proxy_manager.bot_tokens_active() where name = 'test-client';
    if v_cnt <> 0 then raise exception 'FAIL: отключённый токен всё ещё действует'; end if;

    perform bls_proxy_manager.bot_token_touch(repeat('a', 64));
    begin
        perform bls_proxy_manager.admin_bot_client_create('visaglobal', 'test-client', repeat('b', 64), 'wxyz');
        raise exception 'FAIL: дубль имени не отклонён';
    exception when unique_violation then null; end;
    begin
        perform bls_proxy_manager.admin_bot_client_create('ocr', 'x', repeat('c', 64), 'abcd');
        raise exception 'FAIL: цель ocr не должна принимать токены клиентов';
    exception when check_violation then null; end;

    if (select count(*) from bls_proxy_manager.admin_bot_clients_list() where name = 'test-client') <> 1 then
        raise exception 'FAIL: клиент не виден в списке'; end if;
    n := bls_proxy_manager.admin_bot_client_delete(v_id);
    if n <> 1 then raise exception 'FAIL: удаление'; end if;
    raise exception 'TEST_PASSED';
end $$;
