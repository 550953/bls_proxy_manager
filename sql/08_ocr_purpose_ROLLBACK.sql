-- =============================================================================
-- 08_ocr_purpose_ROLLBACK.sql — полный откат 08_ocr_purpose.sql.
-- Возвращает admin_upsert_proxies / admin_get_settings / admin_set_setting к версиям из 03 и 06,
-- удаляет ocr_get_pool / ocr_report_batch, ocr_* настройки и события ocr_*.
-- Прокси НЕ удаляются. У прокси с purposes = {ocr} кликер их и так не берёт.
-- Безопасно запускать повторно. Кликер откат не замечает.
-- =============================================================================
set search_path = bls_proxy_manager, pg_temp;

create or replace function bls_proxy_manager.admin_upsert_proxies(p_items jsonb) returns jsonb
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    it    jsonb;
    v_id  text;
    v_host text;
    v_port integer;
    v_ins integer := 0;
    v_upd integer := 0;
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

        select id into v_id from proxies where host = v_host and port = v_port limit 1;

        if v_id is null then
            v_id := coalesce(nullif(it->>'id', ''), v_host || ':' || v_port);
            insert into proxies(id, scheme, host, port, kind, pool, max_leases)
            values (v_id,
                    coalesce(it->>'scheme', 'socks5'), v_host, v_port,
                    coalesce(it->>'kind', 'shared'), nullif(it->>'pool', ''),
                    coalesce((it->>'max_leases')::integer, 1));
            v_ins := v_ins + 1;
        else
            update proxies
               set scheme     = coalesce(it->>'scheme', scheme),
                   kind       = coalesce(it->>'kind', kind),
                   pool       = coalesce(nullif(it->>'pool', ''), pool),
                   max_leases = coalesce((it->>'max_leases')::integer, max_leases)
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

create or replace function bls_proxy_manager.admin_get_settings() returns table (key text, value text, note text)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select s.key, s.value #>> '{}', s.note from settings s
     where s.key in ('cooldown_ok_s','cooldown_proxy_fault_s','fault_cooldown2_s','fault_disable_count',
                     'repeat_fault_window_min','fault_soft_cooldown_s','site_check_enabled','site_check_attempts')
     order by s.key
$$;

create or replace function bls_proxy_manager.admin_set_setting(p_key text, p_value text) returns void
language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
begin
    if p_key not in ('cooldown_ok_s','cooldown_proxy_fault_s','fault_cooldown2_s','fault_disable_count',
                     'repeat_fault_window_min','fault_soft_cooldown_s','site_check_enabled','site_check_attempts') then
        raise exception 'key not allowed: %', p_key;
    end if;
    if p_value !~ '^[0-9]{1,6}$' then raise exception 'integer 0..999999 expected'; end if;
    update settings set value = to_jsonb(p_value::integer) where key = p_key;
    if not found then raise exception 'unknown key %', p_key; end if;
end $$;

drop function if exists bls_proxy_manager.ocr_get_pool();
drop function if exists bls_proxy_manager.ocr_report_batch(jsonb);

delete from bls_proxy_manager.settings where key like 'ocr\_%';
delete from bls_proxy_manager.proxy_events where event_type in ('ocr_fail', 'ocr_geo');

-- Если OCR-прокси больше не нужны вообще (по умолчанию закомментировано):
-- delete from bls_proxy_manager.proxies where purposes = '{ocr}';

reset search_path;

select count(*) as ocr_functions_left from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'bls_proxy_manager' and proname like 'ocr\_%';
