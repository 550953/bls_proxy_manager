-- Выгружено из живой базы (21.10.2026): эти функции вызывает proxy_service.py, но в архиве их не было
-- (файлы 10–12 и 18–20 не попали). Нужны, чтобы репозиторий воспроизводил боевую схему.
-- account_needs_reset здесь — исходная версия; её заменяет 21_visaglobal_policy.sql.
create or replace function bls_proxy_manager.ack_profile_reset(p_account_id text)
returns void language plpgsql security definer set search_path = bls_proxy_manager, pg_temp
as $$
begin
    if p_account_id is null or length(p_account_id) = 0 then
        raise exception 'account_id required';
    end if;
    insert into proxy_events(account_id, event_type) values (p_account_id, 'profile_reset');
end $$;
