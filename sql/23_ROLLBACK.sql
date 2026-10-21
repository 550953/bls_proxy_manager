-- Откат 23: возвращает функции из копии _fn_backup_23, убирает алиасы и новые коды.
do $$
declare r record;
begin
    for r in select def from bls_proxy_manager._fn_backup_23 loop
        execute r.def;
    end loop;
end $$;
drop function if exists bls_proxy_manager.lease_verdict(uuid);
drop function if exists bls_proxy_manager.error_code_resolve(text, text);
drop table if exists bls_proxy_manager.error_aliases;
delete from bls_proxy_manager.error_codes
 where purpose = 'visaglobal'
   and code in ('CAPTCHA_UNSOLVED','CAPTCHA_EXPIRED','PROFILE_BROKEN','VFS_EMPTY_403201','AUTH_ISSUE');
-- когда откат проверен: drop table bls_proxy_manager._fn_backup_23;
