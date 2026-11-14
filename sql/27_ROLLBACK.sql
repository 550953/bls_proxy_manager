-- Откат 27: удаляет только строки gmail_login и возвращает admin_upsert_proxies и check токенов как было.
-- Журнал (leases, proxy_events) не трогаем; активные аренды gmail_login закрываем.
begin;
set local lock_timeout = '5s';
update bls_proxy_manager.leases set released_at = now(), release_reason = 'rollback_27'
 where purpose = 'gmail_login' and released_at is null;
update bls_proxy_manager.proxies set purposes = array_remove(purposes, 'gmail_login')
 where 'gmail_login' = any (purposes);
delete from bls_proxy_manager.proxy_purpose_state where purpose = 'gmail_login';
delete from bls_proxy_manager.purpose_settings    where purpose = 'gmail_login';
delete from bls_proxy_manager.error_aliases       where purpose = 'gmail_login';
delete from bls_proxy_manager.error_codes         where purpose = 'gmail_login';
delete from bls_proxy_manager.bot_clients         where purpose = 'gmail_login';
alter table bls_proxy_manager.bot_clients drop constraint if exists bot_clients_purpose_check;
alter table bls_proxy_manager.bot_clients
    add constraint bot_clients_purpose_check check (purpose in ('bls', 'visaglobal'));
do $$
declare r record;
begin
    if to_regclass('bls_proxy_manager._fn_backup_27') is not null then
        for r in select def from bls_proxy_manager._fn_backup_27 loop
            execute r.def;
        end loop;
    end if;
end $$;
-- когда откат проверен: drop table bls_proxy_manager._fn_backup_27;
commit;
