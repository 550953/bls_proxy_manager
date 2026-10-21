-- Откат миграции 24: убирает отчёт для дашборда и функцию владельца аренды.
drop function if exists bls_proxy_manager.admin_visa_report(text, integer);
drop function if exists bls_proxy_manager.lease_owner(uuid);
