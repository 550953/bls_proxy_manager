-- 16_lease_purpose.sql — нужен для токенов по целям: сервис проверяет, что аренда принадлежит цели токена.
-- Запускать ДО git push нового proxy_service.py. Безопасно повторять.
create or replace function bls_proxy_manager.lease_purpose(p_lease_id uuid) returns text
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$ select purpose from leases where id = p_lease_id $$;

revoke all on function bls_proxy_manager.lease_purpose(uuid) from public;
grant execute on function bls_proxy_manager.lease_purpose(uuid) to bls_issuer, bls_reporter;

select bls_proxy_manager.lease_purpose(gen_random_uuid()) as must_be_null;
