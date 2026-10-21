-- Проверка миграции 24: только чтение, ничего не меняет.
-- 1) отчёт возвращает все разделы
select jsonb_object_keys(bls_proxy_manager.admin_visa_report('visaglobal', 168)) as section order by 1;
-- ожидается: accounts, avg_bad_ip_share, clients, hours, ips, reasons, unknown

-- 2) владелец последней аренды VisaGlobal (null, если client_id не задан)
select bls_proxy_manager.lease_owner((select id from bls_proxy_manager.leases
                                       where purpose = 'visaglobal' order by acquired_at desc limit 1)) as owner;

-- 3) неизвестная аренда даёт null, а не ошибку
select bls_proxy_manager.lease_owner('00000000-0000-0000-0000-000000000000') is null as unknown_lease_is_null;
