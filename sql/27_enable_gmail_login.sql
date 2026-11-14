-- 27_enable_gmail_login.sql — дать 2–3 ТЕСТОВЫХ прокси цель gmail_login. Запускать ПОСЛЕ 27_gmail_login_purpose.sql.
-- Впишите id прокси ниже. Цели у прокси остаются прежними (добавляется ещё одна). Максимум 3 цели на прокси
-- (ограничение API): прокси, у которых уже 3 цели, пропускаются и выводятся в конце.
-- Для теста лучше выделенные прокси: у bls/visaglobal свой max_leases и общий слот.
with ids as (select unnest(array['ВПИШИТЕ_ID_1', 'ВПИШИТЕ_ID_2', 'ВПИШИТЕ_ID_3']) as id)
update bls_proxy_manager.proxies p
   set purposes = (select array_agg(distinct x order by x) from unnest(p.purposes || array['gmail_login']) x)
 where p.id in (select id from ids)
   and not ('gmail_login' = any (p.purposes))
   and cardinality(p.purposes) < 3;

select bls_proxy_manager.admin_purpose_reset('gmail_login');   -- создаст состояние, вернёт число прокси

-- Проверка: прокси цели и их статус; затем те, кого пропустили из-за лимита целей
select status, count(*) from bls_proxy_manager.v_purpose_status where purpose = 'gmail_login' group by 1;
select id, purposes from bls_proxy_manager.proxies
 where id in ('ВПИШИТЕ_ID_1', 'ВПИШИТЕ_ID_2', 'ВПИШИТЕ_ID_3') and not ('gmail_login' = any (purposes));
