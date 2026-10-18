-- 15_enable_visaglobal.sql — дать часть прокси цель VisaGlobal. Запускать ПОСЛЕ 13 и 14.
-- Поменяйте имя пула и число в двух местах ниже, если нужно. Прокси остаются и для BLS.
update bls_proxy_manager.proxies
   set purposes = (select array_agg(distinct x order by x) from unnest(purposes || array['visaglobal']) x)
 where id in (select id from bls_proxy_manager.proxies
               where pool = 'Proxysoxy_17.10.2026_100' and 'bls' = any(purposes)
               order by random() limit 30);

select bls_proxy_manager.admin_purpose_reset('visaglobal');   -- создаст состояние, вернёт число прокси

-- Проверка: сколько прокси VisaGlobal свободно/в кулдауне
select status, count(*) from bls_proxy_manager.v_purpose_status where purpose = 'visaglobal' group by 1;
