-- 27_snapshot.sql — снимок «до/после» (шаг A1). Запустите ДО 27 и ПОСЛЕ, сохраните оба вывода и сравните.
-- Статичные таблицы должны совпасть байт в байт. Живые (состояние, аренды) сравниваются только по счётчикам и
-- меняются сами по себе от трафика BLS и VisaGlobal, поэтому для них смотрим, чтобы не появилось строк gmail_login.
select 'error_codes' as t, purpose, count(*) as n,
       md5(string_agg(row(code, blame, cooldown_s, reset_profile, quarantine_ok, needs_confirm, probe)::text, '|' order by code)) as h
  from bls_proxy_manager.error_codes where purpose in ('bls','visaglobal','ocr') group by purpose
union all
select 'error_aliases', purpose, count(*), md5(string_agg(row(alias, code)::text, '|' order by alias))
  from bls_proxy_manager.error_aliases where purpose in ('bls','visaglobal','ocr') group by purpose
union all
select 'purpose_settings', purpose, count(*), md5(string_agg(row(key, value)::text, '|' order by key))
  from bls_proxy_manager.purpose_settings where purpose in ('bls','visaglobal','ocr') group by purpose
union all
select 'bot_clients', purpose, count(*), md5(string_agg(row(name, token_hash, enabled)::text, '|' order by name))
  from bls_proxy_manager.bot_clients where purpose <> 'gmail_login' group by purpose
union all
select 'proxies(без purposes gmail_login)', '-', count(*),
       md5(string_agg(row(id, scheme, host, port, array_remove(purposes, 'gmail_login'))::text, '|' order by id))
  from bls_proxy_manager.proxies
union all
select 'proxy_state(live)', '-', count(*), null from bls_proxy_manager.proxy_state
union all
select 'proxy_purpose_state(live)', purpose, count(*), null
  from bls_proxy_manager.proxy_purpose_state where purpose in ('bls','visaglobal','ocr') group by purpose
order by 1, 2;
