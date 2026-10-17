-- 07_reset_all.sql — «выдать все прокси наново». Запускать ПОСЛЕ 06, когда готовы к тесту.
-- Включает все прокси, снимает карантины/кулдауны и обнуляет ступени.
-- Аренды, которые сейчас держат боты, НЕ трогает.
update bls_proxy_manager.proxies set enabled = true;
update bls_proxy_manager.proxy_state
   set free_at = now(), quarantined_until = null, quarantine_reason = null, quarantine_level = 0,
       quarantine_runs = 0, consecutive_failures = 0, probe_failures = 0,
       fault_count = 0, fault_first_at = null, fault_verdict = null, fault_snapshot = null,
       cooldown_reason = null, auto_disabled = false, disabled_reason = null, updated_at = now();
insert into bls_proxy_manager.proxy_events(event_type, detail)
values ('pool_run_reset', jsonb_build_object('source', '07_reset_all'));
select count(*) as proxies_enabled from bls_proxy_manager.proxies where enabled;
