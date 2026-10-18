-- 17_cloudflare_stat.sql — счётчик возвратов с заданным кодом ошибки по цели (для Cloudflare: CF_CHALLENGE_LOOP).
-- Нужен для чипа «Cloudflare» в блоке «Статистика». Ничего не штрафует и не меняет в состоянии прокси.
-- Накатывать в Supabase SQL Editor ДО или ПОСЛЕ git push: без функции сервис просто не покажет чип.
-- Безопасно повторять.
create or replace function bls_proxy_manager.admin_purpose_code_count(
    p_purpose text, p_code text, p_hours integer default 24) returns bigint
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    select count(distinct e.lease_id)
      from proxy_events e
      join leases l on l.id = e.lease_id
     where l.purpose = p_purpose
       and e.event_type = 'error'
       and e.error_code = p_code
       and e.created_at > now() - make_interval(hours => least(greatest(coalesce(p_hours, 24), 1), 336))
       and e.created_at >= coalesce(
             (select nullif(s.value #>> '{}', '')::timestamptz from settings s where s.key = 'stats_since'),
             '-infinity'::timestamptz)
$$;

revoke all on function bls_proxy_manager.admin_purpose_code_count(text,text,integer) from public, anon, authenticated;
grant execute on function bls_proxy_manager.admin_purpose_code_count(text,text,integer) to bls_admin;

-- Проверка: сколько Cloudflare-зависаний у VisaGlobal за 24 ч
select bls_proxy_manager.admin_purpose_code_count('visaglobal', 'CF_CHALLENGE_LOOP', 24) as cf_24h;
