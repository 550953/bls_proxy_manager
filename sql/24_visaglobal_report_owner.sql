-- 24: блок 4 (владелец аренды) и блок 5 (отчёт для дашборда VisaGlobal).
-- Только читает данные и добавляет функции. Откат: 24_ROLLBACK.sql. Проверка: 24_test.sql.
set local lock_timeout = '5s';

-- Блок 4: кто взял аренду (client_id из токена клиента или из запроса acquire)
create or replace function bls_proxy_manager.lease_owner(p_lease_id uuid)
returns text language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$ select client_id from leases where id = p_lease_id $$;
revoke all on function bls_proxy_manager.lease_owner(uuid) from public, anon, authenticated;
grant execute on function bls_proxy_manager.lease_owner(uuid) to bls_issuer, bls_reporter;

-- Блок 5: один JSON со всеми разделами отчёта
create or replace function bls_proxy_manager.admin_visa_report(p_purpose text default 'visaglobal', p_hours integer default 24)
returns jsonb language plpgsql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
declare
    v_h      integer := least(greatest(coalesce(p_hours, 24), 1), 336);
    v_since  timestamptz := coalesce((select nullif(s.value #>> '{}', '')::timestamptz from settings s where s.key = 'stats_since'),
                                     '-infinity'::timestamptz);
    v_from   timestamptz := greatest(now() - make_interval(hours => v_h), v_since);
    v_7d     timestamptz := greatest(now() - interval '7 days', v_since);
    j_reasons jsonb; j_ips jsonb; j_accs jsonb; j_unk jsonb; j_clients jsonb; v_avg numeric;
begin
    -- топ причин: аренд с таким кодом за 1 ч, 24 ч, 7 дней
    select coalesce(jsonb_agg(to_jsonb(x) order by x.n_24h desc, x.n_7d desc), '[]'::jsonb) into j_reasons from (
        select e.error_code as code, max(e.blame) as blame,
               count(distinct e.lease_id) filter (where e.created_at > greatest(now() - interval '1 hour',  v_since)) as n_1h,
               count(distinct e.lease_id) filter (where e.created_at > greatest(now() - interval '24 hours', v_since)) as n_24h,
               count(distinct e.lease_id) as n_7d
          from proxy_events e join leases l on l.id = e.lease_id
         where l.purpose = p_purpose and e.event_type = 'error' and e.error_code is not null
           and coalesce(e.verdict, '') <> 'dup' and e.created_at > v_7d
         group by e.error_code order by 4 desc, 5 desc limit 15) x;

    -- успешность по IP (без паролей): успехи и аренды с ошибкой
    select coalesce(jsonb_agg(to_jsonb(x) order by x.err desc, x.ok), '[]'::jsonb) into j_ips from (
        select e.proxy_id, p.host || ':' || p.port as addr,
               count(*) filter (where e.event_type = 'cycle_ok') as ok,
               count(distinct e.lease_id) filter (where e.event_type = 'error' and coalesce(e.verdict, '') <> 'dup') as err,
               (array_agg(e.error_code order by e.created_at desc) filter (where e.event_type = 'error'))[1] as last_code
          from proxy_events e join leases l on l.id = e.lease_id left join proxies p on p.id = e.proxy_id
         where l.purpose = p_purpose and e.created_at > v_from and e.event_type in ('cycle_ok','error')
         group by e.proxy_id, p.host, p.port order by 4 desc, 3 limit 20) x;

    -- успешность по аккаунту
    select coalesce(jsonb_agg(to_jsonb(x) order by x.err desc, x.ok), '[]'::jsonb) into j_accs from (
        select e.account_id,
               count(*) filter (where e.event_type = 'cycle_ok') as ok,
               count(distinct e.lease_id) filter (where e.event_type = 'error' and coalesce(e.verdict, '') <> 'dup') as err,
               (array_agg(e.error_code order by e.created_at desc) filter (where e.event_type = 'error'))[1] as last_code
          from proxy_events e join leases l on l.id = e.lease_id
         where l.purpose = p_purpose and e.created_at > v_from and e.event_type in ('cycle_ok','error') and e.account_id is not null
         group by e.account_id order by 3 desc, 2 limit 20) x;

    -- лента UNKNOWN: очередь на добавление новых кодов
    select coalesce(jsonb_agg(to_jsonb(x) order by x.t desc), '[]'::jsonb) into j_unk from (
        select e.created_at as t, e.account_id, e.phase, e.detail->>'raw_code' as raw_code,
               e.detail->>'operation_status' as status, e.detail->>'operation_reason' as reason,
               left(e.detail::text, 300) as detail
          from proxy_events e join leases l on l.id = e.lease_id
         where l.purpose = p_purpose and e.event_type = 'error' and e.error_code = 'UNKNOWN' and e.created_at > v_from
         order by e.created_at desc limit 20) x;

    -- доля аренд клиента с ошибкой «вина IP» против среднего
    select coalesce(sum(bad)::numeric / nullif(sum(n), 0), 0) into v_avg from (
        select count(*) as n,
               count(*) filter (where exists (select 1 from proxy_events e where e.lease_id = l.id and e.event_type = 'error'
                                              and e.blame = 'ip' and coalesce(e.verdict,'') <> 'dup')) as bad
          from leases l where l.purpose = p_purpose and l.acquired_at > v_from group by coalesce(l.client_id, '—')) c;
    select coalesce(jsonb_agg(to_jsonb(x) order by x.share desc), '[]'::jsonb) into j_clients from (
        select c.client, c.leases, c.bad_ip, round(c.bad_ip::numeric / nullif(c.leases, 0), 3) as share,
               (c.leases >= 10 and c.bad_ip::numeric / nullif(c.leases, 0) > greatest(2 * v_avg, 0.2)) as flagged
          from (select coalesce(l.client_id, '—') as client, count(*) as leases,
                       count(*) filter (where exists (select 1 from proxy_events e where e.lease_id = l.id and e.event_type = 'error'
                                                      and e.blame = 'ip' and coalesce(e.verdict,'') <> 'dup')) as bad_ip
                  from leases l where l.purpose = p_purpose and l.acquired_at > v_from group by 1) c
         order by 4 desc nulls last limit 20) x;

    return jsonb_build_object('hours', v_h, 'avg_bad_ip_share', round(v_avg, 3), 'reasons', j_reasons,
                              'ips', j_ips, 'accounts', j_accs, 'unknown', j_unk, 'clients', j_clients);
end $$;
revoke all on function bls_proxy_manager.admin_visa_report(text, integer) from public, anon, authenticated;
grant execute on function bls_proxy_manager.admin_visa_report(text, integer) to bls_admin;
