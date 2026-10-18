-- =============================================================================
-- 09_stats.sql — данные для графика «Статистика» в дашборде.
-- Накатывать в Supabase SQL Editor после 03_admin.sql (08 для OCR-ошибок желателен, но не обязателен).
-- Безопасно запускать повторно. Откат: drop function bls_proxy_manager.admin_event_stats(integer);
--
-- ЧТО ВОЗВРАЩАЕТ: по корзинам времени (час — до 72 ч, иначе сутки):
--   ok  = события cycle_ok (успешные циклы BLS)
--   err = события error (BLS) + ocr_fail + ocr_geo (сбои канала OCR / гео-отказ Gemini)
-- Успехи OCR по одному в proxy_events не пишутся (только счётчики), поэтому в ok их нет.
-- События хранятся events_retention_days (по умолчанию 14 суток) — больше 336 ч не отдаём.
-- =============================================================================
create or replace function bls_proxy_manager.admin_event_stats(p_hours integer default 24)
returns table (bucket timestamptz, ok bigint, err bigint)
language sql stable security definer set search_path = bls_proxy_manager, pg_temp
as $$
    with prm as (
        select least(greatest(coalesce(p_hours, 24), 1), 336) as h
    ), unit as (
        select h,
               case when h <= 72 then 'hour' else 'day' end as u,
               case when h <= 72 then interval '1 hour' else interval '1 day' end as step
          from prm
    ), g as (
        select generate_series(date_trunc(u.u, now() - make_interval(hours => u.h)),
                               date_trunc(u.u, now()), u.step) as b,
               u.step
          from unit u
    )
    select g.b as bucket,
           count(e.id) filter (where e.event_type = 'cycle_ok')                              as ok,
           count(e.id) filter (where e.event_type in ('error', 'ocr_fail', 'ocr_geo'))       as err
      from g
      left join proxy_events e
             on e.created_at >= g.b and e.created_at < g.b + g.step
            and e.event_type in ('cycle_ok', 'error', 'ocr_fail', 'ocr_geo')
     group by g.b
     order by g.b
$$;

revoke all on function bls_proxy_manager.admin_event_stats(integer) from public;
grant execute on function bls_proxy_manager.admin_event_stats(integer) to bls_admin;
