-- 27: цель gmail_login (кликер Gmail через ixBrowser). Этап A ТЗ-1: только пул, кликер не трогаем.
-- Зависит от 21–26. Откат: 27_ROLLBACK.sql. Тест: 27_test.sql. Снимок «до/после»: 27_snapshot.sql.
--
-- Принцип: только добавления. Строки других целей (bls, visaglobal, ocr) не меняются.
-- Функции acquire_proxies, report_event, release_lease, purpose_apply_error, lease_verdict НЕ переопределяются:
-- они уже работают по справочнику error_codes для любой цели.
-- Два места с жёстко прописанными целями расширены (определение функции берётся из живой базы, правится одна
-- строка, копия лежит в _fn_backup_27):
--   * bot_clients.purpose — check (токены клиентов из дашборда для gmail_login);
--   * admin_upsert_proxies — белый список purposes (иначе дашборд молча отбросит gmail_login).
-- Прокси на цель этот файл не переводит: см. 27_enable_gmail_login.sql.
begin;
set local lock_timeout = '5s';

do $$
begin
    if to_regclass('bls_proxy_manager.error_aliases') is null
       or to_regclass('bls_proxy_manager.bot_clients') is null then
        raise exception '27: сначала накатите 21–26';
    end if;
end $$;

-- ---------- 1. Справочник кодов ---------------------------------------------
-- blame = unknown у HOST_*: значения host в check пока нет, оно вводится в ТЗ-2. unknown при cooldown_s = 0
-- не штрафует IP и даёт next_action = retry.
insert into bls_proxy_manager.error_codes
    (purpose, code, blame, cooldown_s, reset_profile, quarantine_ok, note, needs_confirm, probe) values
 ('gmail_login','NET_PROXY_DEAD',  'ip',       60,  false, true,  '1003 Proxy detection failed, SOCKS не соединился, проверка IP во вкладке не загрузилась', false, true),
 ('gmail_login','NET_TIMEOUT',     'ip',       30,  false, false, 'страница логина не загрузилась через прокси за таймаут',                                   false, true),
 ('gmail_login','NET_PROXY_AUTH',  'provider',  0,  false, false, '407: алерт админу, IP не трогаем',                                                         false, false),
 ('gmail_login','HOST_BUSY',       'unknown',   0,  false, false, '1008 Server busy после всех повторов profile-update (вина нашего хоста, IP не трогаем)',  false, false),
 ('gmail_login','HOST_ERROR',      'unknown',   0,  false, false, '1000, CDP-таймаут, падение воркера, open_failed без сетевой причины',                     false, false),
 ('gmail_login','IX_START_PAGE',   'unknown',   0,  false, false, 'финальный URL 2ip.io (стартовая страница ixBrowser)',                                       false, false),
 ('gmail_login','CHROME_ERR_PAGE', 'unknown',   0,  false, false, 'финал chrome-error://',                                                                      false, false),
 ('gmail_login','GOOGLE_CAPTCHA',  'ip',       300, false, false, 'капча Google: IP на подтверждение',                                                        true,  false),
 ('gmail_login','GOOGLE_VERIFY',   'account',   0,  false, false, 'verify_id / verify_info: пока вина аккаунта, не IP',                                       false, false),
 ('gmail_login','GOOGLE_BLOCKED',  'account',   0,  false, false, 'аккаунт заблокирован',                                                                     false, false),
 ('gmail_login','UNKNOWN',         'unknown',   0,  false, false, 'не распознано: только журнал',                                                             false, false)
on conflict (purpose, code) do nothing;

-- ---------- 2. Настройки цели (стартовые значения, не измеренные константы) --
insert into bls_proxy_manager.purpose_settings(purpose, key, value, note) values
 ('gmail_login','cooldown_ok_s',          to_jsonb(30),   'пауза после штатного release, сек'),
 ('gmail_login','max_lease_total_s',      to_jsonb(1800), 'потолок аренды с /renew, сек: окно inbox ждёт человека до ~770 с'),
 ('gmail_login','ip_escalate_window_min', to_jsonb(60),   'окно подсчёта повторов ошибок IP, мин'),
 ('gmail_login','ip_cooldown_max_s',      to_jsonb(300),  'потолок кулдауна IP, сек (по логам сон 1–2,5 мин)'),
 ('gmail_login','ip_quarantine_count',    to_jsonb(4),    'повторов ошибок -> карантин (если код quarantine_ok)'),
 ('gmail_login','ip_quarantine_accounts', to_jsonb(2),    'минимум разных аккаунтов среди повторов для карантина')
on conflict (purpose, key) do nothing;

-- ---------- 3. Токены клиентов из дашборда: разрешить gmail_login -----------
alter table bls_proxy_manager.bot_clients drop constraint if exists bot_clients_purpose_check;
alter table bls_proxy_manager.bot_clients
    add constraint bot_clients_purpose_check check (purpose in ('bls', 'visaglobal', 'gmail_login'));

-- ---------- 4. admin_upsert_proxies: белый список целей ---------------------
create table if not exists bls_proxy_manager._fn_backup_27 as
select p.proname, pg_get_functiondef(p.oid) as def
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'bls_proxy_manager' and p.proname = 'admin_upsert_proxies';
revoke all on bls_proxy_manager._fn_backup_27 from public, anon, authenticated;

do $$
declare
    v_def text;
    v_new text;
begin
    select pg_get_functiondef(p.oid) into v_def
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'bls_proxy_manager' and p.proname = 'admin_upsert_proxies';
    if v_def is null then raise exception '27: admin_upsert_proxies не найдена (накатите 14)'; end if;
    if v_def like '%''gmail_login''%' then return; end if;         -- уже расширена
    v_new := replace(v_def, '(''bls'', ''ocr'', ''visaglobal'')', '(''bls'', ''ocr'', ''visaglobal'', ''gmail_login'')');
    if v_new = v_def then
        raise exception '27: в admin_upsert_proxies не найден белый список целей, проверьте определение вручную';
    end if;
    execute v_new;
end $$;

commit;
