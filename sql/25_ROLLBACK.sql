-- Откат миграции 25: убирает токены из базы. Токены из env продолжат работать.
drop function if exists bls_proxy_manager.bot_token_touch(text);
drop function if exists bls_proxy_manager.bot_tokens_active();
drop function if exists bls_proxy_manager.admin_bot_client_delete(uuid);
drop function if exists bls_proxy_manager.admin_bot_client_set_enabled(uuid, boolean);
drop function if exists bls_proxy_manager.admin_bot_client_create(text, text, text, text);
drop function if exists bls_proxy_manager.admin_bot_clients_list();
drop table if exists bls_proxy_manager.bot_clients;
