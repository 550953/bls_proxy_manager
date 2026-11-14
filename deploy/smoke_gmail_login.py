#!/usr/bin/env python3
"""Смоук цели gmail_login (этап A6 ТЗ-1). Только стандартная библиотека.

  python3 deploy/smoke_gmail_login.py --base https://bls-proxy.shikinn.com --token-gmail <токен gmail_login> \
        [--token-visa <токен visaglobal>] [--token-bls <токен bls>]

Что делает (по HTTP, как бот):
  1. gmail_login: acquire -> info с фазой и latency -> error HOST_BUSY (IP не штрафуется) -> error NET_PROXY_DEAD
     на ОТДЕЛЬНОЙ аренде (кулдаун ~60 с у этого прокси) -> release.
  2. Токены visaglobal и bls на acquire gmail_login -> 403.
  3. Пустая выдача: забрать все прокси цели, следующий acquire -> retry_after_seconds, всё вернуть.
  4. Если даны токены других целей: те же вызовы (acquire, info, release ok) на visaglobal и bls — ответы как до выката.
Ничего не удаляет. Побочный эффект: у использованных прокси gmail_login пауза после release (30 с), у прокси,
на которых отправлен NET_PROXY_DEAD, кулдаун ~60 с; у bls/visaglobal после release штатная пауза цели.
Код выхода 0 = все проверки прошли."""
import argparse, json, sys, time, urllib.request, urllib.error

def call(base, path, token, body):
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"X-Bot-Token": token, "Content-Type": "application/json"})
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            code, txt = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        code, txt = e.code, e.read().decode()
    except Exception as e:
        code, txt = -1, str(e)
    try: js = json.loads(txt)
    except Exception: js = {}
    return code, js, int((time.time() - t) * 1000)

fails = 0
def check(name, ok, got=""):
    global fails
    fails += 0 if ok else 1
    print(("PASS" if ok else "FAIL"), name, f"(got: {str(got)[:160]})")

def cycle(base, token, purpose, label, client_ok_reason="ok"):
    """acquire -> info -> release для одной цели. Возвращает (lease|None, ответ acquire)."""
    c, js, ms = call(base, "/acquire", token, {"account_id": "smoke-" + purpose, "count": 1, "ttl_seconds": 120, "purpose": purpose})
    check(f"{label}: acquire 200 ({ms} мс)", c == 200, c)
    leases = js.get("leases") or []
    if not leases:
        check(f"{label}: есть свободный прокси", False, js); return None, js
    lid = leases[0]["lease_id"]
    c, js2, _ = call(base, "/report", token, {"lease_id": lid, "event_type": "info", "phase": "exit_check", "latency_ms": 1500,
                                               "detail": {"outcome": "ok", "slot": 1, "starts_in_flight": 1}})
    check(f"{label}: report info с фазой -> ok", c == 200 and js2.get("ok") is True, js2)
    c, js3, _ = call(base, "/release", token, {"lease_id": lid, "reason": client_ok_reason})
    check(f"{label}: release ok", c == 200 and js3.get("ok") is True, js3)
    return lid, js

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True); ap.add_argument("--token-gmail", required=True)
    ap.add_argument("--token-visa", default=""); ap.add_argument("--token-bls", default="")
    a = ap.parse_args()
    G = a.token_gmail

    print("== 1. gmail_login: полный цикл")
    cycle(a.base, G, "gmail_login", "gmail_login")
    # HOST_BUSY: вина хоста, прокси не штрафуется
    c, js, _ = call(a.base, "/acquire", G, {"account_id": "smoke-host", "count": 1, "ttl_seconds": 120, "purpose": "gmail_login"})
    if c == 200 and js.get("leases"):
        lid = js["leases"][0]["lease_id"]
        c, r, _ = call(a.base, "/report", G, {"lease_id": lid, "event_type": "error", "error_code": "HOST_BUSY", "phase": "ix_apply"})
        check("HOST_BUSY: change_ip=false, next_action=retry", c == 200 and r.get("change_ip") is False and r.get("next_action") == "retry", r)
        call(a.base, "/release", G, {"lease_id": lid, "reason": "failed", "error_code": "HOST_BUSY", "phase": "ix_apply"})
    else:
        check("acquire для HOST_BUSY", False, (c, js))
    # NET_PROXY_DEAD: кулдаун ~60 с, вердикт new_ip
    c, js, _ = call(a.base, "/acquire", G, {"account_id": "smoke-dead", "count": 1, "ttl_seconds": 120, "purpose": "gmail_login"})
    if c == 200 and js.get("leases"):
        lid = js["leases"][0]["lease_id"]
        c, r, _ = call(a.base, "/report", G, {"lease_id": lid, "event_type": "error", "error_code": "NET_PROXY_DEAD",
                                               "phase": "exit_check", "detail": {"profile_id": "smoke-p1"}})
        check("NET_PROXY_DEAD: next_action=new_ip, change_ip=true, blame=ip",
              c == 200 and r.get("next_action") == "new_ip" and r.get("change_ip") is True and r.get("blame") == "ip", r)
        check("NET_PROXY_DEAD: cooldown_s в пределах 30..70", 30 <= int(r.get("cooldown_s") or 0) <= 70, r.get("cooldown_s"))
        call(a.base, "/release", G, {"lease_id": lid, "reason": "failed", "error_code": "NET_PROXY_DEAD", "phase": "exit_check"})
    else:
        check("acquire для NET_PROXY_DEAD (нужен свободный прокси)", False, (c, js))

    print("== 2. чужие токены не берут gmail_login")
    for name, tok in (("visaglobal", a.token_visa), ("bls", a.token_bls)):
        if tok:
            c, _, _ = call(a.base, "/acquire", tok, {"account_id": "smoke-x", "purpose": "gmail_login"})
            check(f"токен {name} -> acquire gmail_login = 403", c == 403, c)

    print("== 3. пустая выдача")
    c, js, _ = call(a.base, "/acquire", G, {"account_id": "smoke-all", "count": 50, "ttl_seconds": 60, "purpose": "gmail_login"})
    taken = [x["lease_id"] for x in (js.get("leases") or [])]
    c2, js2, _ = call(a.base, "/acquire", G, {"account_id": "smoke-empty", "count": 1, "ttl_seconds": 60, "purpose": "gmail_login"})
    check("пустая выдача: leases=[] и есть retry_after_seconds", c2 == 200 and js2.get("leases") == [] and "retry_after_seconds" in js2, js2)
    for lid in taken:
        call(a.base, "/release", G, {"lease_id": lid, "reason": "ok"})

    print("== 4. те же вызовы на старых целях")
    if a.token_visa: cycle(a.base, a.token_visa, "visaglobal", "visaglobal")
    if a.token_bls: cycle(a.base, a.token_bls, "bls", "bls")
    if not (a.token_visa or a.token_bls): print("SKIP токены visaglobal/bls не заданы")

    print("ИТОГ:", "OK" if fails == 0 else f"ПРОВАЛОВ: {fails}")
    sys.exit(1 if fails else 0)

main()
