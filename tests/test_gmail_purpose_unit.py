# Юнит-тест цели gmail_login в proxy_service.py. Запуск: python3 -I tests/test_gmail_purpose_unit.py proxy_service.py
# Берёт настоящие значения и функции из файла (через ast), сеть и база не нужны.
import ast, asyncio, os, secrets, logging, sys, time, hashlib
from typing import Optional
src = open(sys.argv[1], encoding="utf-8").read()
tree = ast.parse(src)
FUNCS = {"_load_purpose_tokens", "_purpose_arg", "require_bot", "_check_lease_scope", "_schedule_fault_check"}
CONSTS = {"ALLOWED_PURPOSES", "PURPOSE_SITES", "PURPOSE_PROBE_CODES", "FAULT_CODES", "BOT_TOKEN_PURPOSES"}
funcs, consts = {}, {}
for n in tree.body:
    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in FUNCS:
        funcs[n.name] = ast.get_source_segment(src, n)
    elif isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id in CONSTS:
        consts[n.targets[0].id] = ast.get_source_segment(src, n)
assert set(funcs) == FUNCS and set(consts) >= CONSTS - {"BOT_TOKEN_PURPOSES"}, (funcs.keys(), consts.keys())

class HTTPException(Exception):
    def __init__(self, code, detail=""): self.code, self.detail = code, detail
class PgErr(Exception): pass
class _asyncpg: PostgresError = PgErr
def Header(default=""): return default
class Request:
    def __init__(self): self.state = type("S", (), {})()

class Pool:
    def __init__(self, purpose, owner=None, proxy="px1"): self.p, self.o, self.px = purpose, owner, proxy
    async def fetchval(self, q, *a):
        if "lease_purpose" in q: return self.p
        if "lease_proxy" in q: return self.px
        return self.o

def make(env):
    os.environ.pop("BLS_BOT_TOKEN_GMAIL_LOGIN", None); os.environ.pop("BLS_BOT_TOKEN_VISAGLOBAL", None)
    os.environ.update(env)
    verified = []
    async def _verify_purpose_fault(proxy_id, purpose): verified.append((purpose, proxy_id))
    async def _verify_fault(proxy_id): verified.append(("bls", proxy_id))
    g = dict(HTTPException=HTTPException, asyncpg=_asyncpg, Header=Header, Request=Request, secrets=secrets,
             os=os, Optional=Optional, SCHEMA="s", log=logging.getLogger("t"), BOT_TOKEN_OCR="tok-ocr",
             BOT_TOKEN_PURPOSES={"bls": "tok-bls"}, BOT_CLIENT_TOKENS={}, pools={},
             time=time, hashlib=hashlib, asyncio=asyncio, _db_tokens={}, _db_tokens_at=1e18,
             _db_tokens_try_at=0.0, _db_touch_at={}, DB_TOKENS_TTL_S=15.0, _db_tokens_lock=asyncio.Lock(),
             _refresh_db_tokens=(lambda *a, **k: asyncio.sleep(0)), _token_hash=lambda t: t,
             _verify_purpose_fault=_verify_purpose_fault, _verify_fault=_verify_fault, _verified=verified)
    for name in ("ALLOWED_PURPOSES", "FAULT_CODES", "PURPOSE_SITES", "PURPOSE_PROBE_CODES"):
        exec(consts[name], g)
    for name in sorted(FUNCS):
        exec(funcs[name], g)
    g["_load_purpose_tokens"]()
    return g

def auth(g, tok):
    r = Request()
    try: return asyncio.run(g["require_bot"](r, tok)), r.state.bot_client
    except HTTPException as e: return e.code, None

def scope(g, lease_purpose, token_purpose):
    g["pools"]["reporter"] = Pool(lease_purpose)
    try: asyncio.run(g["_check_lease_scope"]("L", token_purpose, None)); return 200
    except HTTPException as e: return e.code

def sched(g, purpose, code):
    g["pools"]["reporter"] = Pool(purpose)
    async def go():
        await g["_schedule_fault_check"]("L", code)
        await asyncio.sleep(0)       # дать фоновой задаче отработать
        await asyncio.sleep(0)
    asyncio.run(go())

g = make({"BLS_BOT_TOKEN_GMAIL_LOGIN": "tok-gml", "BLS_BOT_TOKEN_VISAGLOBAL": "tok-vfs"})
g_off = make({"BLS_BOT_TOKEN_VISAGLOBAL": "tok-vfs"})        # токен gmail не задан: цель выключена

out = {
 "старые цели остались в ALLOWED_PURPOSES и в прежнем порядке": g["ALLOWED_PURPOSES"][:3] == ("bls", "ocr", "visaglobal"),
 "gmail_login добавлен в ALLOWED_PURPOSES": "gmail_login" in g["ALLOWED_PURPOSES"],
 "_purpose_arg('gmail_login') -> gmail_login": g["_purpose_arg"]("gmail_login") == "gmail_login",
 "_purpose_arg(None/bls) -> None (путь BLS не изменился)": g["_purpose_arg"](None) is None and g["_purpose_arg"]("bls") is None,
 "PURPOSE_SITES: visaglobal прежний": g["PURPOSE_SITES"]["visaglobal"] == ("visa.vfsglobal.com", 443),
 "PURPOSE_SITES: gmail_login -> accounts.google.com:443": g["PURPOSE_SITES"]["gmail_login"] == ("accounts.google.com", 443),
 "коды проверки после сбоя включают NET_PROXY_DEAD и NET_TIMEOUT (как probe=true в 27)": {"NET_PROXY_DEAD", "NET_TIMEOUT"} <= g["PURPOSE_PROBE_CODES"],
 "токен gmail -> (gmail_login, None)": auth(g, "tok-gml") == ("gmail_login", None),
 "токен visaglobal -> (visaglobal, None)": auth(g, "tok-vfs") == ("visaglobal", None),
 "токен bls -> (bls, None)": auth(g, "tok-bls") == ("bls", None),
 "токен gmail не задан: цель выключена, токен не подходит (401)": auth(g_off, "tok-gml")[0] == 401 and "gmail_login" not in g_off["BOT_TOKEN_PURPOSES"],
 "без токена gmail visaglobal продолжает работать": auth(g_off, "tok-vfs") == ("visaglobal", None),
 "токен visaglobal на аренде gmail_login -> 403": scope(g, "gmail_login", "visaglobal") == 403,
 "токен bls на аренде gmail_login -> 403": scope(g, "gmail_login", "bls") == 403,
 "токен gmail на аренде visaglobal -> 403": scope(g, "visaglobal", "gmail_login") == 403,
 "токен gmail на своей аренде -> ok": scope(g, "gmail_login", "gmail_login") == 200,
}
def raises400(v):
    try: g["_purpose_arg"](v); return False
    except HTTPException as e: return e.code == 400
out["_purpose_arg('ocr') и мусор -> 400"] = raises400("ocr") and raises400("nope")

for code, purpose, want in [("NET_PROXY_DEAD", "gmail_login", [("gmail_login", "px1")]),
                            ("NET_TIMEOUT", "gmail_login", [("gmail_login", "px1")]),
                            ("HOST_BUSY", "gmail_login", []), ("GOOGLE_CAPTCHA", "gmail_login", []),
                            ("NET_PROXY_DEAD", "visaglobal", [("visaglobal", "px1")]),
                            ("PROXY_TIMEOUT", "bls", [("bls", "px1")]), ("HOST_BUSY", "bls", [])]:
    g["_verified"].clear(); sched(g, purpose, code)
    out[f"проверка после сбоя: {purpose}/{code} -> {'запущена' if want else 'нет'}"] = g["_verified"] == want

for k, v in out.items(): print("PASS" if v else "FAIL", k)
assert all(out.values()); print("GMAIL PURPOSE UNIT OK")
