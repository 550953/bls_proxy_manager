import ast, asyncio, os, secrets, logging, sys
src = open(sys.argv[1], encoding="utf-8").read()
tree = ast.parse(src)
want = {"_load_purpose_tokens", "require_bot", "_check_lease_scope"}  # запуск: python3 -I tests/test_block4_unit.py proxy_service.py
funcs = {n.name: ast.get_source_segment(src, n) for n in tree.body
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in want}
assert set(funcs) == want, funcs.keys()

class HTTPException(Exception):
    def __init__(self, code, detail=""): self.code, self.detail = code, detail
class PgErr(Exception): pass
class _asyncpg: PostgresError = PgErr
def Header(default=""): return default
class Request:
    def __init__(self): self.state = type("S", (), {})()

class Pool:
    def __init__(self, purpose, owner): self.p, self.o = purpose, owner
    async def fetchval(self, q, *a):
        return self.p if "lease_purpose" in q else self.o

os.environ["BLS_BOT_CLIENTS_VISAGLOBAL"] = "alice=tok-alice,bob=tok-bob"
os.environ["BLS_BOT_TOKEN_VISAGLOBAL"] = "tok-legacy"
g = dict(HTTPException=HTTPException, asyncpg=_asyncpg, Header=Header, Request=Request, secrets=secrets,
         os=os, Optional=__import__("typing").Optional, SCHEMA="s", log=logging.getLogger("t"),
         ALLOWED_PURPOSES=("bls", "ocr", "visaglobal"), BOT_TOKEN_OCR="tok-ocr",
         BOT_TOKEN_PURPOSES={"bls": "tok-bls"}, BOT_CLIENT_TOKENS={}, pools={},
         time=__import__("time"), hashlib=__import__("hashlib"), asyncio=asyncio, _db_tokens={}, _db_tokens_at=1e18,
         _db_tokens_try_at=0.0, _db_touch_at={}, DB_TOKENS_TTL_S=15.0, _db_tokens_lock=asyncio.Lock(),
         _refresh_db_tokens=(lambda *a, **k: asyncio.sleep(0)), _token_hash=lambda t: t)
# порядок как в файле: сначала загрузка токенов, потом остальные
for name in ("_load_purpose_tokens", "require_bot", "_check_lease_scope"):
    exec(funcs[name], g)
g["_load_purpose_tokens"]()
assert g["BOT_CLIENT_TOKENS"] == {"visaglobal": {"tok-alice": "alice", "tok-bob": "bob"}}, g["BOT_CLIENT_TOKENS"]

def auth(tok):
    r = Request()
    try:
        return asyncio.run(g["require_bot"](r, tok)), r.state.bot_client
    except HTTPException as e:
        return e.code, None

def scope_check(client, purpose="visaglobal", owner="alice", scope="visaglobal"):
    g["pools"]["reporter"] = Pool(purpose, owner)
    try:
        asyncio.run(g["_check_lease_scope"]("L", scope, client)); return 200
    except HTTPException as e: return e.code

out = {
 "токен alice -> (visaglobal, alice)": auth("tok-alice") == ("visaglobal", "alice"),
 "токен bob -> (visaglobal, bob)": auth("tok-bob") == ("visaglobal", "bob"),
 "общий токен цели -> (visaglobal, None)": auth("tok-legacy") == ("visaglobal", None),
 "токен BLS -> (bls, None)": auth("tok-bls") == ("bls", None),
 "чужой токен -> 401": auth("nope")[0] == 401,
 "alice на своей аренде -> ok": scope_check("alice") == 200,
 "bob на аренде alice -> 403": scope_check("bob") == 403,
 "общий токен (без клиента) на аренде alice -> ok": scope_check(None) == 200,
 "аренда без client_id у клиентского токена -> ok": scope_check("bob", owner=None) == 200,
 "токен bls на аренде visaglobal -> 403": scope_check(None, scope="bls") == 403,
}
for k, v in out.items(): print("PASS" if v else "FAIL", k)
assert all(out.values()); print("BLOCK4 UNIT OK")
