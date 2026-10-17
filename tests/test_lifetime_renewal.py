"""浏览器式续期：AT 过期前主动刷新、Set-Cookie 滚动会话、RT/共享态寿命写回覆盖层。离线。"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from email.message import Message
from types import SimpleNamespace

import pytest

from browser import storage_scope
from config import schema
from config.overlay import Overlay
from core.errors import LoginRequired
from core.flow import StageMode, StagePlan
from login import LOGINS
from login.base import LoginContext
from net import lifetime
from net.http import HttpClient
from runtime import engine
from templates import registry as templates

BASE_URL = "https://lifetime.invalid"


def _jwt(exp_in: float, *, iat_ago: float = 3600.0, sub: str = "u1") -> str:
    now = time.time()
    def part(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    return f"{part({'alg': 'HS256'})}.{part({'sub': sub, 'iat': int(now - iat_ago), 'exp': int(now + exp_in)})}.sig"


def _plan(*methods):
    return StagePlan(stage="login", mode=StageMode.CHAIN, candidates=methods, source="chain")


def _case(tmp_path, credentials):
    spec = schema.parse_account({
        "id": "lifetime-test", "name": "lifetime-test", "base_url": BASE_URL,
        "template": "sub2api", "tasks": [{"id": "daily"}], "credentials": credentials,
    })
    overlay = Overlay(path=tmp_path / "overlay.json").load()
    holder = {"account": overlay.apply(spec)}
    http = HttpClient(base_url=BASE_URL)
    login_ctx = LoginContext(account=holder["account"], template=templates.get("sub2api"), http=http)
    ctx = SimpleNamespace(http=http, login_handle=None, browser_service=None)
    return spec, overlay, holder, login_ctx, ctx


def _login(spec, overlay, holder, login_ctx, ctx, plan):
    result = asyncio.run(LOGINS.establish(
        login_ctx, plan, on_credentials=engine._credential_writer(spec, holder, overlay),
    ))
    assert result.state is not None
    engine._apply_login(ctx, login_ctx, result.state, plan, spec, holder, overlay)
    return result.state


def _raw_field(overlay, spec, name):
    document = json.loads(overlay.path.read_text(encoding="utf-8"))
    return document["entries"][spec.id]["fields"][name]


# ── 纯函数 ──
def test_jwt_expiry_and_renewal_window():
    assert lifetime.needs_renewal(_jwt(60)) is True
    assert lifetime.needs_renewal(_jwt(-10)) is True
    assert lifetime.needs_renewal(_jwt(6 * 3600)) is False
    # 10 分钟寿命的 token：窗口按总寿命 25% 收窄，刚签发时不续期。
    assert lifetime.needs_renewal(_jwt(590, iat_ago=10)) is False
    assert lifetime.needs_renewal(_jwt(100, iat_ago=500)) is True
    for opaque in ("", "opaque-token", "a.b.c", "Bearer x.y"):
        assert lifetime.needs_renewal(opaque) is False


def test_credential_ttl_follows_jwt_and_never_becomes_permanent():
    assert abs(lifetime.credential_ttl("access_token", _jwt(7200), default=99) - 7200) <= 2
    assert lifetime.credential_ttl("access_token", _jwt(-100), default=99) == 1
    assert lifetime.credential_ttl("refresh_token", "opaque", default=99) == 99


def test_parse_set_cookie_attributes():
    item = lifetime.parse_set_cookie("session=abc; Path=/; Max-Age=2592000; HttpOnly; Domain=.lifetime.invalid")
    assert (item.name, item.value, item.domain, item.lifetime()) == ("session", "abc", "lifetime.invalid", 2592000)
    assert lifetime.parse_set_cookie("session=; Max-Age=0").deleted()
    expired = lifetime.parse_set_cookie("session=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
    assert expired.deleted()
    assert lifetime.parse_set_cookie("garbage") is None


def test_provider_state_ttl_uses_auth_cookie_expiry():
    now = time.time()
    state = {"cookies": [
        {"name": "_t", "value": "v", "domain": "linux.do", "expires": now + 5 * 86400},
        {"name": "_forum_session", "value": "v", "domain": "linux.do", "expires": now + 3600},
    ]}
    assert abs(storage_scope.provider_state_ttl(state, "linuxdo", default=7, now=now) - 5 * 86400) <= 1
    session_only = {"cookies": [{"name": "_t", "value": "v", "domain": "linux.do", "expires": -1}]}
    assert storage_scope.provider_state_ttl(session_only, "linuxdo", default=7) == 7


def test_overlay_ttl_follows_jwt_exp(tmp_path):
    spec, overlay, *_ = _case(tmp_path, {"access_token": "seed"})
    token = _jwt(2 * 3600)
    assert overlay.record_credentials(spec, origin="refresh", access_token=token, refresh_token="opaque-rt")
    assert abs(_raw_field(overlay, spec, "access_token")["ttl"] - 2 * 3600) <= 2
    assert _raw_field(overlay, spec, "refresh_token")["ttl"] == 30 * 86400


# ── AT 过期前主动续期 ──
def test_near_expiry_access_token_is_refreshed_before_the_request(tmp_path, monkeypatch):
    stale, fresh = _jwt(60), _jwt(3 * 3600, iat_ago=0)
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path, {"access_token": stale, "refresh_token": "rt-1"})
    _login(spec, overlay, holder, login_ctx, ctx, _plan("access_token", "refresh"))
    wire = []

    def send(client, method, path, **kwargs):
        wire.append((path, client.headers.get("Authorization")))
        if path == "/api/v1/auth/refresh":
            return {"access_token": fresh}
        if client.headers.get("Authorization") != f"Bearer {fresh}":
            raise LoginRequired("expired", status=401)
        return {"ok": True}

    monkeypatch.setattr(HttpClient, "_send", send)
    assert ctx.http.get("/protected") == {"ok": True}
    assert [path for path, _ in wire] == ["/api/v1/auth/refresh", "/protected"], "不应先吃一次 401"
    assert wire[-1][1] == f"Bearer {fresh}"
    assert holder["account"].credentials.access_token == fresh
    persisted = Overlay(path=overlay.path).load().apply(spec).credentials
    assert persisted.access_token == fresh and persisted.refresh_token == "rt-1"
    assert abs(_raw_field(overlay, spec, "access_token")["ttl"] - 3 * 3600) <= 3
    # RT 未轮换但被服务端接受：覆盖层续上它的寿命。
    assert _raw_field(overlay, spec, "refresh_token")["origin"] == "refresh"
    # 主动续期不占用 401 重放额度。
    assert ctx.http._renewed is False


def test_fresh_access_token_is_not_renewed_early(tmp_path, monkeypatch):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path, {"access_token": _jwt(6 * 3600), "refresh_token": "rt"})
    _login(spec, overlay, holder, login_ctx, ctx, _plan("access_token", "refresh"))
    paths = []
    monkeypatch.setattr(HttpClient, "_send", lambda client, method, path, **kw: paths.append(path) or {"ok": 1})
    ctx.http.get("/a")
    ctx.http.get("/b")
    assert paths == ["/a", "/b"]


def test_proactive_renewal_never_swaps_to_a_static_cookie(tmp_path, monkeypatch):
    stale = _jwt(60)
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path, {"access_token": stale, "cookie": "session=s"})
    _login(spec, overlay, holder, login_ctx, ctx, _plan("access_token", "cookie"))
    seen = []
    monkeypatch.setattr(HttpClient, "_send", lambda c, m, p, **kw: seen.append(dict(c.headers)) or {"ok": 1})
    assert ctx.http.get("/protected") == {"ok": 1}
    assert seen[0].get("Authorization") == f"Bearer {stale}" and "Cookie" not in seen[0]


def test_failed_proactive_renewal_does_not_hammer_refresh_after_401(tmp_path, monkeypatch):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path, {"access_token": _jwt(-5), "refresh_token": "rt-dead"})
    _login(spec, overlay, holder, login_ctx, ctx, _plan("access_token", "refresh"))
    refreshes = []

    def send(client, method, path, **kwargs):
        if path == "/api/v1/auth/refresh":
            refreshes.append(1)
            raise LoginRequired("invalid refresh token", status=401)
        raise LoginRequired("expired", status=401)

    monkeypatch.setattr(HttpClient, "_send", send)
    with pytest.raises(LoginRequired):
        ctx.http.get("/protected")
    assert len(refreshes) == 1


def test_confirm_never_rolls_back_a_concurrent_rotation(tmp_path, monkeypatch):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path, {"access_token": _jwt(60), "refresh_token": "rt-old"})
    _login(spec, overlay, holder, login_ctx, ctx, _plan("access_token", "refresh"))

    def send(client, method, path, **kwargs):
        if path == "/api/v1/auth/refresh":
            # 另一进程在本次续期期间轮换了 RT。
            Overlay(path=overlay.path).load().record_credentials(spec, origin="refresh", refresh_token="rt-other")
            return {"access_token": _jwt(3600, iat_ago=0)}
        return {"ok": True}

    monkeypatch.setattr(HttpClient, "_send", send)
    ctx.http.get("/protected")
    assert Overlay(path=overlay.path).load().apply(spec).credentials.refresh_token == "rt-other"


# ── Set-Cookie 滚动会话 ──
class _Response:
    def __init__(self, url, set_cookies, body=b'{"ok": true}'):
        self._url, self._body = url, body
        self.headers = Message()
        for value in set_cookies:
            self.headers["Set-Cookie"] = value

    def read(self):
        return self._body

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _serve(monkeypatch, responses):
    class Opener:
        def open(self, request, timeout=None):
            return responses.pop(0)(request.full_url)
    monkeypatch.setattr(HttpClient, "_opener", lambda self: Opener())


def test_rolling_session_cookie_is_followed_and_persisted(tmp_path, monkeypatch):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path, {"cookie": "session=old; theme=dark"})
    _login(spec, overlay, holder, login_ctx, ctx, _plan("cookie"))
    _serve(monkeypatch, [
        lambda url: _Response(url, ["session=new; Path=/; Max-Age=604800; HttpOnly", "tracker=x; Path=/"]),
        lambda url: _Response(url, []),
    ])
    ctx.http.get("/api/user/self")
    assert ctx.http.headers["Cookie"] == "session=new; theme=dark", "未持有的 Cookie 不应被收进来"
    persisted = Overlay(path=overlay.path).load().apply(spec).credentials
    assert persisted.cookie == "session=new; theme=dark"
    field = _raw_field(overlay, spec, "cookie")
    assert field["origin"] == "session" and abs(field["ttl"] - 604800) <= 1


@pytest.mark.parametrize("set_cookie,url", [
    ("acw_tc=rotating; Max-Age=1800", BASE_URL + "/api"),           # 只是 WAF Cookie 在变
    ("session=; Max-Age=0", BASE_URL + "/api"),                    # 删除可能只是风控，不跟随
    ("session=evil; Max-Age=999", "https://other.invalid/api"),     # 跨站重定向后的响应
])
def test_volatile_deleted_or_foreign_cookies_are_not_persisted(tmp_path, monkeypatch, set_cookie, url):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path, {"cookie": "session=old; acw_tc=a"})
    _login(spec, overlay, holder, login_ctx, ctx, _plan("cookie"))
    _serve(monkeypatch, [lambda _u: _Response(url, [set_cookie])])
    ctx.http.get("/api")
    assert Overlay(path=overlay.path).load().entry(spec.id).fields.get("cookie") is None
    assert "session=old" in ctx.http.headers["Cookie"]


def test_sliding_expiry_without_value_change_extends_ttl_once(tmp_path, monkeypatch):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path, {"session_cookie": "session=same"})
    _login(spec, overlay, holder, login_ctx, ctx, _plan("cookie"))
    writes = []
    original = Overlay.record_credentials
    monkeypatch.setattr(Overlay, "record_credentials", lambda *a, **kw: writes.append(kw) or original(*a, **kw))
    _serve(monkeypatch, [lambda url: _Response(url, ["session=same; Max-Age=86400"]) for _ in range(3)])
    for _ in range(3):
        ctx.http.get("/api")
    assert len(writes) == 1 and writes[0]["session_cookie"] == "session=same"
    assert abs(_raw_field(overlay, spec, "session_cookie")["ttl"] - 86400) <= 1
