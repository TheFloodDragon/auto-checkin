"""纯 HTTP 客户端遇阿里云 ESA ``acw_sc__v2`` JS 挑战：按公开算法求值后重发一次。

实测 AnyRouter：OAuth 成功后引擎用 urllib 只读确认 ``/api/user/self``，边缘返回 200 + ``var arg1``
挑战页（4321 字符），被判成「需人机验证」，一次已成功的登录被丢弃。
"""

from __future__ import annotations

import gzip
from email.message import Message
from http.cookiejar import CookieJar

import pytest

from core.errors import LoginRequired, VerificationRequired
from net import esa
from net.http import HttpClient, HttpConfig

ARG1 = "0123456789ABCDEF0123456789ABCDEF01234567"
POSITIONS = ",".join(hex(p) for p in esa.ACW_POSITIONS)
CHALLENGE = f"<html><script>var arg1='{ARG1}';var m=[{POSITIONS}];</script></html>"
USER = '{"success":true,"data":{"id":7,"username":"u"}}'


class _Resp:
    def __init__(self, body: str, headers: list[tuple[str, str]], url: str):
        self._body = gzip.compress(body.encode())
        self.headers = Message()
        self.headers["Content-Encoding"] = "gzip"
        for name, value in headers:
            self.headers[name] = value
        self._url = url

    def read(self):
        return self._body

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class _Opener:
    def __init__(self, replies, jar=None):
        self.replies = list(replies)
        self.sent: list[dict[str, str]] = []
        self.jar = jar

    def open(self, request, timeout=None):
        if self.jar is not None:
            self.jar.add_cookie_header(request)
        self.sent.append({k.lower(): v for k, v in request.header_items()})
        body, headers = self.replies.pop(0)
        return _Resp(body, headers, request.full_url)


DENIED = [("X-Tengine-Error", "denied by http_custom"), ("Set-Cookie", "acw_tc=edge-tc; Path=/; HttpOnly"),
          ("Set-Cookie", "cdn_sec_tc=edge-sec; Path=/")]


def _client(monkeypatch, replies, *, cookie="session=s1; acw_sc__v2=stale", jar=None, logs=None):
    opener = _Opener(replies, jar=jar)
    client = HttpClient(base_url="https://anyrouter.top", config=HttpConfig(max_attempts=1),
                        headers={"Cookie": cookie} if cookie else {}, cookie_jar=jar,
                        log=(logs.append if logs is not None else None), tag="t")
    monkeypatch.setattr(client, "_opener", lambda: opener)
    return client, opener


def _cookies(sent):
    return dict(part.strip().split("=", 1) for part in sent.get("cookie", "").split(";") if "=" in part)


def test_is_esa_challenge_requires_marker_and_arg1():
    assert esa.is_esa_challenge(200, "denied by http_custom", CHALLENGE)
    # 无标记时只接受 HTML + arg1 + 已知置换表的完整挑战页。
    assert esa.is_esa_challenge(200, "", CHALLENGE)
    assert not esa.is_esa_challenge(200, "", f"<html>var arg1='{ARG1}';</html>")
    assert not esa.is_esa_challenge(200, "", CHALLENGE.replace("<html>", "", 1))
    assert not esa.is_esa_challenge(403, "denied by http_custom", CHALLENGE)
    assert not esa.is_esa_challenge(200, "denied by http_custom", "<html>blocked</html>")


def test_challenge_is_solved_and_request_replayed_once(monkeypatch):
    logs: list[str] = []
    client, opener = _client(monkeypatch, [(CHALLENGE, DENIED), (USER, [])], logs=logs)
    assert client.get("/api/user/self")["data"]["id"] == 7
    assert len(opener.sent) == 2
    replay = _cookies(opener.sent[1])
    assert replay["acw_sc__v2"] == esa.acw_sc_v2(ARG1)  # 覆盖旧值而不是追加同名
    assert replay["acw_tc"] == "edge-tc" and replay["cdn_sec_tc"] == "edge-sec" and replay["session"] == "s1"
    assert opener.sent[1]["cookie"].count("acw_sc__v2=") == 1
    # WAF 放行值不进入认证头，也不写进日志。
    assert "acw_sc__v2" not in client.headers["Cookie"].replace("acw_sc__v2=stale", "")
    assert any("ESA JS 挑战" in line for line in logs)
    assert esa.acw_sc_v2(ARG1) not in str(logs)


def test_solved_cookie_is_reused_by_next_request(monkeypatch):
    client, opener = _client(monkeypatch, [(CHALLENGE, DENIED), (USER, []), (USER, [])])
    client.get("/api/user/self")
    client.get("/api/user/self")
    assert len(opener.sent) == 3
    assert _cookies(opener.sent[2])["acw_sc__v2"] == esa.acw_sc_v2(ARG1)


def test_second_challenge_is_not_looped(monkeypatch):
    client, opener = _client(monkeypatch, [(CHALLENGE, DENIED), (CHALLENGE, DENIED)])
    with pytest.raises(VerificationRequired):
        client.get("/api/user/self")
    assert len(opener.sent) == 2


def test_replayed_401_still_classified_as_login(monkeypatch):
    import urllib.error

    client, opener = _client(monkeypatch, [(CHALLENGE, DENIED)])
    original = opener.open

    def open_(request, timeout=None):
        if opener.replies:
            return original(request, timeout)
        headers = Message()
        raise urllib.error.HTTPError(request.full_url, 401, "u", headers,
                                     __import__("io").BytesIO(b'{"success":false,"message":"\xe6\x9c\xaa\xe7\x99\xbb\xe5\xbd\x95"}'))

    opener.open = open_
    with pytest.raises(LoginRequired):
        client.get("/api/user/self")


def test_challenge_without_marker_is_not_touched(monkeypatch):
    """无标记且形态不完整（缺置换表）的页面不按算法猜 Cookie。"""
    bare = f"<html><script>var arg1='{ARG1}';</script></html>"
    client, opener = _client(monkeypatch, [(bare, [])])
    with pytest.raises(VerificationRequired):
        client.get("/api/user/self")
    assert len(opener.sent) == 1
    changed = CHALLENGE.replace("var m=[0xf,", "var m=[0xe,")
    client, opener = _client(monkeypatch, [(changed, [])])
    with pytest.raises(VerificationRequired):
        client.get("/api/user/self")
    assert len(opener.sent) == 1


def test_markerless_acw_challenge_is_solved_once(monkeypatch):
    """CI 实测 AgentRouter：边缘挑战页不带 X-Tengine-Error，重登后的余额读取因此全部落空。"""
    logs: list[str] = []
    client, opener = _client(monkeypatch, [(CHALLENGE, []), (USER, [])], logs=logs)
    assert client.get("/api/user/self")["data"]["id"] == 7
    assert len(opener.sent) == 2
    assert _cookies(opener.sent[1])["acw_sc__v2"] == esa.acw_sc_v2(ARG1)
    assert esa.acw_sc_v2(ARG1) not in str(logs)
    client, opener = _client(monkeypatch, [(CHALLENGE, []), (CHALLENGE, [])])
    with pytest.raises(VerificationRequired):
        client.get("/api/user/self")
    assert len(opener.sent) == 2


def test_challenge_kind_classification():
    assert esa.challenge_kind(CHALLENGE) == "acw"
    assert esa.challenge_kind("<html><div id='nc_1_wrapper'></div></html>") == "slider"
    assert esa.challenge_kind("<html><title>Just a moment...</title></html>") == "cloudflare"
    assert esa.challenge_kind("<html>blocked</html>") == "html"
    assert esa.challenge_kind(USER) == ""


def test_cookie_jar_mode_gets_waf_cookie_in_jar(monkeypatch):
    jar = CookieJar()
    client, opener = _client(monkeypatch, [(CHALLENGE, DENIED), (USER, [])], cookie="", jar=jar)
    assert client.get("/api/user/self")["data"]["id"] == 7
    assert _cookies(opener.sent[1])["acw_sc__v2"] == esa.acw_sc_v2(ARG1)
    assert "cookie" not in {k.lower() for k in client.headers}
