import os
import sys
import time
import unittest

os.environ["APP_ENV"] = "test"
os.environ["ALLOWED_ORIGINS"] = "https://kikosoft.com"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import create_app, ip_prefix, one_line, validate_contact, verify_turnstile  # noqa: E402
from app import MemoryStore, RedisStore, SharedStore  # noqa: E402

ORIGIN = {"Origin": "https://kikosoft.com"}


class Fake:
    def __init__(self, save_ok=True, mail_ok=True):
        self.save_ok, self.mail_ok, self.sent = save_ok, mail_ok, []

    def save(self, data, ip, ua=None):
        if not self.save_ok:
            raise RuntimeError("db")

    def mail(self, data):
        if not self.mail_ok:
            raise RuntimeError("smtp")
        self.sent.append(data)


def payload(**kw):
    base = {"name": "Ada", "email": "ada@example.com", "message": "Hello, I need a website.", "formLoadedAt": (time.time() - 10) * 1000}
    base.update(kw)
    return base


class ContactTests(unittest.TestCase):
    def client(self, svc=None):
        return create_app(svc or Fake()).test_client()

    def post(self, c, body=None, headers=ORIGIN, **kw):
        return c.post("/api/contact", json=payload() if body is None else body, headers=headers, **kw)

    def test_helpers(self):
        self.assertEqual(one_line("a\r\nBcc: x@y.z"), "a Bcc: x@y.z")
        errs, _ = validate_contact({"name": "A", "email": "bad", "message": "x"})
        self.assertEqual(len(errs), 3)
        _, v = validate_contact({"name": "Ada", "email": "ADA@Example.com", "message": "Long enough msg"})
        self.assertEqual(v["email"], "ada@example.com")

    def test_success(self):
        svc = Fake()
        r = self.post(self.client(svc))
        self.assertEqual((r.status_code, r.json["success"]), (200, True))
        self.assertEqual(len(svc.sent), 1)

    def test_validation(self):
        self.assertEqual(self.post(self.client(), payload(email="nope")).status_code, 400)

    def test_honeypot_not_faked(self):
        self.assertEqual(self.post(self.client(), payload(website="spam.com")).status_code, 400)

    def test_too_fast(self):
        self.assertEqual(self.post(self.client(), payload(formLoadedAt=time.time() * 1000)).status_code, 400)

    def test_content_type(self):
        r = self.client().post("/api/contact", data="x=1", headers={**ORIGIN, "Content-Type": "text/plain"})
        self.assertEqual(r.status_code, 415)

    def test_oversize(self):
        self.assertEqual(self.post(self.client(), payload(message="a" * 20000)).status_code, 413)

    def test_origin(self):
        self.assertEqual(self.post(self.client(), headers={"Origin": "https://evil.example"}).status_code, 403)
        self.assertEqual(self.post(self.client(), headers={}).status_code, 403)

    def test_both_fail_is_502(self):
        r = self.post(self.client(Fake(False, False)))
        self.assertEqual((r.status_code, r.json["success"]), (502, False))

    def test_mail_failure_with_db_ok_is_not_success(self):
        r = self.post(self.client(Fake(save_ok=True, mail_ok=False)))
        self.assertEqual((r.status_code, r.json["success"]), (502, False))

    def test_one_channel_ok(self):
        self.assertEqual(self.post(self.client(Fake(save_ok=False))).status_code, 200)

    def test_rate_limit(self):
        c, last = self.client(), None
        for _ in range(7):
            last = self.post(c)
        self.assertEqual(last.status_code, 429)

    def test_headers_and_cors(self):
        r = self.client().options("/api/contact", headers=ORIGIN)
        self.assertEqual(r.headers["Access-Control-Allow-Origin"], "https://kikosoft.com")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        r2 = self.client().options("/api/contact", headers={"Origin": "https://evil.example"})
        self.assertNotIn("Access-Control-Allow-Origin", r2.headers)


def cap(ok=True, reason=""):
    calls = []

    def fn(token, ip):
        calls.append((token, ip))
        return (ok, reason) if token == "good-token-123" or not ok else (False, "missing")
    fn.calls = calls
    return fn


class CaptchaTests(unittest.TestCase):
    def post(self, app, **kw):
        return app.test_client().post("/api/contact", json=payload(**kw), headers=ORIGIN)

    def test_valid_token_passes(self):
        svc, c = Fake(), cap()
        r = self.post(create_app(svc, captcha=c), turnstileToken="good-token-123")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(c.calls[0][0], "good-token-123")

    def test_missing_token_rejected(self):
        svc = Fake()
        r = self.post(create_app(svc, captcha=cap()))
        self.assertEqual((r.status_code, r.json["code"]), (400, "captcha"))
        self.assertEqual(svc.sent, [])

    def test_invalid_token_rejected(self):
        r = self.post(create_app(Fake(), captcha=cap(False, "invalid")), turnstileToken="bad-token-12345")
        self.assertEqual((r.status_code, r.json["code"]), (400, "captcha"))

    def test_provider_down_fails_closed(self):
        r = self.post(create_app(Fake(), captcha=cap(False, "unavailable")), turnstileToken="x" * 20)
        self.assertEqual(r.status_code, 503)

    def test_required_but_unconfigured_fails_closed(self):
        os.environ["CAPTCHA_REQUIRED"] = "true"
        try:
            r = self.post(create_app(Fake()))
        finally:
            del os.environ["CAPTCHA_REQUIRED"]
        self.assertEqual(r.status_code, 503)

    def test_verify_turnstile_rejects_bad_tokens_without_network(self):
        self.assertEqual(verify_turnstile(None, "s"), (False, "missing"))
        self.assertEqual(verify_turnstile("short", "s"), (False, "missing"))


class AbuseTests(unittest.TestCase):
    def test_429_has_retry_after(self):
        c = create_app(Fake()).test_client()
        last = None
        for i in range(7):
            last = c.post("/api/contact", json=payload(message=f"Distinct message number {i}"), headers=ORIGIN)
        self.assertEqual(last.status_code, 429)
        self.assertEqual(last.headers["Retry-After"], "900")

    def test_global_limit(self):
        os.environ["RL_GLOBAL_PER_MIN"] = "3"
        try:
            c = create_app(Fake()).test_client()
            codes = [c.get("/api/health").status_code for _ in range(5)]
        finally:
            del os.environ["RL_GLOBAL_PER_MIN"]
        self.assertEqual(codes[-1], 429)

    def test_repeated_bot_hits_progressively_blocked(self):
        c = create_app(Fake()).test_client()
        codes = [c.post("/api/contact", json=payload(website="x"), headers=ORIGIN).status_code for _ in range(5)]
        self.assertEqual(codes[:5], [400, 400, 400, 400, 400])
        self.assertEqual(c.post("/api/contact", json=payload(), headers=ORIGIN).status_code, 429)

    def test_duplicate_submission_sent_once(self):
        svc = Fake()
        c = create_app(svc).test_client()
        r1 = c.post("/api/contact", json=payload(), headers=ORIGIN)
        r2 = c.post("/api/contact", json=payload(), headers=ORIGIN)
        self.assertEqual((r1.status_code, r2.status_code, len(svc.sent)), (200, 200, 1))

    def test_failed_delivery_is_not_marked_duplicate(self):
        svc = Fake(False, False)
        c = create_app(svc).test_client()
        self.assertEqual(c.post("/api/contact", json=payload(), headers=ORIGIN).status_code, 502)
        svc.mail_ok = True
        r = c.post("/api/contact", json=payload(), headers=ORIGIN)
        self.assertEqual((r.status_code, len(svc.sent)), (200, 1))

    def test_spoofed_xff_ignored_without_trusted_proxy(self):
        c = create_app(Fake()).test_client()
        for i in range(6):
            r = c.post("/api/contact", json=payload(message=f"Spoof attempt number {i}"),
                       headers={**ORIGIN, "X-Forwarded-For": f"10.0.0.{i}"})
        self.assertEqual(r.status_code, 429)

    def test_trusted_proxy_uses_last_hop_only(self):
        os.environ["TRUSTED_PROXY_HOPS"] = "1"
        try:
            c = create_app(Fake()).test_client()
            for i in range(6):  # client forges the left-most value; the proxy-appended right-most is real
                r = c.post("/api/contact", json=payload(message=f"Proxy attempt number {i}"),
                           headers={**ORIGIN, "X-Forwarded-For": f"10.0.0.{i}, 203.0.113.9"})
        finally:
            del os.environ["TRUSTED_PROXY_HOPS"]
        self.assertEqual(r.status_code, 429)

    def test_errors_do_not_leak_internals(self):
        r = create_app(Fake(False, False)).test_client().post("/api/contact", json=payload(), headers=ORIGIN)
        self.assertNotIn("db", r.get_data(as_text=True).lower().replace("could not process", ""))

    def test_production_refuses_insecure_config(self):
        os.environ.update(APP_ENV="production", ALLOWED_ORIGINS="http://kikosoft.com")
        try:
            with self.assertRaises(RuntimeError):
                create_app(Fake())
        finally:
            os.environ.update(APP_ENV="test", ALLOWED_ORIGINS="https://kikosoft.com")

    def test_ip_prefix(self):
        self.assertEqual(ip_prefix("203.0.113.77"), "203.0.113.0/24")
        self.assertEqual(ip_prefix("2001:db8:1:2::5"), "2001:db8:1::/48")
        self.assertEqual(ip_prefix("garbage"), "")


class StoreTests(unittest.TestCase):
    class Broken:
        def hit(self, *a):
            raise ConnectionError("down")
        get = hit

    def test_memory_window_counts(self):
        m = MemoryStore()
        self.assertEqual([m.hit("k", 60) for _ in range(3)], [1, 2, 3])

    def test_redis_outage_falls_back_not_open(self):
        s = SharedStore(self.Broken())
        self.assertEqual([s.hit("k", 60) for _ in range(3)], [1, 2, 3])
        self.assertEqual(s.get("k"), 3)

    def test_redis_store_uses_atomic_script(self):
        class R:
            def eval(self, script, n, key, ttl):
                self.args = (n, key, ttl)
                return 1
        r = R()
        self.assertEqual(RedisStore(r).hit("a", 30), 1)
        self.assertEqual(r.args, (1, "kikosoft:rl:a", 30))


if __name__ == "__main__":
    unittest.main()
