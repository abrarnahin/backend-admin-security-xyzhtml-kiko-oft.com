"""Kikosoft contact API (Flask). Run locally: python app.py   Production: gunicorn app:app"""
import hashlib
import ipaddress
import json
import logging
import os
import re
import smtplib
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage

from flask import Flask, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

# Rate-limit stores consolidated from ratelimit.py. Redis is shared across workers;
# in-process fallback remains bounded and is logged when Redis is unavailable.
import threading
rl_log = logging.getLogger("kikosoft.ratelimit")

LUA_HIT = "local c=redis.call('INCR',KEYS[1]) if c==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end return c"


class MemoryStore:
    def __init__(self, max_keys: int = 10000):
        self.max_keys, self.data, self.lock = max_keys, {}, threading.Lock()

    def _live(self, key, now):
        rec = self.data.get(key)
        if rec and rec[1] > now:
            return rec
        self.data.pop(key, None)
        return None

    def hit(self, key: str, window: int) -> int:
        now = time.monotonic()
        with self.lock:
            rec = self._live(key, now)
            count = (rec[0] if rec else 0) + 1
            self.data[key] = (count, rec[1] if rec else now + window)
            if len(self.data) > self.max_keys:  # bound memory
                self.data = {k: v for k, v in self.data.items() if v[1] > now}
            return count

    def get(self, key: str) -> int:
        with self.lock:
            rec = self._live(key, time.monotonic())
            return rec[0] if rec else 0


class RedisStore:
    def __init__(self, client, prefix: str = "kikosoft:rl:"):
        self.r, self.prefix = client, prefix

    def hit(self, key: str, window: int) -> int:
        return int(self.r.eval(LUA_HIT, 1, self.prefix + key, int(window)))

    def get(self, key: str) -> int:
        v = self.r.get(self.prefix + key)
        return int(v) if v else 0


class SharedStore:
    """Redis when available, otherwise the local store (logged, never fail-open)."""

    def __init__(self, primary=None, fallback=None):
        self.primary, self.fallback = primary, fallback or MemoryStore()
        self.degraded_since = 0.0

    def _call(self, name, *args):
        if self.primary is not None:
            try:
                out = getattr(self.primary, name)(*args)
                self.degraded_since = 0.0
                return out
            except Exception as exc:  # noqa: BLE001 - any Redis failure -> local fallback
                now = time.monotonic()
                if not self.degraded_since or now - self.degraded_since > 60:
                    rl_log.warning("rate-limit backend unavailable (%s); using per-process fallback", type(exc).__name__)
                    self.degraded_since = now
        return getattr(self.fallback, name)(*args)

    def hit(self, key, window):
        return self._call("hit", key, window)

    def get(self, key):
        return self._call("get", key)


def build_store(redis_url: str = ""):
    """Return a SharedStore. Redis is imported lazily so the API runs without it."""
    if not redis_url:
        return SharedStore(None)
    import redis  # noqa: PLC0415

    client = redis.Redis.from_url(redis_url, socket_connect_timeout=1, socket_timeout=1, decode_responses=True)
    return SharedStore(RedisStore(client))

TURNSTILE_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

log = logging.getLogger("kikosoft")
LIMITS = {"name": 120, "email": 254, "message": 3000}
EMAIL_RE = re.compile(r"^[^\s@<>\"',;:]+@[^\s@<>\"',;:]+\.[^\s@<>\"',;:]{2,}$")
CTRL_RE = re.compile(r"[\r\n\u2028\u2029\x00]+")


def one_line(value: str) -> str:
    """Collapse line breaks so user input can never inject mail headers."""
    return CTRL_RE.sub(" ", value).strip()


def validate_contact(body):
    if not isinstance(body, dict):
        return [{"field": "body", "message": "Invalid request."}], None
    errors = [{"field": k, "message": f"{k} is required."} for k in LIMITS if not isinstance(body.get(k), str)]
    if errors:
        return errors, None
    name = one_line(body["name"])
    email = one_line(body["email"]).lower()
    message = body["message"].replace("\r\n", "\n").replace("\x00", "").strip()
    if not 2 <= len(name) <= LIMITS["name"]:
        errors.append({"field": "name", "message": "Name must be 2-120 characters."})
    if len(email) > LIMITS["email"] or not EMAIL_RE.match(email):
        errors.append({"field": "email", "message": "Enter a valid email address."})
    if not 10 <= len(message) <= LIMITS["message"]:
        errors.append({"field": "message", "message": "Message must be 10-3000 characters."})
    return errors, {"name": name, "email": email, "message": message}


def ip_prefix(ip: str) -> str:
    """Truncate an address (IPv4 /24, IPv6 /48) so full IPs are never stored."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    bits = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{bits}", strict=False))


def verify_turnstile(token, secret, ip=None, timeout=5):
    """Server-side Cloudflare Turnstile check. Returns (ok, reason). Fails closed on any error."""
    if not isinstance(token, str) or not 10 <= len(token) <= 2048:
        return False, "missing"
    fields = {"secret": secret, "response": token}
    if ip:
        fields["remoteip"] = ip
    req = urllib.request.Request(TURNSTILE_URL, data=urllib.parse.urlencode(fields).encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed https URL
            out = json.loads(r.read(65536))
    except Exception as exc:  # noqa: BLE001 - network/JSON failure -> reject, never fail open
        log.warning("turnstile unreachable: %s", type(exc).__name__)
        return False, "unavailable"
    if out.get("success") is not True:
        return False, "invalid"
    # Optional hostname/action pinning prevents accepting a token issued for another site/action.
    expected_host = os.environ.get("TURNSTILE_HOSTNAME", "").strip().lower()
    if expected_host and str(out.get("hostname", "")).lower() != expected_host:
        return False, "invalid"
    expected_action = os.environ.get("TURNSTILE_ACTION", "").strip()
    if expected_action and out.get("action") != expected_action:
        return False, "invalid"
    return True, ""


class Services:
    """Real storage + email. Both are optional, but at least one must succeed per request."""

    def save(self, data, ip, ua=None):
        url = os.environ.get("DATABASE_URL")
        if not url:
            raise RuntimeError("DATABASE_URL not set")
        import psycopg  # imported lazily so the API runs without a database

        # The app role is INSERT-only (see schema.sql); the table is created by maintenance.py migrate.
        with psycopg.connect(url, connect_timeout=5) as conn:
            conn.execute(
                "INSERT INTO contact_messages (name,email,message,ip_prefix) VALUES (%s,%s,%s,%s)",
                (data["name"], data["email"], data["message"], ip_prefix(ip or "")),
            )

    def mail(self, data):
        host, to = os.environ.get("SMTP_HOST"), os.environ.get("MAIL_TO")
        if not host or not to:
            raise RuntimeError("SMTP not configured")
        msg = EmailMessage()
        msg["From"] = os.environ.get("MAIL_FROM", os.environ.get("SMTP_USER", ""))
        msg["To"] = to
        msg["Reply-To"] = data["email"]
        msg["Subject"] = f"New Kikosoft contact message from {data['name']}"[:200]
        msg.set_content(f"Name: {data['name']}\nEmail: {data['email']}\n\n{data['message']}")
        port = int(os.environ.get("SMTP_PORT", "587"))
        smtp_cls = smtplib.SMTP_SSL if os.environ.get("SMTP_SECURE") == "true" else smtplib.SMTP
        with smtp_cls(host, port, timeout=10) as s:
            if smtp_cls is smtplib.SMTP:
                s.starttls()
            s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
            s.send_message(msg)


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        raise RuntimeError(f"{name} must be an integer") from None


def create_app(services=None, store=None, captcha=None):
    """`store` = rate-limit store, `captcha` = callable(token, ip) -> (ok, reason); both injectable for tests."""
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024
    production = os.environ.get("APP_ENV") == "production"
    services = services or Services()
    allowed = [o.strip().rstrip("/") for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()]
    min_age = float(os.environ.get("MIN_SUBMIT_SECONDS", "3"))
    secret = os.environ.get("TURNSTILE_SECRET", "")
    captcha_required = os.environ.get("CAPTCHA_REQUIRED", "true" if production else "false").lower() == "true"
    hops = _int("TRUSTED_PROXY_HOPS", 0)
    lim_contact, lim_captcha, lim_global = _int("RL_CONTACT_PER_15MIN", 5), _int("RL_CAPTCHA_PER_5MIN", 10), _int("RL_GLOBAL_PER_MIN", 60)
    lim_strikes = _int("RL_STRIKES_PER_15MIN", 8)

    if production:
        if not allowed or any(not o.startswith("https://") for o in allowed):
            raise RuntimeError("production requires ALLOWED_ORIGINS with https:// origins only")
        if not captcha_required:
            raise RuntimeError("production requires CAPTCHA_REQUIRED=true")
        if not secret and captcha is None:
            raise RuntimeError("production requires TURNSTILE_SECRET")
        # This deployment is intended to deliver contact messages to Gmail.
        # Fail at startup rather than silently running without email delivery.
        mail_required = ("SMTP_HOST", "SMTP_USER", "SMTP_PASS", "MAIL_TO")
        missing_mail = [key for key in mail_required if not os.environ.get(key)]
        if missing_mail:
            raise RuntimeError("production requires SMTP email settings: " + ", ".join(missing_mail))
    if hops > 0:  # trust exactly `hops` proxies; anything further left in X-Forwarded-For is ignored
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=0, x_port=0, x_prefix=0)
    store = store or build_store(os.environ.get("REDIS_URL", ""))
    if captcha is None and secret:
        captcha = lambda token, ip: verify_turnstile(token, secret, ip)  # noqa: E731

    def fail(status, error, retry=None, **extra):
        resp = jsonify(success=False, error=error, **extra)
        resp.status_code = status
        if retry:
            resp.headers["Retry-After"] = str(retry)
        return resp

    def limited(key, limit, window):
        return store.hit(key, window) > limit

    def strike(ip):
        store.hit("strike:" + ip, 900)

    @app.before_request
    def global_limit():
        ip = request.remote_addr or "?"
        if limited("g:" + ip, lim_global, 60):
            return fail(429, "Too many requests.", retry=60)

    @app.after_request
    def headers(resp):
        resp.headers.update({
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
            "Permissions-Policy": "geolocation=(), camera=(), microphone=()", "Cross-Origin-Resource-Policy": "cross-origin",
        })
        if production:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        origin = request.headers.get("Origin")
        if origin and origin in allowed:
            resp.headers.update({"Access-Control-Allow-Origin": origin, "Vary": "Origin",
                                 "Access-Control-Allow-Methods": "POST, OPTIONS",
                                 "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Max-Age": "600"})
        return resp

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    @app.route("/api/contact", methods=["OPTIONS"])
    def preflight():
        return "", 204

    @app.post("/api/contact")
    def contact():
        ip = request.remote_addr or "?"
        if request.headers.get("Origin") not in allowed:
            return fail(403, "Origin not allowed.")
        if store.get("strike:" + ip) >= lim_strikes or limited("c:" + ip, lim_contact, 900):
            return fail(429, "Too many messages. Please try again later.", retry=900)
        if not request.is_json:
            return fail(415, "Content-Type must be application/json.")
        body = request.get_json(silent=True)
        errors, data = validate_contact(body)
        if errors:
            return fail(400, "Validation failed.", details=errors)
        # Layered spam checks reject honestly: bots are never told "success".
        try:
            age = time.time() - float(body.get("formLoadedAt")) / 1000
        except (TypeError, ValueError):
            age = -1
        if body.get("website") or not min_age <= age <= 86400:
            strike(ip)
            return fail(400, "Request rejected.", code="spam")
        if captcha is not None:
            if limited("cap:" + ip, lim_captcha, 300):
                return fail(429, "Too many verification attempts. Please wait a few minutes.", retry=300)
            ok, reason = captcha(body.get("turnstileToken"), ip if ip != "?" else None)
            if not ok:
                if reason == "unavailable":
                    return fail(503, "Verification is temporarily unavailable. Please try again shortly.", code="captcha_unavailable")
                strike(ip)
                msg = "Please complete the human verification challenge." if reason == "missing" else \
                    "Verification failed or expired. Please refresh the challenge and try again."
                return fail(400, msg, code="captcha")
        elif captcha_required:
            return fail(503, "Verification is not configured.", code="captcha_unavailable")
        digest = hashlib.sha256(f"{data['email']}\n{data['message']}".encode()).hexdigest()
        if store.get("dup:" + digest):
            return jsonify(success=True, message="Message already received.")
        results = []
        for fn, args in ((services.save, (data, ip)), (services.mail, (data,))):
            try:
                fn(*args)
                results.append(True)
            except Exception as exc:  # noqa: BLE001 - logged by type only, never shown to the client
                log.error("contact step %s failed: %s", fn.__name__, type(exc).__name__)
                results.append(False)
        # Email delivery is mandatory for this site's contact form. A successful
        # database write alone must not make the frontend claim the email was sent.
        if not results[1]:
            return fail(502, "Could not send your message by email. Please try again later.")
        store.hit("dup:" + digest, 3600)
        log.info("contact accepted ip=%s stored=%s emailed=%s", ip_prefix(ip), results[0], results[1])
        return jsonify(success=True, message="Message received.")

    @app.errorhandler(413)
    def too_large(_):
        return fail(413, "Request too large.")

    @app.errorhandler(404)
    def not_found(_):
        return fail(404, "Not found.")

    @app.errorhandler(405)
    def bad_method(_):
        return fail(405, "Method not allowed.")

    @app.errorhandler(Exception)
    def unexpected(exc):
        log.error("unhandled: %s", type(exc).__name__)
        return fail(500, "Something went wrong.")

    return app


app = create_app() if os.environ.get("APP_ENV") != "test" else None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_app().run(port=int(os.environ.get("PORT", "4000")))
