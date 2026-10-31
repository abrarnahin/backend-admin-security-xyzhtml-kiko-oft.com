"""Admin-only maintenance. Uses ADMIN_DATABASE_URL (never the web app's credentials).

  python maintenance.py migrate            # apply schema.sql
  python maintenance.py purge [DAYS]       # delete messages older than DAYS (default RETENTION_DAYS or 90)
  python maintenance.py delete-email ADDR  # erase everything stored for one email address (deletion request)
"""
import os
import sys

import psycopg


def _conn():
    url = os.environ.get("ADMIN_DATABASE_URL")
    if not url:
        sys.exit("ADMIN_DATABASE_URL is not set")
    return psycopg.connect(url, connect_timeout=10)


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    with _conn() as conn:
        if cmd == "migrate":
            conn.execute(open(os.path.join(os.path.dirname(__file__), "schema.sql"), encoding="utf-8").read())
            print("schema applied")
        elif cmd == "purge":
            days = int(argv[2]) if len(argv) > 2 else int(os.environ.get("RETENTION_DAYS", "90"))
            n = conn.execute("DELETE FROM contact_messages WHERE created_at < now() - make_interval(days => %s)", (days,)).rowcount
            print(f"deleted {n} rows older than {days} days")
        elif cmd == "delete-email" and len(argv) > 2:
            n = conn.execute("DELETE FROM contact_messages WHERE email = %s", (argv[2].strip().lower(),)).rowcount
            print(f"deleted {n} rows")
        else:
            sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
