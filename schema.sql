-- Run ONCE with an administrative role (never from the web app). See docs/DEPLOYMENT.md.
CREATE TABLE IF NOT EXISTS contact_messages (
  id          BIGSERIAL PRIMARY KEY,
  name        VARCHAR(120) NOT NULL,
  email       VARCHAR(254) NOT NULL,
  message     TEXT NOT NULL,
  ip_prefix   VARCHAR(64),             -- truncated (IPv4 /24, IPv6 /48); full IPs are not stored
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS contact_messages_created_at_idx ON contact_messages (created_at);

-- Least-privilege application role: it can only INSERT. Replace the password, then put it in DATABASE_URL.
-- CREATE ROLE kikosoft_app LOGIN PASSWORD '<generate-a-long-random-password>';
-- GRANT INSERT ON contact_messages TO kikosoft_app;
-- GRANT USAGE ON SEQUENCE contact_messages_id_seq TO kikosoft_app;
-- Separate admin/maintenance role (reads + purges) is used only by maintenance.py via ADMIN_DATABASE_URL.
