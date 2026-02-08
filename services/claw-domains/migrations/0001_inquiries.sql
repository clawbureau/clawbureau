-- claw-domains: inquiry / offer capture
-- Tracks inbound interest per domain for pricing intelligence.

CREATE TABLE IF NOT EXISTS inquiries (
  id           TEXT PRIMARY KEY,
  domain       TEXT NOT NULL,
  name         TEXT DEFAULT '',
  email        TEXT NOT NULL,
  offer_amount REAL,
  message      TEXT DEFAULT '',
  referrer     TEXT DEFAULT '',
  country      TEXT DEFAULT 'XX',
  user_agent   TEXT DEFAULT '',
  created_at   TEXT DEFAULT (datetime('now'))
);

CREATE INDEX idx_inquiries_domain   ON inquiries(domain);
CREATE INDEX idx_inquiries_created  ON inquiries(created_at);
CREATE INDEX idx_inquiries_email    ON inquiries(email);
