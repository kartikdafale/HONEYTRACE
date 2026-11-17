-- HoneyTrace schema
CREATE DATABASE IF NOT EXISTS honeytrace;
USE honeytrace;

CREATE TABLE IF NOT EXISTS events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(64) NOT NULL,
  user_agent TEXT,
  activity_type VARCHAR(50) NOT NULL,   -- e.g. 'failed_login', 'decoy_click', 'form_probe'
  username_tried VARCHAR(100),          -- whatever username the attacker typed (never real creds)
  risk_level VARCHAR(20) NOT NULL,      -- 'low', 'medium', 'high'
  details TEXT,                         -- free-text note, e.g. which decoy link
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_events_created_at ON events (created_at);
CREATE INDEX idx_events_ip ON events (ip_address);
