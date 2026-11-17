require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "honeytrace",
  waitForConnections: true,
  connectionLimit: 10,
});

// Pull the real client IP even behind a proxy/load balancer.
function getClientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (fwd) return fwd.split(",")[0].trim();
  return req.socket.remoteAddress;
}

// Very simple rule engine. Tune thresholds as you learn what normal traffic looks like.
async function scoreRisk(ip, activityType) {
  if (activityType === "decoy_click") return "medium";
  if (activityType === "form_probe") return "medium"; // e.g. SQLi-looking input, script tags, etc.

  // failed_login: escalate based on how many failed attempts this IP has made recently
  const [rows] = await pool.query(
    `SELECT COUNT(*) AS cnt FROM events
     WHERE ip_address = ? AND activity_type = 'failed_login'
       AND created_at > (NOW() - INTERVAL 10 MINUTE)`,
    [ip]
  );
  const recentFails = rows[0].cnt;
  if (recentFails >= 5) return "high";
  if (recentFails >= 2) return "medium";
  return "low";
}

// Called by the fake login page / decoy page whenever something worth logging happens.
app.post("/api/log-event", async (req, res) => {
  try {
    const ip = getClientIp(req);
    const userAgent = req.headers["user-agent"] || "";
    const { activityType, usernameTried, details } = req.body;

    if (!activityType) {
      return res.status(400).json({ error: "activityType is required" });
    }

    const riskLevel = await scoreRisk(ip, activityType);

    await pool.query(
      `INSERT INTO events (ip_address, user_agent, activity_type, username_tried, risk_level, details)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [ip, userAgent, activityType, usernameTried || null, riskLevel, details || null]
    );

    res.json({ ok: true, riskLevel });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "failed to log event" });
  }
});

// Aggregated counts for the pie chart (by risk level) and bar chart (activity type).
app.get("/api/stats", async (req, res) => {
  try {
    const [byRisk] = await pool.query(
      `SELECT risk_level, COUNT(*) AS count FROM events GROUP BY risk_level`
    );
    const [byType] = await pool.query(
      `SELECT activity_type, COUNT(*) AS count FROM events GROUP BY activity_type`
    );
    const [byDay] = await pool.query(
      `SELECT DATE(created_at) AS day, COUNT(*) AS count
       FROM events
       WHERE created_at > (NOW() - INTERVAL 14 DAY)
       GROUP BY DATE(created_at)
       ORDER BY day`
    );
    const [totals] = await pool.query(
      `SELECT COUNT(*) AS totalEvents,
              COUNT(DISTINCT ip_address) AS uniqueIps
       FROM events`
    );

    res.json({ byRisk, byType, byDay, totals: totals[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "failed to load stats" });
  }
});

// Recent activity table.
app.get("/api/recent", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 25, 200);
    const [rows] = await pool.query(
      `SELECT ip_address, user_agent, activity_type, username_tried, risk_level, details, created_at
       FROM events ORDER BY created_at DESC LIMIT ?`,
      [limit]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "failed to load recent events" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`HoneyTrace server running on http://localhost:${PORT}`));
