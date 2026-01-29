import express from "express";
import http from "http";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Server as SocketIOServer } from "socket.io";
import { db, initDb, nowMs, minutesBetween, formatHoursMinutes } from "./db.js";

initDb();

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server);

const PORT = 3000;
const JWT_SECRET = "schimba_asta_cu_un_secret_lung";
const TOKEN_COOKIE = "pontaj_token";

app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const token = req.cookies[TOKEN_COOKIE];
  if (!token) return res.status(401).json({ error: "Neautentificat" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token invalid" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user?.role !== role) return res.status(403).json({ error: "Interzis" });
    next();
  };
}

function getOpenShift(userId) {
  return db
    .prepare("SELECT * FROM shifts WHERE user_id=? AND stop_time IS NULL ORDER BY id DESC LIMIT 1")
    .get(userId);
}

function getOpenBreak(shiftId) {
  return db
    .prepare("SELECT * FROM breaks WHERE shift_id=? AND break_stop IS NULL ORDER BY id DESC LIMIT 1")
    .get(shiftId);
}

function getAdminSnapshot() {
  const rows = db.prepare(`
    SELECT
      s.id AS shift_id,
      u.first_name,
      u.last_name,
      s.start_time,
      s.stop_time,
      s.status,
      s.total_work_minutes,
      s.total_break_minutes
    FROM shifts s
    JOIN users u ON u.id = s.user_id
    ORDER BY s.id DESC
    LIMIT 300
  `).all();

  return rows.map((r) => {
    const start = new Date(r.start_time).toLocaleString();
    const stop = r.stop_time ? new Date(r.stop_time).toLocaleString() : "";
    return {
      shift_id: r.shift_id,
      first_name: r.first_name,
      last_name: r.last_name,
      start,
      stop,
      status: r.status,
      work: formatHoursMinutes(r.total_work_minutes),
      break: formatHoursMinutes(r.total_break_minutes)
    };
  });
}

function emitUpdate() {
  io.emit("admin_snapshot", getAdminSnapshot());
}

function deleteWorkerById(id) {
  const u = db.prepare("SELECT id, role FROM users WHERE id=?").get(id);
  if (!u) return { ok: false, status: 404, error: "Utilizator inexistent" };
  if (u.role === "admin") return { ok: false, status: 400, error: "Nu poți șterge admin" };

  const tx = db.transaction(() => {
    const shiftIds = db.prepare("SELECT id FROM shifts WHERE user_id=?").all(id).map((r) => r.id);

    for (const sid of shiftIds) {
      db.prepare("DELETE FROM breaks WHERE shift_id=?").run(sid);
    }
    db.prepare("DELETE FROM shifts WHERE user_id=?").run(id);

    const info = db.prepare("DELETE FROM users WHERE id=?").run(id);
    if (info.changes === 0) throw new Error("Utilizator inexistent");
  });

  tx();
  return { ok: true };
}

app.post("/api/login", (req, res) => {
  const { first_name, last_name, password } = req.body || {};
  if (!first_name || !last_name || !password) return res.status(400).json({ error: "Date lipsă" });

  const user = db.prepare(
    "SELECT * FROM users WHERE first_name=? AND last_name=? AND active=1 LIMIT 1"
  ).get(first_name.trim(), last_name.trim());

  if (!user) return res.status(401).json({ error: "Date greșite" });

  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Date greșite" });

  const token = signToken({
    id: user.id,
    role: user.role,
    first_name: user.first_name,
    last_name: user.last_name
  });

  res.cookie(TOKEN_COOKIE, token, { httpOnly: true, sameSite: "lax" });
  res.json({ role: user.role });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie(TOKEN_COOKIE);
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  res.json({
    id: req.user.id,
    role: req.user.role,
    first_name: req.user.first_name,
    last_name: req.user.last_name
  });
});

app.post("/api/worker/start", auth, (req, res) => {
  if (req.user.role !== "worker") return res.status(403).json({ error: "Interzis" });

  const open = getOpenShift(req.user.id);
  if (open) return res.status(400).json({ error: "Ai deja un pontaj deschis" });

  const t = nowMs();
  const info = db
    .prepare("INSERT INTO shifts (user_id, start_time, status) VALUES (?, ?, ?)")
    .run(req.user.id, t, "working");

  emitUpdate();
  res.json({ ok: true, shift_id: info.lastInsertRowid, start_time: t });
});

app.post("/api/worker/break/start", auth, (req, res) => {
  if (req.user.role !== "worker") return res.status(403).json({ error: "Interzis" });

  const shift = getOpenShift(req.user.id);
  if (!shift) return res.status(400).json({ error: "Nu ai pontaj deschis" });
  if (shift.status === "break") return res.status(400).json({ error: "Ești deja în pauză" });

  const openBr = getOpenBreak(shift.id);
  if (openBr) return res.status(400).json({ error: "Pauză deja deschisă" });

  const t = nowMs();
  db.prepare("INSERT INTO breaks (shift_id, break_start) VALUES (?, ?)").run(shift.id, t);
  db.prepare("UPDATE shifts SET status=? WHERE id=?").run("break", shift.id);

  emitUpdate();
  res.json({ ok: true, break_start: t });
});

app.post("/api/worker/break/stop", auth, (req, res) => {
  if (req.user.role !== "worker") return res.status(403).json({ error: "Interzis" });

  const shift = getOpenShift(req.user.id);
  if (!shift) return res.status(400).json({ error: "Nu ai pontaj deschis" });

  const br = getOpenBreak(shift.id);
  if (!br) return res.status(400).json({ error: "Nu ai pauză deschisă" });

  const t = nowMs();
  const brMin = minutesBetween(br.break_start, t);

  db.prepare("UPDATE breaks SET break_stop=?, break_minutes=? WHERE id=?").run(t, brMin, br.id);

  const newTotalBreak = shift.total_break_minutes + brMin;
  db.prepare("UPDATE shifts SET total_break_minutes=?, status=? WHERE id=?")
    .run(newTotalBreak, "working", shift.id);

  emitUpdate();
  res.json({ ok: true, break_stop: t, break_minutes: brMin });
});

app.post("/api/worker/stop", auth, (req, res) => {
  if (req.user.role !== "worker") return res.status(403).json({ error: "Interzis" });

  const shift = getOpenShift(req.user.id);
  if (!shift) return res.status(400).json({ error: "Nu ai pontaj deschis" });

  const br = getOpenBreak(shift.id);
  if (br) return res.status(400).json({ error: "Închide pauza înainte de Stop" });

  const t = nowMs();
  const totalMinutes = minutesBetween(shift.start_time, t);
  const workMinutes = Math.max(0, totalMinutes - shift.total_break_minutes);

  db.prepare("UPDATE shifts SET stop_time=?, total_work_minutes=?, status=? WHERE id=?")
    .run(t, workMinutes, "stopped", shift.id);

  emitUpdate();
  res.json({
    ok: true,
    stop_time: t,
    total_work_minutes: workMinutes,
    total_break_minutes: shift.total_break_minutes
  });
});

app.get("/api/admin/snapshot", auth, requireRole("admin"), (req, res) => {
  res.json(getAdminSnapshot());
});

app.get("/api/admin/users", auth, requireRole("admin"), (req, res) => {
  const users = db.prepare(`
    SELECT id, first_name, last_name, role, active
    FROM users
    ORDER BY last_name, first_name
  `).all();
  res.json(users);
});

app.post("/api/admin/users", auth, requireRole("admin"), (req, res) => {
  const { first_name, last_name, password } = req.body || {};
  if (!first_name || !last_name || !password) return res.status(400).json({ error: "Date lipsă" });

  const exists = db.prepare("SELECT 1 FROM users WHERE first_name=? AND last_name=? LIMIT 1")
    .get(first_name.trim(), last_name.trim());

  if (exists) return res.status(400).json({ error: "Utilizator existent" });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(
    "INSERT INTO users (first_name, last_name, password_hash, role) VALUES (?, ?, ?, ?)"
  ).run(first_name.trim(), last_name.trim(), hash, "worker");

  res.json({ ok: true, id: info.lastInsertRowid });
});

app.post("/api/admin/users/:id/delete", auth, requireRole("admin"), (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: "ID invalid" });

    const r = deleteWorkerById(id);
    if (!r.ok) return res.status(r.status).json({ error: r.error });

    emitUpdate();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e?.message || e) });
  }
});

io.on("connection", (socket) => {
  socket.emit("admin_snapshot", getAdminSnapshot());
});

server.listen(PORT, () => {
  console.log(`Server pornit: http://localhost:${PORT}`);
  console.log(`Admin: nume Admin, prenume Pontaj, parola admin123`);
});