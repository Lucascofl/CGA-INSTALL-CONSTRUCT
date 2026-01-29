import Database from "better-sqlite3";
import bcrypt from "bcryptjs";

export const db = new Database("pontaj.db");

export function initDb() {
  db.exec(`
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'worker',
      active INTEGER NOT NULL DEFAULT 1,
      UNIQUE(first_name, last_name)
    );

    CREATE TABLE IF NOT EXISTS shifts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      start_time INTEGER NOT NULL,
      stop_time INTEGER,
      status TEXT NOT NULL DEFAULT 'working',
      total_work_minutes INTEGER NOT NULL DEFAULT 0,
      total_break_minutes INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS breaks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      shift_id INTEGER NOT NULL,
      break_start INTEGER NOT NULL,
      break_stop INTEGER,
      break_minutes INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(shift_id) REFERENCES shifts(id)
    );
  `);

  const adminExists = db.prepare("SELECT 1 FROM users WHERE role='admin' LIMIT 1").get();
  if (!adminExists) {
    const hash = bcrypt.hashSync("admin123", 10);
    db.prepare(
      "INSERT INTO users (first_name, last_name, password_hash, role) VALUES (?, ?, ?, ?)"
    ).run("Admin", "Pontaj", hash, "admin");
  }
}

export function nowMs() {
  return Date.now();
}

export function minutesBetween(aMs, bMs) {
  return Math.max(0, Math.round((bMs - aMs) / 60000));
}

export function formatHoursMinutes(totalMinutes) {
  const h = Math.floor(totalMinutes / 60);
  const m = totalMinutes % 60;
  const mm = String(m).padStart(2, "0");
  return `${h}:${mm}`;
}