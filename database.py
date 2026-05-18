import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path("reports") / "phishing_reports.db"


def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            message_id TEXT,
            sender TEXT,
            subject TEXT,
            risk_level TEXT,
            score INTEGER,
            recommendation TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_report(message_id, sender, subject, risk_level, score, recommendation):
    init_db()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO reports (
            created_at,
            message_id,
            sender,
            subject,
            risk_level,
            score,
            recommendation
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(timespec="seconds"),
        message_id,
        sender,
        subject,
        risk_level,
        score,
        recommendation
    ))

    conn.commit()
    conn.close()