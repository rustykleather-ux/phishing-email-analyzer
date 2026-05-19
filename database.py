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

def get_recent_reports(limit=25):
    init_db()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM reports
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


def get_report_stats():
    init_db()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM reports")
    total_reports = cursor.fetchone()[0]

    cursor.execute("""
        SELECT risk_level, COUNT(*)
        FROM reports
        GROUP BY risk_level
    """)
    by_risk = dict(cursor.fetchall())

    cursor.execute("""
        SELECT sender, COUNT(*) as count
        FROM reports
        GROUP BY sender
        ORDER BY count DESC
        LIMIT 5
    """)
    top_senders = cursor.fetchall()

    conn.close()

    return {
        "total_reports": total_reports,
        "by_risk": by_risk,
        "top_senders": top_senders
    }

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