import json
import sqlite3
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "reports" / "phishing_reports.db"


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
            recommendation TEXT,
            status TEXT DEFAULT 'New',
            analyst_notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

def save_report(message_id, sender, subject, risk_level, score, recommendation, iocs=None):
    init_db()
    add_iocs_column_if_missing()
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
def add_iocs_column_if_missing():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(reports)")
    columns = [column[1] for column in cursor.fetchall()]

    if "iocs_json" not in columns:
        cursor.execute("ALTER TABLE reports ADD COLUMN iocs_json TEXT DEFAULT '[]'")
        conn.commit()

    conn.close()
def get_report_iocs(report_id):
    init_db()
    add_iocs_column_if_missing()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        "SELECT iocs_json FROM reports WHERE id = ?",
        (report_id,)
    )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return {}

    return json.loads(row["iocs_json"] or "{}")


    conn.commit()
    conn.close()