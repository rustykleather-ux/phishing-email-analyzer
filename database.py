import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DB_PATH = Path("reports") / "phishing_reports.db"


def using_postgres():
    return DATABASE_URL.startswith("postgres")


def get_connection():
    if using_postgres():
        import psycopg2
        import psycopg2.extras

        return psycopg2.connect(
            DATABASE_URL,
            cursor_factory=psycopg2.extras.RealDictCursor
        )

    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    if using_postgres():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                created_at TEXT NOT NULL,
                message_id TEXT,
                sender TEXT,
                subject TEXT,
                risk_level TEXT,
                score INTEGER,
                recommendation TEXT,
                status TEXT DEFAULT 'New',
                analyst_notes TEXT DEFAULT '',
                iocs_json TEXT DEFAULT '{}'
            )
        """)
    else:
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
                iocs_json TEXT DEFAULT '{}'
            )
        """)

    conn.commit()
    conn.close()


def migrate_db():
    init_db()
    
    conn = get_connection()
    cursor = conn.cursor()
    

    if using_postgres():
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'reports'
        """)
        columns = [row["column_name"] for row in cursor.fetchall()]
    else:
        cursor.execute("PRAGMA table_info(reports)")
        columns = [column[1] for column in cursor.fetchall()]

    if "status" not in columns:
        cursor.execute("ALTER TABLE reports ADD COLUMN status TEXT DEFAULT 'New'")

    if "analyst_notes" not in columns:
        cursor.execute("ALTER TABLE reports ADD COLUMN analyst_notes TEXT DEFAULT ''")

    if "iocs_json" not in columns:
        cursor.execute("ALTER TABLE reports ADD COLUMN iocs_json TEXT DEFAULT '{}'")

    try:
        cursor.execute("ALTER TABLE reports ADD COLUMN reported_by TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()


def init_audit_db():
    conn = get_connection()
    cursor = conn.cursor()

    if using_postgres():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                created_at TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT,
                report_id INTEGER,
                details_json TEXT DEFAULT '{}'
            )
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT,
                report_id INTEGER,
                details_json TEXT DEFAULT '{}'
            )
        """)

    conn.commit()
    conn.close()


def save_report(
    message_id,
    sender,
    subject,
    risk_level,
    score,
    recommendation,
    iocs=None
):
    migrate_db()

    conn = get_connection()
    cursor = conn.cursor()

    iocs_json = json.dumps(iocs or {})
    created_at = datetime.now().isoformat(timespec="seconds")

    if using_postgres():
        cursor.execute("""
            INSERT INTO reports (
                created_at,
                message_id,
                sender,
                subject,
                risk_level,
                score,
                recommendation,
                status,
                analyst_notes,
                iocs_json
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            created_at,
            message_id,
            sender,
            subject,
            risk_level,
            score,
            recommendation,
            "New",
            "",
            iocs_json
        ))
    else:
        cursor.execute("""
            INSERT INTO reports (
                created_at,
                message_id,
                sender,
                subject,
                risk_level,
                score,
                recommendation,
                status,
                analyst_notes,
                iocs_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            created_at,
            message_id,
            sender,
            subject,
            risk_level,
            score,
            recommendation,
            "New",
            "",
            iocs_json
        ))

    conn.commit()
    conn.close()


def get_recent_reports(limit=25):
    migrate_db()

    conn = get_connection()
    cursor = conn.cursor()

    if using_postgres():
        cursor.execute("""
            SELECT *
            FROM reports
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))
        rows = cursor.fetchall()
    else:
        cursor.execute("""
            SELECT *
            FROM reports
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        rows = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return rows


def get_report_stats():
    migrate_db()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS count FROM reports")
    total_row = cursor.fetchone()

    total_reports = total_row["count"] if using_postgres() else total_row[0]

    cursor.execute("""
        SELECT risk_level, COUNT(*) AS count
        FROM reports
        GROUP BY risk_level
    """)

    by_risk = {}

    for row in cursor.fetchall():
        if using_postgres():
            by_risk[row["risk_level"]] = row["count"]
        else:
            by_risk[row[0]] = row[1]

    cursor.execute("""
        SELECT sender, COUNT(*) AS count
        FROM reports
        GROUP BY sender
        ORDER BY count DESC
        LIMIT 5
    """)

    top_senders = []

    for row in cursor.fetchall():
        if using_postgres():
            top_senders.append((row["sender"], row["count"]))
        else:
            top_senders.append((row[0], row[1]))

    conn.close()

    return {
        "total_reports": total_reports,
        "by_risk": by_risk,
        "top_senders": top_senders
    }


def get_report_iocs(report_id):
    migrate_db()

    conn = get_connection()
    cursor = conn.cursor()

    if using_postgres():
        cursor.execute(
            "SELECT iocs_json FROM reports WHERE id = %s",
            (report_id,)
        )
        row = cursor.fetchone()
    else:
        cursor.execute(
            "SELECT iocs_json FROM reports WHERE id = ?",
            (report_id,)
        )
        row = cursor.fetchone()

    conn.close()

    if not row:
        return {}

    return json.loads(row["iocs_json"] or "{}")


def get_report_by_id(report_id):
    migrate_db()

    conn = get_connection()
    cursor = conn.cursor()

    if using_postgres():
        cursor.execute(
            "SELECT * FROM reports WHERE id = %s",
            (report_id,)
        )
        row = cursor.fetchone()
    else:
        cursor.execute(
            "SELECT * FROM reports WHERE id = ?",
            (report_id,)
        )
        row = cursor.fetchone()

    conn.close()

    if not row:
        return None

    return dict(row)


def update_report_status(report_id, status):
    migrate_db()

    conn = get_connection()
    cursor = conn.cursor()

    if using_postgres():
        cursor.execute(
            "UPDATE reports SET status = %s WHERE id = %s",
            (status, report_id)
        )
    else:
        cursor.execute(
            "UPDATE reports SET status = ? WHERE id = ?",
            (status, report_id)
        )

    conn.commit()
    conn.close()


def save_audit_event(action, details=None, report_id=None, actor="system"):
    init_audit_db()

    conn = get_connection()
    cursor = conn.cursor()

    details_json = json.dumps(details or {})
    created_at = datetime.now().isoformat(timespec="seconds")

    if using_postgres():
        cursor.execute("""
            INSERT INTO audit_logs (
                created_at,
                action,
                actor,
                report_id,
                details_json
            )
            VALUES (%s, %s, %s, %s, %s)
        """, (
            created_at,
            action,
            actor,
            report_id,
            details_json
        ))
    else:
        cursor.execute("""
            INSERT INTO audit_logs (
                created_at,
                action,
                actor,
                report_id,
                details_json
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            created_at,
            action,
            actor,
            report_id,
            details_json
        ))

    conn.commit()
    conn.close()

def update_report_notes(report_id, notes):
    migrate_db()

    conn = get_connection()
    cursor = conn.cursor()

    if using_postgres():
        cursor.execute(
            "UPDATE reports SET analyst_notes = %s WHERE id = %s",
            (notes, report_id)
        )
    else:
        cursor.execute(
            "UPDATE reports SET analyst_notes = ? WHERE id = ?",
            (notes, report_id)
        )

    conn.commit()
    conn.close()

def get_recent_audit_logs(limit=25):
    init_audit_db()

    conn = get_connection()
    cursor = conn.cursor()

    if using_postgres():
        cursor.execute("""
            SELECT *
            FROM audit_logs
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))
        rows = cursor.fetchall()
    else:
        cursor.execute("""
            SELECT *
            FROM audit_logs
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        rows = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return rows