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
            recommendation,
            iocs_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(timespec="seconds"),
        message_id,
        sender,
        subject,
        risk_level,
        score,
        recommendation,
        json.dumps(iocs or {})
    ))

    

    print("Committed report to database")