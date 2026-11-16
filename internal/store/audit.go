package store

// RecordAudit inserts a security or OAuth event into audit_logs.
func (s *Store) RecordAudit(eventType, actor, ip, userAgent, target, detail, status string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_logs (event_type, actor, ip, user_agent, target, detail, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		eventType, actor, ip, userAgent, target, detail, status, nowUnix(),
	)
	return err
}

// ListAuditLogs returns audit log entries newest first along with total count.
func (s *Store) ListAuditLogs(limit, offset int) ([]AuditLog, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM audit_logs`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.Query(
		`SELECT id, event_type, actor, ip, user_agent, target, detail, status, created_at
		 FROM audit_logs ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var l AuditLog
		if err := rows.Scan(&l.ID, &l.EventType, &l.Actor, &l.IP, &l.UserAgent, &l.Target, &l.Detail, &l.Status, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}
