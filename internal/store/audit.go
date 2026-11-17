package store

import "strings"

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
	return s.ListAuditLogsFiltered(AuditFilter{Limit: limit, Offset: offset})
}

// ListAuditLogsFiltered returns audit log entries matching optional status, category prefix, and search query.
func (s *Store) ListAuditLogsFiltered(f AuditFilter) ([]AuditLog, int, error) {
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	var conds []string
	var args []any

	if st := strings.TrimSpace(f.Status); st != "" {
		conds = append(conds, "status = ?")
		args = append(args, st)
	}
	if cat := strings.TrimSpace(f.Category); cat != "" {
		conds = append(conds, "event_type LIKE ?")
		args = append(args, cat+"%")
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + q + "%"
		conds = append(conds, "(actor LIKE ? OR ip LIKE ? OR target LIKE ? OR detail LIKE ? OR event_type LIKE ?)")
		args = append(args, like, like, like, like, like)
	}

	whereClause := ""
	if len(conds) > 0 {
		whereClause = " WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := s.rdb.QueryRow(`SELECT COUNT(1) FROM audit_logs`+whereClause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	queryArgs := append(append([]any{}, args...), limit, offset)
	rows, err := s.rdb.Query(
		`SELECT id, event_type, actor, ip, user_agent, target, detail, status, created_at
		 FROM audit_logs`+whereClause+` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`,
		queryArgs...,
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
