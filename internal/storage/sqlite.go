package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Pivot struct {
	Type       string
	Value      string
	Confidence float64
	Source     string
}

type InvestigationLink struct {
	ParentID    int64
	PivotType   string
	PivotValue  string
	Depth       int
}

type Investigation struct {
	ID         int64
	PhoneE164  string
	CaseName   string
	Tags       []string
	Notes      string
	RiskScore  int
	RiskBand   string
	CreatedAt  time.Time
	PivotType  string
	PivotValue string
}

type PriorMatch struct {
	PivotType     string
	PivotValue    string
	Investigation Investigation
}

func Open(dbPath string) (*Store, error) {
	if dbPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dbPath = filepath.Join(home, ".phoneaccess", "investigations.db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS investigations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		phone_e164 TEXT NOT NULL,
		case_name TEXT,
		tags TEXT,
		notes TEXT,
		risk_score INTEGER,
		risk_band TEXT,
		parent_investigation_id INTEGER,
		pivot_type TEXT,
		pivot_value TEXT,
		pivot_depth INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		report_json TEXT
	);

	CREATE TABLE IF NOT EXISTS pivots (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		investigation_id INTEGER REFERENCES investigations(id),
		pivot_type TEXT,
		pivot_value TEXT,
		confidence REAL,
		source TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS api_usage (
		usage_key TEXT NOT NULL,
		month_key TEXT NOT NULL,
		count INTEGER NOT NULL DEFAULT 0,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (usage_key, month_key)
	);

	CREATE INDEX IF NOT EXISTS idx_phone ON investigations(phone_e164);
	CREATE INDEX IF NOT EXISTS idx_pivot_value ON pivots(pivot_value);

	CREATE TABLE IF NOT EXISTS photo_hashes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		investigation_id INTEGER REFERENCES investigations(id),
		phone_e164 TEXT,
		source TEXT,
		phash TEXT,
		photo_path TEXT,
		hamming_threshold INTEGER DEFAULT 10,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_phash ON photo_hashes(phash);
	`
	_, err := db.Exec(schema)
	if err != nil {
		return err
	}
	return ensureInvestigationColumns(db)
}

func ensureInvestigationColumns(db *sql.DB) error {
	columns := map[string]string{
		"parent_investigation_id": "INTEGER",
		"pivot_type":              "TEXT",
		"pivot_value":             "TEXT",
		"pivot_depth":              "INTEGER",
	}
	for name, typ := range columns {
		exists, err := investigationColumnExists(db, name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.Exec(fmt.Sprintf(`ALTER TABLE investigations ADD COLUMN %s %s`, name, typ)); err != nil {
			return err
		}
	}
	return nil
}

func investigationColumnExists(db *sql.DB, column string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(investigations)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) ConsumeMonthlyQuota(usageKey string, limit int, now time.Time) (bool, int, error) {
	if strings.TrimSpace(usageKey) == "" || limit <= 0 {
		return true, 0, nil
	}

	monthKey := now.UTC().Format("2006-01")
	tx, err := s.db.Begin()
	if err != nil {
		return false, 0, err
	}
	defer tx.Rollback()

	var current int
	err = tx.QueryRow(`
		SELECT count
		FROM api_usage
		WHERE usage_key = ? AND month_key = ?
	`, usageKey, monthKey).Scan(&current)
	if err != nil && err != sql.ErrNoRows {
		return false, 0, err
	}
	if current >= limit {
		return false, current, nil
	}

	next := current + 1
	_, err = tx.Exec(`
		INSERT INTO api_usage (usage_key, month_key, count, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(usage_key, month_key)
		DO UPDATE SET count = excluded.count, updated_at = CURRENT_TIMESTAMP
	`, usageKey, monthKey, next)
	if err != nil {
		return false, 0, err
	}
	if err := tx.Commit(); err != nil {
		return false, 0, err
	}
	return true, next, nil
}

func (s *Store) SaveInvestigation(e164, jsonReport string, score int, band string, pivots []Pivot, links ...InvestigationLink) (int64, []PriorMatch, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()

	var parentID any
	var pivotType any
	var pivotValue any
	var pivotDepth any
	if len(links) > 0 {
		link := links[0]
		if link.ParentID > 0 {
			parentID = link.ParentID
		}
		if strings.TrimSpace(link.PivotType) != "" {
			pivotType = strings.TrimSpace(link.PivotType)
		}
		if strings.TrimSpace(link.PivotValue) != "" {
			pivotValue = strings.TrimSpace(link.PivotValue)
		}
		if link.Depth > 0 {
			pivotDepth = link.Depth
		}
	}

	res, err := tx.Exec(`
		INSERT INTO investigations (phone_e164, case_name, tags, notes, risk_score, risk_band, parent_investigation_id, pivot_type, pivot_value, pivot_depth, report_json)
		VALUES (?, '', '', '', ?, ?, ?, ?, ?, ?, ?)
	`, e164, score, band, parentID, pivotType, pivotValue, pivotDepth, jsonReport)
	if err != nil {
		return 0, nil, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, nil, err
	}

	var matches []PriorMatch

	// Save pivots and find matches
	for _, p := range pivots {
		// Insert pivot
		_, err := tx.Exec(`
			INSERT INTO pivots (investigation_id, pivot_type, pivot_value, confidence, source)
			VALUES (?, ?, ?, ?, ?)
		`, id, p.Type, p.Value, p.Confidence, p.Source)
		if err != nil {
			return 0, nil, err
		}

		// Find matches (where investigation_id != id and pivot_value == p.Value)
		rows, err := tx.Query(`
			SELECT i.id, i.phone_e164, i.case_name, i.tags, i.notes, i.risk_score, i.risk_band, i.created_at
			FROM pivots p2
			JOIN investigations i ON p2.investigation_id = i.id
			WHERE p2.pivot_value = ? AND p2.investigation_id != ?
			GROUP BY i.id
		`, p.Value, id)
		if err != nil {
			return 0, nil, err
		}

		for rows.Next() {
			var inv Investigation
			var tagsStr string
			if err := rows.Scan(&inv.ID, &inv.PhoneE164, &inv.CaseName, &tagsStr, &inv.Notes, &inv.RiskScore, &inv.RiskBand, &inv.CreatedAt); err == nil {
				if tagsStr != "" {
					inv.Tags = strings.Split(tagsStr, ",")
				}
				matches = append(matches, PriorMatch{
					PivotType:     p.Type,
					PivotValue:    p.Value,
					Investigation: inv,
				})
			}
		}
		rows.Close()
	}

	if err := tx.Commit(); err != nil {
		return 0, nil, err
	}

	// Deduplicate matches
	return id, dedupMatches(matches), nil
}

func dedupMatches(matches []PriorMatch) []PriorMatch {
	seen := map[string]bool{}
	var out []PriorMatch
	for _, m := range matches {
		key := fmt.Sprintf("%d-%s-%s", m.Investigation.ID, m.PivotType, m.PivotValue)
		if !seen[key] {
			seen[key] = true
			out = append(out, m)
		}
	}
	return out
}

func (s *Store) ListInvestigations() ([]Investigation, error) {
	rows, err := s.db.Query(`
		SELECT id, phone_e164, case_name, tags, notes, risk_score, risk_band, created_at
		FROM investigations
		ORDER BY id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Investigation
	for rows.Next() {
		var inv Investigation
		var tagsStr string
		if err := rows.Scan(&inv.ID, &inv.PhoneE164, &inv.CaseName, &tagsStr, &inv.Notes, &inv.RiskScore, &inv.RiskBand, &inv.CreatedAt); err != nil {
			return nil, err
		}
		if tagsStr != "" {
			inv.Tags = strings.Split(tagsStr, ",")
		}
		out = append(out, inv)
	}
	return out, nil
}

func (s *Store) Search(query string) ([]Investigation, error) {
	like := "%" + query + "%"
	rows, err := s.db.Query(`
		SELECT id, phone_e164, case_name, tags, notes, risk_score, risk_band, created_at
		FROM investigations
		WHERE case_name LIKE ? OR tags LIKE ? OR notes LIKE ? OR phone_e164 LIKE ?
		ORDER BY id DESC
	`, like, like, like, like)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Investigation
	for rows.Next() {
		var inv Investigation
		var tagsStr string
		if err := rows.Scan(&inv.ID, &inv.PhoneE164, &inv.CaseName, &tagsStr, &inv.Notes, &inv.RiskScore, &inv.RiskBand, &inv.CreatedAt); err != nil {
			return nil, err
		}
		if tagsStr != "" {
			inv.Tags = strings.Split(tagsStr, ",")
		}
		out = append(out, inv)
	}
	return out, nil
}

func (s *Store) GetInvestigationReport(id int64) (string, error) {
	var report string
	err := s.db.QueryRow(`SELECT report_json FROM investigations WHERE id = ?`, id).Scan(&report)
	return report, err
}

// ListChildInvestigations returns investigations whose parent_investigation_id equals parentID.
func (s *Store) ListChildInvestigations(parentID int64) ([]Investigation, error) {
	rows, err := s.db.Query(`
		SELECT id, phone_e164, case_name, tags, notes, risk_score, risk_band, created_at,
		       COALESCE(pivot_type,''), COALESCE(pivot_value,'')
		FROM investigations
		WHERE parent_investigation_id = ?
		ORDER BY id ASC
	`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Investigation
	for rows.Next() {
		var inv Investigation
		var tagsStr string
		if err := rows.Scan(&inv.ID, &inv.PhoneE164, &inv.CaseName, &tagsStr, &inv.Notes,
			&inv.RiskScore, &inv.RiskBand, &inv.CreatedAt, &inv.PivotType, &inv.PivotValue); err != nil {
			return nil, err
		}
		if tagsStr != "" {
			inv.Tags = strings.Split(tagsStr, ",")
		}
		out = append(out, inv)
	}
	return out, nil
}

func (s *Store) UpdateTag(id int64, tag string) error {
	var tagsStr string
	err := s.db.QueryRow(`SELECT tags FROM investigations WHERE id = ?`, id).Scan(&tagsStr)
	if err != nil {
		return err
	}
	var tags []string
	if tagsStr != "" {
		tags = strings.Split(tagsStr, ",")
	}
	for _, t := range tags {
		if t == tag {
			return nil // already exists
		}
	}
	tags = append(tags, tag)
	_, err = s.db.Exec(`UPDATE investigations SET tags = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, strings.Join(tags, ","), id)
	return err
}

func (s *Store) UpdateNote(id int64, text string) error {
	var existing string
	err := s.db.QueryRow(`SELECT notes FROM investigations WHERE id = ?`, id).Scan(&existing)
	if err != nil {
		return err
	}
	if existing != "" {
		existing += "\n"
	}
	existing += text
	_, err = s.db.Exec(`UPDATE investigations SET notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, existing, id)
	return err
}

func (s *Store) UpdateName(id int64, name string) error {
	_, err := s.db.Exec(`UPDATE investigations SET case_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, name, id)
	return err
}

func (s *Store) Delete(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM pivots WHERE investigation_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM investigations WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}
