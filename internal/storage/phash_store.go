package storage

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// PhotoHashRecord holds a stored profile photo perceptual hash and its context.
type PhotoHashRecord struct {
	ID              int64
	InvestigationID int64
	PhoneE164       string
	CaseName        string
	Source          string
	PHash           string
	PhotoPath       string
	HammingDist     int
	CreatedAt       time.Time
}

// StorePhotoHash persists a profile photo pHash linked to an investigation.
func (s *Store) StorePhotoHash(investigationID int64, e164, source, phash, photoPath string) error {
	_, err := s.db.Exec(`
		INSERT INTO photo_hashes (investigation_id, phone_e164, source, phash, photo_path)
		VALUES (?, ?, ?, ?, ?)
	`, investigationID, e164, source, phash, photoPath)
	return err
}

// FindSimilarHashes returns all stored hashes within threshold Hamming distance of phash,
// excluding the investigation with the given self ID (pass 0 to include all).
func (s *Store) FindSimilarHashes(phash string, threshold, selfInvestigationID int) ([]PhotoHashRecord, error) {
	if phash == "" {
		return nil, nil
	}
	targetBits, err := hexToUint64(phash)
	if err != nil {
		return nil, nil
	}

	rows, err := s.db.Query(`
		SELECT ph.id, ph.investigation_id, ph.phone_e164, ph.source, ph.phash, ph.photo_path, ph.created_at,
		       COALESCE(i.case_name, '')
		FROM photo_hashes ph
		LEFT JOIN investigations i ON ph.investigation_id = i.id
		WHERE ph.phash != ''
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []PhotoHashRecord
	for rows.Next() {
		var rec PhotoHashRecord
		var createdAt sql.NullString
		var caseName string
		if err := rows.Scan(&rec.ID, &rec.InvestigationID, &rec.PhoneE164, &rec.Source,
			&rec.PHash, &rec.PhotoPath, &createdAt, &caseName); err != nil {
			continue
		}
		if int(rec.InvestigationID) == selfInvestigationID && selfInvestigationID != 0 {
			continue
		}
		candidateBits, err := hexToUint64(rec.PHash)
		if err != nil {
			continue
		}
		dist := hammingDistance(targetBits, candidateBits)
		if dist > threshold {
			continue
		}
		rec.HammingDist = dist
		rec.CaseName = caseName
		if createdAt.Valid {
			rec.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt.String)
		}
		matches = append(matches, rec)
	}
	return matches, rows.Err()
}

func hexToUint64(h string) (uint64, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 8 {
		return 0, fmt.Errorf("invalid phash %q", h)
	}
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, nil
}

func hammingDistance(a, b uint64) int {
	diff := a ^ b
	count := 0
	for diff != 0 {
		count += int(diff & 1)
		diff >>= 1
	}
	return count
}
