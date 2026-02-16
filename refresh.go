package jwtkit

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"
)

type RefreshToken struct {
	Value  string             `json:"value"`
	Record RefreshTokenRecord `json:"record"`
}

type RefreshTokenRecord struct {
	ID           string     `json:"id"`
	FamilyID     string     `json:"family_id"`
	Subject      string     `json:"subject"`
	TokenHash    string     `json:"token_hash"`
	IssuedAt     time.Time  `json:"issued_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	ParentID     string     `json:"parent_id,omitempty"`
	ReplacedByID string     `json:"replaced_by_id,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`
}

// RefreshTokenStore is intentionally storage-agnostic.
// Redis/SQL implementations can live in another package.
type RefreshTokenStore interface {
	SaveRefreshToken(record RefreshTokenRecord) error
	GetRefreshTokenByHash(tokenHash string) (*RefreshTokenRecord, error)
	RevokeRefreshToken(tokenID, replacedByID string, revokedAt time.Time, reason string) error
	RevokeRefreshFamily(familyID string, revokedAt time.Time, reason string) error
}

func (m *Manager) IssueRefreshToken(subject string) (*RefreshToken, error) {
	return m.issueRefreshToken(subject, "", "")
}

func (m *Manager) RotateRefreshToken(current RefreshTokenRecord) (*RefreshToken, error) {
	if err := current.CanRotate(m.now()); err != nil {
		return nil, err
	}
	return m.issueRefreshToken(current.Subject, current.FamilyID, current.ID)
}

func (m *Manager) ValidateRefreshToken(value string, record RefreshTokenRecord) error {
	tokenValue := strings.TrimSpace(value)
	if tokenValue == "" {
		return ErrInvalidRefreshToken
	}
	if err := m.validateRefreshTokenFormat(tokenValue); err != nil {
		return err
	}
	if !CompareRefreshTokenHash(tokenValue, record.TokenHash) {
		return ErrInvalidRefreshToken
	}
	if record.IsRevoked() {
		return ErrRevokedRefreshToken
	}
	if record.IsExpired(m.now()) {
		return ErrExpiredRefreshToken
	}
	return nil
}

func (m *Manager) issueRefreshToken(subject, familyID, parentID string) (*RefreshToken, error) {
	if subject == "" {
		return nil, ErrEmptySubject
	}

	raw, err := m.randomBytes(m.cfg.RefreshTokenEntropy)
	if err != nil {
		return nil, err
	}
	tokenID, err := m.randomHex(m.cfg.RefreshTokenIDBytes)
	if err != nil {
		return nil, err
	}
	if familyID == "" {
		familyID, err = m.randomHex(m.cfg.RefreshTokenFamilyLen)
		if err != nil {
			return nil, err
		}
	}

	now := m.now()
	value := base64.RawURLEncoding.EncodeToString(raw)
	record := RefreshTokenRecord{
		ID:        tokenID,
		FamilyID:  familyID,
		Subject:   subject,
		TokenHash: HashRefreshToken(value),
		IssuedAt:  now,
		ExpiresAt: now.Add(m.cfg.RefreshTokenTTL),
		ParentID:  parentID,
	}

	return &RefreshToken{
		Value:  value,
		Record: record,
	}, nil
}

func (m *Manager) validateRefreshTokenFormat(value string) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return ErrInvalidRefreshToken
	}
	if len(raw) != m.cfg.RefreshTokenEntropy {
		return ErrInvalidRefreshToken
	}
	return nil
}

func HashRefreshToken(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func CompareRefreshTokenHash(token, expectedHash string) bool {
	tokenHash := HashRefreshToken(token)
	cleanExpected := strings.ToLower(strings.TrimSpace(expectedHash))
	return subtle.ConstantTimeCompare([]byte(tokenHash), []byte(cleanExpected)) == 1
}

func (r RefreshTokenRecord) IsExpired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && now.UTC().After(r.ExpiresAt.UTC())
}

func (r RefreshTokenRecord) IsRevoked() bool {
	return r.RevokedAt != nil
}

func (r RefreshTokenRecord) CanRotate(now time.Time) error {
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Subject) == "" || strings.TrimSpace(r.FamilyID) == "" {
		return ErrInvalidRefreshToken
	}
	if r.IsRevoked() {
		return ErrRevokedRefreshToken
	}
	if r.IsExpired(now) {
		return ErrExpiredRefreshToken
	}
	return nil
}

func RevokeRefreshToken(record *RefreshTokenRecord, replacedByID, reason string, at time.Time) error {
	if record == nil {
		return ErrInvalidRefreshToken
	}
	if record.IsRevoked() {
		return ErrRevokedRefreshToken
	}

	ts := at.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	record.RevokedAt = &ts
	record.ReplacedByID = strings.TrimSpace(replacedByID)
	record.RevokeReason = strings.TrimSpace(reason)

	return nil
}
