package jwtkit

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCreateAndParseAccessToken(t *testing.T) {
	now := time.Date(2026, time.January, 1, 10, 0, 0, 0, time.UTC)
	m := newTestManager(t, now)

	token, err := m.CreateAccessToken("user-42", CustomClaims{
		Username: "alireza",
		Roles:    []string{"admin"},
	})
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	claims, err := m.ParseAccessToken(token)
	if err != nil {
		t.Fatalf("ParseAccessToken() error = %v", err)
	}

	if claims.Subject != "user-42" {
		t.Fatalf("unexpected subject: %q", claims.Subject)
	}
	if claims.TokenType != TokenAccess {
		t.Fatalf("unexpected token type: %q", claims.TokenType)
	}
	if claims.Username != "alireza" {
		t.Fatalf("unexpected username: %q", claims.Username)
	}
}

func TestParseRejectsUnexpectedTokenType(t *testing.T) {
	now := time.Date(2026, time.January, 1, 10, 0, 0, 0, time.UTC)
	m := newTestManager(t, now)

	claims := Claims{
		TokenType: TokenRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-42",
			Issuer:    "issuer-test",
			Audience:  jwt.ClaimStrings{"api"},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
	}
	tkn := jwt.NewWithClaims(m.signingMethod(), claims)
	signed, err := tkn.SignedString(m.cfg.signingKey())
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	_, err = m.ParseAccessToken(signed)
	if !errors.Is(err, ErrUnexpectedTokenType) {
		t.Fatalf("expected ErrUnexpectedTokenType, got %v", err)
	}
}

func TestIssueValidateRotateRefreshToken(t *testing.T) {
	now := time.Date(2026, time.January, 1, 10, 0, 0, 0, time.UTC)
	m := newTestManager(t, now)

	issued, err := m.IssueRefreshToken("user-42")
	if err != nil {
		t.Fatalf("IssueRefreshToken() error = %v", err)
	}
	if issued.Value == "" {
		t.Fatalf("refresh token value is empty")
	}
	if issued.Record.TokenHash == "" {
		t.Fatalf("refresh token hash is empty")
	}

	if err := m.ValidateRefreshToken(issued.Value, issued.Record); err != nil {
		t.Fatalf("ValidateRefreshToken() error = %v", err)
	}

	rotated, err := m.RotateRefreshToken(issued.Record)
	if err != nil {
		t.Fatalf("RotateRefreshToken() error = %v", err)
	}
	if rotated.Record.FamilyID != issued.Record.FamilyID {
		t.Fatalf("family id must stay the same")
	}
	if rotated.Record.ParentID != issued.Record.ID {
		t.Fatalf("parent id mismatch")
	}
	if rotated.Value == issued.Value {
		t.Fatalf("rotated token must be different")
	}

	if err := RevokeRefreshToken(&issued.Record, rotated.Record.ID, "rotated", now); err != nil {
		t.Fatalf("RevokeRefreshToken() error = %v", err)
	}
	if !issued.Record.IsRevoked() {
		t.Fatalf("expected revoked token")
	}
}

func TestExtractBearerToken(t *testing.T) {
	token, err := ExtractBearerToken("Bearer abc.def")
	if err != nil {
		t.Fatalf("ExtractBearerToken() error = %v", err)
	}
	if token != "abc.def" {
		t.Fatalf("unexpected token value: %q", token)
	}
}

func TestNewRejectsWeakSecret(t *testing.T) {
	_, err := New(Config{
		Algorithm:       HS256,
		HMACSecret:      []byte("short"),
		Issuer:          "issuer-test",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
	})
	if err == nil {
		t.Fatalf("expected config validation error")
	}
}

func newTestManager(t *testing.T, now time.Time) *Manager {
	t.Helper()

	m, err := New(Config{
		Algorithm:       HS256,
		HMACSecret:      []byte("01234567890123456789012345678901"),
		Issuer:          "issuer-test",
		Audience:        []string{"api"},
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return m
}
