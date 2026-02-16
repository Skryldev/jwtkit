package jwtkit

import (
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	cfg    Config
	randMu sync.Mutex
}

func New(cfg Config, opts ...Option) (*Manager, error) {
	for _, opt := range opts {
		opt(&cfg)
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Manager{cfg: normalized}, nil
}

func MustNew(cfg Config, opts ...Option) *Manager {
	m, err := New(cfg, opts...)
	if err != nil {
		panic(err)
	}
	return m
}

func (m *Manager) signingMethod() jwt.SigningMethod {
	switch m.cfg.Algorithm {
	case RS256:
		return jwt.SigningMethodRS256
	case ES256:
		return jwt.SigningMethodES256
	default:
		return jwt.SigningMethodHS256
	}
}

func (m *Manager) signingKey() (any, error) {
	key := m.cfg.signingKey()
	if key == nil {
		return nil, ErrSigningNotConfigured
	}
	return key, nil
}

func (m *Manager) CreateAccessToken(sub string, custom CustomClaims) (string, error) {
	if sub == "" {
		return "", ErrEmptySubject
	}

	signingKey, err := m.signingKey()
	if err != nil {
		return "", err
	}

	now := m.now()
	jti, err := m.randomHex(m.cfg.AccessTokenIDBytes)
	if err != nil {
		return "", err
	}

	var aud jwt.ClaimStrings
	if len(m.cfg.Audience) > 0 {
		aud = append(jwt.ClaimStrings(nil), m.cfg.Audience...)
	}

	claims := Claims{
		TokenType:    TokenAccess,
		CustomClaims: custom,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   sub,
			Issuer:    m.cfg.Issuer,
			Audience:  aud,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.cfg.AccessTokenTTL)),
		},
	}

	token := jwt.NewWithClaims(m.signingMethod(), claims)
	if m.cfg.KeyID != "" {
		token.Header["kid"] = m.cfg.KeyID
	}

	return token.SignedString(signingKey)
}

// CreateRefreshToken is kept for backward compatibility.
// Deprecated: use IssueRefreshToken to also get the hashable metadata record.
func (m *Manager) CreateRefreshToken(sub string, _ CustomClaims) (string, error) {
	refresh, err := m.IssueRefreshToken(sub)
	if err != nil {
		return "", err
	}
	return refresh.Value, nil
}

// Parse is kept for backward compatibility and only accepts access JWT.
func (m *Manager) Parse(tokenStr string) (*Claims, error) {
	return m.ParseAccessToken(tokenStr)
}

func (m *Manager) ParseAccessToken(tokenStr string) (*Claims, error) {
	if strings.TrimSpace(tokenStr) == "" {
		return nil, ErrInvalidToken
	}

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims, m.keyFunc,
		jwt.WithValidMethods([]string{string(m.cfg.Algorithm)}),
		jwt.WithLeeway(m.cfg.ClockSkew),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotValidYet
		}
		if errors.Is(err, ErrMissingKeyID) {
			return nil, ErrMissingKeyID
		}
		if errors.Is(err, ErrUnknownKeyID) {
			return nil, ErrUnknownKeyID
		}
		if errors.Is(err, ErrInvalidAlg) {
			return nil, ErrInvalidAlg
		}
		return nil, ErrInvalidToken
	}

	if !tkn.Valid {
		return nil, ErrInvalidToken
	}

	if err := m.validateAccessClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func (m *Manager) validateAccessClaims(claims *Claims) error {
	now := m.now()

	if claims.TokenType != TokenAccess {
		return ErrUnexpectedTokenType
	}
	if claims.Subject == "" {
		return ErrInvalidToken
	}
	if claims.Issuer != m.cfg.Issuer {
		return ErrInvalidToken
	}

	if len(m.cfg.Audience) > 0 && !intersects(claims.Audience, m.cfg.Audience) {
		return ErrInvalidToken
	}

	if claims.ExpiresAt == nil {
		return ErrInvalidToken
	}
	if now.After(claims.ExpiresAt.Time.Add(m.cfg.ClockSkew)) {
		return ErrExpiredToken
	}
	if claims.NotBefore != nil && now.Add(m.cfg.ClockSkew).Before(claims.NotBefore.Time) {
		return ErrTokenNotValidYet
	}
	if claims.IssuedAt == nil {
		return ErrInvalidToken
	}
	if claims.IssuedAt.Time.After(now.Add(m.cfg.ClockSkew)) {
		return ErrTokenNotValidYet
	}

	return nil
}

func (m *Manager) now() time.Time {
	return m.cfg.Now().UTC()
}

func (m *Manager) randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	m.randMu.Lock()
	defer m.randMu.Unlock()
	if _, err := io.ReadFull(m.cfg.Entropy, b); err != nil {
		return nil, err
	}
	return b, nil
}

func (m *Manager) randomHex(size int) (string, error) {
	b, err := m.randomBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func intersects(tokenAud jwt.ClaimStrings, required []string) bool {
	for _, ta := range tokenAud {
		for _, ra := range required {
			if ta == ra {
				return true
			}
		}
	}
	return false
}
