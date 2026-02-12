package jwtkit

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	cfg Config
}

func New(cfg Config, opts ...Option) *Manager {
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Manager{cfg: cfg}
}

func (m *Manager) signingMethod() jwt.SigningMethod {
	switch m.cfg.Algorithm {
	case RS256:
		return jwt.SigningMethodRS256
	default:
		return jwt.SigningMethodHS256
	}
}

func (m *Manager) CreateRefreshToken(
	sub string,
	custom CustomClaims,
) (string, error) {
	now := time.Now()

	claims := Claims{
		CustomClaims: custom,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    m.cfg.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.cfg.RefreshTokenTTL)), // TTL خاص refresh
		},
	}

	token := jwt.NewWithClaims(m.signingMethod(), claims)

	if m.cfg.KeyID != "" {
		token.Header["kid"] = m.cfg.KeyID
	}

	return token.SignedString(m.signingKey())
}


func (m *Manager) signingKey() any {
	if m.cfg.Algorithm == RS256 {
		return m.cfg.PrivateKey
	}
	return m.cfg.HMACSecret
}

func (m *Manager) CreateAccessToken(sub string, custom CustomClaims) (string, error) {
	now := time.Now()

	claims := Claims{
		CustomClaims: custom,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    m.cfg.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.cfg.AccessTokenTTL)),
		},
	}

	token := jwt.NewWithClaims(m.signingMethod(), claims)
	if m.cfg.KeyID != "" {
		token.Header["kid"] = m.cfg.KeyID
	}

	return token.SignedString(m.signingKey())
}

func (m *Manager) Parse(tokenStr string) (*Claims, error) {
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims, m.keyFunc,
		jwt.WithValidMethods([]string{string(m.cfg.Algorithm)}),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	if !tkn.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}