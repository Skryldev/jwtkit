package jwtkit

import "github.com/golang-jwt/jwt/v5"

func (m *Manager) keyFunc(t *jwt.Token) (any, error) {
	if t.Method.Alg() != string(m.cfg.Algorithm) {
		return nil, ErrInvalidAlg
	}

	if m.cfg.Algorithm == RS256 {
		return m.cfg.PublicKey, nil
	}
	return m.cfg.HMACSecret, nil
}