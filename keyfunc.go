package jwtkit

import "github.com/golang-jwt/jwt/v5"

func (m *Manager) keyFunc(t *jwt.Token) (any, error) {
	if t == nil || t.Method == nil {
		return nil, ErrInvalidAlg
	}
	if t.Method.Alg() != string(m.cfg.Algorithm) {
		return nil, ErrInvalidAlg
	}

	if len(m.cfg.VerificationKeys) > 0 {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, ErrMissingKeyID
		}

		key, ok := m.cfg.VerificationKeys[kid]
		if !ok {
			return nil, ErrUnknownKeyID
		}
		return key, nil
	}

	key := m.cfg.verificationKey()
	if key == nil {
		return nil, ErrInvalidConfig
	}
	return key, nil
}
