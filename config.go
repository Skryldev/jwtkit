package jwtkit

import "time"

type Algorithm string

const (
	HS256 Algorithm = "HS256"
	RS256 Algorithm = "RS256"
)

type Config struct {
	Algorithm        Algorithm
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	Issuer           string

	// HS256
	HMACSecret []byte

	// RS256
	PrivateKey any
	PublicKey  any

	// Key rotation
	KeyID string
}

type Option func(*Config)

func WithIssuer(iss string) Option {
	return func(c *Config) { c.Issuer = iss }
}

func WithAccessTTL(d time.Duration) Option {
	return func(c *Config) { c.AccessTokenTTL = d }
}

func WithRefreshTTL(d time.Duration) Option {
	return func(c *Config) { c.RefreshTokenTTL = d }
}