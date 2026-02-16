package jwtkit

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"strings"
	"time"
)

type Algorithm string

const (
	HS256 Algorithm = "HS256"
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
)

const (
	defaultAccessTokenTTL         = 15 * time.Minute
	maxAccessTokenTTL             = 30 * time.Minute
	defaultRefreshTokenTTL        = 7 * 24 * time.Hour
	maxRefreshTokenTTL            = 90 * 24 * time.Hour
	defaultClockSkew              = 30 * time.Second
	minHMACSecretBytes            = 32
	defaultRefreshEntropyBytes    = 32
	minRefreshTokenEntropyBytes   = 32
	defaultRefreshTokenIDBytes    = 16
	defaultRefreshTokenFamilySize = 16
	defaultAccessTokenIDBytes     = 16
)

type Config struct {
	Algorithm             Algorithm
	AccessTokenTTL        time.Duration
	RefreshTokenTTL       time.Duration
	ClockSkew             time.Duration
	RefreshTokenEntropy   int
	RefreshTokenIDBytes   int
	RefreshTokenFamilyLen int
	AccessTokenIDBytes    int

	Issuer   string
	Audience []string

	// HS256
	HMACSecret []byte

	// RS256 / ES256
	PrivateKey any
	PublicKey  any

	// Key rotation
	KeyID            string
	VerificationKeys map[string]any

	// For deterministic tests. Defaults to time.Now and crypto/rand.Reader.
	Now     func() time.Time
	Entropy io.Reader
}

type Option func(*Config)

func WithIssuer(iss string) Option {
	return func(c *Config) { c.Issuer = iss }
}

func WithAudience(aud ...string) Option {
	return func(c *Config) { c.Audience = append([]string(nil), aud...) }
}

func WithAccessTTL(d time.Duration) Option {
	return func(c *Config) { c.AccessTokenTTL = d }
}

func WithRefreshTTL(d time.Duration) Option {
	return func(c *Config) { c.RefreshTokenTTL = d }
}

func WithClockSkew(d time.Duration) Option {
	return func(c *Config) { c.ClockSkew = d }
}

func WithKeyID(kid string) Option {
	return func(c *Config) { c.KeyID = kid }
}

func WithVerificationKeys(keys map[string]any) Option {
	return func(c *Config) { c.VerificationKeys = cloneKeyMap(keys) }
}

func WithNow(fn func() time.Time) Option {
	return func(c *Config) { c.Now = fn }
}

func WithEntropy(r io.Reader) Option {
	return func(c *Config) { c.Entropy = r }
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) withDefaults() Config {
	out := c

	if out.Algorithm == "" {
		out.Algorithm = HS256
	}
	if out.AccessTokenTTL == 0 {
		out.AccessTokenTTL = defaultAccessTokenTTL
	}
	if out.RefreshTokenTTL == 0 {
		out.RefreshTokenTTL = defaultRefreshTokenTTL
	}
	if out.ClockSkew == 0 {
		out.ClockSkew = defaultClockSkew
	}
	if out.RefreshTokenEntropy == 0 {
		out.RefreshTokenEntropy = defaultRefreshEntropyBytes
	}
	if out.RefreshTokenIDBytes == 0 {
		out.RefreshTokenIDBytes = defaultRefreshTokenIDBytes
	}
	if out.RefreshTokenFamilyLen == 0 {
		out.RefreshTokenFamilyLen = defaultRefreshTokenFamilySize
	}
	if out.AccessTokenIDBytes == 0 {
		out.AccessTokenIDBytes = defaultAccessTokenIDBytes
	}
	if out.Now == nil {
		out.Now = time.Now
	}
	if out.Entropy == nil {
		out.Entropy = rand.Reader
	}

	out.HMACSecret = append([]byte(nil), out.HMACSecret...)
	out.Issuer = strings.TrimSpace(out.Issuer)
	out.Audience = sanitizeAudience(out.Audience)
	out.VerificationKeys = cloneKeyMap(out.VerificationKeys)

	switch out.Algorithm {
	case RS256:
		if out.PublicKey == nil {
			if pk, ok := out.PrivateKey.(*rsa.PrivateKey); ok && pk != nil {
				out.PublicKey = &pk.PublicKey
			}
		}
	case ES256:
		if out.PublicKey == nil {
			if pk, ok := out.PrivateKey.(*ecdsa.PrivateKey); ok && pk != nil {
				out.PublicKey = &pk.PublicKey
			}
		}
	}

	return out
}

func (c Config) validate() error {
	switch c.Algorithm {
	case HS256, RS256, ES256:
	default:
		return fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidConfig, c.Algorithm)
	}

	if strings.TrimSpace(c.Issuer) == "" {
		return fmt.Errorf("%w: issuer is required", ErrInvalidConfig)
	}
	if c.AccessTokenTTL <= 0 {
		return fmt.Errorf("%w: access token ttl must be > 0", ErrInvalidConfig)
	}
	if c.AccessTokenTTL > maxAccessTokenTTL {
		return fmt.Errorf("%w: access token ttl must be <= %s", ErrInvalidConfig, maxAccessTokenTTL)
	}
	if c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("%w: refresh token ttl must be > 0", ErrInvalidConfig)
	}
	if c.RefreshTokenTTL <= c.AccessTokenTTL {
		return fmt.Errorf("%w: refresh token ttl must be greater than access token ttl", ErrInvalidConfig)
	}
	if c.RefreshTokenTTL > maxRefreshTokenTTL {
		return fmt.Errorf("%w: refresh token ttl must be <= %s", ErrInvalidConfig, maxRefreshTokenTTL)
	}
	if c.ClockSkew < 0 {
		return fmt.Errorf("%w: clock skew cannot be negative", ErrInvalidConfig)
	}
	if c.RefreshTokenEntropy < minRefreshTokenEntropyBytes {
		return fmt.Errorf("%w: refresh token entropy must be >= %d bytes", ErrInvalidConfig, minRefreshTokenEntropyBytes)
	}
	if c.RefreshTokenIDBytes <= 0 {
		return fmt.Errorf("%w: refresh token id bytes must be > 0", ErrInvalidConfig)
	}
	if c.RefreshTokenFamilyLen <= 0 {
		return fmt.Errorf("%w: refresh token family length must be > 0", ErrInvalidConfig)
	}
	if c.AccessTokenIDBytes <= 0 {
		return fmt.Errorf("%w: access token id bytes must be > 0", ErrInvalidConfig)
	}

	if len(c.VerificationKeys) == 0 {
		if err := validateVerificationKey(c.Algorithm, c.verificationKey()); err != nil {
			return err
		}
	} else {
		for kid, key := range c.VerificationKeys {
			if strings.TrimSpace(kid) == "" {
				return fmt.Errorf("%w: verification key id cannot be empty", ErrInvalidConfig)
			}
			if err := validateVerificationKey(c.Algorithm, key); err != nil {
				return err
			}
		}
		if c.hasSigningKey() {
			if strings.TrimSpace(c.KeyID) == "" {
				return fmt.Errorf("%w: key id is required when signing with rotated keys", ErrInvalidConfig)
			}
			if _, ok := c.VerificationKeys[c.KeyID]; !ok {
				return fmt.Errorf("%w: key id %q not found in verification keys", ErrInvalidConfig, c.KeyID)
			}
		}
	}

	if c.PrivateKey != nil {
		if err := validateSigningKey(c.Algorithm, c.PrivateKey); err != nil {
			return err
		}
	}

	return nil
}

func validateVerificationKey(alg Algorithm, key any) error {
	switch alg {
	case HS256:
		secret, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("%w: hs256 verification key must be []byte", ErrInvalidConfig)
		}
		if len(secret) < minHMACSecretBytes {
			return fmt.Errorf("%w: hs256 secret must be at least %d bytes", ErrInvalidConfig, minHMACSecretBytes)
		}
	case RS256:
		if _, ok := key.(*rsa.PublicKey); !ok {
			return fmt.Errorf("%w: rs256 public key must be *rsa.PublicKey", ErrInvalidConfig)
		}
	case ES256:
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("%w: es256 public key must be *ecdsa.PublicKey", ErrInvalidConfig)
		}
	}
	return nil
}

func validateSigningKey(alg Algorithm, key any) error {
	switch alg {
	case HS256:
		secret, ok := key.([]byte)
		if !ok {
			return fmt.Errorf("%w: hs256 signing key must be []byte", ErrInvalidConfig)
		}
		if len(secret) < minHMACSecretBytes {
			return fmt.Errorf("%w: hs256 secret must be at least %d bytes", ErrInvalidConfig, minHMACSecretBytes)
		}
	case RS256:
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("%w: rs256 private key must be *rsa.PrivateKey", ErrInvalidConfig)
		}
	case ES256:
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return fmt.Errorf("%w: es256 private key must be *ecdsa.PrivateKey", ErrInvalidConfig)
		}
	}
	return nil
}

func (c Config) hasSigningKey() bool {
	switch c.Algorithm {
	case HS256:
		return len(c.HMACSecret) > 0
	case RS256, ES256:
		return c.PrivateKey != nil
	default:
		return false
	}
}

func (c Config) signingKey() any {
	switch c.Algorithm {
	case HS256:
		return c.HMACSecret
	case RS256, ES256:
		return c.PrivateKey
	default:
		return nil
	}
}

func (c Config) verificationKey() any {
	switch c.Algorithm {
	case HS256:
		return c.HMACSecret
	case RS256, ES256:
		return c.PublicKey
	default:
		return nil
	}
}

func cloneKeyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sanitizeAudience(in []string) []string {
	if len(in) == 0 {
		return nil
	}

	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, aud := range in {
		a := strings.TrimSpace(aud)
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}

	if len(out) == 0 {
		return nil
	}
	return out
}
