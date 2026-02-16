package jwtkit

import "github.com/golang-jwt/jwt/v5"

type TokenType string

const (
	TokenAccess  TokenType = "access"
	TokenRefresh TokenType = "refresh" // Deprecated: refresh tokens are opaque, not JWT.
)

type Claims struct {
	TokenType TokenType `json:"typ"`
	CustomClaims
	jwt.RegisteredClaims
}

type CustomClaims struct {
	Username string   `json:"username,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}
