package jwtkit

import "errors"

var (
	ErrInvalidConfig       = errors.New("invalid jwt configuration")
	ErrSigningNotConfigured = errors.New("signing key is not configured")
	ErrInvalidToken        = errors.New("invalid token")
	ErrExpiredToken        = errors.New("token expired")
	ErrTokenNotValidYet    = errors.New("token not valid yet")
	ErrUnexpectedTokenType = errors.New("unexpected token type")
	ErrInvalidAlg          = errors.New("unexpected signing algorithm")
	ErrMissingKeyID        = errors.New("missing key id")
	ErrUnknownKeyID        = errors.New("unknown key id")
	ErrMissingAuth         = errors.New("missing authorization header")
	ErrInvalidAuthFmt      = errors.New("invalid authorization header format")
	ErrEmptySubject        = errors.New("subject is required")

	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrExpiredRefreshToken = errors.New("refresh token expired")
	ErrRevokedRefreshToken = errors.New("refresh token revoked")
)
