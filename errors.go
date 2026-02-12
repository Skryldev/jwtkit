package jwtkit

import "errors"

var (
	ErrInvalidToken   = errors.New("invalid token")
	ErrExpiredToken   = errors.New("token expired")
	ErrInvalidAlg     = errors.New("unexpected signing algorithm")
	ErrMissingAuth    = errors.New("missing authorization header")
	ErrInvalidAuthFmt = errors.New("invalid authorization header format")
)