package jwtkit

import "strings"

func ExtractBearerToken(authHeader string) (string, error) {
	header := strings.TrimSpace(authHeader)
	if header == "" {
		return "", ErrMissingAuth
	}

	parts := strings.Fields(header)
	if len(parts) != 2 {
		return "", ErrInvalidAuthFmt
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrInvalidAuthFmt
	}
	if strings.TrimSpace(parts[1]) == "" {
		return "", ErrInvalidAuthFmt
	}

	return parts[1], nil
}
