package jwtkit

import (
	"github.com/gin-gonic/gin"
)

const DefaultGinClaimsContextKey = "jwtkit.claims"

type GinMiddlewareConfig struct {
	ContextKey string
	OnError    func(*gin.Context, error)
}

func GinJWT(m *Manager) gin.HandlerFunc {
	return GinJWTWithConfig(m, GinMiddlewareConfig{})
}

func GinJWTWithConfig(m *Manager, cfg GinMiddlewareConfig) gin.HandlerFunc {
	contextKey := cfg.ContextKey
	if contextKey == "" {
		contextKey = DefaultGinClaimsContextKey
	}

	onError := cfg.OnError
	if onError == nil {
		onError = func(c *gin.Context, err error) {
			c.AbortWithStatusJSON(401, gin.H{"error": err.Error()})
		}
	}

	return func(c *gin.Context) {
		if m == nil {
			onError(c, ErrInvalidConfig)
			return
		}

		token, err := ExtractBearerToken(c.GetHeader("Authorization"))
		if err != nil {
			onError(c, err)
			return
		}

		claims, err := m.ParseAccessToken(token)
		if err != nil {
			onError(c, err)
			return
		}

		c.Set(contextKey, claims)
		c.Next()
	}
}

func ClaimsFromGin(c *gin.Context, keys ...string) (*Claims, bool) {
	key := DefaultGinClaimsContextKey
	if len(keys) > 0 && keys[0] != "" {
		key = keys[0]
	}

	v, ok := c.Get(key)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*Claims)
	return claims, ok
}
