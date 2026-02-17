<div dir="rtl">

# jwtkit

`jwtkit` یک ماژول JWT production-grade برای Go است که مسئولیت احراز هویت مبتنی بر توکن را به‌صورت شفاف، امن و قابل‌استفاده‌مجدد پیاده‌سازی می‌کند.

این ماژول:

- Access Token را به‌صورت JWT امضاشده و stateless تولید و اعتبارسنجی می‌کند.
- Refresh Token را به‌صورت opaque/random (غیر JWT) با متادیتای قابل ذخیره‌سازی ارائه می‌دهد.
- برای rotation/revoke الگوی استاندارد ارائه می‌کند و storage-agnostic است.

`jwtkit` عمداً فقط مسئول JWT و منطق توکن است؛ وابستگی داخلی به Redis، RabbitMQ یا سرویس hash خارجی ندارد. در صورت نیاز به persistence یا pub/sub، کافی است از interfaceهای موجود به زیرساخت خودتان وصل شوید.

---

## 1) مقدمه: Access Token vs Refresh Token

### Access Token (JWT)

- کوتاه‌عمر (short-lived) و مناسب Authorization در هر request
- شامل claims استاندارد (`sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`) + claims سفارشی
- stateless و قابل verify بدون DB

### Refresh Token (Opaque Random)

- بلندعمرتر از access token
- به‌صورت رشته random با entropy بالا تولید می‌شود (JWT نیست)
- در سرور به‌صورت hash شده نگه‌داری می‌شود (`TokenHash`)
- مناسب rotation، revoke و تشخیص reuse

### Best Practice معماری

- Access Token در header: `Authorization: Bearer <token>`
- Refresh Token در `HttpOnly + Secure` cookie
- Access کوتاه‌عمر، Refresh قابل rotate/revoke

---

## 2) ویژگی‌ها

- Production-ready با validation سخت‌گیرانه config
- Thread-safe (مدیریت concurrent برای entropy/random)
- Modular و reusable برای monolith، microservice و distributed systems
- پشتیبانی از `HS256`, `RS256`, `ES256`
- جلوگیری از `alg confusion` با verify محدود به الگوریتم تنظیم‌شده
- پشتیبانی از `kid` و `VerificationKeys` برای key rotation
- تولید access token کوتاه‌مدت با claims استاندارد
- تولید refresh token امن با hash helper و rotation-ready metadata
- middleware آماده برای Gin
- بدون lock-in به storage خاص (interface آماده برای DB/Redis/...)

---

## 3) نصب و پیش‌نیازها

### نصب

```bash
go get github.com/Skryldev/jwtkit
```

### Import

```go
import "github.com/Skryldev/jwtkit"
```

### پیش‌نیازها

- Go: طبق `go.mod` ماژول، نسخه `1.25.5` یا بالاتر
- Dependency اصلی JWT: `github.com/golang-jwt/jwt/v5`
- برای middleware آماده: `github.com/gin-gonic/gin`

---

## 4) نحوه استفاده

### 4.1) ساخت Manager و تولید Access Token

<div dir="ltr">

```go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Skryldev/jwtkit"
)

func ConfigJWT() *jwtkit.Manager {
secret := []byte(os.Getenv("JWT_HS256_SECRET"))
if len(secret) < 32 {
	panic("JWT_HS256_SECRET must be at least 32 bytes")
}

manager, err := jwtkit.New(jwtkit.Config{
	Algorithm:       jwtkit.HS256,
	HMACSecret:      secret,
	Issuer:          "auth-service",
	Audience:        []string{"api-gateway"},
	AccessTokenTTL:  15 * time.Minute,
	RefreshTokenTTL: 7 * 24 * time.Hour,
	ClockSkew:       30 * time.Second,
	})

	if err != nil {
		panic(fmt.Sprintf("failed to create JWT manager: %v", err))
	}

	return manager
}

func GenerateAccessToken(manager *jwtkit.Manager, userID, username string, roles []string) string {
accessToken, err := manager.CreateAccessToken(userID, jwtkit.CustomClaims{
	Username: username,
	Roles:    roles,
	})
if err != nil {
	panic(fmt.Sprintf("failed to generate access token: %v", err))
	}
	return accessToken
}

func ParseAndValidateToken(manager *jwtkit.Manager, token string) *jwtkit.CustomClaims {
claims, err := manager.ParseAccessToken(token)
	if err != nil {
switch {
case jwtkit.IsErrExpiredToken(err):
	panic("token expired")
case jwtkit.IsErrTokenNotValidYet(err):
	panic("token not active yet")
default:
	panic(fmt.Sprintf("invalid token: %v", err))
	}
}
	return claims
}

func main() {
manager := ConfigJWT()

accessToken := GenerateAccessToken(manager, "user-42", "alireza", []string{"admin"})
fmt.Println("Access Token:", accessToken)

claims := ParseAndValidateToken(manager, accessToken)
fmt.Println("Subject:", claims.Subject)
fmt.Println("Roles:", claims.Roles)
}
```
<div dir="rtl">


### 4.2) تولید Refresh Token

<div dir="ltr">

```go
issued, err := manager.IssueRefreshToken("user-42")
if err != nil {
	return err
}

// برای کلاینت
refreshTokenValue := issued.Value

// برای ذخیره‌سازی سمت سرور (DB/Redis/...)
refreshRecord := issued.Record
// refreshRecord.TokenHash -> مقدار hash شده برای ذخیره امن
```
<div dir="rtl">

### 4.2.1) قرارداد storage برای Refresh Token

<div dir="ltr">

```go
type RefreshTokenStore interface {
	SaveRefreshToken(record jwtkit.RefreshTokenRecord) error
	GetRefreshTokenByHash(tokenHash string) (*jwtkit.RefreshTokenRecord, error)
	RevokeRefreshToken(tokenID, replacedByID string, revokedAt time.Time, reason string) error
	RevokeRefreshFamily(familyID string, revokedAt time.Time, reason string) error
}
```
<div dir="rtl">

### 4.3) Verify کردن Refresh Token

<div dir="ltr">

```go
raw := refreshTokenFromClient
hash := jwtkit.HashRefreshToken(raw)

record, err := store.GetRefreshTokenByHash(hash)
if err != nil || record == nil {
	return jwtkit.ErrInvalidRefreshToken
}

if err := manager.ValidateRefreshToken(raw, *record); err != nil {
	return err // ErrInvalidRefreshToken / ErrExpiredRefreshToken / ErrRevokedRefreshToken
}
```
<div dir="rtl">

### 4.4) Flow کامل refresh (verify + rotate + issue new access)

<div dir="ltr">

```go
func RefreshFlow(manager *jwtkit.Manager, store jwtkit.RefreshTokenStore, rawRefresh string) (string, *jwtkit.RefreshToken, error) {
	hash := jwtkit.HashRefreshToken(rawRefresh)
	current, err := store.GetRefreshTokenByHash(hash)
	if err != nil || current == nil {
		return "", nil, jwtkit.ErrInvalidRefreshToken
	}

	if err := manager.ValidateRefreshToken(rawRefresh, *current); err != nil {
		// دفاع در برابر reuse: revoke کل family
		_ = store.RevokeRefreshFamily(current.FamilyID, time.Now().UTC(), "refresh validation failed")
		return "", nil, err
	}

	next, err := manager.RotateRefreshToken(*current)
	if err != nil {
		return "", nil, err
	}

	now := time.Now().UTC()
	if err := store.RevokeRefreshToken(current.ID, next.Record.ID, now, "rotated"); err != nil {
		return "", nil, err
	}
	if err := store.SaveRefreshToken(next.Record); err != nil {
		return "", nil, err
	}

	access, err := manager.CreateAccessToken(current.Subject, jwtkit.CustomClaims{})
	if err != nil {
		return "", nil, err
	}

	return access, next, nil
}
```
<div dir="rtl">

### 4.5) نکات امنیتی هنگام استفاده

- Refresh token را در cookie با ویژگی‌های `HttpOnly`, `Secure`, `SameSite` نگه دارید.
- Access token را ترجیحاً در memory نگه دارید؛ از localStorage برای سناریوهای حساس اجتناب کنید.
- خطاهای token را log کنید، اما raw token را log نکنید.
- روی refresh endpoint rate limit و anomaly detection قرار دهید.
- همه مسیرها را فقط روی TLS سرو کنید.

---

## 5) Configuration

`jwtkit.Config` مهم‌ترین تنظیمات امنیتی را در اختیار شما می‌گذارد.

| فیلد | توضیح | پیش‌فرض/محدودیت |
|---|---|---|
| `Algorithm` | الگوریتم امضا (`HS256`, `RS256`, `ES256`) | پیش‌فرض: `HS256` |
| `HMACSecret` | کلید برای `HS256` | حداقل 32 بایت |
| `PrivateKey` / `PublicKey` | کلیدهای `RS256`/`ES256` | نوع کلید باید صحیح باشد |
| `Issuer` | مقدار `iss` | الزامی |
| `Audience` | مقدار `aud` | اختیاری (با sanitize) |
| `AccessTokenTTL` | عمر access token | پیش‌فرض: `15m`, حداکثر: `30m` |
| `RefreshTokenTTL` | عمر refresh token | پیش‌فرض: `7d`, حداکثر: `90d`, باید > access TTL |
| `ClockSkew` | خطای ساعت مجاز | پیش‌فرض: `30s` |
| `KeyID` | مقدار `kid` برای token header | برای rotation توصیه‌شده |
| `VerificationKeys` | map کلیدهای verify برای rotation | در verify با `kid` استفاده می‌شود |
| `RefreshTokenEntropy` | بایت random برای refresh token | پیش‌فرض: `32`, حداقل: `32` |
| `RefreshTokenIDBytes` | طول شناسه داخلی refresh token | پیش‌فرض: `16` |
| `RefreshTokenFamilyLen` | طول family id | پیش‌فرض: `16` |
| `AccessTokenIDBytes` | طول `jti` در access token | پیش‌فرض: `16` |
| `Now`, `Entropy` | override برای تست‌پذیری | اختیاری |

### نمونه تنظیمات production-grade (HS256)

<div dir="ltr">

```go
cfg := jwtkit.Config{
	Algorithm:       jwtkit.HS256,
	HMACSecret:      []byte(os.Getenv("JWT_HS256_SECRET_32_PLUS_BYTES")),
	Issuer:          "auth-service",
	Audience:        []string{"api-gateway", "orders-api"},
	AccessTokenTTL:  10 * time.Minute,
	RefreshTokenTTL: 14 * 24 * time.Hour,
	ClockSkew:       30 * time.Second,
	KeyID:           "hs-2026-01",
	VerificationKeys: map[string]any{
		"hs-2026-01": []byte(os.Getenv("JWT_HS256_SECRET_32_PLUS_BYTES")),
	},
}
manager, err := jwtkit.New(cfg)
if err != nil {
	panic(err)
}
_ = manager
```
<div dir="rtl">

### نمونه تنظیمات production-grade (RS256 در معماری microservice)

<div dir="ltr">

```go
// auth-service (sign + verify)
authManager, err := jwtkit.New(jwtkit.Config{
	Algorithm:       jwtkit.RS256,
	PrivateKey:      authPrivateKey, // *rsa.PrivateKey
	PublicKey:       authPublicKey,  // *rsa.PublicKey
	KeyID:           "rsa-2026-01",
	VerificationKeys: map[string]any{
		"rsa-2026-01": authPublicKey,
	},
	Issuer:          "auth-service",
	Audience:        []string{"api-gateway"},
	AccessTokenTTL:  10 * time.Minute,
	RefreshTokenTTL: 14 * 24 * time.Hour,
})

// resource-service (verify-only)
verifyOnlyManager, err := jwtkit.New(jwtkit.Config{
	Algorithm: jwtkit.RS256,
	VerificationKeys: map[string]any{
		"rsa-2026-01": authPublicKey,
	},
	Issuer:          "auth-service",
	Audience:        []string{"api-gateway"},
	AccessTokenTTL:  10 * time.Minute,
	RefreshTokenTTL: 14 * 24 * time.Hour,
})
if err != nil {
	panic(err)
}

// verifyOnlyManager.ParseAccessToken(...) مجاز است
// verifyOnlyManager.CreateAccessToken(...) => ErrSigningNotConfigured
_ = authManager
_ = verifyOnlyManager
```
<div dir="rtl">

---

## 6) Best Practices

- Access Token را کوتاه‌عمر نگه دارید (`5-15m`).
- Refresh Token را فقط random/opaque نگه دارید و raw آن را ذخیره نکنید.
- همیشه `TokenHash` را ذخیره کنید.
- Rotation را اجباری کنید.
- اگر reuse یا tampering مشاهده شد، کل refresh family را revoke کنید.
- مدیریت خطا را به‌صورت دسته‌بندی‌شده انجام دهید: برای access از `ErrExpiredToken`, `ErrInvalidToken`, `ErrTokenNotValidYet` و برای refresh از `ErrInvalidRefreshToken`, `ErrExpiredRefreshToken`, `ErrRevokedRefreshToken`.
- در معماری microservice فقط `auth-service` مجاز به sign باشد، سرویس‌های دیگر verify-only باشند، و از `kid` + `VerificationKeys` برای key rotation بدون downtime استفاده کنید.

---

## 7) نمونه کد عملی

### 7.1) Middleware برای HTTP Server (Gin)

<div dir="ltr">

```go
r := gin.Default()

r.Use(jwtkit.GinJWTWithConfig(manager, jwtkit.GinMiddlewareConfig{
	ContextKey: "auth.claims",
	OnError: func(c *gin.Context, err error) {
		switch {
		case errors.Is(err, jwtkit.ErrExpiredToken):
			c.AbortWithStatusJSON(401, gin.H{"error": "token expired"})
		default:
			c.AbortWithStatusJSON(401, gin.H{"error": "unauthorized"})
		}
	},
}))
```
<div dir="rtl">

### 7.2) استفاده از claims در handler

<div dir="ltr">

```go
r.GET("/me", func(c *gin.Context) {
	claims, ok := jwtkit.ClaimsFromGin(c, "auth.claims")
	if !ok {
		c.JSON(401, gin.H{"error": "missing claims"})
		return
	}

	c.JSON(200, gin.H{
		"user_id":  claims.Subject,
		"username": claims.Username,
		"roles":    claims.Roles,
	})
})
```
<div dir="rtl">

### 7.3) Refresh flow برای auto-renew access token

<div dir="ltr">

```go
func (h *AuthHandler) Refresh(c *gin.Context) {
	rawRefresh, err := c.Cookie("refresh_token")
	if err != nil || rawRefresh == "" {
		c.JSON(401, gin.H{"error": "missing refresh token"})
		return
	}

	newAccess, nextRefresh, err := RefreshFlow(h.jwt, h.store, rawRefresh)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid refresh flow"})
		return
	}

	c.SetCookie(
		"refresh_token",
		nextRefresh.Value,
		int(time.Until(nextRefresh.Record.ExpiresAt).Seconds()),
		"/auth/refresh",
		"example.com",
		true,  // Secure
		true,  // HttpOnly
	)

	c.JSON(200, gin.H{
		"access_token": newAccess,
		"token_type":   "Bearer",
		"expires_in":   int((10 * time.Minute).Seconds()),
	})
}
```
<div dir="rtl">
---

## 8) FAQ

### چرا refresh token را hash می‌کنیم؟

اگر DB لو برود، مهاجم با hash نمی‌تواند مستقیم از refresh token استفاده کند. ذخیره hash (مثل password) سطح ریسک را به‌شدت کم می‌کند.

### تفاوت JWT و random token چیست؟

- JWT self-contained است و برای verify معمولاً DB نمی‌خواهد.
- random token opaque است و برای validate به lookup در storage نیاز دارد.
- برای refresh، opaque token امن‌تر و قابل revoke/rotate دقیق‌تر است.

### token را در client کجا نگه داریم؟

- Refresh token: `HttpOnly + Secure + SameSite` cookie
- Access token: در memory (نه localStorage برای سناریوهای حساس)
- همیشه روی HTTPS

### logout و revoke امن چطور انجام می‌شود؟

- logout فعلی: refresh record فعلی را revoke کنید.
- logout از همه دستگاه‌ها: کل `FamilyID` یا همه tokenهای subject را revoke کنید.
- در صورت تشخیص refresh reuse: کل family را revoke و session را terminate کنید.

---

## نکات پایانی

- `jwtkit` برای کار production طراحی شده، اما امنیت نهایی به پیاده‌سازی دقیق شما در storage، شبکه، rate limit و monitoring وابسته است.
- ماژول intentionally storage-agnostic است تا بتوانید آن را با PostgreSQL/Redis/Memory و هر معماری صف یا event دلخواه ادغام کنید.
