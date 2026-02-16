<div dir="rtl">

# jwtkit

پکیج `jwtkit` یک ماژول سبک، امن و production-ready برای **ایجاد، امضا و اعتبارسنجی JWT** در Go است.
این پکیج برای استفاده در هر نوع پروژه Go (Gin، Fiber، Echo یا net/http) طراحی شده و از بهترین شیوه‌های Go برای **performance، security و maintainability** پیروی می‌کند.

---

## ✨ ویژگی ها

- پشتیبانی از **HS256 (HMAC)** و **RS256 (RSA)**
- Access Token و Refresh Token
- Claims استاندارد (`exp`, `iat`, `nbf`, `sub`)
- Claims سفارشی (username, roles, ...)
- Middleware آماده برای Gin / Fiber / Echo
- Stateless و concurrency-safe
- جلوگیری از alg attack
- آماده‌ی production

---

## 📦 نصب

```bash
go get github.com/Skryldev/jwtkit
```
---
## 🚀 Basic Usage (HS256)
### 1️⃣ ساخت JWT Manager

<div dir="ltr">

```go
jwtMgr := jwtkit.New(jwtkit.Config{
	Algorithm:        jwtkit.HS256,
	HMACSecret:      []byte(os.Getenv("JWT_SECRET")),
	AccessTokenTTL:  15 * time.Minute,
	RefreshTokenTTL: 7 * 24 * time.Hour,
	Issuer:          "my-app",
})
```

<div dir="rtl">

## 2️⃣ ساخت Access Token

<div dir="ltr">

```go
accessToken, err := jwtMgr.CreateAccessToken(
"user-42",
jwtkit.CustomClaims{
Username: "alireza",
Roles:    []string{"user", "admin"},
  },
)
```

<div dir="rtl">

## 3️⃣ ساخت Refresh Token

<div dir="ltr">

```go
refreshToken, err := jwtMgr.CreateRefreshToken(
	"user-42",
	jwtkit.CustomClaims{
		Username: "alireza",
	},
)
```

<div dir="rtl">

## 🔍 Verify / Parse Token

<div dir="ltr">

```go
claims, err := jwtMgr.Parse(accessToken)
if err != nil {
	// token invalid or expired
	return
}

fmt.Println(claims.Subject)   // user-42
fmt.Println(claims.Username)  // alireza
fmt.Println(claims.Roles)     // [user admin]
```

<div dir="rtl">

---
## 🧩 استفاده از Middleware (Gin)
### 1️⃣ اضافه‌کردن Middleware

<div dir="ltr">

```go
r := gin.Default()
r.Use(middleware.GinJWT(jwtMgr))
```

<div dir="rtl">

## 2️⃣ استفاده از Claims در Handler

<div dir="ltr">

```go
r.GET("/profile", func(c *gin.Context) {
	claims := c.MustGet("claims").(*jwtkit.Claims)

	c.JSON(200, gin.H{
		"user_id":  claims.Subject,
		"username": claims.Username,
		"roles":    claims.Roles,
	})
})
```

<div dir="rtl">

### Verify Refresh Token

<div dir="ltr">

```go
claims, err := jwtMgr.Parse(refreshToken)
if err != nil {
	return unauthorized
}
```

<div dir="rtl">

##### سپس:
* بررسی وجود در DB / Redis
* بررسی revoke نشده بودن
* بررسی نوع توکن (refresh)
## استفاده از 🔐 RS256 (Asymmetric JWT)

<div dir="ltr">

```go
jwtMgr := jwtkit.New(jwtkit.Config{
	Algorithm:        jwtkit.RS256,
	PrivateKey:      privateKey, // *rsa.PrivateKey
	PublicKey:       publicKey,  // *rsa.PublicKey
	AccessTokenTTL:  15 * time.Minute,
	RefreshTokenTTL: 7 * 24 * time.Hour,
	Issuer:          "my-app",
})
```

<div dir="rtl">

---
## ❌ اشتباهات رایج
*  استفاده از Refresh Token در middleware
* TTL بلند برای Access Token
* ذخیره raw refresh token
* استفاده از HTTP بدون TLS

## 🟢 پیشنهادات
- Access Token کوتاه‌عمر (۱۰–۱۵ دقیقه)
- Refresh Token با rotation
- Secret حداقل ۳۲ بایت
- HTTPS الزامی
- Refresh Token فقط در endpoint مخصوص
- ذخیره Refresh Token در Redis
