// Package jwt decodes (without verifying) the OpenAI OAuth JWTs found in
// Codex credentials. Only the payload is inspected; signatures are never
// checked because the bridge is a client, not a resource server.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	authClaimKey    = "https://api.openai.com/auth"
	profileClaimKey = "https://api.openai.com/profile"
)

// Claims is the subset of claims the bridge relies on.
type Claims struct {
	Email             string
	AccountID         string // chatgpt_account_id
	UserID            string
	PlanType          string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	SubscriptionUntil time.Time
	Raw               map[string]any
}

// ErrNotJWT is returned when the input does not look like a JWT.
var ErrNotJWT = errors.New("not a JWT")

// IsJWT reports whether s has the three dot separated segments of a JWT.
func IsJWT(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "eyJ") {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts[:2] {
		if p == "" {
			return false
		}
	}
	return true
}

// Decode extracts the payload claims of token. It tolerates padded and
// unpadded base64url encodings.
func Decode(token string) (*Claims, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) < 2 || parts[1] == "" {
		return nil, ErrNotJWT
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, ErrNotJWT
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, ErrNotJWT
	}
	c := &Claims{Raw: raw}
	c.Email = str(raw["email"])
	if profile, ok := raw[profileClaimKey].(map[string]any); ok && c.Email == "" {
		c.Email = str(profile["email"])
	}
	if auth, ok := raw[authClaimKey].(map[string]any); ok {
		c.AccountID = str(auth["chatgpt_account_id"])
		c.UserID = firstNonEmpty(str(auth["chatgpt_user_id"]), str(auth["user_id"]))
		c.PlanType = str(auth["chatgpt_plan_type"])
		if s := str(auth["chatgpt_subscription_active_until"]); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				c.SubscriptionUntil = t
			}
		}
	}
	if exp, ok := number(raw["exp"]); ok && exp > 0 {
		c.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := number(raw["iat"]); ok && iat > 0 {
		c.IssuedAt = time.Unix(int64(iat), 0)
	}
	return c, nil
}

// Expiry returns the exp claim of token or the zero time.
func Expiry(token string) time.Time {
	c, err := Decode(token)
	if err != nil {
		return time.Time{}
	}
	return c.ExpiresAt
}

func decodeSegment(seg string) ([]byte, error) {
	seg = strings.TrimSpace(seg)
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, nil
	}
	padded := seg + strings.Repeat("=", (4-len(seg)%4)%4)
	if b, err := base64.URLEncoding.DecodeString(padded); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(padded)
}

func str(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	}
	return 0, false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
