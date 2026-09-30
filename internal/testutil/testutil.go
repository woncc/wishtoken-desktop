// Package testutil holds helpers shared by the test suites.
package testutil

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MakeJWT builds an unsigned JWT with the given payload claims.
func MakeJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// ChatGPTClaims returns claims shaped like OpenAI's OAuth tokens.
func ChatGPTClaims(email, accountID, plan string, exp time.Time) map[string]any {
	return map[string]any{
		"email": email,
		"exp":   exp.Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": accountID,
			"chatgpt_plan_type":  plan,
			"chatgpt_user_id":    "user-" + accountID,
		},
	}
}

// SSE renders events as a server-sent event stream.
func SSE(events ...map[string]any) string {
	var sb strings.Builder
	for _, ev := range events {
		raw, _ := json.Marshal(ev)
		kind, _ := ev["type"].(string)
		fmt.Fprintf(&sb, "event: %s\ndata: %s\n\n", kind, raw)
	}
	return sb.String()
}
