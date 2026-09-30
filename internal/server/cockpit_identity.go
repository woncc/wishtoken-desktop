package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/account"
	"github.com/xxx-holic/wishtoken-desktop/internal/config"
	"github.com/xxx-holic/wishtoken-desktop/internal/httpx"
	"github.com/xxx-holic/wishtoken-desktop/internal/jwt"
	"github.com/xxx-holic/wishtoken-desktop/internal/oauth"
)

// Cockpit exports access-token-only accounts as personal_access_token. Codex
// hydrates that shape through whoami, whose official endpoint accepts PATs but
// rejects OAuth access tokens. This local adapter validates the OAuth token at
// the upstream usage endpoint before returning its own token-derived metadata.
// Complete OAuth bundles do not call this route. No ID token is manufactured.
func (s *Server) handleCockpitIdentity(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/cockpit-auth/"), "/")
	key := s.Config().CockpitKey
	// Empty addresses and hostnames are not proof of a loopback socket.
	if !config.IsLoopbackPeer(r.RemoteAddr) || len(parts) != 4 || key == "" || subtle.ConstantTimeCompare([]byte(parts[0]), []byte(key)) != 1 || strings.Join(parts[1:], "/") != "v1/user-auth-credential/whoami" || r.Method != http.MethodGet || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeError(w, r, 401, "identity_auth", "authentication_error", "invalid local identity request")
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) > 32768 {
		writeError(w, r, 401, "missing_token", "authentication_error", "missing token")
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	client, err := httpx.NewClient(httpx.Options{ProxyURL: s.Config().ProxyURL, Timeout: 20 * time.Second})
	if err != nil {
		writeError(w, r, 503, "identity_unavailable", "server_error", "identity client unavailable")
		return
	}
	serveCockpitIdentity(w, r, client, token)
}

func serveCockpitIdentity(w http.ResponseWriter, r *http.Request, client *http.Client, token string) {
	// Preserve real personal-access-token behavior for other Cockpit instances.
	if !jwt.IsJWT(token) {
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://auth.openai.com/api/accounts/v1/user-auth-credential/whoami", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, e := client.Do(req)
		if e != nil {
			writeError(w, r, 503, "identity_unavailable", "server_error", "upstream identity unavailable")
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
		return
	}
	claims, err := jwt.Decode(token)
	if err != nil || claims.AccountID == "" || claims.UserID == "" || claims.ExpiresAt.IsZero() || !time.Now().Before(claims.ExpiresAt) {
		writeError(w, r, 401, "invalid_oauth_token", "authentication_error", "invalid or expired OAuth access token")
		return
	}
	a := account.Account{AccessToken: token, AccountID: claims.AccountID, UserID: claims.UserID, Email: claims.Email, PlanType: claims.PlanType}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if _, err = oauth.QueryUsage(ctx, client, &a, oauth.UsageIdentity{UserAgent: "codex_cli_rs/0.146.0", Originator: "codex_cli_rs"}); err != nil {
		status := http.StatusServiceUnavailable
		if e, ok := err.(*oauth.UsageError); ok && (e.Status == 401 || e.Status == 403) {
			status = e.Status
		}
		writeError(w, r, status, "oauth_validation_failed", "authentication_error", "upstream OAuth validation failed; refresh the account in Cockpit")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(object{"email": a.Email, "chatgpt_user_id": a.UserID, "chatgpt_account_id": a.AccountID, "chatgpt_plan_type": a.PlanType, "chatgpt_account_is_fedramp": false})
}
