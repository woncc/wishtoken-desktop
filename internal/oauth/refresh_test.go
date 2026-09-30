package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/account"
	"github.com/xxx-holic/wishtoken-desktop/internal/testutil"
)

type rewriteTransport struct{ target *url.URL }

func (t rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = t.target.Scheme
	r.URL.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

func TestRefreshSuccessAndApply(t *testing.T) {
	idToken := testutil.MakeJWT(testutil.ChatGPTClaims("r@example.com", "acct_r", "pro", time.Now().Add(time.Hour)))
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": idToken, "refresh_token": "rt_rotated_123456", "id_token": idToken, "expires_in": 3600})
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewriteTransport{target: target}}
	tokens, err := Refresh(context.Background(), client, "rt_old_123456")
	if err != nil {
		t.Fatal(err)
	}
	if gotForm.Get("grant_type") != "refresh_token" || gotForm.Get("client_id") != ClientID || gotForm.Get("refresh_token") != "rt_old_123456" {
		t.Fatalf("unexpected form: %v", gotForm)
	}
	if tokens.RefreshToken != "rt_rotated_123456" || tokens.AccessToken != idToken {
		t.Fatalf("unexpected tokens: %+v", tokens)
	}
	acc := &account.Account{RefreshToken: "rt_old_123456"}
	Apply(acc, tokens)
	if acc.Email != "r@example.com" || acc.AccountID != "acct_r" || acc.PlanType != "pro" || acc.RefreshToken != "rt_rotated_123456" {
		t.Fatalf("apply did not fill claims: %+v", acc)
	}
}

func TestRefreshPermanentFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Refresh token is invalid"}`))
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewriteTransport{target: target}}
	_, err := RefreshWithRetry(context.Background(), client, "rt_bad_123456", 3)
	if err == nil || !IsPermanent(err) {
		t.Fatalf("expected permanent failure, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "invalid_grant") || !strings.Contains(msg, "Refresh token is invalid") || strings.Contains(msg, "rt_bad_123456") {
		t.Fatalf("unexpected permanent error: %s", msg)
	}
	acc := &account.Account{RefreshToken: "rt_bad_123456"}
	if err := RefreshAccount(context.Background(), client, acc); err == nil || acc.RefreshFailures != 1 || acc.LastError == "" {
		t.Fatalf("RefreshAccount bookkeeping: err=%v acc=%+v", err, acc)
	}
	if !strings.Contains(acc.LastError, "invalid_grant") || strings.Contains(acc.LastError, "rt_bad_123456") {
		t.Fatalf("LastError unsafe: %s", acc.LastError)
	}
}
