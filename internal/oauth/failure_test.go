package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/xxx-holic/wishtoken-desktop/internal/account"
)

func TestRefreshFailureStripsCredentials(t *testing.T) {
	refresh := "rt_submitted_123456"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	opaque := "AbCdEf0123456789xyzTOKENVALUEEXTRA"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"rejected %s %s %s"}`, refresh, jwt, opaque)
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewriteTransport{target: target}}
	acc := &account.Account{RefreshToken: refresh}
	err := RefreshAccount(context.Background(), client, acc)
	if err == nil || !IsPermanent(err) {
		t.Fatalf("expected permanent failure, got %v", err)
	}
	for _, leaked := range []string{refresh, jwt, "eyJ", opaque} {
		if strings.Contains(err.Error(), leaked) || strings.Contains(acc.LastError, leaked) {
			t.Fatalf("leaked %q in err=%s last=%s", leaked, err.Error(), acc.LastError)
		}
	}
	if !strings.Contains(acc.LastError, "invalid_grant") || !strings.Contains(acc.LastError, "rejected") {
		t.Fatalf("lost operator context: %s", acc.LastError)
	}
}

func TestRefreshNonJSONBodyIsNotEchoed(t *testing.T) {
	refresh := "rt_plainbody_123456"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("raw token " + refresh))
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewriteTransport{target: target}}
	_, err := Refresh(context.Background(), client, refresh)
	if err == nil || strings.Contains(err.Error(), refresh) || strings.Contains(err.Error(), "raw token") {
		t.Fatalf("echoed non-JSON body: %v", err)
	}
	if err.Error() != "oauth token endpoint returned 502" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUsageErrorOmitsCredentials(t *testing.T) {
	token := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("mode") == "html" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html><body>" + token + "</body></html>"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":{"code":"invalid_api_key","message":"rejected %s"}}`, token)
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewriteTransport{target: target}}
	_, err := QueryUsage(context.Background(), client, &account.Account{AccessToken: token, AccountID: "acct_usage"}, UsageIdentity{})
	if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "eyJ") {
		t.Fatalf("usage error leaked: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_api_key") || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("lost usage context: %v", err)
	}
	htmlClient := &http.Client{Transport: modeTransport{target: target, mode: "html"}}
	_, err = QueryUsage(context.Background(), htmlClient, &account.Account{AccessToken: token, AccountID: "acct_usage"}, UsageIdentity{})
	if err == nil || err.Error() != "usage endpoint returned 403" || strings.Contains(err.Error(), token) {
		t.Fatalf("html usage body echoed: %v", err)
	}
}

type modeTransport struct {
	target *url.URL
	mode   string
}

func (t modeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = t.target.Scheme
	r.URL.Host = t.target.Host
	q := r.URL.Query()
	q.Set("mode", t.mode)
	r.URL.RawQuery = q.Encode()
	return http.DefaultTransport.RoundTrip(r)
}

func TestLoginCallbackOmitsCredentialText(t *testing.T) {
	token := "rt_callback_123456789"
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"
	s := &LoginSession{done: make(chan struct{})}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&error_description="+url.QueryEscape("rejected "+token+" "+jwt), nil)
	rec := httptest.NewRecorder()
	s.handleCallback(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, token) || strings.Contains(body, "eyJ") || !strings.Contains(body, "access_denied") {
		t.Fatalf("callback page: %s", body)
	}
	if s.err == nil || strings.Contains(s.err.Error(), token) || strings.Contains(s.err.Error(), "eyJ") || !strings.Contains(s.err.Error(), "access_denied") {
		t.Fatalf("session error: %v", s.err)
	}
}

func TestLoginExchangePageOmitsToken(t *testing.T) {
	code := "authcode_123456789"
	verifier := "verifier_1234567890"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"rejected %s %s"}`, r.PostForm.Get("code"), r.PostForm.Get("code_verifier"))
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	s := &LoginSession{
		state:    "st",
		verifier: verifier,
		client:   &http.Client{Transport: rewriteTransport{target: target}},
		done:     make(chan struct{}),
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=st&code="+url.QueryEscape(code), nil)
	rec := httptest.NewRecorder()
	s.handleCallback(rec, req)
	if strings.Contains(rec.Body.String(), code) || strings.Contains(rec.Body.String(), verifier) {
		t.Fatalf("exchange page leaked: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "token exchange failed") {
		t.Fatalf("exchange page: %s", rec.Body.String())
	}
	if s.err == nil || strings.Contains(s.err.Error(), code) || strings.Contains(s.err.Error(), verifier) || !strings.Contains(s.err.Error(), "invalid_grant") {
		t.Fatalf("exchange error: %v", s.err)
	}
}
