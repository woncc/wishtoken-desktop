package jwt

import (
	"strings"
	"testing"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/testutil"
)

func TestDecodeClaims(t *testing.T) {
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	token := testutil.MakeJWT(testutil.ChatGPTClaims("a@example.com", "acct_123", "pro", exp))
	if !IsJWT(token) {
		t.Fatalf("expected IsJWT to accept %q", token[:20])
	}
	claims, err := Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Email != "a@example.com" || claims.AccountID != "acct_123" || claims.PlanType != "pro" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if !claims.ExpiresAt.Equal(exp) {
		t.Fatalf("expiry mismatch: %v vs %v", claims.ExpiresAt, exp)
	}
	if claims.UserID != "user-acct_123" {
		t.Fatalf("user id: %q", claims.UserID)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "abc", "eyJ.x", "not.a.jwt"} {
		if _, err := Decode(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	if IsJWT("rt_" + strings.Repeat("x", 32)) {
		t.Fatal("refresh token must not be detected as JWT")
	}
}
