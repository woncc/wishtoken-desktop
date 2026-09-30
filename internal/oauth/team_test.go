package oauth

import (
	"github.com/xxx-holic/wishtoken-desktop/internal/account"
	"github.com/xxx-holic/wishtoken-desktop/internal/testutil"
	"testing"
	"time"
)

func TestRefreshKeepsSelectedTeamWorkspace(t *testing.T) {
	a := account.Account{AccountID: "selected-team", UserID: "member", PlanType: "team"}
	token := testutil.MakeJWT(testutil.ChatGPTClaims("member@example.com", "personal-default", "free", time.Now().Add(time.Hour)))
	Apply(&a, &Tokens{AccessToken: token, IDToken: token, ExpiresAt: time.Now().Add(time.Hour)})
	if a.AccountID != "selected-team" || a.PlanType != "team" {
		t.Fatal("refresh switched Team workspace")
	}
}
