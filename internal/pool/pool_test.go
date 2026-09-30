package pool

import (
	"context"
	"github.com/xxx-holic/wishtoken-desktop/internal/account"
	"github.com/xxx-holic/wishtoken-desktop/internal/config"
	"testing"
	"time"
)

func TestMemberConcurrencyAndCancellation(t *testing.T) {
	s, _ := account.Open("")
	p := New(s, config.Default)
	var release []func()
	for i := 0; i < 5; i++ {
		r, e := p.Acquire(context.Background(), "one")
		if e != nil {
			t.Fatal(e)
		}
		release = append(release, r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, e := p.Acquire(ctx, "one"); e == nil {
		t.Fatal("sixth request passed")
	}
	r, e := p.Acquire(context.Background(), "two")
	if e != nil {
		t.Fatal("other member blocked")
	}
	r()
	release[0]()
	release[0]()
	r, e = p.Acquire(context.Background(), "one")
	if e != nil {
		t.Fatal(e)
	}
	r()
	for _, r := range release {
		r()
	}
}

func TestSingleMemberRecoversAfterCooldown(t *testing.T) {
	s, _ := account.Open("")
	x, _ := s.Upsert(account.Account{AccountID: "team", UserID: "one", AccessToken: "at"})
	p := New(s, config.Default)
	p.ReportRateLimited(x.ID, time.Millisecond, "temporary")
	if _, e := p.Pick(context.Background(), PickOptions{}); e == nil {
		t.Fatal("cooling account selected")
	}
	time.Sleep(3 * time.Millisecond)
	if _, e := p.Pick(context.Background(), PickOptions{}); e != nil {
		t.Fatal("account did not recover", e)
	}
}
