package account

import (
	"path/filepath"
	"testing"
)

func TestTeamMembersNeverMergeByWorkspace(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := Account{AccountID: "team", UserID: "member-a", AccessToken: "a"}
	b := Account{AccountID: "team", UserID: "member-b", AccessToken: "b"}
	x, _ := s.Upsert(a)
	y, _ := s.Upsert(b)
	if x.ID == y.ID || s.Count() != 2 {
		t.Fatal("Team members were merged")
	}
	a.AccessToken = "a-refreshed"
	z, _ := s.Upsert(a)
	if z.ID != x.ID || z.Created {
		t.Fatal("same member was not updated")
	}
	a.AccountID = "other-team"
	z, _ = s.Upsert(a)
	if !z.Created || s.Count() != 3 {
		t.Fatal("different workspace was merged")
	}
}
