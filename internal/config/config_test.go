package config

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeAndAllowlist(t *testing.T) {
	cfg := Default()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if !cfg.BPSModelAllowed("GPT-6-Astra") || !cfg.BPSModelAllowed("gpt-6-astra-2026-08-01") || cfg.BPSModelAllowed("gpt-6-astra-turbo") || cfg.BPSModelAllowed("gpt-5.6-luna") {
		t.Fatalf("allowlist behaviour wrong: %v", cfg.BPSModels)
	}
	cfg.BPSModels = []string{"*"}
	if !cfg.BPSModelAllowed("anything") {
		t.Fatal("wildcard should allow all")
	}
	cfg.RoutePolicy = "bogus"
	if err := cfg.Normalize(); err == nil {
		t.Fatal("expected policy error")
	}
	cfg.RoutePolicy = "codex"
	cfg.Listen = "0.0.0.0:8790"
	if err := cfg.Normalize(); err == nil {
		t.Fatal("non-loopback without allow_remote must fail")
	}
	cfg.AllowRemote = true
	if err := cfg.Normalize(); err == nil {
		t.Fatal("allow_remote without api key must fail")
	}
	cfg.APIKey = "k"
	if err := cfg.Normalize(); err != nil || cfg.RoutePolicy != PolicyCodexOnly {
		t.Fatalf("normalize: %v policy=%s", err, cfg.RoutePolicy)
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg, err := Load(path)
	if err != nil || cfg.Listen != "127.0.0.1:8791" {
		t.Fatalf("default load: %v %+v", err, cfg)
	}
	cfg.DefaultModel = "gpt-6-astra"
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	again, err := Load(path)
	if err != nil || again.DefaultModel != "gpt-6-astra" {
		t.Fatalf("reload: %v %+v", err, again)
	}
}

func TestIsLoopback(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:1", "localhost:8790", "[::1]:8790", "127.0.0.1", ""} {
		if !IsLoopback(ok) {
			t.Fatalf("%q should be loopback", ok)
		}
	}
	for _, bad := range []string{":8791", "0.0.0.0:8790", "192.168.1.2:80", "example.com:443"} {
		if IsLoopback(bad) {
			t.Fatalf("%q should not be loopback", bad)
		}
	}
}

func TestLoopbackPeerAndBoundSocket(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:9", "[::1]:9", "::1", "127.0.0.1", "[::ffff:127.0.0.1]:9", "[::1%lo]:9"} {
		if !IsLoopbackPeer(ok) {
			t.Fatalf("%q should be a loopback peer", ok)
		}
	}
	for _, bad := range []string{"", "localhost:9", "localhost", "203.0.113.9:9", "203.0.113.9", "0.0.0.0:9", "[::]:9", "example.test:80"} {
		if IsLoopbackPeer(bad) {
			t.Fatalf("%q should not be a loopback peer", bad)
		}
	}
	if err := RequireLoopbackListener(false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}); err != nil {
		t.Fatal(err)
	}
	if err := RequireLoopbackListener(false, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 9}); err != nil {
		t.Fatal(err)
	}
	if err := RequireLoopbackListener(false, &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 9}); err == nil {
		t.Fatal("non-loopback socket accepted")
	}
	if err := RequireLoopbackListener(false, nil); err == nil {
		t.Fatal("nil socket accepted")
	}
	if err := RequireLoopbackListener(true, &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 9}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := RequireLoopbackListener(false, ln.Addr()); err != nil {
		t.Fatal(err)
	}
}

func TestSaveReplacesPermissiveFileAndIgnoresTempSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(dir, "stolen.json")
	if err := os.WriteFile(elsewhere, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, path+".tmp"); err != nil {
		t.Skip(err)
	}
	cfg := Default()
	cfg.APIKey = "synthetic-local-bridge-key"
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), cfg.APIKey) {
		t.Fatalf("config missing key: %q %v", raw, err)
	}
	kept, err := os.ReadFile(elsewhere)
	if err != nil || string(kept) != "keep" {
		t.Fatalf("config temp symlink was followed: %q %v", kept, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("config mode %o", info.Mode().Perm())
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Skip(err)
	}
	cfg.DefaultModel = "gpt-6-astra"
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	kept, err = os.ReadFile(elsewhere)
	if err != nil || string(kept) != "keep" || strings.Contains(string(kept), cfg.APIKey) {
		t.Fatalf("config symlink was followed: %q %v", kept, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("config path remained a symlink")
	}
}

func TestRefuseNonLoopbackListen(t *testing.T) {
	if err := RefuseNonLoopbackListen(""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty: %v", err)
	}
	if err := RefuseNonLoopbackListen(":8791"); err == nil {
		t.Fatal("missing host accepted")
	}
	if err := RefuseNonLoopbackListen("203.0.113.10:1"); err == nil || !strings.Contains(err.Error(), "203.0.113.10") {
		t.Fatalf("public ip: %v", err)
	}
	for _, ok := range []string{"127.0.0.1:8791", "[::1]:8791", "[::ffff:127.0.0.1]:8791"} {
		if err := RefuseNonLoopbackListen(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
	previous := lookupIP
	t.Cleanup(func() { lookupIP = previous })
	lookupIP = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("127.0.0.1")}, nil
	}
	if err := RefuseNonLoopbackListen("localhost:8791"); err == nil || !strings.Contains(err.Error(), "203.0.113.10") {
		t.Fatalf("mixed lookup: %v", err)
	}
	lookupIP = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, nil
	}
	if err := RefuseNonLoopbackListen("localhost:8791"); err != nil {
		t.Fatal(err)
	}
}
