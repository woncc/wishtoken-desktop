package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteOwnerFileReplacesPermissiveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "accounts.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	payload := []byte("synthetic-export-not-a-credential")
	if err := writeOwnerFile(path, payload); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("content %q err %v", got, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("file mode %o", info.Mode().Perm())
		}
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if parent.Mode().Perm() != 0o755 {
			t.Fatalf("existing parent mode changed: %o", parent.Mode().Perm())
		}
		created := filepath.Join(dir, "fresh", "inner", "accounts.json")
		if err := writeOwnerFile(created, payload); err != nil {
			t.Fatal(err)
		}
		for _, parentPath := range []string{filepath.Dir(created), filepath.Dir(filepath.Dir(created))} {
			info, err := os.Stat(parentPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm()&0o077 != 0 {
				t.Fatalf("created parent %s mode %o", parentPath, info.Mode().Perm())
			}
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".owner-*")); len(matches) != 0 {
		t.Fatalf("temporary export left behind: %v", matches)
	}
}

func TestWriteOwnerFileDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if err := writeOwnerFile(link, []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	kept, err := os.ReadFile(target)
	if err != nil || string(kept) != "keep" {
		t.Fatalf("symlink target changed: %q %v", kept, err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("export left a symlink in place")
	}
	got, err := os.ReadFile(link)
	if err != nil || string(got) != "replacement" {
		t.Fatalf("replacement %q %v", got, err)
	}
}

func TestWriteOwnerFileRejectsEmptyAndDirectory(t *testing.T) {
	if err := writeOwnerFile("  ", []byte("x")); err == nil {
		t.Fatal("empty path accepted")
	}
	dir := t.TempDir()
	if err := writeOwnerFile(dir, []byte("x")); err == nil {
		t.Fatal("directory path accepted")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".owner-*")); len(matches) != 0 {
		t.Fatalf("temporary export left behind: %v", matches)
	}
}
