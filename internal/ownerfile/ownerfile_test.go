package ownerfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteReplacesPermissiveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "secret.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := []byte("synthetic-export-not-a-credential")
	if err := Write(path, payload); err != nil {
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
		created := filepath.Join(dir, "fresh", "inner", "secret.json")
		if err := Write(created, payload); err != nil {
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
		t.Fatalf("temporary file left behind: %v", matches)
	}
}

func TestWriteDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if err := Write(link, []byte("replacement")); err != nil {
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
		t.Fatal("write left a symlink in place")
	}
	got, err := os.ReadFile(link)
	if err != nil || string(got) != "replacement" {
		t.Fatalf("replacement %q %v", got, err)
	}
}

func TestWriteRejectsEmptyAndDirectory(t *testing.T) {
	if err := Write("  ", []byte("x")); err == nil {
		t.Fatal("empty path accepted")
	}
	dir := t.TempDir()
	if err := Write(dir, []byte("x")); err == nil {
		t.Fatal("directory path accepted")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".owner-*")); len(matches) != 0 {
		t.Fatalf("temporary file left behind: %v", matches)
	}
}

func TestWriteIgnoresPredictableTempSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "stolen.json")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret.json")
	if err := os.Symlink(target, path+".tmp"); err != nil {
		t.Skip(err)
	}
	if err := Write(path, []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	kept, err := os.ReadFile(target)
	if err != nil || string(kept) != "keep" {
		t.Fatalf("temp symlink was followed: %q %v", kept, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "synthetic" {
		t.Fatalf("destination %q %v", got, err)
	}
}

func TestOpenAppendPreservesLogAndRejectsNonFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "service.log")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := OpenAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("new\n")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old\nnew\n" {
		t.Fatalf("append %q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("log mode %o", info.Mode().Perm())
		}
	}
	if _, err := OpenAppend("  "); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, err := OpenAppend(dir); err == nil {
		t.Fatal("directory path accepted")
	}
}

func TestOpenAppendReplacesSymlink(t *testing.T) {
	dir := t.TempDir()
	stolen := filepath.Join(dir, "stolen.log")
	if err := os.WriteFile(stolen, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "service.log")
	if err := os.Symlink(stolen, link); err != nil {
		t.Skip(err)
	}
	file, err := OpenAppend(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("local\n")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	kept, err := os.ReadFile(stolen)
	if err != nil || string(kept) != "keep" {
		t.Fatalf("log append followed a symlink: %q %v", kept, err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("log path remained a symlink")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("replacement log mode %o", info.Mode().Perm())
	}
	got, err := os.ReadFile(link)
	if err != nil || string(got) != "local\n" {
		t.Fatalf("replacement log %q %v", got, err)
	}
}
