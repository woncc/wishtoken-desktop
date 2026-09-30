package main

import "github.com/xxx-holic/wishtoken-desktop/internal/ownerfile"

// writeOwnerFile replaces path with an owner-only file. The temporary file is
// created alongside the destination and renamed over it, so a symlink is not
// followed and an existing permissive mode is not preserved.
func writeOwnerFile(path string, data []byte) error {
	return ownerfile.Write(path, data)
}
