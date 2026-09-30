//go:build !windows

package main

func checkCockpitProcess(string, string) error { return nil }
func rememberCockpitProcess(int, string)       {}
