//go:build ignore

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	commands  = []string{"chimney-relay", "chimney-client", "udp_stress"}
	platforms = []struct {
		goos   string
		goarch string
		ext    string
	}{
		{"linux", "amd64", ""},
		{"linux", "arm64", ""},
		{"windows", "amd64", ".exe"},
		{"darwin", "amd64", ""},
		{"darwin", "arm64", ""},
	}
)

func main() {
	version := flag.String("version", "", "release version, for example v0.2.17")
	dist := flag.String("dist", "dist", "release artifact directory")
	flag.Parse()

	if *version == "" {
		fail("version is required")
	}

	expected := expectedArtifacts(*version)
	for _, name := range expected {
		path := filepath.Join(*dist, name)
		info, err := os.Stat(path)
		if err != nil {
			fail("missing artifact %s: %v", name, err)
		}
		if info.IsDir() {
			fail("artifact %s is a directory", name)
		}
		if info.Size() == 0 {
			fail("artifact %s is empty", name)
		}
	}

	sums, err := readChecksums(filepath.Join(*dist, "SHA256SUMS"))
	if err != nil {
		fail("%v", err)
	}
	for _, name := range expected {
		if name == "SHA256SUMS" {
			continue
		}
		want, ok := sums[name]
		if !ok {
			fail("SHA256SUMS missing entry for %s", name)
		}
		got, err := fileSHA256(filepath.Join(*dist, name))
		if err != nil {
			fail("hash %s: %v", name, err)
		}
		if got != want {
			fail("checksum mismatch for %s: got %s want %s", name, got, want)
		}
	}

	var extra []string
	for name := range sums {
		if !contains(expected, name) {
			extra = append(extra, name)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		fail("SHA256SUMS contains unexpected entries: %s", strings.Join(extra, ", "))
	}

	fmt.Printf("verified %d release artifacts in %s for %s\n", len(expected), *dist, *version)
}

func expectedArtifacts(version string) []string {
	var out []string
	for _, platform := range platforms {
		suffix := platform.goos + "-" + platform.goarch
		for _, cmd := range commands {
			out = append(out, fmt.Sprintf("%s-%s-%s%s", cmd, version, suffix, platform.ext))
		}
	}
	out = append(out,
		fmt.Sprintf("chimney-%s.spdx.json", version),
		"RELEASE_NOTES.md",
		"SHA256SUMS",
	)
	sort.Strings(out)
	return out
}

func readChecksums(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open SHA256SUMS: %w", err)
	}
	defer f.Close()

	sums := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("parse SHA256SUMS line %d: expected 2 fields", lineNo)
		}
		sum := strings.ToLower(fields[0])
		if len(sum) != sha256.Size*2 {
			return nil, fmt.Errorf("parse SHA256SUMS line %d: invalid sha256 length", lineNo)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return nil, fmt.Errorf("parse SHA256SUMS line %d: invalid sha256: %w", lineNo, err)
		}
		name := filepath.Base(fields[1])
		if name == "SHA256SUMS" {
			return nil, fmt.Errorf("SHA256SUMS must not contain itself")
		}
		if _, exists := sums[name]; exists {
			return nil, fmt.Errorf("duplicate SHA256SUMS entry for %s", name)
		}
		sums[name] = sum
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read SHA256SUMS: %w", err)
	}
	return sums, nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "verify-release-artifacts: "+format+"\n", args...)
	os.Exit(1)
}
