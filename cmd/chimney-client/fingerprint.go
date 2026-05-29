// Package main implements uTLS fingerprint selection and rotation.
//
// The -fingerprint flag accepts a comma-separated list of fingerprint names.
// Examples:
//
//	-fingerprint chrome                     (single fingerprint)
//	-fingerprint chrome,firefox,safari      (rotate across 3 browsers)
//	-fingerprint chrome-120,chrome-100      (rotate across Chrome versions)
package main

import (
	"fmt"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// FingerprintRotator cycles through a list of uTLS ClientHelloIDs.
// It is safe for concurrent use across multiple connections.
type FingerprintRotator struct {
	ids  []utls.ClientHelloID
	cur  int
	mu   sync.Mutex
}

// NewFingerprintRotator creates a rotator from a list of fingerprint names.
// Each name can be a short alias (e.g. "chrome") or include a version
// (e.g. "chrome-120", "firefox-105").
func NewFingerprintRotator(names []string) (*FingerprintRotator, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("at least one fingerprint name is required")
	}

	ids := make([]utls.ClientHelloID, 0, len(names))
	for _, name := range names {
		id, err := parseFingerprint(strings.TrimSpace(name))
		if err != nil {
			return nil, fmt.Errorf("invalid fingerprint %q: %w", name, err)
		}
		ids = append(ids, id)
	}

	return &FingerprintRotator{ids: ids}, nil
}

// Next returns the next fingerprint in the rotation.
func (r *FingerprintRotator) Next() utls.ClientHelloID {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.ids[r.cur]
	r.cur = (r.cur + 1) % len(r.ids)
	return id
}

// parseFingerprint maps a name string to a uTLS ClientHelloID.
func parseFingerprint(name string) (utls.ClientHelloID, error) {
	// Normalize: lowercase, hyphens to underscores
	normalized := strings.ToLower(name)

	switch normalized {
	// --- Chrome variants ---
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "chrome-58":
		return utls.HelloChrome_58, nil
	case "chrome-62":
		return utls.HelloChrome_62, nil
	case "chrome-70":
		return utls.HelloChrome_70, nil
	case "chrome-72":
		return utls.HelloChrome_72, nil
	case "chrome-83":
		return utls.HelloChrome_83, nil
	case "chrome-87":
		return utls.HelloChrome_87, nil
	case "chrome-96":
		return utls.HelloChrome_96, nil
	case "chrome-100":
		return utls.HelloChrome_100, nil
	case "chrome-102":
		return utls.HelloChrome_102, nil
	case "chrome-106":
		return utls.HelloChrome_106_Shuffle, nil
	case "chrome-120":
		return utls.HelloChrome_120, nil
	case "chrome-120-pq":
		return utls.HelloChrome_120_PQ, nil

	// --- Firefox variants ---
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "firefox-55":
		return utls.HelloFirefox_55, nil
	case "firefox-56":
		return utls.HelloFirefox_56, nil
	case "firefox-63":
		return utls.HelloFirefox_63, nil
	case "firefox-65":
		return utls.HelloFirefox_65, nil
	case "firefox-99":
		return utls.HelloFirefox_99, nil
	case "firefox-102":
		return utls.HelloFirefox_102, nil
	case "firefox-105":
		return utls.HelloFirefox_105, nil
	case "firefox-120":
		return utls.HelloFirefox_120, nil

	// --- Safari ---
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "safari-16":
		return utls.HelloSafari_16_0, nil

	// --- iOS ---
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "ios-11":
		return utls.HelloIOS_11_1, nil
	case "ios-12":
		return utls.HelloIOS_12_1, nil
	case "ios-13":
		return utls.HelloIOS_13, nil
	case "ios-14":
		return utls.HelloIOS_14, nil

	// --- Edge ---
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "edge-85":
		return utls.HelloEdge_85, nil
	case "edge-106":
		return utls.HelloEdge_106, nil

	// --- Android ---
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil

	// --- Chinese browsers ---
	case "360":
		return utls.Hello360_Auto, nil
	case "360-7":
		return utls.Hello360_7_5, nil
	case "360-11":
		return utls.Hello360_11_0, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "qq-11":
		return utls.HelloQQ_11_1, nil

	// --- Randomized ---
	case "randomized":
		return utls.HelloRandomized, nil
	case "randomized-alpn":
		return utls.HelloRandomizedALPN, nil
	case "randomized-noalpn":
		return utls.HelloRandomizedNoALPN, nil

	// --- Golang ---
	case "golang":
		return utls.HelloGolang, nil

	default:
		return utls.ClientHelloID{},
			fmt.Errorf("unknown fingerprint %q (available: chrome, firefox, safari, ios, edge, android, 360, qq, randomized, golang — with optional -version)", name)
	}
}

// FingerprintNames returns a comma-separated list for flag default/usage.
func FingerprintNames(rotator *FingerprintRotator) string {
	if rotator == nil {
		return ""
	}
	names := make([]string, len(rotator.ids))
	for i, id := range rotator.ids {
		names[i] = fmt.Sprintf("%s:%s", id.Client, id.Version)
	}
	return strings.Join(names, ",")
}
