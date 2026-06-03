package main

import (
	"net/http"
	"testing"
)

func TestAdminAuthorizedWithBearerToken(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/admin/stats", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("Authorization", "Bearer secret")

	if !adminAuthorized(req, "secret") {
		t.Fatal("expected bearer token to authorize request")
	}
}

func TestAdminAuthorizedWithHeaderToken(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/admin/stats", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-Admin-Token", "secret")

	if !adminAuthorized(req, "secret") {
		t.Fatal("expected X-Admin-Token to authorize request")
	}
}

func TestAdminAuthorizedRejectsRemoteWithoutToken(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/admin/stats", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "203.0.113.10:12345"

	if adminAuthorized(req, "") {
		t.Fatal("expected remote request without token to be rejected")
	}
}

func TestAdminAuthorizedAllowsLoopbackWithoutToken(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/admin/stats", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.1:12345"

	if !adminAuthorized(req, "") {
		t.Fatal("expected loopback request without token to be authorized")
	}
}
