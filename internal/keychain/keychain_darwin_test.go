// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

//go:build darwin && cgo

package keychain_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychain"
	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychaintest"
)

// These tests run against throwaway keychains in temporary directories.
// Every query names its keychain explicitly, so the user's login keychain is
// never searched.

func TestMain(m *testing.M) {
	// A test must fail rather than wait on a macOS dialog.
	keychain.SetUserInteractionAllowed(false)
	os.Exit(m.Run())
}

func TestFindGenericPassword(t *testing.T) {
	t.Parallel()
	kc := keychaintest.New(t)
	secret := keychaintest.RandomSecret(t)
	kc.AddGenericPassword(t, "example-service", "alice", secret)
	kc.AddGenericPassword(t, "example-service", "bob", keychaintest.RandomSecret(t))

	got, err := keychain.FindPassword(keychain.Query{
		Kind: keychain.GenericPassword, Service: "example-service", Account: "alice", Keychain: kc.Path,
	})
	if err != nil {
		t.Fatalf("FindPassword: %v", err)
	}
	if got != secret {
		t.Fatal("FindPassword returned a different password than the one stored")
	}
}

func TestFindInternetPassword(t *testing.T) {
	t.Parallel()
	kc := keychaintest.New(t)
	secret := keychaintest.RandomSecret(t)
	kc.AddInternetPassword(t, "git.example.com", "alice", secret)
	// A generic password with the same names must not match.
	kc.AddGenericPassword(t, "git.example.com", "alice", keychaintest.RandomSecret(t))

	got, err := keychain.FindPassword(keychain.Query{
		Kind: keychain.InternetPassword, Service: "git.example.com", Account: "alice", Keychain: kc.Path,
	})
	if err != nil {
		t.Fatalf("FindPassword: %v", err)
	}
	if got != secret {
		t.Fatal("FindPassword returned a different password than the one stored")
	}
}

func TestFindPasswordUnicode(t *testing.T) {
	t.Parallel()
	kc := keychaintest.New(t)
	secret := "contraseña-ñandú-" + keychaintest.RandomSecret(t)
	kc.AddGenericPassword(t, "servicio-ñ", "cuenta-ü", secret)

	got, err := keychain.FindPassword(keychain.Query{
		Kind: keychain.GenericPassword, Service: "servicio-ñ", Account: "cuenta-ü", Keychain: kc.Path,
	})
	if err != nil {
		t.Fatalf("FindPassword: %v", err)
	}
	if got != secret {
		t.Fatal("FindPassword returned a different password than the one stored")
	}
}

func TestFindPasswordErrors(t *testing.T) {
	t.Parallel()
	kc := keychaintest.New(t)
	secret := keychaintest.RandomSecret(t)
	kc.AddGenericPassword(t, "present", "alice", secret)
	kc.AddRestrictedGenericPassword(t, "restricted", "alice", secret)
	kc.AddGenericPasswordHex(t, "binary", "alice", "fffe00c3")
	locked := keychaintest.New(t)
	locked.AddGenericPassword(t, "present", "alice", secret)
	locked.Lock(t)

	tests := map[string]struct {
		q        keychain.Query
		wantCode keychain.Code
	}{
		"missing item": {
			q:        keychain.Query{Kind: keychain.GenericPassword, Service: "absent", Account: "alice", Keychain: kc.Path},
			wantCode: keychain.CodeNotFound,
		},
		"wrong account": {
			q:        keychain.Query{Kind: keychain.GenericPassword, Service: "present", Account: "mallory", Keychain: kc.Path},
			wantCode: keychain.CodeNotFound,
		},
		"wrong kind": {
			q:        keychain.Query{Kind: keychain.InternetPassword, Service: "present", Account: "alice", Keychain: kc.Path},
			wantCode: keychain.CodeNotFound,
		},
		"missing keychain file": {
			q:        keychain.Query{Kind: keychain.GenericPassword, Service: "present", Account: "alice", Keychain: filepath.Join(t.TempDir(), "absent.keychain-db")},
			wantCode: keychain.CodeKeychainNotFound,
		},
		"keychain path is a directory": {
			q:        keychain.Query{Kind: keychain.GenericPassword, Service: "present", Account: "alice", Keychain: t.TempDir()},
			wantCode: keychain.CodeKeychainNotFound,
		},
		"restricted access control": {
			q:        keychain.Query{Kind: keychain.GenericPassword, Service: "restricted", Account: "alice", Keychain: kc.Path},
			wantCode: keychain.CodeAccessDenied,
		},
		"locked keychain": {
			q:        keychain.Query{Kind: keychain.GenericPassword, Service: "present", Account: "alice", Keychain: locked.Path},
			wantCode: keychain.CodeLocked,
		},
		"data that is not text": {
			q:        keychain.Query{Kind: keychain.GenericPassword, Service: "binary", Account: "alice", Keychain: kc.Path},
			wantCode: keychain.CodeInvalidData,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := keychain.FindPassword(tc.q)
			if err == nil {
				t.Fatal("expected an error")
			}
			if got != "" {
				t.Error("a failed lookup returned a non-empty password")
			}
			var kerr *keychain.Error
			if !errors.As(err, &kerr) {
				t.Fatalf("expected *keychain.Error, got %T: %v", err, err)
			}
			if kerr.Code != tc.wantCode {
				t.Fatalf("got code %d (%v), want %d", kerr.Code, err, tc.wantCode)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("the error message contains the secret")
			}
		})
	}
}

func TestFindPasswordInvalidQuery(t *testing.T) {
	t.Parallel()
	_, err := keychain.FindPassword(keychain.Query{Kind: keychain.GenericPassword, Service: "svc", Account: "acct", Keychain: "relative.keychain-db"})
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("expected a validation error, got %v", err)
	}
	var kerr *keychain.Error
	if errors.As(err, &kerr) {
		t.Fatal("a validation error must not be a *keychain.Error")
	}
}
