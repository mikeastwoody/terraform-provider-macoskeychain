// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

//go:build darwin

package keychain_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychain"
	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychaintest"
)

// These tests run /usr/bin/security against throwaway keychains in temporary
// directories. Every query names its keychain explicitly, so the user's
// login keychain and keychain search list are never searched. No keychain is
// ever locked, so no test can show a macOS dialog.

// TestFindGenericPassword reads an item created the way most people store
// secrets, with `security add-generic-password` and no -A or -T option: its
// access control trusts only /usr/bin/security, so reading it through
// security needs no confirmation.
func TestFindGenericPassword(t *testing.T) {
	t.Parallel()
	kc := keychaintest.New(t)
	secret := keychaintest.RandomSecret(t)
	kc.AddGenericPassword(t, "example-service", "alice", secret)
	kc.AddGenericPassword(t, "example-service", "bob", keychaintest.RandomSecret(t))

	got, err := keychain.FindPassword(context.Background(), keychain.Query{
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

	got, err := keychain.FindPassword(context.Background(), keychain.Query{
		Kind: keychain.InternetPassword, Service: "git.example.com", Account: "alice", Keychain: kc.Path,
	})
	if err != nil {
		t.Fatalf("FindPassword: %v", err)
	}
	if got != secret {
		t.Fatal("FindPassword returned a different password than the one stored")
	}
}

// TestFindPasswordExactText checks values that security prints in different
// forms: non-ASCII text, which it prints in hexadecimal, and ASCII text that
// looks like hexadecimal, which must not be decoded.
func TestFindPasswordExactText(t *testing.T) {
	t.Parallel()
	kc := keychaintest.New(t)

	tests := map[string]string{
		"Unicode":                   "contraseña-ñandú-" + keychaintest.RandomSecret(t),
		"ASCII that looks like hex": "636f6e7472617365c3b1612dc3b1616e64c3ba",
		"ASCII that starts with 0x": "0x636F6E74",
		"ASCII with a single quote": "it's-" + keychaintest.RandomSecret(t),
	}
	for name, secret := range tests {
		kc.AddGenericPassword(t, "exact-"+name, "cuenta-ü", secret)
	}

	for name, secret := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := keychain.FindPassword(context.Background(), keychain.Query{
				Kind: keychain.GenericPassword, Service: "exact-" + name, Account: "cuenta-ü", Keychain: kc.Path,
			})
			if err != nil {
				t.Fatalf("FindPassword: %v", err)
			}
			if got != secret {
				t.Fatalf("FindPassword returned %q, want %q", got, secret)
			}
		})
	}
}

func TestFindPasswordErrors(t *testing.T) {
	t.Parallel()
	kc := keychaintest.New(t)
	secret := keychaintest.RandomSecret(t)
	kc.AddGenericPassword(t, "present", "alice", secret)
	kc.AddGenericPasswordHex(t, "binary", "alice", "fffe00c3")

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
		"data that is not text": {
			q:        keychain.Query{Kind: keychain.GenericPassword, Service: "binary", Account: "alice", Keychain: kc.Path},
			wantCode: keychain.CodeInvalidData,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := keychain.FindPassword(context.Background(), tc.q)
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
	_, err := keychain.FindPassword(context.Background(), keychain.Query{Kind: keychain.GenericPassword, Service: "svc", Account: "acct", Keychain: "relative.keychain-db"})
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("expected a validation error, got %v", err)
	}
	var kerr *keychain.Error
	if errors.As(err, &kerr) {
		t.Fatal("a validation error must not be a *keychain.Error")
	}
}
