// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

//go:build !darwin

package keychain_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychain"
)

func TestFindPasswordUnsupportedPlatform(t *testing.T) {
	t.Parallel()
	_, err := keychain.FindPassword(context.Background(), keychain.Query{Kind: keychain.GenericPassword, Service: "svc", Account: "acct"})
	if !errors.Is(err, keychain.ErrUnsupportedPlatform) {
		t.Fatalf("expected ErrUnsupportedPlatform, got %v", err)
	}
	if !strings.Contains(err.Error(), "macOS") {
		t.Fatalf("the error does not explain the platform requirement: %v", err)
	}
}

func TestFindPasswordUnsupportedPlatformValidatesFirst(t *testing.T) {
	t.Parallel()
	_, err := keychain.FindPassword(context.Background(), keychain.Query{Kind: keychain.GenericPassword, Account: "acct"})
	if err == nil || errors.Is(err, keychain.ErrUnsupportedPlatform) {
		t.Fatalf("expected a validation error, got %v", err)
	}
}
