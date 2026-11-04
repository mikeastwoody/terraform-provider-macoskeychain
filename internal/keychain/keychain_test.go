// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

package keychain

import (
	"strings"
	"testing"
)

func TestQueryValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		q       Query
		wantErr string
	}{
		"generic":               {q: Query{Kind: GenericPassword, Service: "svc", Account: "acct"}},
		"internet":              {q: Query{Kind: InternetPassword, Service: "example.com", Account: "acct"}},
		"absolute keychain":     {q: Query{Kind: GenericPassword, Service: "svc", Account: "acct", Keychain: "/tmp/x.keychain-db"}},
		"empty service":         {q: Query{Kind: GenericPassword, Account: "acct"}, wantErr: "service must not be empty"},
		"empty server":          {q: Query{Kind: InternetPassword, Account: "acct"}, wantErr: "server must not be empty"},
		"empty account":         {q: Query{Kind: GenericPassword, Service: "svc"}, wantErr: "account must not be empty"},
		"NUL in service":        {q: Query{Kind: GenericPassword, Service: "s\x00vc", Account: "acct"}, wantErr: "must not contain NUL"},
		"invalid UTF-8 account": {q: Query{Kind: GenericPassword, Service: "svc", Account: "\xff"}, wantErr: "account must be valid UTF-8"},
		"relative keychain":     {q: Query{Kind: GenericPassword, Service: "svc", Account: "acct", Keychain: "login.keychain-db"}, wantErr: "must be absolute"},
		"tilde keychain":        {q: Query{Kind: GenericPassword, Service: "svc", Account: "acct", Keychain: "~/x.keychain-db"}, wantErr: "pathexpand()"},
		"NUL in keychain":       {q: Query{Kind: GenericPassword, Service: "svc", Account: "acct", Keychain: "/tmp/\x00"}, wantErr: "must not contain NUL"},
		"unknown kind":          {q: Query{Kind: Kind(7), Service: "svc", Account: "acct"}, wantErr: "unsupported item kind 7"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.q.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected an error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status int32
		locked bool
		want   Code
	}{
		{statusItemNotFound, false, CodeNotFound},
		{statusItemNotFound, true, CodeNotFound},
		{statusNoSuchKeychain, false, CodeKeychainNotFound},
		{statusUserCanceled, false, CodeCanceled},
		{statusAuthFailed, false, CodeAccessDenied},
		{statusAuthFailed, true, CodeLocked},
		{statusInteractionNotAllowed, false, CodeInteractionNotAllowed},
		{statusInteractionNotAllowed, true, CodeLocked},
		{statusInteractionRequired, false, CodeInteractionNotAllowed},
		{-50, false, CodeOther},
	}
	for _, tc := range tests {
		if got := classify(tc.status, tc.locked); got != tc.want {
			t.Errorf("classify(%d, %t) = %d, want %d", tc.status, tc.locked, got, tc.want)
		}
	}
}

func TestErrorString(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  *Error
		want string
	}{
		"status and message": {&Error{Code: CodeNotFound, Status: -25300, Message: "The specified item could not be found in the keychain."},
			"item not found (OSStatus -25300: The specified item could not be found in the keychain.)"},
		"status only":  {&Error{Code: CodeOther, Status: -50}, "keychain error (OSStatus -50)"},
		"message only": {&Error{Code: CodeKeychainNotFound, Message: "the path is a directory"}, "keychain file not found (the path is a directory)"},
		"bare":         {&Error{Code: CodeInvalidData}, "item data is not valid UTF-8 text"},
	}
	for name, tc := range tests {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

func TestKindString(t *testing.T) {
	t.Parallel()

	if got := GenericPassword.String(); got != "generic password" {
		t.Errorf("GenericPassword.String() = %q", got)
	}
	if got := InternetPassword.String(); got != "internet password" {
		t.Errorf("InternetPassword.String() = %q", got)
	}
	if got := Kind(9).String(); got != "unknown item kind 9" {
		t.Errorf("Kind(9).String() = %q", got)
	}
}
