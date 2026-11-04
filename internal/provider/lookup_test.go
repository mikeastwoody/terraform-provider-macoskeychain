// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychain"
)

func TestExplain(t *testing.T) {
	t.Parallel()

	q := keychain.Query{Kind: keychain.GenericPassword, Service: "my service", Account: "alice", Keychain: "/tmp/ci.keychain-db"}
	tests := map[string]struct {
		spec        itemSpec
		q           keychain.Query
		err         error
		wantSummary string
		wantDetail  []string
	}{
		"not found": {
			spec: genericPasswordSpec, q: q,
			err:         &keychain.Error{Code: keychain.CodeNotFound, ExitStatus: 44},
			wantSummary: "Keychain item not found",
			wantDetail: []string{
				`No generic password item with service "my service" and account "alice" exists in the keychain "/tmp/ci.keychain-db"`,
				"security find-generic-password -s 'my service' -a alice /tmp/ci.keychain-db",
				"security exited with status 44",
			},
		},
		"not found in search list": {
			spec: internetPasswordSpec, q: keychain.Query{Kind: keychain.InternetPassword, Service: "example.com", Account: "bob"},
			err:         &keychain.Error{Code: keychain.CodeNotFound, ExitStatus: 44},
			wantSummary: "Keychain item not found",
			wantDetail: []string{
				`No internet password item with server "example.com" and account "bob" exists in the user's keychain search list`,
				"security find-internet-password -s example.com -a bob\n",
			},
		},
		"keychain file not found": {
			spec: genericPasswordSpec, q: q,
			err:         &keychain.Error{Code: keychain.CodeKeychainNotFound},
			wantSummary: "Keychain file not found",
			wantDetail:  []string{`"/tmp/ci.keychain-db" does not exist`},
		},
		"locked or interaction not allowed": {
			spec: genericPasswordSpec, q: q,
			err:         &keychain.Error{Code: keychain.CodeInteractionNotAllowed, ExitStatus: 36},
			wantSummary: "Keychain is locked or needs confirmation",
			wantDetail:  []string{"SSH", "security unlock-keychain /tmp/ci.keychain-db", "Always Allow"},
		},
		"access denied": {
			spec: genericPasswordSpec, q: q,
			err:         &keychain.Error{Code: keychain.CodeAccessDenied, ExitStatus: 51},
			wantSummary: "Access to the keychain item denied",
			wantDetail:  []string{"refused to let /usr/bin/security read", "status 51"},
		},
		"canceled": {
			spec: genericPasswordSpec, q: q,
			err:         &keychain.Error{Code: keychain.CodeCanceled, ExitStatus: 128},
			wantSummary: "Access to the keychain item canceled",
			wantDetail:  []string{"dialog for the generic password item", "was canceled"},
		},
		"invalid data": {
			spec: genericPasswordSpec, q: q,
			err:         &keychain.Error{Code: keychain.CodeInvalidData},
			wantSummary: "Keychain item is not text",
			wantDetail:  []string{"not valid UTF-8"},
		},
		"other": {
			spec: genericPasswordSpec, q: q,
			err:         &keychain.Error{Code: keychain.CodeOther, ExitStatus: 206},
			wantSummary: "Keychain error",
			wantDetail:  []string{"security exited with status 206"},
		},
		"unsupported platform": {
			spec: genericPasswordSpec, q: q,
			err:         fmt.Errorf("%w: running on linux/amd64", keychain.ErrUnsupportedPlatform),
			wantSummary: "macOS Keychain not available",
			wantDetail:  []string{"linux/amd64"},
		},
		"invalid query": {
			spec: genericPasswordSpec, q: q,
			err:         errors.New("service must not be empty"),
			wantSummary: "Invalid keychain lookup",
			wantDetail:  []string{"service must not be empty"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			summary, detail := tc.spec.explain(tc.q, tc.err)
			if summary != tc.wantSummary {
				t.Errorf("summary = %q, want %q", summary, tc.wantSummary)
			}
			for _, want := range tc.wantDetail {
				if !strings.Contains(detail+"\n", want) {
					t.Errorf("detail does not contain %q:\n%s", want, detail)
				}
			}
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		spec      itemSpec
		cfg       lookupConfig
		wantPaths []string
	}{
		"valid": {
			spec: genericPasswordSpec,
			cfg:  lookupConfig{Primary: types.StringValue("svc"), Account: types.StringValue("acct"), Keychain: types.StringValue("/tmp/k.keychain-db")},
		},
		"unknown and null values are not checked": {
			spec: genericPasswordSpec,
			cfg:  lookupConfig{Primary: types.StringUnknown(), Account: types.StringUnknown(), Keychain: types.StringNull()},
		},
		"every attribute invalid": {
			spec:      internetPasswordSpec,
			cfg:       lookupConfig{Primary: types.StringValue(""), Account: types.StringValue(""), Keychain: types.StringValue("relative")},
			wantPaths: []string{"server", "account", "keychain"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			diags := tc.spec.validate(tc.cfg)
			if len(diags) != len(tc.wantPaths) {
				t.Fatalf("got %d diagnostics, want %d: %v", len(diags), len(tc.wantPaths), diags)
			}
			for i, d := range diags {
				withPath, ok := d.(diag.DiagnosticWithPath)
				if !ok {
					t.Fatalf("diagnostic %d has no attribute path: %v", i, d)
				}
				if got := withPath.Path().String(); got != tc.wantPaths[i] {
					t.Errorf("diagnostic %d is for %q, want %q", i, got, tc.wantPaths[i])
				}
			}
		})
	}
}

func TestReadUnknownSkipsLookup(t *testing.T) {
	t.Parallel()
	got, diags := genericPasswordSpec.read(context.Background(), lookupConfig{
		Primary: types.StringValue("svc"), Account: types.StringUnknown(), Keychain: types.StringNull(),
	})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if !got.IsUnknown() {
		t.Fatal("an unknown lookup attribute must give an unknown password")
	}
}

func TestShellQuote(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"plain":               "plain",
		"/tmp/ci.keychain-db": "/tmp/ci.keychain-db",
		"user@example.com":    "user@example.com",
		"with space":          "'with space'",
		"it's":                `'it'\''s'`,
		"":                    "''",
		"$(touch /tmp/pwned)": "'$(touch /tmp/pwned)'",
		"contraseña":          "'contraseña'",
	}
	for in, want := range tests {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
