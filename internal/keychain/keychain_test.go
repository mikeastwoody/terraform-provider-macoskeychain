// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

package keychain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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

// fakeSecurity is a stand-in for /usr/bin/security that records its
// arguments and prints canned output.
type fakeSecurity struct {
	path     string
	argvFile string
}

// newFakeSecurity writes a program that records its arguments, prints stdout
// and stderr, and exits with status.
func newFakeSecurity(t *testing.T, stdout, stderr string, status int) fakeSecurity {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake security program is a shell script")
	}
	dir := t.TempDir()
	f := fakeSecurity{path: filepath.Join(dir, "security"), argvFile: filepath.Join(dir, "argv")}
	for name, content := range map[string]string{"stdout": stdout, "stderr": stderr} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := "#!/bin/sh\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\"; done > '" + f.argvFile + "'\n" +
		"cat '" + filepath.Join(dir, "stdout") + "'\n" +
		"cat '" + filepath.Join(dir, "stderr") + "' >&2\n" +
		"exit " + strconv.Itoa(status) + "\n"
	if err := os.WriteFile(f.path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

// argv returns the arguments the fake was run with, or nil if it never ran.
func (f fakeSecurity) argv(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(f.argvFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

// attributes is what security prints to standard output with -g. It is
// never part of the password.
const attributes = "keychain: \"/tmp/x.keychain-db\"\nversion: 256\nclass: \"genp\"\nattributes:\n    \"acct\"<blob>=\"alice\"\n"

func TestFindPasswordDecodesSecurityOutput(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		stderr string
		want   string
	}{
		"printable ASCII":                {stderr: "password: \"plain-secret\"\n", want: "plain-secret"},
		"ASCII that looks like hex":      {stderr: "password: \"636f6e74726173\"\n", want: "636f6e74726173"},
		"ASCII that starts with 0x":      {stderr: "password: \"0x4142\"\n", want: "0x4142"},
		"ASCII with quotes and spaces":   {stderr: "password: \" a\"b \"\n", want: ` a"b `},
		"empty password":                 {stderr: "password: \n", want: ""},
		"Unicode, printed as hex":        {stderr: "password: 0x636F6E7472617365C3B1612DC3B1616E64C3BA  \"contrase\\303\\261a-\\303\\261and\\303\\272\"\n", want: "contraseña-ñandú"},
		"backslash, printed as hex":      {stderr: "password: 0x615C6263  \"a\\134bc\"\n", want: `a\bc`},
		"trailing newline, kept":         {stderr: "password: 0x6162630A  \"abc\\012\"\n", want: "abc\n"},
		"lowercase hex":                  {stderr: "password: 0x616263  \"abc\"\n", want: "abc"},
		"hex without a quoted rendering": {stderr: "password: 0x616263\n", want: "abc"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeSecurity(t, attributes, tc.stderr, 0)
			got, err := findPassword(context.Background(), fake.path, Query{Kind: GenericPassword, Service: "svc", Account: "alice"})
			if err != nil {
				t.Fatalf("findPassword: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFindPasswordArguments(t *testing.T) {
	t.Parallel()
	keychainPath := filepath.Join(t.TempDir(), "ci.keychain-db")
	if err := os.WriteFile(keychainPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		q    Query
		want []string
	}{
		"generic password in the search list": {
			q:    Query{Kind: GenericPassword, Service: "svc", Account: "alice"},
			want: []string{"find-generic-password", "-s", "svc", "-a", "alice", "-g"},
		},
		"internet password in a keychain file": {
			q:    Query{Kind: InternetPassword, Service: "git.example.com", Account: "-bob", Keychain: keychainPath},
			want: []string{"find-internet-password", "-s", "git.example.com", "-a", "-bob", "-g", keychainPath},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeSecurity(t, attributes, "password: \"secret\"\n", 0)
			if _, err := findPassword(context.Background(), fake.path, tc.q); err != nil {
				t.Fatalf("findPassword: %v", err)
			}
			if got := fake.argv(t); strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
				t.Fatalf("security ran with %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFindPasswordErrorsFromSecurity(t *testing.T) {
	t.Parallel()
	const secret = "test-secret-6f1c2b"

	tests := map[string]struct {
		stderr   string
		status   int
		wantCode Code
		wantText string
	}{
		"item not found": {
			stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n", status: 44,
			wantCode: CodeNotFound, wantText: "item not found (security exited with status 44)",
		},
		"interaction not allowed": {
			stderr: "security: SecKeychainItemCopyAttributesAndData: User interaction is not allowed.\n", status: 36,
			wantCode: CodeInteractionNotAllowed, wantText: "status 36",
		},
		"access denied": {
			stderr: "security: SecKeychainItemCopyAttributesAndData: The user name or passphrase you entered is not correct.\n", status: 51,
			wantCode: CodeAccessDenied, wantText: "status 51",
		},
		"canceled": {
			stderr: "security: SecKeychainItemCopyAttributesAndData: User canceled the operation.\n", status: 128,
			wantCode: CodeCanceled, wantText: "status 128",
		},
		"other status": {
			stderr: "security: SecKeychainSearchCreateFromAttributes: One or more parameters passed to a function were not valid.\n", status: 206,
			wantCode: CodeOther, wantText: "keychain error (security exited with status 206)",
		},
		"failure after printing the password": {
			stderr: "password: \"" + secret + "\"\nsecurity: failed\n", status: 1,
			wantCode: CodeOther, wantText: "status 1",
		},
		"unexpected output that contains the password": {
			stderr: "pass: \"" + secret + "\"\n", status: 0,
			wantCode: CodeOther, wantText: "unexpected output from security",
		},
		"an extra line": {
			stderr: "password: \"" + secret + "\"\nwarning: " + secret + "\n", status: 0,
			wantCode: CodeOther, wantText: "unexpected output from security",
		},
		"unterminated quote": {
			stderr: "password: \"" + secret + "\n", status: 0,
			wantCode: CodeOther, wantText: "unexpected output from security",
		},
		"odd number of hex digits": {
			stderr: "password: 0x616  \"" + secret + "\"\n", status: 0,
			wantCode: CodeOther, wantText: "unexpected output from security",
		},
		"invalid hex digits": {
			stderr: "password: 0x61ZZ  \"" + secret + "\"\n", status: 0,
			wantCode: CodeOther, wantText: "unexpected output from security",
		},
		"no output": {
			stderr: "", status: 0,
			wantCode: CodeOther, wantText: "unexpected output from security",
		},
		"data that is not text": {
			stderr: "password: 0xFFFE00C3  \n", status: 0,
			wantCode: CodeInvalidData, wantText: "not valid UTF-8",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeSecurity(t, attributes+secret, tc.stderr, tc.status)
			got, err := findPassword(context.Background(), fake.path, Query{Kind: GenericPassword, Service: "svc", Account: "alice"})
			assertKeychainError(t, got, err, tc.wantCode, secret)
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("error %q does not contain %q", err, tc.wantText)
			}
		})
	}
}

func TestFindPasswordKeychainFileChecks(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing keychain file":        filepath.Join(t.TempDir(), "absent.keychain-db"),
		"keychain path is a directory": t.TempDir(),
	}
	for name, keychainPath := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fake := newFakeSecurity(t, attributes, "password: \"secret\"\n", 0)
			got, err := findPassword(context.Background(), fake.path, Query{Kind: GenericPassword, Service: "svc", Account: "alice", Keychain: keychainPath})
			assertKeychainError(t, got, err, CodeKeychainNotFound, "secret")
			if fake.argv(t) != nil {
				t.Fatal("security ran although the keychain file check failed")
			}
		})
	}
}

func TestFindPasswordCanceledContext(t *testing.T) {
	t.Parallel()
	fake := newFakeSecurity(t, attributes, "password: \"secret\"\n", 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := findPassword(ctx, fake.path, Query{Kind: GenericPassword, Service: "svc", Account: "alice"})
	assertKeychainError(t, got, err, CodeOther, "secret")
	if !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("error %q does not mention the canceled context", err)
	}
}

func TestFindPasswordMissingProgram(t *testing.T) {
	t.Parallel()
	got, err := findPassword(context.Background(), filepath.Join(t.TempDir(), "security"), Query{Kind: GenericPassword, Service: "svc", Account: "alice"})
	assertKeychainError(t, got, err, CodeOther, "")
}

func assertKeychainError(t *testing.T, got string, err error, wantCode Code, secret string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	if got != "" {
		t.Fatal("a failed lookup returned a non-empty password")
	}
	var kerr *Error
	if !errors.As(err, &kerr) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if kerr.Code != wantCode {
		t.Fatalf("got code %d (%v), want %d", kerr.Code, err, wantCode)
	}
	if secret != "" && strings.Contains(err.Error(), secret) {
		t.Fatal("the error message contains the secret")
	}
}

func TestDecodePasswordDoesNotShareMemory(t *testing.T) {
	t.Parallel()
	for _, out := range []string{"password: \"abc\"\n", "password: 0x616263  \"abc\"\n"} {
		buf := []byte(out)
		got, err := decodePassword(buf)
		if err != nil {
			t.Fatalf("decodePassword(%q): %v", out, err)
		}
		clear(buf)
		if !bytes.Equal(got, []byte("abc")) {
			t.Fatalf("clearing the output changed the decoded password of %q", out)
		}
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := map[int]Code{
		44:  CodeNotFound,
		36:  CodeInteractionNotAllowed,
		51:  CodeAccessDenied,
		128: CodeCanceled,
		1:   CodeOther,
		2:   CodeOther,
	}
	for status, want := range tests {
		if got := classify(status); got != want {
			t.Errorf("classify(%d) = %d, want %d", status, got, want)
		}
	}
}

func TestErrorString(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  *Error
		want string
	}{
		"status only":  {&Error{Code: CodeNotFound, ExitStatus: 44}, "item not found (security exited with status 44)"},
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
