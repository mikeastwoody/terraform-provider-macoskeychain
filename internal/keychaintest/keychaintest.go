// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

// Package keychaintest creates throwaway macOS keychains for tests.
//
// Every keychain lives in the test's temporary directory and is deleted when
// the test ends. Nothing here reads or writes the user's login keychain, and
// the user's keychain search list is checked to be unchanged. Commands are
// sent to `security -i` on standard input, so test values never appear on a
// command line.
package keychaintest

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const securityPath = "/usr/bin/security"

// Keychain is a throwaway keychain file.
type Keychain struct {
	// Path is the absolute path of the keychain file.
	Path string

	password string
}

// New creates an unlocked, empty keychain in t's temporary directory and
// registers its deletion. It skips the test when not running on macOS.
func New(t testing.TB) *Keychain {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("throwaway keychains need macOS")
	}

	before := searchList(t)
	k := &Keychain{
		Path:     filepath.Join(t.TempDir(), "test.keychain-db"),
		password: RandomSecret(t),
	}
	run(t, fmt.Sprintf("create-keychain -p %s %s", quote(t, k.password), quote(t, k.Path)))
	t.Cleanup(func() {
		// delete-keychain also removes the file from any search list.
		cmd := exec.Command(securityPath, "delete-keychain", k.Path)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("deleting throwaway keychain %s: %v: %s", k.Path, err, out)
		}
	})
	if after := searchList(t); after != before {
		t.Fatalf("creating a throwaway keychain changed the user's keychain search list:\nbefore: %s\nafter:  %s", before, after)
	}

	// No auto-lock timeout, so a slow test run does not lock it mid-test.
	run(t, "set-keychain-settings "+quote(t, k.Path))
	k.Unlock(t)
	return k
}

// AddGenericPassword adds a generic password item that any application may
// read without confirmation (security's -A flag).
func (k *Keychain) AddGenericPassword(t testing.TB, service, account, secret string) {
	t.Helper()
	run(t, fmt.Sprintf("add-generic-password -A -s %s -a %s -w %s %s",
		quote(t, service), quote(t, account), quote(t, secret), quote(t, k.Path)))
}

// AddRestrictedGenericPassword adds a generic password item with the default
// access control of `security add-generic-password`: only /usr/bin/security
// may read it without confirmation. This is how most people store secrets
// from the command line.
func (k *Keychain) AddRestrictedGenericPassword(t testing.TB, service, account, secret string) {
	t.Helper()
	run(t, fmt.Sprintf("add-generic-password -s %s -a %s -w %s %s",
		quote(t, service), quote(t, account), quote(t, secret), quote(t, k.Path)))
}

// AddGenericPasswordHex adds a generic password item, readable by any
// application, whose data is the bytes encoded in hexData. It stores data
// that is not text.
func (k *Keychain) AddGenericPasswordHex(t testing.TB, service, account, hexData string) {
	t.Helper()
	run(t, fmt.Sprintf("add-generic-password -A -s %s -a %s -X %s %s",
		quote(t, service), quote(t, account), quote(t, hexData), quote(t, k.Path)))
}

// AddInternetPassword adds an internet password item that any application
// may read without confirmation.
func (k *Keychain) AddInternetPassword(t testing.TB, server, account, secret string) {
	t.Helper()
	run(t, fmt.Sprintf("add-internet-password -A -s %s -a %s -w %s %s",
		quote(t, server), quote(t, account), quote(t, secret), quote(t, k.Path)))
}

// Lock locks the keychain.
func (k *Keychain) Lock(t testing.TB) {
	t.Helper()
	run(t, "lock-keychain "+quote(t, k.Path))
}

// Unlock unlocks the keychain with its password.
func (k *Keychain) Unlock(t testing.TB) {
	t.Helper()
	run(t, fmt.Sprintf("unlock-keychain -p %s %s", quote(t, k.password), quote(t, k.Path)))
}

// RandomSecret returns a random value to store as a test secret.
func RandomSecret(t testing.TB) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating random secret: %v", err)
	}
	return "test-" + hex.EncodeToString(b)
}

// run sends one command line to `security -i` on standard input. The
// command's output is reported on failure; it never contains a password
// because none of the commands used here print one.
func run(t testing.TB, line string) {
	t.Helper()
	cmd := exec.Command(securityPath, "-i")
	cmd.Stdin = strings.NewReader(line + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		verb, _, _ := strings.Cut(line, " ")
		t.Fatalf("security %s: %v: %s", verb, err, out.String())
	}
}

// quote wraps s in double quotes for the `security -i` command parser. Test
// values never need escaping, so anything that would is rejected.
func quote(t testing.TB, s string) string {
	t.Helper()
	if s == "" || strings.ContainsAny(s, "\"\\\n\r") {
		t.Fatal("keychaintest: a value is empty or contains a quote, backslash or line break, which security -i cannot take")
	}
	return `"` + s + `"`
}

func searchList(t testing.TB) string {
	t.Helper()
	out, err := exec.Command(securityPath, "list-keychains", "-d", "user").Output()
	if err != nil {
		t.Fatalf("reading the user's keychain search list: %v", err)
	}
	return strings.Join(strings.Fields(string(out)), " ")
}
