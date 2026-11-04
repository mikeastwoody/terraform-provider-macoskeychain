// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

// Package keychain reads password items from the macOS Keychain by running
// /usr/bin/security, the same tool that `security add-generic-password`
// stores items with. Items created that way trust /usr/bin/security, so
// reading them never shows a macOS dialog. It only reads: it never creates,
// changes or deletes keychain items.
//
// The password travels from the security child process to this package only
// through a pipe. It is never on a command line or in an environment, and
// nothing in this package logs, formats or returns it in an error. Errors
// carry a classification and security's exit status, never the text that
// security printed.
package keychain

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

// securityPath is the only program this package runs. It is an absolute
// path, so PATH is never searched.
const securityPath = "/usr/bin/security"

// Kind selects the keychain item class to search.
type Kind int

const (
	// GenericPassword matches generic password items, identified by service
	// and account. This is the class that `security add-generic-password`
	// creates.
	GenericPassword Kind = iota

	// InternetPassword matches internet password items, identified by server
	// and account. This is the class that `security add-internet-password`
	// creates.
	InternetPassword
)

// String returns a human-readable name for the item class.
func (k Kind) String() string {
	switch k {
	case GenericPassword:
		return "generic password"
	case InternetPassword:
		return "internet password"
	default:
		return fmt.Sprintf("unknown item kind %d", int(k))
	}
}

// Query describes the single password item to read.
type Query struct {
	// Kind is the item class to search.
	Kind Kind

	// Service is the item's service for a generic password, or its server
	// for an internet password. It must not be empty.
	Service string

	// Account is the item's account. It must not be empty.
	Account string

	// Keychain is the absolute path of the keychain file to search. When it
	// is empty, the user's default keychain search list is searched.
	Keychain string
}

// Validate reports whether the query is well formed. It does not touch the
// keychain.
func (q Query) Validate() error {
	if q.Kind != GenericPassword && q.Kind != InternetPassword {
		return fmt.Errorf("unsupported item kind %d", int(q.Kind))
	}
	if err := ValidateAttribute(q.primaryName(), q.Service); err != nil {
		return err
	}
	if err := ValidateAttribute("account", q.Account); err != nil {
		return err
	}
	return ValidateKeychainPath(q.Keychain)
}

func (q Query) primaryName() string {
	if q.Kind == InternetPassword {
		return "server"
	}
	return "service"
}

// args returns the security command line that prints the item's password
// to standard error.
func (q Query) args() []string {
	command := "find-generic-password"
	if q.Kind == InternetPassword {
		command = "find-internet-password"
	}
	args := []string{command, "-s", q.Service, "-a", q.Account, "-g"}
	if q.Keychain != "" {
		args = append(args, q.Keychain)
	}
	return args
}

// ValidateAttribute reports whether value is usable as the named lookup
// attribute: non-empty, valid UTF-8 and free of NUL bytes.
func ValidateAttribute(name, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("%s must not be empty", name)
	case !utf8.ValidString(value):
		return fmt.Errorf("%s must be valid UTF-8 text", name)
	case strings.ContainsRune(value, 0):
		return fmt.Errorf("%s must not contain NUL characters", name)
	}
	return nil
}

// ValidateKeychainPath reports whether path is usable as a keychain path. The
// empty string is valid and selects the default search list; anything else
// must be an absolute path without NUL bytes. Use OpenTofu's pathexpand()
// function to expand a leading "~".
func ValidateKeychainPath(path string) error {
	if path == "" {
		return nil
	}
	if strings.ContainsRune(path, 0) {
		return errors.New("keychain path must not contain NUL characters")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("keychain path %q must be absolute; use pathexpand() to expand a leading \"~\"", path)
	}
	return nil
}

// ErrUnsupportedPlatform is returned on every platform other than macOS.
var ErrUnsupportedPlatform = errors.New("the macOS Keychain is not available on this platform")

// FindPassword returns the password of the first item that matches q. It
// returns an *Error for keychain failures and a plain error for an invalid
// query or an unsupported platform.
func FindPassword(ctx context.Context, q Query) (string, error) {
	if err := q.Validate(); err != nil {
		return "", err
	}
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("%w: the provider is running on %s/%s, and it can only read the Keychain on macOS",
			ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
	}
	return findPassword(ctx, securityPath, q)
}

// findPassword runs the security program at path for q, which must be valid.
func findPassword(ctx context.Context, path string, q Query) (string, error) {
	if q.Keychain != "" {
		// security reports a missing keychain file as a missing item, so
		// check the file first to say what is actually wrong.
		info, err := os.Stat(q.Keychain)
		switch {
		case os.IsNotExist(err):
			return "", &Error{Code: CodeKeychainNotFound}
		case err != nil:
			return "", &Error{Code: CodeOther, Message: err.Error()}
		case info.IsDir():
			return "", &Error{Code: CodeKeychainNotFound, Message: "the path is a directory"}
		}
	}

	// With -g, security prints the item's attributes to standard output,
	// which is discarded, and the password to standard error.
	var stderr bytes.Buffer
	stderr.Grow(4096)
	defer func() { clear(stderr.Bytes()) }()
	cmd := exec.CommandContext(ctx, path, q.args()...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", &Error{Code: CodeOther, Message: ctxErr.Error()}
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			status := exitErr.ExitCode()
			return "", &Error{Code: classify(status), ExitStatus: status}
		}
		return "", &Error{Code: CodeOther, Message: err.Error()}
	}

	password, err := decodePassword(stderr.Bytes())
	if err != nil {
		return "", &Error{Code: CodeOther, Message: err.Error()}
	}
	defer clear(password)
	if !utf8.Valid(password) {
		return "", &Error{Code: CodeInvalidData}
	}
	return string(password), nil
}

// decodePassword extracts the password from what `security find-*-password
// -g` writes to standard error: one line made of "password: " and then
// nothing for an empty password, the password in double quotes when it is
// printable ASCII other than a backslash, or "0x", the password's bytes in
// hexadecimal, and a quoted rendering that is ignored. The returned slice
// does not share memory with out. Errors never include out.
func decodePassword(out []byte) ([]byte, error) {
	errUnexpected := errors.New("unexpected output from security")
	line, ok := bytes.CutSuffix(out, []byte("\n"))
	if !ok || bytes.IndexByte(line, '\n') >= 0 {
		return nil, errUnexpected
	}
	rest, ok := bytes.CutPrefix(line, []byte("password: "))
	if !ok {
		return nil, errUnexpected
	}

	if len(rest) == 0 {
		return []byte{}, nil
	}
	if quoted, ok := bytes.CutPrefix(rest, []byte(`"`)); ok {
		text, ok := bytes.CutSuffix(quoted, []byte(`"`))
		if !ok {
			return nil, errUnexpected
		}
		return bytes.Clone(text), nil
	}
	digits, ok := bytes.CutPrefix(rest, []byte("0x"))
	if !ok {
		return nil, errUnexpected
	}
	if end := bytes.IndexByte(digits, ' '); end >= 0 {
		digits = digits[:end]
	}
	if len(digits) == 0 || len(digits)%2 != 0 {
		return nil, errUnexpected
	}
	data := make([]byte, hex.DecodedLen(len(digits)))
	if _, err := hex.Decode(data, digits); err != nil {
		clear(data)
		return nil, errUnexpected
	}
	return data, nil
}

// Code classifies a keychain failure so callers can explain it.
type Code int

const (
	// CodeOther is any failure without a more specific code.
	CodeOther Code = iota

	// CodeNotFound means no item matched the query.
	CodeNotFound

	// CodeKeychainNotFound means the keychain file in Query.Keychain does not exist.
	CodeKeychainNotFound

	// CodeInteractionNotAllowed means macOS needed to show a dialog, to
	// unlock the keychain or to confirm access to the item, but the session
	// does not allow it, for example over SSH.
	CodeInteractionNotAllowed

	// CodeAccessDenied means macOS refused access to the item, for example
	// because access was denied or a wrong keychain password was entered in
	// a macOS dialog.
	CodeAccessDenied

	// CodeCanceled means a macOS dialog for the item was canceled.
	CodeCanceled

	// CodeInvalidData means the item's data is not valid UTF-8 text.
	CodeInvalidData
)

// Error is a keychain failure. It never contains secret material.
type Error struct {
	// Code classifies the failure.
	Code Code

	// ExitStatus is the exit status of security when it exited with an
	// error, and 0 otherwise.
	ExitStatus int

	// Message is a short explanation of a failure that has no exit status.
	// It never comes from security's output, and it may be empty.
	Message string
}

// Error implements the error interface.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Code.describe())
	switch {
	case e.ExitStatus != 0:
		fmt.Fprintf(&b, " (security exited with status %d)", e.ExitStatus)
	case e.Message != "":
		fmt.Fprintf(&b, " (%s)", e.Message)
	}
	return b.String()
}

func (c Code) describe() string {
	switch c {
	case CodeNotFound:
		return "item not found"
	case CodeKeychainNotFound:
		return "keychain file not found"
	case CodeInteractionNotAllowed:
		return "user interaction is not allowed in this session"
	case CodeAccessDenied:
		return "access to the item was denied"
	case CodeCanceled:
		return "the macOS dialog was canceled"
	case CodeInvalidData:
		return "item data is not valid UTF-8 text"
	default:
		return "keychain error"
	}
}

// security exits with the low byte of the Security framework's OSStatus.
// These are the statuses this package interprets, from <Security/SecBase.h>
// and <MacTypes.h>.
const (
	exitItemNotFound          = 44  // errSecItemNotFound, -25300
	exitAuthFailed            = 51  // errSecAuthFailed, -25293
	exitInteractionNotAllowed = 36  // errSecInteractionNotAllowed, -25308
	exitUserCanceled          = 128 // userCanceledErr, -128
)

// classify maps an exit status of security to a Code.
func classify(status int) Code {
	switch status {
	case exitItemNotFound:
		return CodeNotFound
	case exitInteractionNotAllowed:
		return CodeInteractionNotAllowed
	case exitAuthFailed:
		return CodeAccessDenied
	case exitUserCanceled:
		return CodeCanceled
	default:
		return CodeOther
	}
}
