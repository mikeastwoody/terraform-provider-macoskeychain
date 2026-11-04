// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

// Package keychain reads password items from the macOS Keychain through the
// Security framework. It only reads: it never creates, changes or deletes
// keychain items.
//
// Nothing in this package logs, formats or returns secret material in an
// error. Errors carry the lookup attributes (service or server, account and
// keychain path), which are configuration rather than secrets, and the
// Security framework's own status code and description.
package keychain

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Kind selects the keychain item class to search.
type Kind int

const (
	// GenericPassword matches generic password items (kSecClassGenericPassword),
	// identified by service and account. This is the class that
	// `security add-generic-password` creates.
	GenericPassword Kind = iota

	// InternetPassword matches internet password items (kSecClassInternetPassword),
	// identified by server and account. This is the class that
	// `security add-internet-password` creates.
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

// ErrUnsupportedPlatform is returned on every platform where the provider
// cannot reach the macOS Security framework.
var ErrUnsupportedPlatform = errors.New("the macOS Keychain is not available on this platform")

// Code classifies a keychain failure so callers can explain it.
type Code int

const (
	// CodeOther is any failure without a more specific code.
	CodeOther Code = iota

	// CodeNotFound means no item matched the query.
	CodeNotFound

	// CodeKeychainNotFound means the keychain file in Query.Keychain does not exist.
	CodeKeychainNotFound

	// CodeLocked means the keychain is locked and could not be unlocked
	// without user interaction.
	CodeLocked

	// CodeAccessDenied means the item exists but its access control does not
	// let this program read it without a confirmation that could not be shown.
	CodeAccessDenied

	// CodeInteractionNotAllowed means macOS needed to show a dialog (unlock
	// or access confirmation) but the session does not allow it, for example
	// over SSH.
	CodeInteractionNotAllowed

	// CodeCanceled means the user denied access in a macOS dialog.
	CodeCanceled

	// CodeInvalidData means the item's data is not valid UTF-8 text.
	CodeInvalidData
)

// Error is a keychain failure. It never contains secret material.
type Error struct {
	// Code classifies the failure.
	Code Code

	// Status is the Security framework OSStatus, or 0 when the failure was
	// detected before calling the framework.
	Status int32

	// Message is the Security framework's description of Status, or a short
	// explanation when Status is 0. It may be empty.
	Message string
}

// Error implements the error interface.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Code.describe())
	switch {
	case e.Status != 0 && e.Message != "":
		fmt.Fprintf(&b, " (OSStatus %d: %s)", e.Status, e.Message)
	case e.Status != 0:
		fmt.Fprintf(&b, " (OSStatus %d)", e.Status)
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
	case CodeLocked:
		return "keychain is locked"
	case CodeAccessDenied:
		return "access to the item was denied"
	case CodeInteractionNotAllowed:
		return "user interaction is not allowed in this session"
	case CodeCanceled:
		return "access was denied in the macOS dialog"
	case CodeInvalidData:
		return "item data is not valid UTF-8 text"
	default:
		return "keychain error"
	}
}

// Security framework status codes this package interprets. Values are from
// <Security/SecBase.h> and <MacTypes.h>; they are duplicated here so that
// classification is testable on every platform.
const (
	statusUserCanceled          = -128   // userCanceledErr
	statusAuthFailed            = -25293 // errSecAuthFailed
	statusNoSuchKeychain        = -25294 // errSecNoSuchKeychain
	statusItemNotFound          = -25300 // errSecItemNotFound
	statusInteractionNotAllowed = -25308 // errSecInteractionNotAllowed
	statusInteractionRequired   = -25315 // errSecInteractionRequired
)

// classify maps a Security framework status to a Code. locked reports whether
// the keychain that was searched is known to be locked at the time of the
// failure; it disambiguates errSecAuthFailed, which the framework returns
// both for a locked keychain and for an access-control refusal when it may
// not show a dialog.
func classify(status int32, locked bool) Code {
	switch status {
	case statusItemNotFound:
		return CodeNotFound
	case statusNoSuchKeychain:
		return CodeKeychainNotFound
	case statusUserCanceled:
		return CodeCanceled
	case statusInteractionNotAllowed, statusInteractionRequired:
		if locked {
			return CodeLocked
		}
		return CodeInteractionNotAllowed
	case statusAuthFailed:
		if locked {
			return CodeLocked
		}
		return CodeAccessDenied
	default:
		return CodeOther
	}
}
