// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychain"
)

// itemSpec describes how one ephemeral resource type maps to a keychain item
// class.
type itemSpec struct {
	// kind is the keychain item class.
	kind keychain.Kind

	// primaryAttr is the schema attribute that holds the item's service
	// (generic password) or server (internet password).
	primaryAttr string

	// findCommand is the `security` subcommand that lists the same item,
	// used in hints.
	findCommand string
}

var (
	genericPasswordSpec = itemSpec{
		kind:        keychain.GenericPassword,
		primaryAttr: "service",
		findCommand: "find-generic-password",
	}
	internetPasswordSpec = itemSpec{
		kind:        keychain.InternetPassword,
		primaryAttr: "server",
		findCommand: "find-internet-password",
	}
)

// lookupConfig holds the lookup attributes shared by every ephemeral
// resource in this provider.
type lookupConfig struct {
	Primary  types.String
	Account  types.String
	Keychain types.String
}

// validate checks the lookup attributes whose values are known. Unknown
// values are checked again when the resource is opened.
func (s itemSpec) validate(c lookupConfig) diag.Diagnostics {
	var diags diag.Diagnostics
	check := func(attr string, v types.String, fn func(string) error) {
		if v.IsNull() || v.IsUnknown() {
			return
		}
		if err := fn(v.ValueString()); err != nil {
			diags.AddAttributeError(path.Root(attr), "Invalid attribute value", err.Error())
		}
	}
	check(s.primaryAttr, c.Primary, func(v string) error { return keychain.ValidateAttribute(s.primaryAttr, v) })
	check("account", c.Account, func(v string) error { return keychain.ValidateAttribute("account", v) })
	check("keychain", c.Keychain, keychain.ValidateKeychainPath)
	return diags
}

// read looks up the password for c. It returns an unknown value when any
// lookup attribute is unknown.
func (s itemSpec) read(ctx context.Context, c lookupConfig) (types.String, diag.Diagnostics) {
	if c.Primary.IsUnknown() || c.Account.IsUnknown() || c.Keychain.IsUnknown() {
		return types.StringUnknown(), nil
	}

	diags := s.validate(c)
	if diags.HasError() {
		return types.StringUnknown(), diags
	}

	q := keychain.Query{
		Kind:     s.kind,
		Service:  c.Primary.ValueString(),
		Account:  c.Account.ValueString(),
		Keychain: c.Keychain.ValueString(),
	}

	tflog.Debug(ctx, "Reading password from the macOS Keychain", map[string]any{
		"kind":     q.Kind.String(),
		"service":  q.Service,
		"account":  q.Account,
		"keychain": q.Keychain,
	})

	password, err := keychain.FindPassword(ctx, q)
	if err != nil {
		summary, detail := s.explain(q, err)
		diags.AddError(summary, detail)
		return types.StringUnknown(), diags
	}
	return types.StringValue(password), diags
}

// explain turns a keychain error into a diagnostic summary and detail. The
// error never carries secret material, and neither does the text built here:
// it names only the lookup attributes, which are configuration.
func (s itemSpec) explain(q keychain.Query, err error) (summary, detail string) {
	location := "the user's keychain search list"
	keychainArg := ""
	if q.Keychain != "" {
		location = fmt.Sprintf("the keychain %q", q.Keychain)
		keychainArg = " " + shellQuote(q.Keychain)
	}
	item := fmt.Sprintf("%s item with %s %q and account %q", q.Kind, s.primaryAttr, q.Service, q.Account)

	if errors.Is(err, keychain.ErrUnsupportedPlatform) {
		return "macOS Keychain not available", err.Error()
	}

	var kerr *keychain.Error
	if !errors.As(err, &kerr) {
		return "Invalid keychain lookup", err.Error()
	}

	switch kerr.Code {
	case keychain.CodeNotFound:
		summary = "Keychain item not found"
		detail = fmt.Sprintf("No %s exists in %s. Check the attribute values; this command lists the item's attributes without its password:\n\n  security %s -s %s -a %s%s",
			item, location, s.findCommand, shellQuote(q.Service), shellQuote(q.Account), keychainArg)
	case keychain.CodeKeychainNotFound:
		summary = "Keychain file not found"
		detail = fmt.Sprintf("The keychain file %q does not exist or is not a file.", q.Keychain)
	case keychain.CodeInteractionNotAllowed:
		summary = "Keychain is locked or needs confirmation"
		detail = fmt.Sprintf("Reading the %s needs a macOS dialog, to unlock the keychain or to confirm access to the item, but this session cannot show one, for example because it is an SSH session. Unlock the keychain first with `security unlock-keychain%s` and run the command again. If the keychain is already unlocked, the item's access control does not trust /usr/bin/security: read it once from a logged-in desktop session and choose Always Allow.",
			item, keychainArg)
	case keychain.CodeAccessDenied:
		summary = "Access to the keychain item denied"
		detail = fmt.Sprintf("macOS refused to let /usr/bin/security read the %s in %s, for example because access was denied or a wrong keychain password was entered in a macOS dialog.",
			item, location)
	case keychain.CodeCanceled:
		summary = "Access to the keychain item canceled"
		detail = fmt.Sprintf("The macOS dialog for the %s was canceled.", item)
	case keychain.CodeInvalidData:
		summary = "Keychain item is not text"
		detail = fmt.Sprintf("The password of the %s is not valid UTF-8 text, so the provider cannot return it as a string.", item)
	default:
		summary = "Keychain error"
		detail = fmt.Sprintf("Reading the %s from %s failed.", item, location)
	}
	return summary, detail + "\n\nKeychain error: " + kerr.Error()
}

// shellQuote quotes s for a POSIX shell so hints can be pasted as-is.
func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, isShellUnsafe) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// isShellUnsafe reports whether r needs quoting in a POSIX shell word.
func isShellUnsafe(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	default:
		return !strings.ContainsRune("-_./@:+=,", r)
	}
}
