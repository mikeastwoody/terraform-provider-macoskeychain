// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

//go:build !darwin || !cgo

package keychain

import (
	"fmt"
	"runtime"
)

// FindPassword always fails on this platform: the provider reads the
// Keychain through the macOS Security framework, which needs macOS and a
// cgo-enabled build.
func FindPassword(q Query) (string, error) {
	if err := q.Validate(); err != nil {
		return "", err
	}
	return "", unsupportedPlatformError()
}

// SetUserInteractionAllowed does nothing on this platform.
func SetUserInteractionAllowed(bool) {}

// unsupportedPlatformError explains why this build cannot read the Keychain.
func unsupportedPlatformError() error {
	if runtime.GOOS == "darwin" {
		return fmt.Errorf("%w: this build of the provider was compiled without cgo, which the Security framework needs", ErrUnsupportedPlatform)
	}
	return fmt.Errorf("%w: the provider is running on %s/%s, and it can only read the Keychain on macOS", ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
}
