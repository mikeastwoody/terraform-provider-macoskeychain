// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func TestValueWOIsWriteOnly(t *testing.T) {
	t.Parallel()
	var resp resource.SchemaResponse
	writeOnlyResource{}.Schema(context.Background(), resource.SchemaRequest{}, &resp)

	attr, ok := resp.Schema.Attributes["value_wo"].(schema.StringAttribute)
	if !ok || !attr.WriteOnly {
		t.Fatalf("value_wo must be a write-only string, got %#v", resp.Schema.Attributes["value_wo"])
	}
	if diags := resp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("invalid schema: %v", diags)
	}
}

func TestWriteHash(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "proof")
	if err := writeHash(path, "abc"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The SHA-256 of "abc" from FIPS 180-4.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
	if string(got) != want {
		t.Fatalf("proof file = %q, want %q", got, want)
	}
}
