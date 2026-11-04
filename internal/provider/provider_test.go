// Copyright IBM Corp. 2021, 2026
// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"os"
	"runtime"
	"sort"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychain"
	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychaintest"
)

// testAccProtoV6ProviderFactoriesWithEcho serves this provider and the echo
// provider in-process. The echo provider copies an ephemeral value into its
// own state, which is how tests observe what an ephemeral resource returned.
var testAccProtoV6ProviderFactoriesWithEcho = map[string]func() (tfprotov6.ProviderServer, error){
	"macoskeychain": providerserver.NewProtocol6WithError(New("test")()),
	"echo":          echoprovider.NewProviderServer(),
}

func TestMain(m *testing.M) {
	// Acceptance tests serve the provider in this process. A misconfigured
	// test must fail rather than wait on a macOS dialog.
	keychain.SetUserInteractionAllowed(false)
	os.Exit(m.Run())
}

func testAccPreCheck(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("acceptance tests need macOS")
	}
}

// testAccKeychain returns a throwaway keychain for an acceptance test, or
// skips the test when acceptance tests are not enabled, so that unit test
// runs do not create keychains.
func testAccKeychain(t *testing.T) *keychaintest.Keychain {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance tests run only when TF_ACC is set")
	}
	testAccPreCheck(t)
	return keychaintest.New(t)
}

func TestProviderExposesOnlyEphemeralResources(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := New("test")()

	var meta fwprovider.MetadataResponse
	p.Metadata(ctx, fwprovider.MetadataRequest{}, &meta)
	if meta.TypeName != "macoskeychain" {
		t.Fatalf("provider type name = %q", meta.TypeName)
	}

	var schemaResp fwprovider.SchemaResponse
	p.Schema(ctx, fwprovider.SchemaRequest{}, &schemaResp)
	if n := len(schemaResp.Schema.Attributes) + len(schemaResp.Schema.Blocks); n != 0 {
		t.Fatalf("the provider schema has %d attributes or blocks, want none", n)
	}

	// Managed resources and data sources store their values in the state;
	// this provider must never offer one.
	if n := len(p.Resources(ctx)); n != 0 {
		t.Fatalf("the provider has %d managed resources, want none", n)
	}
	if n := len(p.DataSources(ctx)); n != 0 {
		t.Fatalf("the provider has %d data sources, want none", n)
	}
	if _, ok := p.(fwprovider.ProviderWithFunctions); ok {
		t.Fatal("the provider must not offer functions")
	}
	if _, ok := p.(fwprovider.ProviderWithListResources); ok {
		t.Fatal("the provider must not offer list resources")
	}
	if _, ok := p.(fwprovider.ProviderWithActions); ok {
		t.Fatal("the provider must not offer actions")
	}

	pe, ok := p.(fwprovider.ProviderWithEphemeralResources)
	if !ok {
		t.Fatal("the provider does not offer ephemeral resources")
	}
	var names []string
	for _, newResource := range pe.EphemeralResources(ctx) {
		var resp ephemeral.MetadataResponse
		newResource().Metadata(ctx, ephemeral.MetadataRequest{ProviderTypeName: meta.TypeName}, &resp)
		names = append(names, resp.TypeName)

		var schemaResp ephemeral.SchemaResponse
		newResource().Schema(ctx, ephemeral.SchemaRequest{}, &schemaResp)
		password, ok := schemaResp.Schema.Attributes["password"]
		if !ok {
			t.Fatalf("%s has no password attribute", resp.TypeName)
		}
		if !password.IsSensitive() || !password.IsComputed() {
			t.Fatalf("%s.password must be computed and sensitive", resp.TypeName)
		}
	}
	sort.Strings(names)
	want := []string{"macoskeychain_internet_password", "macoskeychain_password"}
	if len(names) != len(want) || names[0] != want[0] || names[1] != want[1] {
		t.Fatalf("ephemeral resources = %v, want %v", names, want)
	}
}
