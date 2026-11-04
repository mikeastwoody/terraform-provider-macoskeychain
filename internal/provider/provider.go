// Copyright IBM Corp. 2021, 2026
// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

// Package provider implements the macoskeychain provider. It exposes only
// ephemeral resources, so nothing it reads is ever written to a plan or state
// file.
package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure MacOSKeychainProvider satisfies the provider interfaces it needs.
var _ provider.Provider = &MacOSKeychainProvider{}
var _ provider.ProviderWithEphemeralResources = &MacOSKeychainProvider{}

// MacOSKeychainProvider defines the provider implementation.
type MacOSKeychainProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// Metadata returns the provider type name and version.
func (p *MacOSKeychainProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "macoskeychain"
	resp.Version = p.version
}

// Schema returns the provider schema, which has no attributes.
func (p *MacOSKeychainProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads secrets from the macOS Keychain as ephemeral values, which OpenTofu " +
			"and Terraform never write to plan or state files. The provider has no configuration " +
			"attributes and only works on macOS.",
	}
}

// Configure has nothing to configure.
func (p *MacOSKeychainProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

// Resources returns no managed resources: anything a managed resource holds
// is stored in the state.
func (p *MacOSKeychainProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

// DataSources returns no data sources: data source results are stored in the
// state.
func (p *MacOSKeychainProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// EphemeralResources returns the provider's ephemeral resources.
func (p *MacOSKeychainProvider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		NewPasswordEphemeralResource,
		NewInternetPasswordEphemeralResource,
	}
}

// New returns a constructor for the provider at the given version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &MacOSKeychainProvider{
			version: version,
		}
	}
}
