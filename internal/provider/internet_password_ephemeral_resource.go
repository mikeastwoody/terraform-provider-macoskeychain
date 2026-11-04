// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ ephemeral.EphemeralResource = &InternetPasswordEphemeralResource{}
var _ ephemeral.EphemeralResourceWithValidateConfig = &InternetPasswordEphemeralResource{}

// NewInternetPasswordEphemeralResource returns the
// macoskeychain_internet_password ephemeral resource.
func NewInternetPasswordEphemeralResource() ephemeral.EphemeralResource {
	return &InternetPasswordEphemeralResource{}
}

// InternetPasswordEphemeralResource reads an internet password item.
type InternetPasswordEphemeralResource struct{}

// InternetPasswordEphemeralResourceModel describes the ephemeral resource
// data model.
type InternetPasswordEphemeralResourceModel struct {
	Server   types.String `tfsdk:"server"`
	Account  types.String `tfsdk:"account"`
	Keychain types.String `tfsdk:"keychain"`
	Password types.String `tfsdk:"password"`
}

func (m InternetPasswordEphemeralResourceModel) lookup() lookupConfig {
	return lookupConfig{Primary: m.Server, Account: m.Account, Keychain: m.Keychain}
}

// Metadata returns the ephemeral resource type name.
func (r *InternetPasswordEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_internet_password"
}

// Schema returns the ephemeral resource schema.
func (r *InternetPasswordEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the password of an internet password item from the macOS Keychain, " +
			"the kind of item that `security add-internet-password` creates and that browsers and Git " +
			"credential helpers store. The item is looked up by server and account; when several items " +
			"match (for example with different protocols or paths), the first match is returned. " +
			"The password is an ephemeral value: it is never written to a plan or state file.",

		Attributes: map[string]schema.Attribute{
			"server": schema.StringAttribute{
				MarkdownDescription: "Server of the item, such as `github.com` (the `-s` option of `security add-internet-password`).",
				Required:            true,
			},
			"account": schema.StringAttribute{
				MarkdownDescription: "Account of the item (the `-a` option of `security add-internet-password`).",
				Required:            true,
			},
			"keychain": schema.StringAttribute{
				MarkdownDescription: "Absolute path of the keychain file to search, for example `pathexpand(\"~/Library/Keychains/ci.keychain-db\")`. " +
					"When omitted, the user's keychain search list is searched, as `security find-internet-password` does.",
				Optional: true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "Password of the item.",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

// ValidateConfig checks the lookup attributes before the resource is opened.
func (r *InternetPasswordEphemeralResource) ValidateConfig(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	var data InternetPasswordEphemeralResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(internetPasswordSpec.validate(data.lookup())...)
}

// Open reads the password from the Keychain.
func (r *InternetPasswordEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data InternetPasswordEphemeralResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	password, diags := internetPasswordSpec.read(ctx, data.lookup())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Password = password

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
