// Copyright IBM Corp. 2021, 2026
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
var _ ephemeral.EphemeralResource = &GenericPasswordEphemeralResource{}
var _ ephemeral.EphemeralResourceWithValidateConfig = &GenericPasswordEphemeralResource{}

// NewGenericPasswordEphemeralResource returns the
// macoskeychain_generic_password ephemeral resource.
func NewGenericPasswordEphemeralResource() ephemeral.EphemeralResource {
	return &GenericPasswordEphemeralResource{}
}

// GenericPasswordEphemeralResource reads a generic password item.
type GenericPasswordEphemeralResource struct{}

// GenericPasswordEphemeralResourceModel describes the ephemeral resource data
// model.
type GenericPasswordEphemeralResourceModel struct {
	Service  types.String `tfsdk:"service"`
	Account  types.String `tfsdk:"account"`
	Keychain types.String `tfsdk:"keychain"`
	Password types.String `tfsdk:"password"`
}

func (m GenericPasswordEphemeralResourceModel) lookup() lookupConfig {
	return lookupConfig{Primary: m.Service, Account: m.Account, Keychain: m.Keychain}
}

// Metadata returns the ephemeral resource type name.
func (r *GenericPasswordEphemeralResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_generic_password"
}

// Schema returns the ephemeral resource schema.
func (r *GenericPasswordEphemeralResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Reads the password of a generic password item from the macOS Keychain, " +
			"the kind of item that `security add-generic-password` and Keychain Access create. " +
			"The item is looked up by service and account. The password is an ephemeral value: " +
			"it is never written to a plan or state file.",

		Attributes: map[string]schema.Attribute{
			"service": schema.StringAttribute{
				MarkdownDescription: "Service of the item (the `-s` option of `security add-generic-password`, shown as *Where* in Keychain Access).",
				Required:            true,
			},
			"account": schema.StringAttribute{
				MarkdownDescription: "Account of the item (the `-a` option of `security add-generic-password`).",
				Required:            true,
			},
			"keychain": schema.StringAttribute{
				MarkdownDescription: "Absolute path of the keychain file to search, for example `pathexpand(\"~/Library/Keychains/ci.keychain-db\")`. " +
					"When omitted, the user's keychain search list is searched, as `security find-generic-password` does.",
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
func (r *GenericPasswordEphemeralResource) ValidateConfig(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	var data GenericPasswordEphemeralResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(genericPasswordSpec.validate(data.lookup())...)
}

// Open reads the password from the Keychain.
func (r *GenericPasswordEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data GenericPasswordEphemeralResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	password, diags := genericPasswordSpec.read(ctx, data.lookup())
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	data.Password = password

	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
