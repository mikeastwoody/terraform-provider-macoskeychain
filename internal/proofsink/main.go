// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

// Command proofsink is a provider used only by
// scripts/prove-no-secret-in-state.sh, and it is never released. No provider
// available without a network offers a write-only argument, so this one does:
// its single resource writes the SHA-256 of the value it received to a file,
// which lets the script prove the value arrived intact without printing it.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func main() {
	err := providerserver.Serve(context.Background(), func() provider.Provider { return sinkProvider{} }, providerserver.ServeOpts{
		Address: "registry.opentofu.org/mikeastwoody/proofsink",
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}

type sinkProvider struct{}

func (sinkProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "proofsink"
}

func (sinkProvider) Schema(context.Context, provider.SchemaRequest, *provider.SchemaResponse) {}

func (sinkProvider) Configure(context.Context, provider.ConfigureRequest, *provider.ConfigureResponse) {
}

func (sinkProvider) DataSources(context.Context) []func() datasource.DataSource { return nil }

func (sinkProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{func() resource.Resource { return writeOnlyResource{} }}
}

// writeOnlyModel holds the resource's attributes. A write-only value exists
// only in the configuration, so the plan and the state always hold null.
type writeOnlyModel struct {
	ValueWO   types.String `tfsdk:"value_wo"`
	ProofFile types.String `tfsdk:"proof_file"`
}

type writeOnlyResource struct{}

func (writeOnlyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_write_only"
}

func (writeOnlyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Writes the SHA-256 of a write-only value to a file.",
		Attributes: map[string]schema.Attribute{
			"value_wo": schema.StringAttribute{
				Description: "The value to hash. It is never stored.",
				Required:    true,
				WriteOnly:   true,
			},
			"proof_file": schema.StringAttribute{
				Description: "The file that receives the hash.",
				Required:    true,
			},
		},
	}
}

func (writeOnlyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	state := record(ctx, req.Config, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	}
}

func (writeOnlyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	state := record(ctx, req.Config, &resp.Diagnostics)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	}
}

func (writeOnlyResource) Read(context.Context, resource.ReadRequest, *resource.ReadResponse) {}

func (writeOnlyResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {}

// record reads the configuration, writes the hash of its write-only value to
// the proof file and returns what the state should hold. Diagnostics never
// include the value.
func record(ctx context.Context, cfg tfsdk.Config, diags *diag.Diagnostics) writeOnlyModel {
	var config writeOnlyModel
	diags.Append(cfg.Get(ctx, &config)...)
	if diags.HasError() {
		return writeOnlyModel{}
	}
	if config.ValueWO.IsNull() || config.ValueWO.IsUnknown() {
		diags.AddError("No write-only value", "The provider received no known value for value_wo.")
		return writeOnlyModel{}
	}
	if err := writeHash(config.ProofFile.ValueString(), config.ValueWO.ValueString()); err != nil {
		diags.AddError("Cannot write the proof file", err.Error())
		return writeOnlyModel{}
	}
	return writeOnlyModel{ValueWO: types.StringNull(), ProofFile: config.ProofFile}
}

// writeHash writes the hexadecimal SHA-256 of value to path.
func writeHash(path, value string) error {
	sum := sha256.Sum256([]byte(value))
	return os.WriteFile(path, []byte(hex.EncodeToString(sum[:])+"\n"), 0o600)
}
