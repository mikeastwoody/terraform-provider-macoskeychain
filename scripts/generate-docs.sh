#!/usr/bin/env bash
# Copyright (c) 2026 mikeastwood
# SPDX-License-Identifier: MPL-2.0
#
# Regenerates docs/ from the provider schema, templates/ and examples/.
# OpenTofu reads the schema from a fresh build of the provider, so no
# Terraform binary is downloaded. TOFU=/path/to/tofu chooses the binary.

set -euo pipefail

tofu=${TOFU:-tofu}
repo=$(cd "$(dirname "$0")/.." && pwd)
tmp=${TMPDIR:-/tmp}
work=$(mktemp -d "${tmp%/}/macoskeychain-docs.XXXXXX")
trap 'rm -rf "$work"' EXIT

"$tofu" fmt -recursive "$repo/examples/"

(cd "$repo" && go build -o "$work/plugins/terraform-provider-macoskeychain" .)

cat >"$work/cli.tfrc" <<TFRC
provider_installation {
  dev_overrides {
    "registry.opentofu.org/mikeastwoody/macoskeychain" = "$work/plugins"
  }
  direct {}
}
TFRC

mkdir "$work/config"
cat >"$work/config/main.tf" <<'TF'
terraform {
  required_providers {
    macoskeychain = {
      source = "mikeastwoody/macoskeychain"
    }
  }
}
TF

# tfplugindocs looks the schema up by the bare provider name.
TF_CLI_CONFIG_FILE="$work/cli.tfrc" "$tofu" -chdir="$work/config" providers schema -json |
	sed 's|"registry.opentofu.org/mikeastwoody/macoskeychain":|"macoskeychain":|' >"$work/schema.json"

cd "$repo/tools"
go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate \
	--provider-dir .. \
	--provider-name macoskeychain \
	--rendered-provider-name "macOS Keychain" \
	--providers-schema "$work/schema.json"
