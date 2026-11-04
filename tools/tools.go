// Copyright IBM Corp. 2021, 2026
// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

//go:build generate

package tools

import (
	_ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
)

// Format the examples and generate the documentation. The script reads the
// provider schema with OpenTofu and runs tfplugindocs.
//go:generate bash ../scripts/generate-docs.sh
