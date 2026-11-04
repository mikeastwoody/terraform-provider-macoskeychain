// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychaintest"
)

func TestAccInternetPasswordEphemeralResource(t *testing.T) {
	kc := testAccKeychain(t)
	secret := keychaintest.RandomSecret(t)
	kc.AddInternetPassword(t, "git.example.com", "alice", secret)
	// A generic password with the same names must not match.
	kc.AddGenericPassword(t, "git.example.com", "alice", keychaintest.RandomSecret(t))

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks:   ephemeralVersionChecks,
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				// First: the post-test destroy runs with the last step's configuration.
				Config: testAccEchoConfig(`ephemeral "macoskeychain_internet_password" "test" {
  server   = "absent.example.com"
  account  = "alice"
  keychain = %q
}`, kc.Path, "ephemeral.macoskeychain_internet_password.test.password"),
				ExpectError: regexp.MustCompile(`No internet password item with server "absent.example.com"`),
			},
			{
				Config: testAccEchoConfig(`ephemeral "macoskeychain_internet_password" "test" {
  server   = "git.example.com"
  account  = "alice"
  keychain = %q
}`, kc.Path, "ephemeral.macoskeychain_internet_password.test.password"),
				ExpectNonEmptyPlan: cliIsOpenTofu111(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data"), knownvalue.StringExact(secret)),
				},
			},
		},
	})
}

// TestAccInternetPasswordEphemeralResourceNoLeak proves that the password is
// written to neither the plan nor the state; only its length reaches the
// echo provider's state.
func TestAccInternetPasswordEphemeralResourceNoLeak(t *testing.T) {
	kc := testAccKeychain(t)
	secret := keychaintest.RandomSecret(t)
	kc.AddInternetPassword(t, "git.example.com", "alice", secret)

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks:   ephemeralVersionChecks,
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				Config: testAccEchoConfig(`ephemeral "macoskeychain_internet_password" "test" {
  server   = "git.example.com"
  account  = "alice"
  keychain = %q
}`, kc.Path, "length(ephemeral.macoskeychain_internet_password.test.password)"),
				ExpectNonEmptyPlan: cliIsOpenTofu111(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{expectAbsentFromPlan(secret)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data"), knownvalue.Int64Exact(int64(len(secret)))),
					expectAbsentFromState(secret),
				},
			},
		},
	})
}
