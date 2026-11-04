// Copyright IBM Corp. 2021, 2026
// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/mikeastwoody/terraform-provider-macoskeychain/internal/keychaintest"
)

// Ephemeral resources need Terraform 1.10 or OpenTofu 1.11.
var ephemeralVersionChecks = []tfversion.TerraformVersionCheck{
	tfversion.SkipBelow(tfversion.Version1_10_0),
}

// cliIsOpenTofu111 reports whether TF_ACC_TERRAFORM_PATH is OpenTofu 1.11,
// which lists every ephemeral resource in the plan with the action "open"
// (OpenTofu 1.12 stopped storing them in the plan, opentofu#3897).
// terraform-plugin-testing counts that entry as a change, so there a step
// that applies a configuration with an ephemeral resource never gets an empty
// plan and must set ExpectNonEmptyPlan.
var cliIsOpenTofu111 = sync.OnceValue(func() bool {
	out, err := exec.Command(os.Getenv("TF_ACC_TERRAFORM_PATH"), "version").Output()
	return err == nil && strings.HasPrefix(string(out), "OpenTofu v1.11.")
})

// TestAccGenericPasswordEphemeralResource reads items created with
// `security add-generic-password` and no -A or -T option, whose access
// control trusts only /usr/bin/security, as most command-line users create
// them.
func TestAccGenericPasswordEphemeralResource(t *testing.T) {
	kc := testAccKeychain(t)
	secret := keychaintest.RandomSecret(t)
	kc.AddGenericPassword(t, "tf-acc-service", "alice", secret)
	kc.AddGenericPassword(t, "tf-acc-service", "bob", keychaintest.RandomSecret(t))

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks:   ephemeralVersionChecks,
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				// The echo provider copies the ephemeral value into its own
				// state, which is the only way to observe it in a test.
				Config: testAccEchoConfig(`ephemeral "macoskeychain_generic_password" "test" {
  service  = "tf-acc-service"
  account  = "alice"
  keychain = %q
}`, kc.Path, "ephemeral.macoskeychain_generic_password.test.password"),
				ExpectNonEmptyPlan: cliIsOpenTofu111(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data"), knownvalue.StringExact(secret)),
				},
			},
		},
	})
}

// TestAccGenericPasswordEphemeralResourceNoLeak proves that the password reaches the
// configuration that uses it but is written to neither the plan nor the
// state. Only a hash of it crosses into the echo provider's state.
func TestAccGenericPasswordEphemeralResourceNoLeak(t *testing.T) {
	kc := testAccKeychain(t)
	secret := keychaintest.RandomSecret(t)
	kc.AddGenericPassword(t, "tf-acc-service", "alice", secret)
	sum := sha256.Sum256([]byte(secret))

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks:   ephemeralVersionChecks,
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			{
				Config: testAccEchoConfig(`ephemeral "macoskeychain_generic_password" "test" {
  service  = "tf-acc-service"
  account  = "alice"
  keychain = %q
}`, kc.Path, "sha256(ephemeral.macoskeychain_generic_password.test.password)"),
				ExpectNonEmptyPlan: cliIsOpenTofu111(),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply:             []plancheck.PlanCheck{expectAbsentFromPlan(secret)},
					PostApplyPostRefresh: []plancheck.PlanCheck{expectAbsentFromPlan(secret)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("echo.test", tfjsonpath.New("data"), knownvalue.StringExact(hex.EncodeToString(sum[:]))),
					expectAbsentFromState(secret),
				},
			},
		},
	})
}

func TestAccGenericPasswordEphemeralResourceErrors(t *testing.T) {
	kc := testAccKeychain(t)
	kc.AddGenericPassword(t, "tf-acc-service", "alice", keychaintest.RandomSecret(t))

	step := func(service, account, keychainPath string, want string) resource.TestStep {
		return resource.TestStep{
			Config: testAccEchoConfig(fmt.Sprintf(`ephemeral "macoskeychain_generic_password" "test" {
  service  = %q
  account  = %q
  keychain = %%q
}`, service, account), keychainPath, "ephemeral.macoskeychain_generic_password.test.password"),
			ExpectError: regexp.MustCompile(want),
		}
	}

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks:   ephemeralVersionChecks,
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactoriesWithEcho,
		Steps: []resource.TestStep{
			step("tf-acc-absent", "alice", kc.Path, `Keychain item not found`),
			step("tf-acc-service", "mallory", kc.Path, `No generic password item with service "tf-acc-service" and\s+account "mallory"`),
			step("tf-acc-service", "alice", filepath.Join(t.TempDir(), "absent.keychain-db"), `Keychain file not found`),
			step("tf-acc-service", "alice", "relative.keychain-db", `must be absolute`),
			step("", "alice", kc.Path, `service must not be empty`),
			step("tf-acc-service", "", kc.Path, `account must not be empty`),
		},
	})
}

// testAccEchoConfig renders an ephemeral resource block (with one %q verb for
// the keychain path) and an echo provider whose data is echoExpr.
func testAccEchoConfig(ephemeralBlock, keychainPath, echoExpr string) string {
	return fmt.Sprintf(ephemeralBlock, keychainPath) + fmt.Sprintf(`

provider "echo" {
  data = %s
}

resource "echo" "test" {}
`, echoExpr)
}
