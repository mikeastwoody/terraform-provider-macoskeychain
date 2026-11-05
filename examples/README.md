# Examples

This directory contains examples that are mostly used for documentation, but can also be run/tested manually via the OpenTofu or Terraform CLI.

The document generation tool looks for files in the following locations by default. All other *.tf files besides the ones mentioned below are ignored by the documentation tool. This is useful for creating examples that can run and/or are testable even if some parts are not relevant for the documentation.

* **provider/provider.tf** example file for the provider index page
* **ephemeral-resources/`full ephemeral resource name`/ephemeral-resource.tf** example file for the named ephemeral resource page

**no-secret-in-state/** is a configuration that hands a Keychain password to a command and to write-only arguments without storing it. It runs only through `scripts/prove-no-secret-in-state.sh`, because `tofu init` cannot find its test-only provider for the write-only arguments, which is in no registry: the script builds it and installs it with `dev_overrides`. The script runs the configuration against a throwaway keychain and checks that the password arrives intact and appears in neither the saved plan nor the state.
