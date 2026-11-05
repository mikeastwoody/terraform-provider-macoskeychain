# Examples

This directory contains examples that are mostly used for documentation, but can also be run/tested manually via the OpenTofu or Terraform CLI.

The document generation tool looks for files in the following locations by default. All other *.tf files besides the ones mentioned below are ignored by the documentation tool. This is useful for creating examples that can run and/or are testable even if some parts are not relevant for the documentation.

* **provider/provider.tf** example file for the provider index page
* **ephemeral-resources/`full ephemeral resource name`/ephemeral-resource.tf** example file for the named ephemeral resource page

**no-secret-in-state/** is a runnable configuration that hands a Keychain password to a command and to write-only arguments without storing it. `scripts/prove-no-secret-in-state.sh` runs it against a throwaway keychain, with a test-only provider for the write-only arguments, and checks that the password arrives intact and appears in neither the saved plan nor the state.
