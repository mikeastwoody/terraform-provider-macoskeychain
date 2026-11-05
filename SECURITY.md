# Security policy

## Reporting a vulnerability

Report it privately through GitHub:
[open a private report](https://github.com/mikeastwoody/terraform-provider-macoskeychain/security/advisories/new).
Only the maintainer can see it. Please do not open a public issue or pull request
for a vulnerability.

Include the provider version, your OpenTofu or Terraform version, your macOS
version and the steps that reproduce the problem. Never include a real password:
use a throwaway value.

## What counts

Anything that breaks the provider's
[security model](README.md#security-model), such as a password that reaches a
plan, a state file, a log, an error message or a command line, or a read that
bypasses an item's access control. The limits that the same section describes,
such as other code running as your user that the item trusts, are not
vulnerabilities in the provider.
