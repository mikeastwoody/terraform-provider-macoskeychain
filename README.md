# terraform-provider-macoskeychain

An [OpenTofu](https://opentofu.org) and Terraform provider that reads secrets
from the macOS Keychain as **ephemeral values**: they reach the provider blocks
and write-only arguments that need them, and they are never written to a plan
or state file.

The provider offers only ephemeral resources. It has no managed resources and
no data sources, because both store what they read in the state.

| Ephemeral resource | Reads |
|---|---|
| [`macoskeychain_password`](docs/ephemeral-resources/password.md) | A generic password item, by service and account (what `security add-generic-password` and Keychain Access create). |
| [`macoskeychain_internet_password`](docs/ephemeral-resources/internet_password.md) | An internet password item, by server and account (what `security add-internet-password` and Git credential helpers create). |

## Why another Keychain provider

Existing Keychain providers read secrets through data sources, which copy the
password into the state in plain text. Before ephemeral resources existed, the
usual workaround was a shell wrapper that read the Keychain and exported the
secret as a `TF_VAR_*` variable. This provider replaces both: the secret goes
from the Keychain to the configuration that uses it, and nowhere else.

## Requirements

- macOS 13 or later.
- OpenTofu 1.11 or later, or Terraform 1.10 or later (the first versions with
  ephemeral resources).

On other platforms the provider still installs, so `init` and `validate` work
in mixed teams and CI, but every ephemeral resource fails with an error that
explains why.

## Usage

Store the secret once from a terminal. With `-w` at the end, `security`
prompts for the value, so it never lands in your shell history:

```shell
security add-generic-password -s sentry-auth-token -a deploy -w
```

Then read it where it is needed:

```terraform
terraform {
  required_providers {
    macoskeychain = {
      source = "mikeastwoody/macoskeychain"
    }
  }
}

ephemeral "macoskeychain_password" "sentry" {
  service = "sentry-auth-token"
  account = "deploy"
}

# Provider configurations accept ephemeral values...
provider "sentry" {
  token = ephemeral.macoskeychain_password.sentry.password
}

# ...and so do write-only arguments, which are never stored either.
ephemeral "macoskeychain_password" "database" {
  service  = "app-database-password"
  account  = "app"
  keychain = pathexpand("~/Library/Keychains/infra.keychain-db") # optional
}

resource "google_secret_manager_secret_version" "database" {
  secret                 = google_secret_manager_secret.database.id
  secret_data_wo         = ephemeral.macoskeychain_password.database.password
  secret_data_wo_version = 1
}
```

Without `keychain`, the user's keychain search list is searched, as
`security find-generic-password` does. See [`docs/`](docs/index.md) for every
attribute and [`examples/`](examples/) for more configurations.

## Security model

- **Nothing reaches the plan or the state.** Every value the provider returns
  is ephemeral, and `password` is also marked sensitive. OpenTofu rejects an
  ephemeral value in any argument that would be stored. The acceptance tests
  and [`scripts/prove-no-secret-in-state.sh`](scripts/prove-no-secret-in-state.sh)
  check this against real plan and state files.
- **The secret stays in process.** The provider calls the macOS Security
  framework (`SecItemCopyMatching`) through cgo. It starts no subprocess, so
  the secret never appears on a command line or in an environment, and it
  never logs it. Error messages name only the service or server, the account
  and the keychain path.
- **Read only.** The provider never creates, changes or deletes keychain items.
- **macOS decides who may read an item.** The provider does not bypass the
  item's access control list; see the next section.

The provider does not protect a secret from other code running as your user
that the item's access control trusts, and the secret is in the memory of
OpenTofu and of every provider that receives it.

## Granting access to an item

Every keychain item has an access control list of applications that may read
it without asking. An item created with `security add-generic-password` and no
`-T` or `-A` option trusts only `/usr/bin/security`, so the first time the
provider reads it, macOS asks:

- **Allow** grants access for this read only. OpenTofu opens ephemeral
  resources during both plan and apply, so expect to be asked for each.
- **Always Allow** adds this provider binary to the item's access control list.

Release builds are not signed with an Apple Developer ID, so macOS identifies
each provider version by its code hash and asks again after an upgrade.

When no dialog can be shown (an SSH session, CI), the read fails with an error
instead of waiting. In that case, unlock the keychain first with
`security unlock-keychain`, and create the item so that the provider may read
it without confirmation:

- `security add-generic-password -T /path/to/terraform-provider-macoskeychain_vX.Y.Z ...`
  trusts that one binary, which is the narrower choice.
- `security add-generic-password -A ...` lets any application read the item
  without confirmation. Use it only for keychains dedicated to automation.

## Errors

The provider explains each failure without echoing secret material:

| Error | Meaning |
|---|---|
| Keychain item not found | No item matches; the message includes a `security find-…` command that lists the item's attributes (not its password). |
| Keychain file not found | The `keychain` path does not exist. |
| Keychain is locked | The keychain is locked and macOS could not ask for its password. |
| Keychain needs user interaction | macOS needed a dialog but the session cannot show one (SSH, CI). |
| Access to the keychain item denied | The item's access control does not trust the provider, or access was denied in the dialog. |
| Keychain item is not text | The item's data is not valid UTF-8. |
| macOS Keychain not available | The provider is running on another platform. |

## Development

You need [Go](https://go.dev/doc/install) (see `go.mod`), Xcode's command line
tools (for cgo) and OpenTofu.

```shell
make build      # go build ./...
make lint       # golangci-lint
make test       # unit tests; the keychain tests use throwaway keychains
make testacc    # acceptance tests against OpenTofu (TOFU=terraform for Terraform)
make prove      # a real plan -out and apply that proves no secret is stored
make generate   # format examples/ and regenerate docs/ with tfplugindocs
```

The tests never read or write your login keychain. Each one creates a keychain
in a temporary directory with `security create-keychain`, checks that your
keychain search list did not change, and deletes the keychain afterwards. They
also turn off macOS dialogs for the test process, so a misconfigured test fails
instead of waiting for a click.

To try a local build with OpenTofu, point a
[development override](https://opentofu.org/docs/cli/config/config-file/) (`dev_overrides`)
at the directory that holds the binary:

```terraform
provider_installation {
  dev_overrides {
    "registry.opentofu.org/mikeastwoody/macoskeychain" = "/path/to/go/bin"
  }
  direct {}
}
```

### Releases

Pushing a `v*` tag runs GoReleaser on a macOS runner (the darwin builds need
cgo). It builds zips for every platform, a `SHA256SUMS` file signed with GPG
and the registry manifest, and creates a draft GitHub release to review before
publishing. The workflow needs the `GPG_PRIVATE_KEY` and `PASSPHRASE`
repository secrets.

## License

[MPL-2.0](LICENSE). Built from HashiCorp's
[terraform-provider-scaffolding-framework](https://github.com/hashicorp/terraform-provider-scaffolding-framework)
template, also MPL-2.0.

Maintained by [mikeastwood](https://mikeastwood.dev).
