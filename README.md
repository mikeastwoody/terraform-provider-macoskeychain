# terraform-provider-macoskeychain

An [OpenTofu](https://opentofu.org) and Terraform provider that reads secrets
from the macOS Keychain as **ephemeral values**: they reach the provider blocks
and write-only arguments that need them, and they are never written to a plan
or state file.

The provider offers only ephemeral resources. It has no managed resources and
no data sources, because both store what they read in the state.

| Ephemeral resource | Reads |
|---|---|
| [`macoskeychain_generic_password`](docs/ephemeral-resources/generic_password.md) | A generic password item, by service and account (what `security add-generic-password` and Keychain Access create). |
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

ephemeral "macoskeychain_generic_password" "sentry" {
  service = "sentry-auth-token"
  account = "deploy"
}

# Provider configurations accept ephemeral values...
provider "sentry" {
  token = ephemeral.macoskeychain_generic_password.sentry.password
}

# ...and so do write-only arguments, which are never stored either.
ephemeral "macoskeychain_generic_password" "database" {
  service  = "app-database-password"
  account  = "app"
  keychain = pathexpand("~/Library/Keychains/infra.keychain-db") # optional
}

resource "google_secret_manager_secret_version" "database" {
  secret                 = google_secret_manager_secret.database.id
  secret_data_wo         = ephemeral.macoskeychain_generic_password.database.password
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
- **The secret travels only through a pipe.** The provider reads the item by
  running `/usr/bin/security find-generic-password` (or
  `find-internet-password`), by absolute path, and reads the password from that
  child process's output. The secret never appears on a command line or in an
  environment, and the provider never logs it. Error messages name only the
  service or server, the account, the keychain path and the exit status of
  `security`, never its output.
- **Read only.** The provider never creates, changes or deletes keychain items.
- **macOS decides who may read an item.** The provider does not bypass the
  item's access control list; `security` reads the item on its behalf. See the
  next section.

The provider does not protect a secret from other code running as your user
that the item's access control trusts, and the secret is in the memory of
OpenTofu and of every provider that receives it.

## Granting access to an item

Every keychain item has an access control list of applications that may read
it without asking. An item created with `security add-generic-password` (or
`add-internet-password`) and no `-T` or `-A` option trusts only
`/usr/bin/security`. The provider reads items through that same
`/usr/bin/security`, so it reads them without any macOS dialog: at plan and at
apply, in SSH sessions once the keychain is unlocked, and after every provider
upgrade. Store secrets that way and there is nothing to grant.

An item created by another application, such as Keychain Access or a browser,
may not trust `/usr/bin/security`. The first time the provider reads it, macOS
asks whether `security` may use it; choose **Always Allow** so it does not ask
again. Because the trusted program is `/usr/bin/security` and not the provider
binary, the answer survives provider upgrades. When no dialog can be shown (an
SSH session, CI), the read fails with an error instead: read the item once from
a logged-in desktop session, or create it again with `security`.

A locked keychain needs its password. In a desktop session macOS asks for it;
in an SSH session, unlock the keychain first with `security unlock-keychain`.

## Errors

The provider explains each failure without echoing secret material:

| Error | Meaning |
|---|---|
| Keychain item not found | No item matches; the message includes a `security find-…` command that lists the item's attributes (not its password). |
| Keychain file not found | The `keychain` path does not exist. |
| Keychain is locked or needs confirmation | macOS needed a dialog, to unlock the keychain or to confirm access to the item, but the session cannot show one (SSH, CI). |
| Access to the keychain item denied | macOS refused access, for example because access was denied or a wrong keychain password was entered in a dialog. |
| Access to the keychain item canceled | The macOS dialog was canceled. |
| Keychain item is not text | The item's data is not valid UTF-8. |
| macOS Keychain not available | The provider is running on another platform. |

## Development

You need [Go](https://go.dev/doc/install) (see `go.mod`) and OpenTofu. The
provider is pure Go, so it cross-compiles for every platform without cgo.

```shell
make build      # go build ./...
make lint       # golangci-lint
make test       # unit tests; a fake `security` for every error, throwaway keychains for the rest
make testacc    # acceptance tests against OpenTofu (TOFU=terraform for Terraform)
make prove      # a real plan -out and apply that proves no secret is stored
make generate   # format examples/ and regenerate docs/ with tfplugindocs
```

The tests never read or write your login keychain. Each one creates a keychain
in a temporary directory with `security create-keychain`, checks that your
keychain search list did not change, and deletes the keychain afterwards. No
test locks a keychain or reads an item that does not trust `security`, so no
test shows a macOS dialog; the locked and access-denied errors are tested with
a fake `security` program instead.

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

Pushing a `v*` tag runs GoReleaser. It builds zips for every platform
(all with `CGO_ENABLED=0`), a `SHA256SUMS` file signed with GPG and the
registry manifest, and creates a draft GitHub release to review before
publishing. The workflow needs the `GPG_PRIVATE_KEY` and `PASSPHRASE`
repository secrets.

## License

[MPL-2.0](LICENSE). Built from HashiCorp's
[terraform-provider-scaffolding-framework](https://github.com/hashicorp/terraform-provider-scaffolding-framework)
template, also MPL-2.0.

Maintained by [mikeastwood](https://mikeastwood.dev).
