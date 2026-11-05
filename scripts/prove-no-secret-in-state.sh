#!/usr/bin/env bash
# Copyright (c) 2026 mikeastwood
# SPDX-License-Identifier: MPL-2.0
#
# Proves with a real OpenTofu (or Terraform) run that a password read by this
# provider reaches, byte for byte, a command and a write-only argument after an
# apply, and is written to neither a saved plan nor the state.
#
# It builds the provider and proofsink (a test-only provider with a write-only
# argument), creates a throwaway keychain in a temporary directory, stores a
# random password in it, runs `plan -out` and `apply` on
# examples/no-secret-in-state, compares the hashes of what each consumer
# received, searches every file the run wrote for the password, and deletes the
# keychain. It never reads or writes the login keychain, and it never prints the
# password.
#
# Usage: scripts/prove-no-secret-in-state.sh   (TOFU=/path/to/tofu to choose the binary)

set -euo pipefail

tofu=${TOFU:-tofu}
repo=$(cd "$(dirname "$0")/.." && pwd)
tmp=${TMPDIR:-/tmp}
work=$(mktemp -d "${tmp%/}/macoskeychain-proof.XXXXXX")
keychain="$work/proof.keychain-db"

cleanup() {
	/usr/bin/security delete-keychain "$keychain" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT

# random_hex N prints N random hex characters (N even).
random_hex() {
	xxd -p -c 256 -l "$(($1 / 2))" /dev/urandom
}

# Commands go to `security -i` on standard input, so neither the keychain
# password nor the secret appears on a command line.
security_stdin() {
	printf '%s\n' "$1" | /usr/bin/security -i
}

echo "== OpenTofu: $("$tofu" version | head -n 1)"

echo "== Building the provider and proofsink"
mkdir -p "$work/plugins"
(cd "$repo" && go build -o "$work/plugins/terraform-provider-macoskeychain" .)
(cd "$repo" && go build -o "$work/plugins/terraform-provider-proofsink" ./internal/proofsink)

echo "== Creating a throwaway keychain in $work"
keychain_password=$(random_hex 32)
search_list_before=$(/usr/bin/security list-keychains -d user)
security_stdin "create-keychain -p \"$keychain_password\" \"$keychain\""
security_stdin "set-keychain-settings \"$keychain\""
security_stdin "unlock-keychain -p \"$keychain_password\" \"$keychain\""
if [[ "$(/usr/bin/security list-keychains -d user)" != "$search_list_before" ]]; then
	echo "FAIL: creating the throwaway keychain changed the user's keychain search list" >&2
	exit 1
fi

secret="proof-$(random_hex 40)"
service="macoskeychain-proof"
account="proof-$(random_hex 8)"
# No -A or -T: like most command-line items, it trusts only /usr/bin/security,
# which is what the provider runs to read it.
security_stdin "add-generic-password -s \"$service\" -a \"$account\" -w \"$secret\" \"$keychain\""
expected_sha=$(printf '%s' "$secret" | shasum -a 256 | cut -d ' ' -f 1)
echo "   stored a ${#secret}-character password with SHA-256 ${expected_sha:0:12}..."

cat >"$work/cli.tfrc" <<EOF
provider_installation {
  dev_overrides {
    "registry.opentofu.org/mikeastwoody/macoskeychain"  = "$work/plugins"
    "registry.terraform.io/mikeastwoody/macoskeychain" = "$work/plugins"
    "registry.opentofu.org/mikeastwoody/proofsink"     = "$work/plugins"
    "registry.terraform.io/mikeastwoody/proofsink"     = "$work/plugins"
  }
  direct {}
}
EOF
export TF_CLI_CONFIG_FILE="$work/cli.tfrc"
export TF_IN_AUTOMATION=1

config="$work/config"
cp -R "$repo/examples/no-secret-in-state" "$config"
proof_file="$work/proof.sha256"
write_only_proof_file="$work/write-only.sha256"
nonsensitive_proof_file="$work/nonsensitive.sha256"
vars=(
	-var "service=$service" -var "account=$account" -var "keychain=$keychain" -var "proof_file=$proof_file"
	-var "write_only_proof_file=$write_only_proof_file" -var "nonsensitive_proof_file=$nonsensitive_proof_file"
)

# run_tofu LOG ARGS... runs the CLI in the configuration directory with its
# output in LOG, which the final search also covers, and stops on failure.
run_tofu() {
	local log=$1
	shift
	if ! "$tofu" -chdir="$config" "$@" >"$log" 2>&1; then
		echo "FAIL: $tofu $1 exited with an error:" >&2
		cat "$log" >&2
		exit 1
	fi
}

echo "== $tofu plan -out=proof.tfplan"
run_tofu "$work/plan.log" plan -input=false -no-color -out=proof.tfplan "${vars[@]}"
grep -E '^(Plan:|  # |OpenTofu will perform|Terraform will perform)' "$work/plan.log" || true

echo "== $tofu apply proof.tfplan"
run_tofu "$work/apply.log" apply -input=false -no-color proof.tfplan
grep -E '^(Apply complete|terraform_data|proofsink_write_only)' "$work/apply.log" || true

# Everything to search goes to a file first: `! producer | grep -q` could
# pass by mistake under pipefail when grep finds a match and exits early.
mkdir "$work/rendered"
unzip -p "$config/proof.tfplan" >"$work/rendered/plan-file-contents"
run_tofu "$work/rendered/plan.json" show -json proof.tfplan
run_tofu "$work/rendered/state.json" show -json
printf '%s' "$secret" >"$work/control"

echo "== Checks"
failed=0
check() {
	local description=$1
	shift
	if "$@"; then
		echo "   PASS  $description"
	else
		echo "   FAIL  $description"
		failed=1
	fi
}
# A grep error (exit 2, such as a missing file) fails the check.
contains() { grep -aqF -- "$secret" "$1"; }
lacks() {
	local rc=0
	grep -aqF -- "$secret" "$1" || rc=$?
	[[ $rc -eq 1 ]]
}
no_file_contains() {
	local rc=0
	grep -rlaF --exclude=proof.keychain-db --exclude=control -- "$secret" "$work" >/dev/null || rc=$?
	[[ $rc -eq 1 ]]
}

received_sha=$(cut -d ' ' -f 1 "$proof_file")
write_only_sha=$(cut -d ' ' -f 1 "$write_only_proof_file")
nonsensitive_sha=$(cut -d ' ' -f 1 "$nonsensitive_proof_file")
check "the command received the stored password (SHA-256 ${received_sha:0:12}...)" test "$received_sha" = "$expected_sha"
check "the write-only argument received the stored password (SHA-256 ${write_only_sha:0:12}...)" test "$write_only_sha" = "$expected_sha"
check "the write-only argument received it through nonsensitive() (SHA-256 ${nonsensitive_sha:0:12}...)" test "$nonsensitive_sha" = "$expected_sha"
check "control: the search finds the password where it is present" contains "$work/control"
check "the state file exists" test -s "$config/terraform.tfstate"
check "the saved plan exists" test -s "$config/proof.tfplan"
check "the password is not in terraform.tfstate" lacks "$config/terraform.tfstate"
check "the password is not in any file inside the saved plan (unzipped)" lacks "$work/rendered/plan-file-contents"
check "the password is not in \`show -json\` of the saved plan" lacks "$work/rendered/plan.json"
check "the password is not in \`show -json\` of the state" lacks "$work/rendered/state.json"
check "the password is not in any file the run wrote, including CLI output" no_file_contains

if [[ $failed -ne 0 ]]; then
	echo "== FAILED" >&2
	exit 1
fi
echo "== OK: the password reached the command and the write-only arguments intact, and was written to neither the plan nor the state"
