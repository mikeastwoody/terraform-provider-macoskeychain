# A configuration that reads a password and hands it to a command and to
# write-only arguments. It runs only through scripts/prove-no-secret-in-state.sh:
# it needs proofsink, a test-only provider in no registry, which the script builds
# from internal/proofsink and installs with dev_overrides. Nothing in it needs a
# network: terraform_data and local-exec are built into OpenTofu.

terraform {
  required_version = ">= 1.11.0"

  required_providers {
    macoskeychain = {
      source = "mikeastwoody/macoskeychain"
    }
    proofsink = {
      source = "mikeastwoody/proofsink"
    }
  }
}

variable "service" {
  type = string
}

variable "account" {
  type = string
}

variable "keychain" {
  type    = string
  default = null
}

variable "proof_file" {
  description = "File where the command writes the SHA-256 of the password it received."
  type        = string
}

variable "write_only_proof_file" {
  description = "File where proofsink writes the SHA-256 of the value its write-only argument received."
  type        = string
}

variable "nonsensitive_proof_file" {
  description = "The same, for the write-only argument that receives the password through nonsensitive()."
  type        = string
}

ephemeral "macoskeychain_generic_password" "demo" {
  service  = var.service
  account  = var.account
  keychain = var.keychain
}

# terraform_data stores its arguments in the state, so the password goes only
# to the provisioner's environment, which OpenTofu never records. The command
# writes a hash of what it received, so the run can prove the right value
# arrived without printing it.
resource "terraform_data" "consumer" {
  provisioner "local-exec" {
    command = "printf '%s' \"$SECRET\" | shasum -a 256 > \"$PROOF_FILE\""
    environment = {
      SECRET     = ephemeral.macoskeychain_generic_password.demo.password
      PROOF_FILE = var.proof_file
    }
  }
}

# A write-only argument reaches the resource's provider at apply and is never
# stored. proofsink writes a hash of what it received.
resource "proofsink_write_only" "direct" {
  value_wo   = ephemeral.macoskeychain_generic_password.demo.password
  proof_file = var.write_only_proof_file
}

# The form the provider's documentation gives for migrating a write-only
# argument: nonsensitive() drops the sensitive mark, not the ephemeral one.
resource "proofsink_write_only" "nonsensitive" {
  value_wo   = nonsensitive(ephemeral.macoskeychain_generic_password.demo.password)
  proof_file = var.nonsensitive_proof_file
}
