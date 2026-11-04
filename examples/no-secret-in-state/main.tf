# A runnable configuration that reads a password and hands it to a command,
# used by scripts/prove-no-secret-in-state.sh. Nothing in it needs a network
# provider: terraform_data and local-exec are built into OpenTofu.

terraform {
  required_version = ">= 1.11.0"

  required_providers {
    macoskeychain = {
      source = "mikeastwoody/macoskeychain"
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

ephemeral "macoskeychain_password" "demo" {
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
      SECRET     = ephemeral.macoskeychain_password.demo.password
      PROOF_FILE = var.proof_file
    }
  }
}
