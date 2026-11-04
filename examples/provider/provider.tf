terraform {
  required_providers {
    macoskeychain = {
      source = "mikeastwoody/macoskeychain"
    }
  }
}

# The provider has no configuration attributes.
provider "macoskeychain" {}
