# Store the secret once from a terminal. With -w at the end, security prompts
# for the value, so it never lands in your shell history:
#
#   security add-generic-password -s sentry-auth-token -a deploy -w

ephemeral "macoskeychain_password" "sentry" {
  service = "sentry-auth-token"
  account = "deploy"
}

# Provider configurations accept ephemeral values.
provider "sentry" {
  token = ephemeral.macoskeychain_password.sentry.password
}

# So do write-only arguments, which are never stored either. This item lives in
# a separate keychain file instead of the default search list.
ephemeral "macoskeychain_password" "database" {
  service  = "app-database-password"
  account  = "app"
  keychain = pathexpand("~/Library/Keychains/infra.keychain-db")
}

resource "google_secret_manager_secret_version" "database" {
  secret                 = google_secret_manager_secret.database.id
  secret_data_wo         = ephemeral.macoskeychain_password.database.password
  secret_data_wo_version = 1
}
