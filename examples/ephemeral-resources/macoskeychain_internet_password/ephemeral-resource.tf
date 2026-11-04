# Internet passwords are what `security add-internet-password` creates and what
# Git credential helpers store:
#
#   security add-internet-password -s github.com -a deploy-bot -w

ephemeral "macoskeychain_internet_password" "github" {
  server  = "github.com"
  account = "deploy-bot"
}

provider "github" {
  token = ephemeral.macoskeychain_internet_password.github.password
}
