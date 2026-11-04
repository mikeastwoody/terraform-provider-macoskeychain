## 0.1.0 (November 4, 2026)

FEATURES:

* **New Ephemeral Resource:** `macoskeychain_generic_password` reads a generic password item from the macOS Keychain by service and account, optionally from a given keychain file. The password is never written to a plan or state file.
* **New Ephemeral Resource:** `macoskeychain_internet_password` reads an internet password item by server and account, with the same guarantees.
* Reads through `/usr/bin/security`, so items created with `security add-generic-password` are read without a macOS dialog, and provider upgrades never ask for access again. The password reaches the provider through a pipe from that child process, never a command line. Pure Go, without cgo.
* Clear errors for a missing item or keychain file, a locked keychain or a session that cannot show macOS dialogs (SSH), denied or canceled access, and platforms other than macOS. No error includes secret material or the output of `security`.
