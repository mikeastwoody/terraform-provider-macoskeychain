## 0.1.0 (Unreleased)

FEATURES:

* **New Ephemeral Resource:** `macoskeychain_password` reads a generic password item from the macOS Keychain by service and account, optionally from a given keychain file. The password is never written to a plan or state file.
* **New Ephemeral Resource:** `macoskeychain_internet_password` reads an internet password item by server and account, with the same guarantees.
* Clear errors for a missing item or keychain file, a locked keychain, an item whose access control does not trust the provider, a session that cannot show macOS dialogs, and platforms other than macOS. No error includes secret material.
