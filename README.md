# PersonaSecureWallet
A Python App to view and save encrypted data such as passwords and other secrets.

All encryption before storing the data on disk is done by using existing third-party software, such as OpenSSL and 7-Zip.

Before saving data, a passphrase should be defined, otherwise the file is saved in plain text.
Once entered, the passphrase will be used for the whole session or until is is set to something else), to either load other files or to save the current file.
