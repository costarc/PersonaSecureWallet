# Personal Secure Wallet
A Python App to view and save encrypted data such as passwords and other secrets.

All encryption before storing the data on disk is done by using existing third-party software, such as OpenSSL and 7-Zip.

Before saving data, a passphrase should be defined, otherwise the file is saved in plain text.
Once entered, the passphrase will be used for the whole session or until is is set to something else), to either load other files or to save the current file.

The encryption method set in the external commands will ve AES-256.

# Quick Start Guide
All you need is "PersonalSecureWallet.pyw"

Use the Edit -> Options menu to hoose the encryption software to use (must be insalled on your computer)
Use Edit -> Passphrase to define the password to encrypt the file 
Enter the data you want in the text area, then use File -> Save As.. to save to disk

Do not forget your password, or your data will be definitively lost.
